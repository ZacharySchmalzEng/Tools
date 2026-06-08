<#
.SYNOPSIS
    Unified state-driven deduplication engine for cross-OS profile consolidation.

.DESCRIPTION
    Consolidates scattered Windows and Linux profiles via cryptographic deduplication.
    Operates in two mutually exclusive modes:
    -Plan: Scans the target NTFS path, calculates SHA-256 hashes for namespace collisions, 
           and outputs a deterministic CSV execution plan.
    -Apply: Ingests the CSV state plan and executes filesystem mutations. Enforces strict 
            failures on unresolved 'RequiresReview' tags to prevent data destruction.

.AUTHOR
    Zachary Schmalz

.LINK
    https://github.com/ZacharySchmalzEng

.NOTES
    Date: 2026-06-08
    Architecture: State-Driven (Plan & Apply) via ParameterSets
#>
[CmdletBinding(DefaultParameterSetName='Plan')]
param (
    [Parameter(Mandatory=$true, ParameterSetName='Plan')]
    [switch]$Plan,

    [Parameter(Mandatory=$true, ParameterSetName='Apply')]
    [switch]$Apply,

    [Parameter(ParameterSetName='Plan', Position=0)]
    [Alias('Drive', 'Path')]
    [string]$SourcePath = "D:\",

    [Parameter(ParameterSetName='Plan')]
    [string]$DestinationPath = "D:\Merged_Profiles\",

    [Parameter(Mandatory=$false)]
    [string]$StateFilePath = "D:\Dedupe_StatePlan.csv"
)

# -------------------------------------------------------------------------
# PHASE 1: ANALYSIS & STATE GENERATION (-Plan)
# -------------------------------------------------------------------------
if ($PSCmdlet.ParameterSetName -eq 'Plan') {
    # Normalize paths for substring math during traversal
    $SourcePath = Join-Path $SourcePath "\"
    $DestinationPath = Join-Path $DestinationPath "\"
    $StatePlan = [System.Collections.Generic.List[PSObject]]::new()

    Write-Host "[*] [PLAN MODE] Initiating MFT traversal and hash calculation on $SourcePath..." -ForegroundColor Cyan

    $ProfileArtifacts = @("Documents", "Downloads", "Desktop", "Music", "Pictures", ".bashrc", "NTUSER.DAT")
    # Bypass system-level noise. Applies cleanly whether scanning a root drive or sub-directory.
    $ExcludePattern = "^(System Volume Information|\`$RECYCLE\.BIN|Windows)"

    $Directories = Get-ChildItem -Path $SourcePath -Directory -Recurse -Depth 4 -ErrorAction SilentlyContinue | Where-Object {
        -not ($_.FullName.Substring($SourcePath.Length) -match $ExcludePattern)
    }

    foreach ($Dir in $Directories) {
        $Matched = 0
        foreach ($Artifact in $ProfileArtifacts) {
            if (Test-Path (Join-Path $Dir.FullName $Artifact)) { $Matched++ }
        }
        
        if ($Matched -ge 2) {
            $Files = Get-ChildItem -Path $Dir.FullName -File -Recurse -ErrorAction SilentlyContinue
            foreach ($File in $Files) {
                $RelativePath = $File.FullName.Substring($Dir.FullName.Length + 1)
                $TargetFilePath = Join-Path $DestinationPath $RelativePath
                
                $Action = "CleanMove"
                $SourceHash = $null
                $TargetHash = $null
                $FinalDestination = $TargetFilePath

                if (Test-Path $TargetFilePath) {
                    $SourceHash = (Get-FileHash -Path $File.FullName -Algorithm SHA256).Hash
                    $TargetHash = (Get-FileHash -Path $TargetFilePath -Algorithm SHA256).Hash
                    
                    if ($SourceHash -eq $TargetHash) {
                        $Action = "DeleteDuplicate"
                    } else {
                        $Action = "RequiresReview"
                    }
                }

                $StatePlan.Add([PSCustomObject]@{
                    Action            = $Action
                    SourcePath        = $File.FullName
                    DestinationPath   = $FinalDestination
                    SourceHash        = $SourceHash
                    TargetHash        = $TargetHash
                })
            }
        }
    }

    $StatePlan | Export-Csv -Path $StateFilePath -NoTypeInformation -Encoding UTF8
    Write-Host "[+] [PLAN MODE] State plan generated at: $StateFilePath." -ForegroundColor Green
    return
}

# -------------------------------------------------------------------------
# PHASE 2: STATE EXECUTION (-Apply)
# -------------------------------------------------------------------------
if ($PSCmdlet.ParameterSetName -eq 'Apply') {
    if (-not (Test-Path $StateFilePath)) { throw "State file not found at $StateFilePath" }

    $ExecutionPlan = Import-Csv -Path $StateFilePath
    Write-Host "[*] [APPLY MODE] Ingested $($ExecutionPlan.Count) records. Commencing execution..." -ForegroundColor Cyan

    foreach ($Item in $ExecutionPlan) {
        if ($Item.Action -eq "Skip") { continue }

        if ($Item.Action -eq "RequiresReview") {
            Write-Host " [HALT] Unresolved collision detected for $($Item.SourcePath). Skipping file." -ForegroundColor Red
            continue
        }

        $TargetDir = Split-Path $Item.DestinationPath -Parent
        if (-not (Test-Path $TargetDir)) { New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null }

        try {
            switch ($Item.Action) {
                "CleanMove" {
                    Move-Item -Path $Item.SourcePath -Destination $Item.DestinationPath -ErrorAction Stop
                    Write-Host " [MOVE] $($Item.SourcePath)"
                }
                "Rename" {
                    Move-Item -Path $Item.SourcePath -Destination $Item.DestinationPath -ErrorAction Stop
                    Write-Host " [RENAME] $($Item.SourcePath) -> $($Item.DestinationPath)" -ForegroundColor Yellow
                }
                "Overwrite" {
                    Move-Item -Path $Item.SourcePath -Destination $Item.DestinationPath -Force -ErrorAction Stop
                    Write-Host " [OVERWRITE] Disparate target destroyed. Moved $($Item.SourcePath)" -ForegroundColor DarkMagenta
                }
                "DeleteDuplicate" {
                    Remove-Item -Path $Item.SourcePath -Force -ErrorAction Stop
                    Write-Host " [DELETE] True Duplicate: $($Item.SourcePath)" -ForegroundColor DarkGray
                }
                Default {
                    Write-Host " [ERROR] Unknown action '$($Item.Action)' for $($Item.SourcePath)" -ForegroundColor Red
                }
            }
        } catch {
            Write-Host " [ERROR] Failed to process $($Item.SourcePath): $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    Write-Host "[+] [APPLY MODE] Execution complete." -ForegroundColor Green
}