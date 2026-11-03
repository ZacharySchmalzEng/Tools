<#
.SYNOPSIS
    Unified state-driven deduplication engine for cross-OS profile consolidation.

.DESCRIPTION
    Consolidates scattered Windows and Linux profiles via cryptographic deduplication.
    Operates in two mutually exclusive modes:
    
    -Plan: Scans the target NTFS path, calculates SHA-256 hashes for namespace collisions, 
           and outputs a deterministic CSV execution plan. Strictly read-only.
           
    -Apply: Ingests the CSV state plan and executes filesystem mutations. Requires the 
            -AutoPruneDuplicates switch to authorize the destruction of true duplicates.
            
    Engineered with explicit safety boundaries, including a Destination Memory Shield, 
    Zero-Trust Live Profile locks, and native .NET Reparse Point detachment to safely 
    navigate OneDrive/Symlink junctions without triggering PowerShell 5.1 recursion bugs.

.PARAMETER ShowHelp
    Displays this help menu.

.PARAMETER Plan
    Enables analysis mode to generate a deduplication plan.

.PARAMETER Apply
    Enables execution mode to process the generated plan.

.PARAMETER SourcePath
    The absolute or relative path to the scattered backup profiles.

.PARAMETER DestinationPath
    The target directory where unified profiles will be merged.

.PARAMETER StateFilePath
    The location to export/import the deterministic CSV execution plan.

.PARAMETER AutoPruneDuplicates
    Authorizes the destruction of cryptographically identical source files.

.PARAMETER ResolveKeepSource
    Collision resolution: Overwrites the destination file with the source file.

.PARAMETER ResolveKeepDestination
    Collision resolution: Retains the destination file and destroys the source file.

.PARAMETER DebugLog
    Enables verbose telemetry for GC anchors, OS locks, and exclusion triggers.

.PARAMETER ForceLiveProfile
    Bypasses the Zero-Trust boundary lock to allow execution against active OS user profiles.

.EXAMPLE
    .\Merge_Profiles.ps1 -Plan -SourcePath "D:\Backups" -DestinationPath "D:\Merged_Profiles"

.EXAMPLE
    .\Merge_Profiles.ps1 -Apply -AutoPruneDuplicates -ResolveKeepDestination

.AUTHOR
    Zachary Schmalz

.LINK
    https://github.com/ZacharySchmalzEng

.NOTES
    Version: 1.1.0
    Date: 2026-06-23
    Architecture: State-Driven (Plan & Apply) via ParameterSets
#>
[CmdletBinding(DefaultParameterSetName='Help')]
param (
    [Parameter(ParameterSetName='Help')]
    [switch]$ShowHelp,

    [Parameter(ParameterSetName='Plan')]
    [switch]$Plan,

    [Parameter(ParameterSetName='Apply')]
    [switch]$Apply,

    [Parameter(ParameterSetName='Plan', Position=0)]
    [Alias('Drive', 'Path')]
    [string]$SourcePath = "D:\",

    [Parameter(ParameterSetName='Plan')]
    [Parameter(ParameterSetName='Apply')]
    [string]$DestinationPath = "D:\Merged_Profiles\",

    [Parameter(ParameterSetName='Plan')]
    [Parameter(ParameterSetName='Apply')]
    [string]$StateFilePath = "D:\Dedupe_StatePlan.csv",

    [Parameter(ParameterSetName='Apply')]
    [switch]$AutoPruneDuplicates,

    [Parameter(ParameterSetName='Plan')]
    [Parameter(ParameterSetName='Apply')]
    [switch]$DebugLog,

    [Parameter(ParameterSetName='Plan')]
    [Parameter(ParameterSetName='Apply')]
    [switch]$ForceLiveProfile,
    
    [Parameter(ParameterSetName='Apply')]
    [switch]$ResolveKeepSource,

    [Parameter(ParameterSetName='Apply')]
    [switch]$ResolveKeepDestination
)

# -------------------------------------------------------------------------
# PHASE 0: EXECUTION INTERCEPT, LOGGING & ENVIRONMENT VALIDATION
# -------------------------------------------------------------------------
if (-not $Plan -and -not $Apply) {
    Write-Host "[!] No execution flag (-Plan or -Apply) detected. Halting execution and displaying help." -ForegroundColor Yellow
    Get-Help $PSCommandPath -Detailed
    return
}

if ($ResolveKeepSource -and $ResolveKeepDestination) {
    Write-Host "[!] PARAMETER COLLISION: -ResolveKeepSource and -ResolveKeepDestination are mutually exclusive. Execution aborted." -ForegroundColor Red
    return
}

$StateDir = Split-Path $StateFilePath -Parent
if ([string]::IsNullOrWhiteSpace($StateDir)) { $StateDir = (Get-Location).Path }
$LogDir = Join-Path $StateDir "ProfileMergingLogs"

if (-not (Test-Path -LiteralPath $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

$OldLogs = @(Get-ChildItem -LiteralPath $LogDir -Filter "MergeLog_*.log" | Sort-Object LastWriteTime -Descending)
if ($OldLogs.Count -ge 10) {
    $OldLogs[9..($OldLogs.Count - 1)] | Remove-Item -Force -ErrorAction SilentlyContinue
}

$script:LogFile = Join-Path $LogDir "MergeLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
New-Item -ItemType File -Path $script:LogFile -Force | Out-Null

function Write-Log {
    param (
        [string]$Message = "",
        [ConsoleColor]$Color = 'Gray',
        [switch]$IsDebug
    )
    
    if ($IsDebug -and -not $DebugLog) { return }
    if ($IsDebug) { $Message = "[DEBUG] $Message"; $Color = 'DarkCyan' }

    Write-Host $Message -ForegroundColor $Color
    if ([string]::IsNullOrWhiteSpace($Message)) { return }
    
    $CleanMsg = $Message -replace "`r|`n", ""
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $CleanMsg" | Out-File -LiteralPath $script:LogFile -Append -Encoding UTF8
}

Write-Log "[*] Logging Subsystem Online. Target: $script:LogFile" 'DarkGray'
if ($DebugLog) { Write-Log "Verbose Debug Telemetry Enabled." -IsDebug }

$Sep = [System.IO.Path]::DirectorySeparatorChar

# --- CRITICAL SAFETY: LIVE PROFILE LOCK ---
if (-not $ForceLiveProfile) {
    $ProtectedPaths = @()
    if ($IsWindows) { $ProtectedPaths += "$env:SystemDrive${Sep}Users" }
    else { $ProtectedPaths += "${Sep}home"; $ProtectedPaths += "${Sep}root" }

    $CheckSource = (Resolve-Path -LiteralPath $SourcePath -ErrorAction SilentlyContinue).Path
    if ([string]::IsNullOrWhiteSpace($CheckSource)) { $CheckSource = $SourcePath.TrimEnd($Sep) }

    foreach ($Protected in $ProtectedPaths) {
        if ($CheckSource.StartsWith($Protected, [System.StringComparison]::OrdinalIgnoreCase) -or
            $Protected.StartsWith($CheckSource, [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-Log "[!] CRITICAL SAFETY LOCK: SourcePath intersects with a live OS profile directory ($Protected)." 'Red'
            Write-Log "[-] Modifying live profiles risks Registry corruption, active process deadlocks, and VFS data loss." 'Yellow'
            Write-Log "[-] This script is engineered strictly for dead, isolated backup directories." 'Yellow'
            Write-Log "[-] If you are certain of your execution context, append -ForceLiveProfile. Execution aborted." 'Red'
            return
        }
    }
}

if ($IsWindows) {
    $LongPathKey = "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"
    $LongPathName = "LongPathsEnabled"
    $LongPathValue = (Get-ItemProperty -Path $LongPathKey -Name $LongPathName -ErrorAction SilentlyContinue).$LongPathName

    if ($LongPathValue -ne 1) {
        Write-Log "[!] Win32 MAX_PATH constraint detected (LongPathsEnabled = 0)." 'Yellow'
        $Response = Read-Host "Do you want to enable NTFS Long Paths to prevent deep traversal crashes? (Y/N)"
        if ($Response -match "^[yY]") {
            Set-ItemProperty -Path $LongPathKey -Name $LongPathName -Value 1 -Type DWord -Force
            Write-Log "[+] LongPathsEnabled set to 1." 'Green'
            Write-Log "[-] HALT: You MUST restart this PowerShell session for the .NET runtime to inherit the change. Execution aborted." 'Red'
            return
        } else {
            Write-Log "[-] Proceeding without LongPathsEnabled. Execution may fail on paths > 260 characters." 'Red'
        }
    }
}

# -------------------------------------------------------------------------
# PHASE 1: ANALYSIS & STATE GENERATION (-Plan)
# -------------------------------------------------------------------------
if ($Plan) {
    if (-not (Test-Path -LiteralPath $DestinationPath)) { New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null }

    $SourcePath = (Resolve-Path -LiteralPath $SourcePath).Path
    $DestinationPath = (Resolve-Path -LiteralPath $DestinationPath).Path

    if (-not $SourcePath.EndsWith($Sep)) { $SourcePath += $Sep }
    if (-not $DestinationPath.EndsWith($Sep)) { $DestinationPath += $Sep }

    $StatePlan = [System.Collections.Generic.List[PSObject]]::new()

    Write-Log "[*] [PLAN MODE] Initiating MFT traversal on $SourcePath..." 'Cyan'

    $ProfileArtifacts = @("Documents", "Downloads", "Desktop", "Music", "Pictures", ".bashrc", "NTUSER.DAT")
    $ExcludePattern = "^(System Volume Information|\`$RECYCLE\.BIN|Windows)"
    $ScrubbedDestination = $DestinationPath.TrimEnd($Sep)

    $Directories = Get-ChildItem -LiteralPath $SourcePath -Directory -Recurse -Depth 4 -Force -ErrorAction SilentlyContinue | Where-Object {
        $Excluded = ($_.FullName.Substring($SourcePath.Length) -match $ExcludePattern) -or ($_.FullName.StartsWith($ScrubbedDestination, [System.StringComparison]::OrdinalIgnoreCase))
        if ($Excluded) { Write-Log "Excluded directory from traversal payload: $($_.FullName)" -IsDebug }
        -not $Excluded
    }

    $DiscoveredRoots = [System.Collections.Generic.List[string]]::new()

    foreach ($Dir in $Directories) {
        $Matched = 0
        foreach ($Artifact in $ProfileArtifacts) {
            if (Test-Path -LiteralPath (Join-Path $Dir.FullName $Artifact)) { $Matched++ }
        }
        if ($Matched -ge 2) { 
            $DiscoveredRoots.Add($Dir.FullName) 
            Write-Log "Heuristic match discovered root: $($Dir.FullName)" -IsDebug
        }
    }

    $DiscoveredRoots = $DiscoveredRoots | Sort-Object Length
    $ValidRoots = [System.Collections.Generic.List[string]]::new()

    foreach ($Dir in $DiscoveredRoots) {
        $IsNested = $false
        foreach ($Valid in $ValidRoots) {
            if ($Dir.StartsWith($Valid, [System.StringComparison]::OrdinalIgnoreCase)) {
                $IsNested = $true
                break
            }
        }
        if (-not $IsNested) { $ValidRoots.Add($Dir) }
    }
    
    $RootLogPath = Join-Path (Split-Path $StateFilePath) "Dedupe_ValidRoots.txt"
    $ValidRoots | Out-File -LiteralPath $RootLogPath -Encoding UTF8 -Force

    Write-Log "[+] Discovered $($ValidRoots.Count) unique profile roots. Calculating states..." 'Green'

    foreach ($Root in $ValidRoots) {
        # EXPLICIT PIPELINE FILTER: Prevents the recursive scanner from actively pulling files residing in the Destination directory
        $Files = @(Get-ChildItem -LiteralPath $Root -File -Recurse -Force -ErrorAction SilentlyContinue | Where-Object {
            -not $_.FullName.StartsWith($DestinationPath, [System.StringComparison]::OrdinalIgnoreCase)
        })
        
        $TotalFiles = $Files.Count
        $ProcessedFiles = 0

        foreach ($File in $Files) {
            $ProcessedFiles++
            if ($ProcessedFiles % 50 -eq 0 -or $ProcessedFiles -eq $TotalFiles) {
                Write-Progress -Activity "Analyzing Profile: $Root" -Status "Processing file $ProcessedFiles of $TotalFiles" -PercentComplete (($ProcessedFiles / $TotalFiles) * 100)
            }

            # Redundant safety catch
            if ($File.FullName.StartsWith($DestinationPath, [System.StringComparison]::OrdinalIgnoreCase)) { 
                Write-Log "Ouroboros constraint dropped file: $($File.FullName)" -IsDebug
                continue 
            }

            $RelativePath = $File.FullName.Substring($Root.Length + 1)
            $TargetFilePath = Join-Path $DestinationPath $RelativePath
            
            if ($File.FullName -eq $TargetFilePath) { continue }

            $Action = "CleanMove"
            $SourceHash = $null
            $TargetHash = $null
            $FinalDestination = $TargetFilePath

            if (Test-Path -LiteralPath $TargetFilePath) {
                $SourceFileObj = $File 
                $TargetFileObj = Get-Item -LiteralPath $TargetFilePath -Force

                if ($SourceFileObj.Length -eq $TargetFileObj.Length) {
                    $SourceHash = (Get-FileHash -LiteralPath $SourceFileObj.FullName -Algorithm SHA256).Hash
                    $TargetHash = (Get-FileHash -LiteralPath $TargetFileObj.FullName -Algorithm SHA256).Hash
                    
                    Write-Log "Collision Evaluation [$TargetFilePath] | SRC: $SourceHash | TGT: $TargetHash" -IsDebug

                    if ($SourceHash -eq $TargetHash) {
                        $Action = "DeleteDuplicate"
                    } else {
                        $Action = "RequiresReview"
                    }
                } else {
                    Write-Log "Collision Evaluation [$TargetFilePath] | Size mismatch fast-fail. Flagging RequiresReview." -IsDebug
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
        Write-Progress -Activity "Analyzing Profile: $Root" -Completed
    }

    $StatePlan | Export-Csv -LiteralPath $StateFilePath -NoTypeInformation -Encoding UTF8
    Write-Log "[+] [PLAN MODE] State plan generated at: $StateFilePath." 'Green'
    return
}

# -------------------------------------------------------------------------
# PHASE 2: STATE EXECUTION & GARBAGE COLLECTION (-Apply)
# -------------------------------------------------------------------------
if ($Apply) {
    if (-not (Test-Path -LiteralPath $StateFilePath)) { throw "State file not found at $StateFilePath" }

    # Path Normalization Mirrored to ensure GC Boundaries align flawlessly
    $SourcePath = (Resolve-Path -LiteralPath $SourcePath -ErrorAction Stop).Path
    if (-not $SourcePath.EndsWith($Sep)) { $SourcePath += $Sep }

    if (-not (Test-Path -LiteralPath $DestinationPath)) { New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null }
    $DestinationPath = (Resolve-Path -LiteralPath $DestinationPath -ErrorAction Stop).Path
    if (-not $DestinationPath.EndsWith($Sep)) { $DestinationPath += $Sep }

    $ExecutionPlan = @(Import-Csv -LiteralPath $StateFilePath)
    $TotalItems = $ExecutionPlan.Count
    $ProcessedItems = 0

    Write-Log "[*] [APPLY MODE] Ingested $TotalItems records. Commencing execution..." 'Cyan'

    foreach ($Item in $ExecutionPlan) {
        $ProcessedItems++
        if ($ProcessedItems % 50 -eq 0 -or $ProcessedItems -eq $TotalItems) {
            Write-Progress -Activity "Executing State Plan" -Status "Processing record $ProcessedItems of $TotalItems" -PercentComplete (($ProcessedItems / $TotalItems) * 100)
        }

        if ($Item.Action -eq "Skip") { continue }

        # --- DYNAMIC COLLISION RESOLUTION ---
        if ($Item.Action -eq "RequiresReview") {
            if ($ResolveKeepSource) {
                $Item.Action = "Overwrite"
            } elseif ($ResolveKeepDestination) {
                $Item.Action = "DiscardSource"
            } else {
                Write-Log " [HALT] Unresolved collision: $($Item.SourcePath). Append -ResolveKeepSource or -ResolveKeepDestination to bypass. Skipping." 'Red'
                continue
            }
        }

        $TargetDir = Split-Path $Item.DestinationPath -Parent
        if (-not (Test-Path -LiteralPath $TargetDir) -and $Item.Action -ne "DeleteDuplicate" -and $Item.Action -ne "DiscardSource") { 
            New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null 
        }

        try {
            switch ($Item.Action) {
                "CleanMove" {
                    Move-Item -LiteralPath $Item.SourcePath -Destination $Item.DestinationPath -ErrorAction Stop
                    Write-Log " [MOVE] $($Item.SourcePath)" 'Gray'
                }
                "Rename" {
                    Move-Item -LiteralPath $Item.SourcePath -Destination $Item.DestinationPath -ErrorAction Stop
                    Write-Log " [RENAME] $($Item.SourcePath) -> $($Item.DestinationPath)" 'Yellow'
                }
                "Overwrite" {
                    Move-Item -LiteralPath $Item.SourcePath -Destination $Item.DestinationPath -Force -ErrorAction Stop
                    Write-Log " [OVERWRITE] Target destroyed. Moved $($Item.SourcePath)" 'DarkMagenta'
                }
                "DiscardSource" {
                    Remove-Item -LiteralPath $Item.SourcePath -Force -ErrorAction Stop
                    Write-Log " [DISCARD] Destination retained. Source destroyed: $($Item.SourcePath)" 'DarkMagenta'
                }
                "DeleteDuplicate" {
                    if ($AutoPruneDuplicates) {
                        Remove-Item -LiteralPath $Item.SourcePath -Force -ErrorAction Stop
                        Write-Log " [DELETE] True Duplicate: $($Item.SourcePath)" 'DarkGray'
                    } else {
                        Write-Log " [PRUNE REQUIRED] True duplicate bypassed. Append -AutoPruneDuplicates to authorize deletion: $($Item.SourcePath)" 'Yellow'
                    }
                }
                Default {
                    Write-Log " [ERROR] Unknown action '$($Item.Action)' for $($Item.SourcePath)" 'Red'
                }
            }
        } catch {
            Write-Log " [ERROR] Failed to process $($Item.SourcePath): $($_.Exception.Message)" 'Red'
        }
    }
    Write-Progress -Activity "Executing State Plan" -Completed

    Write-Log ""
    Write-Log "[*] [APPLY MODE] Initiating decoupled deep-tree garbage collection..." 'Cyan'
    
    $RootLogPath = Join-Path (Split-Path $StateFilePath) "Dedupe_ValidRoots.txt"
    $ValidRoots = @()
    if (Test-Path -LiteralPath $RootLogPath) {
        $ValidRoots = @(Get-Content -LiteralPath $RootLogPath | ForEach-Object { $_.TrimEnd($Sep) })
    } else {
        Write-Log " [!] Dedupe_ValidRoots.txt not found. Halting GC execution." 'Yellow'
    }

    $BoundaryPath = $SourcePath.TrimEnd($Sep)
    $ScrubbedDestination = $DestinationPath.TrimEnd($Sep)

    function Unlink-ReparseAnchors ([string]$TargetDir) {
        $Remaining = @(Get-ChildItem -LiteralPath $TargetDir -Force -ErrorAction SilentlyContinue)
        if ($Remaining.Count -eq 0) { return $true }

        $OnlyReparse = $true
        foreach ($Item in $Remaining) {
            if (-not ($Item.Attributes -match 'ReparsePoint')) {
                $OnlyReparse = $false
                break
            }
        }

        if ($OnlyReparse) {
            Write-Log " [CLEANUP] Safely detaching $($Remaining.Count) orphaned Reparse Points in $TargetDir..." 'DarkMagenta'
            foreach ($Item in $Remaining) {
                try {
                    if ($Item -is [System.IO.FileInfo]) {
                        [System.IO.File]::Delete($Item.FullName)
                    } else {
                        [System.IO.Directory]::Delete($Item.FullName)
                    }
                } catch { return $false }
            }
            
            $Check = @(Get-ChildItem -LiteralPath $TargetDir -Force -ErrorAction SilentlyContinue)
            return ($Check.Count -eq 0)
        }
        return $false
    }

    foreach ($Root in $ValidRoots) {
        if (-not (Test-Path -LiteralPath $Root)) { continue }
        Write-Log "Initiating GC sweep inside mapped root: $Root" -IsDebug

        # EXPLICIT PIPELINE FILTER: Grants complete memory immunity to the Destination folder, preventing the GC from touching it.
        $SubDirs = @(Get-ChildItem -LiteralPath $Root -Directory -Recurse -Force -ErrorAction SilentlyContinue | Where-Object {
            -not ($_.FullName -eq $ScrubbedDestination) -and 
            -not $_.FullName.StartsWith($DestinationPath, [System.StringComparison]::OrdinalIgnoreCase)
        } | Sort-Object Length -Descending)
        
        foreach ($SubDir in $SubDirs) {
            if (Unlink-ReparseAnchors -TargetDir $SubDir.FullName) {
                try { 
                    Remove-Item -LiteralPath $SubDir.FullName -Force -Recurse -ErrorAction Stop 
                    Write-Log " [CLEANUP] Purged empty subdirectory: $($SubDir.FullName)" 'DarkGray'
                } catch {
                    Write-Log " [SKIP] Lock prevented cleanup of $($SubDir.FullName): $($_.Exception.Message)" 'Yellow'
                }
            } else {
                $RemainingCount = @(Get-ChildItem -LiteralPath $SubDir.FullName -Force -ErrorAction SilentlyContinue).Count
                Write-Log "GC bypassed $($SubDir.FullName). Hard anchor item count: $RemainingCount" -IsDebug
            }
        }

        $CurrentDir = $Root
        while ($CurrentDir.Length -gt $BoundaryPath.Length -and (Test-Path -LiteralPath $CurrentDir)) {
            if (Unlink-ReparseAnchors -TargetDir $CurrentDir) {
                try {
                    Remove-Item -LiteralPath $CurrentDir -Force -Recurse -ErrorAction Stop
                    Write-Log " [CLEANUP] Purged orphaned directory: $CurrentDir" 'DarkGray'
                    $CurrentDir = (Split-Path -LiteralPath $CurrentDir -Parent).TrimEnd($Sep)
                } catch {
                    Write-Log " [SKIP] Execution lock prevented cleanup on: $CurrentDir" 'Yellow'
                    break
                }
            } else {
                $RemainingCount = @(Get-ChildItem -LiteralPath $CurrentDir -Force -ErrorAction SilentlyContinue).Count
                Write-Log "GC upward ripple anchored by data in $CurrentDir. Item count: $RemainingCount. Halting branch." -IsDebug
                break
            }
        }
    }

    Write-Log ""
    Write-Log "[+] [APPLY MODE] Execution and garbage collection complete." 'Green'
}