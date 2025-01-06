################################################################################
##  Remote Collection Requirement Checker V2.1                                ##
##  Written 10/30/2018                                                        ##
##  Updated 12/24/2024                                                        ##
##                                                                            ##
##  Authors:                                                                  ##
##  Cody Puckett -  Support Services Manager                                  ##
##  Justin Henning - Tier 4 Sofware Engineer                                  ##
##  Zachary Schmalz - Tier 4 Systems Engineer                                 ##
##                                                                            ##
##  Description:                                                              ##
##  Check Host has necessary settings for Remote Windows Event Log Collection ##
##  and update the DP settings.                                               ##
################################################################################

##Varables
#Set DP Address here:
$mediatorIP = 'x.x.x.x'


#If not run as admin, lauch PowerShell under Administrator Context.
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{   
    $arguments = "& '" + $myinvocation.mycommand.definition + "'"
    Start-Process powershell -Verb runAs -ArgumentList $arguments
    Break
}

#File to output.
$OutputFile = "C:\Users\$env:UserName\Desktop\RemoteCollection.txt";

#Hostname/OS Variables
$hostname = hostname;
$OS = (gwmi win32_operatingsystem).caption;


#Check Computer Hostname and ipconfig
 "This script was executed on the following system:" | Out-File -FilePath $OutputFile
 '****************************************************************************************'| Out-File -FilePath $OutputFile -Append
''| Out-File -FilePath $OutputFile -Append
"Hostname:$hostname" | Out-File -FilePath $OutputFile -Append
ipconfig | Out-File -FilePath $OutputFile -Append
'****************************************************************************************'| Out-File -FilePath $OutputFile -Append

''| Out-File -FilePath $OutputFile -Append
"Current Host Operating System: $OS" | Out-File -FilePath $OutputFile -Append
'****************************************************************************************'| Out-File -FilePath $OutputFile -Append

''| Out-File -FilePath $OutputFile -Append
#Check required services are enabled.
"A host value is required for functionality. Setting values:" | Out-File -FilePath $OutputFile -Append
'****************************************************************************************'| Out-File -FilePath $OutputFile -Append
#Make backup and then create new scsm.ini
try 
{
    Remove-Item -Path 'C:\Program Files\LogRhythm\LogRhythm System Monitor\config\scsm.ini.bak' -ErrorAction SilentlyContinue
	Rename-Item 'C:\Program Files\LogRhythm\LogRhythm System Monitor\config\scsm.ini' -NewName 'C:\Program Files\LogRhythm\LogRhythm System Monitor\config\scsm.ini.bak'
	
	$MediatorBlock = "[Mediator 1]`nClientAddress=0`nHost=$mediatorIP`nServerPort=443`nClientPort=0"
	Set-Content -Path 'C:\Program Files\LogRhythm\LogRhythm System Monitor\config\scsm.ini' -Value $MediatorBlock
    
    Restart-Service scsm
}
catch 
{
    "Update failed" | Out-File -FilePath $OutputFile -Append
}

''| Out-File -FilePath $OutputFile -Append

#Enable TLS 1.2
"TLS 1.2 is required for DP communication. Enabling TLS 1.2." | Out-File -FilePath $OutputFile -Append
'****************************************************************************************'| Out-File -FilePath $OutputFile -Append
# Create the key if it does not exist
If (-NOT (Test-Path 'HklmSoftwarePath\Policies\Microsoft\Cryptography\Configuration\SSL\00010002')) 
{
  New-Item -Path 'HklmSoftwarePath\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Force | Out-Null
  New-ItemProperty -Path "HklmSoftwarePath\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name "Functions"  -PropertyType String -Value ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384")
  New-ItemProperty -Path "HklmSoftwarePath\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name "EccCurves" -PropertyType MultiString -Value @("NistP256", "NistP384")
}  

''| Out-File -FilePath $OutputFile -Append

#Check required services are enabled.
"The Following shows 4 services that must be running in order for remote collection to function properly." | Out-File -FilePath $OutputFile -Append
'****************************************************************************************'| Out-File -FilePath $OutputFile -Append
$Services = @('Server', 'RemoteRegistry');
ForEach($service in $services) 
{
    if((Get-Service -Name $service).Status -eq 'Running')
    {
        "$service Service is Running - (PASS)" | Out-File -FilePath $OutputFile -Append
    }
    else {
        "$service Service is NOT Running - FAIL!. You need to start this service in order for remote collection to function properly! Attempting to restart." | Out-File -FilePath $OutputFile -Append
		Restart-Service $services
    }
}

''| Out-File -FilePath $OutputFile -Append
#Check Firewall Rules are Enabled.
''| Out-File -FilePath $OutputFile -Append
"This section will show 3 Fire wall rules that should state Enabled: Yes in order for remote collection to function properly" | Out-File -FilePath $OutputFile -Append
'****************************************************************************************' | Out-File -FilePath $OutputFile -Append
$fwRules = @('Remote Event Log Management (NP-In)','Remote Event Log Management (RPC)','Remote Event Log Management (RPC-EPMAP)');
ForEach($rule in $fwRules) 
{
    "$rule Enabled: $(if((netsh advfirewall firewall show rule name= "$rule" | Select-String -Pattern '^.*Enabled:\s+No').length -gt 0){"NO - FAIL!"}else{"YES - (PASS)"})" | Out-File -FilePath $OutputFile -Append
}
"Firewall Rule Configurations: " | Out-File -FilePath $OutputFile -Append
ForEach($rule in $fwRules) 
{
    netsh advfirewall firewall show rule name= "$rule" | Out-File -FilePath $OutputFile -Append
}

#Check File and Printer Sharing is enabled.
''| Out-File -FilePath $OutputFile -Append
"The following shows File and Printer Sharing for all NICs, File and Printer Sharing for Microsoft Networks must be enabled for remote collection to function properly!" | Out-File -FilePath $OutputFile -Append
'****************************************************************************************' | Out-File -FilePath $OutputFile -Append
ForEach($binding in (Get-NetAdapterBinding | Where-Object {$_.DisplayName -eq 'File and Printer Sharing for Microsoft Networks'})) {
    "$($binding.Name) - Enabled: $(if($binding.DisplayName -eq 'File and Printer Sharing for Microsoft Networks') {if($binding.Enabled){"$($binding.Enabled) -- (PASS)"}else{"$($binding.Enabled) -- FAIL!"}})" | Out-File -FilePath $OutputFile -Append
}
"All Adapter Bindings: " | Out-File -FilePath $OutputFile -Append
Get-NetAdapterBinding | Where-Object {$_.DisplayName -eq 'File and Printer Sharing for Microsoft Networks'} | Out-File -FilePath $OutputFile -Append
  
 
#Check Registry Permissions  
'****************************************************************************************' | Out-File -FilePath $OutputFile -Append
"The following shows user permissions for 2 registry keys, the service account running on the agent that is performing the remote collection and must be a part of the Event Log Readers Group in order for remote collection to function properly" | Out-File -FilePath $OutputFile -Append


######

$acl = Get-Acl -Path "HKLM:\SYSTEM\ControlSet001\Services\EventLog\Security\Microsoft-Windows-Security-Auditing"
$acl | Format-List | Out-File -FilePath $OutputFile -Append

$acl = Get-Acl -Path "HKLM:\SYSTEM\CurrentControlSet\services\eventlog\Security\Microsoft-Windows-Security-Auditing"
$acl | Format-List | Out-File -FilePath $OutputFile -Append 

  
'****************************************************************************************' | Out-File -FilePath $OutputFile -Append
'This section will check permissions of the Application/System/Security event log registry keys.  This should tell you if the service account the agent is running under is a part of the event log readers group'| Out-File -FilePath $OutputFile -Append
    
net localgroup "Event Log Readers" | Out-File -FilePath $OutputFile -Append
net localgroup "Administrators" | Out-File -FilePath $OutputFile -Append

#Check Ports are open

'' | Out-File -FilePath $OutputFile -Append  
'This section will check if ports are open, verifying communication.' | Out-File -FilePath $OutputFile -Append
'****************************************************************************************' | Out-File -FilePath $OutputFile -Append
'' | Out-File -FilePath $OutputFile -Append

$ports = @(135, 139, 445, 443)
ForEach($port in $ports) 
{ 
    "Port $port : Listening: $(if( $(Netstat -ano | findstr ":$port" | Select-String -Pattern "^.*TCP\s+(?:[0-9]{1,3}\.){3}[0-9]{1,3}:$port\s+0\.0\.0\.0:0\s+LISTENING").length -gt 0 ) {"YES - PASS"} else{"NO - FAIL!"})" | Out-File -FilePath $OutputFile -Append
}


'' | Out-File -FilePath $OutputFile -Append
'****************************************************************************************' | Out-File -FilePath $OutputFile -Append
ForEach($port in $ports) 
{
    "Netstat output for port $port, verify we see communication" | Out-File -FilePath $OutputFile -Append
    Netstat -ano | findstr ":$port" | Out-File -FilePath $OutputFile -Append
    '****************************************************************************************' | Out-File -FilePath $OutputFile -Append
}

Write-Host "Output saved to $OutputFile"
Sleep -s 15