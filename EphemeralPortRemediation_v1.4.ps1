<####################################################################################################################
#Author: Zachary Schmalz SysEngIV
#Version: 1.4
#Version changes: v1.4 Added a reload of the Windows Registry v1.3 Cleaner output v1.2 added elevation functions 
#v1.1 Fixed typos v1.0 Original release
#
#Description: This script is designed to expand the available range and make the OS more aggressive in truncating 
#hung ports,thus minimizing the impacts.
#See https://docs.microsoft.com/en-us/windows/client-management/troubleshoot-tcpip-port-exhaust for more information
####################################################################################################################>

#Check if powershell is running as admin
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 
{
	#Expand ephemeral port range
	Write-Host "Expanding ephemeral port values"
	netsh int ipv4 set dynamicport tcp start=10000 num=55535 | out-null
	netsh int ipv4 set dynamicport udp start=10000 num=55535 | out-null
	Write-Host "Expanded ephemeral port values`n"

	#Update registry
	Write-Host "Updating registry keys"
	$path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'

	New-ItemProperty -Path $path -Name 'TcpTimedWaitDelay' -Value 30 -PropertyType DWord -Force  | Out-Null
	New-ItemProperty -Path $path -Name 'StrictTimeWaitSeqCheck' -Value 1 -PropertyType DWord -Force  | Out-Null
	Write-Host "Updated HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\ with the following values:`nTcpTimedWaitDelay to 30 `nStrictTimeWaitSeqCheck to 1`n"
	
	
	#Reboot prompt
	$title = 'A reboot is required to complete the remediation.'
	$question = 'Would you like to reboot now?'

	$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))

	$decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
	if ($decision -eq 0)
	{
		Write-Host "`nRebooting in one minute.'n"
		shutdown /r /t 60
	} 
	else
	{
		#Reload Windows Registry
		$title = "Restarting the explorer.exe process is recommended.`n"
		$question = 'Would you like to restart explorer.exe now?'

		$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
		$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
		$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))

		$decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
		if ($decision -eq 0)
		{
			taskkill /f /im explorer.exe
			start explorer.exe
		} 
		else
		{
			Write-Host "Please complete remidation during next maintaince window."
			Pause
			exit
		}
	}
}
else 
{
	Start-Process -FilePath "powershell" -ArgumentList "$('-File ""')$(Get-Location)$('\')$($MyInvocation.MyCommand.Name)$('""')" -Verb runAs
}
