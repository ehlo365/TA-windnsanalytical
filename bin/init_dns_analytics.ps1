
param
(
      [Parameter(Mandatory = $false)] [string] $computername = "."
    , [Parameter(Mandatory = $false)] [switch] $bounce
)


$eventlogSettings = Get-WinEvent -ListLog 'Microsoft-Windows-DNSServer/Analytical'  -ComputerName $computername

# Disable and re-enable the log to clear it
$eventlogSettings.IsEnabled = $false
$eventlogSettings.SaveChanges()


#  Bug - can't change the mode via API  https://github.com/PowerShell/xWinEventLog/issues/18
# $eventlogSettings.LogMode = [System.Diagnostics.Eventing.Reader.EventLogMode]::Retain
$eventlogSettings.IsEnabled = $true
$eventlogSettings.SaveChanges()

$eventlogSettings

# Modify ETW Trace Provider to only log QUERY_RECEIVED, RECURSE_RESPONSE_IN and RESPONSE_SUCCESS Events.
try {
	Set-EtwTraceProvider -Guid '{EB79061A-A566-4698-9119-3ED2807060E7}' -SessionName 'EventLog-Microsoft-Windows-DNSServer-Analytical' -MatchAnyKeyword "0x0000000000000023" -ErrorAction Stop
}
catch {
	#[Console]::Error.WriteLine(("INFO [{0}:{1}] Failed to modify ETW Trace Provider." -f $scriptname, $PID)) 
}

if($bounce)
{
    Invoke-Command -Computer $computername -ScriptBlock {
        Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue | Stop-Service
		
		# Clean up any stranded scripted input processes
		Get-WmiObject  -Class Win32_Process -Filter "name = 'powershell.exe' AND CommandLine LIKE '%\\etc\\apps\\%\\bin\\get_dns_analytics.ps1%'"  | %{Write-Host ("Terminating existing instance {0}" -f $_.ProcessID);  $_.Terminate();}
		
        Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue | Start-Service
        
        Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
        Get-WmiObject  -Class Win32_Process -Filter "name = 'powershell.exe' AND CommandLine LIKE '%\\etc\\apps\\%\\bin\\get_dns_analytics.ps1%'"  | Select-Object ProcessID,CommandLine
    }
}

