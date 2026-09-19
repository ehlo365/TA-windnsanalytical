<#
.PARAMETER ComputerName
    Specify the target computer for which to initialize the DNS analytics.

.PARAMETER Bounce
    If specified, the Splunk Forwarder service will be restarted to apply changes.

.PARAMETER MatchAnyKeyword
    Specify which events to log for the ETW Trace Provider.
    0x0000000000000003: QUERY_RECEIVED and RESPONSE_SUCCESS
    0x0000000000000023: QUERY_RECEIVED, RESPONSE_SUCCESS and RECURSE_RESPONSE_IN

#>
param (
    [Parameter(Mandatory = $false, HelpMessage="Specify the target computer for which to initialize the DNS analytics.")] 
    [string]$ComputerName = $env:computername,
    [Parameter(Mandatory = $false, HelpMessage="Restart the Splunk Forwarder service to apply changes.")]
    [switch]$Bounce,
    [Parameter(Mandatory = $false, HelpMessage="Keyword to match any DNS event.")]
    [string]$MatchAnyKeyword = "0x0000000000000003"
)

$eventlogSettings = Get-WinEvent -ListLog 'Microsoft-Windows-DNSServer/Analytical' -ComputerName $ComputerName

# Disable and re-enable the log to clear it
$eventlogSettings.IsEnabled = $false
$eventlogSettings.SaveChanges()


#  Bug - can't change the mode via API  https://github.com/PowerShell/xWinEventLog/issues/18
# $eventlogSettings.LogMode = [System.Diagnostics.Eventing.Reader.EventLogMode]::Retain
$eventlogSettings.IsEnabled = $true
$eventlogSettings.SaveChanges()

$eventlogSettings

try {
	Set-EtwTraceProvider -Guid '{EB79061A-A566-4698-9119-3ED2807060E7}' -SessionName 'EventLog-Microsoft-Windows-DNSServer-Analytical' -MatchAnyKeyword $MatchAnyKeyword -ErrorAction Stop
}
catch {
	#[Console]::Error.WriteLine(("INFO [{0}:{1}] Failed to modify ETW Trace Provider." -f $scriptname, $PID)) 
}

if($Bounce)
{
    Invoke-Command -Computer $ComputerName -ScriptBlock {
        Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue | Stop-Service
		
		# Clean up any stranded scripted input processes
		Get-WmiObject  -Class Win32_Process -Filter "name = 'powershell.exe' AND CommandLine LIKE '%\\etc\\apps\\%\\bin\\get_dns_analytics.ps1%'"  | %{Write-Host ("Terminating existing instance {0}" -f $_.ProcessID);  $_.Terminate();}
		
        Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue | Start-Service
        
        Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
        Get-WmiObject  -Class Win32_Process -Filter "name = 'powershell.exe' AND CommandLine LIKE '%\\etc\\apps\\%\\bin\\get_dns_analytics.ps1%'"  | Select-Object ProcessID,CommandLine
    }
}
