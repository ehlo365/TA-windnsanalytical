<#
.SYNOPSIS
    Retrieves DNS analytics from the Windows DNS Server analytical log.
    This script collects and processes DNS events from the analytical log, applying filters and ignoring specified zones.

.DESCRIPTION
    This script is designed to facilitate the collection and analysis of DNS events from the Windows DNS Server analytical log. It supports filtering events using XPath expressions and allows ignoring specific DNS zones to reduce noise in the collected data.

.PARAMETER MaxRuntimeSecs
    Maximum runtime for the script in seconds, after which it will be terminated.

.PARAMETER FilterXPath
    XPath filter to select specific DNS events from the analytical log. This should be a valid XPath expression and match the events logged in init_dns_analytics.ps1.

.PARAMETER SplunkdLogging
    Enable logging to splunkd.log.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, HelpMessage="Maximum runtime for the script in seconds, after which it will be terminated.")]
    [int]$MaxRuntimeSecs = 55,
    [Parameter(Mandatory = $false, HelpMessage="XPath filter to select specific DNS events from the analytical log. This should be a valid XPath expression and match the events logged in init_dns_analytics.ps1")]
    [string]$FilterXPath = "*[System[EventID=256 or EventID=257] and EventData[Data[@Name='InterfaceIP']!='127.0.0.1']]",  # trim noise, log only QUERY_RECEIVED and RESPONSE_SUCCESS events
    [Parameter(Mandatory = $false, HelpMessage="Enable logging to splunkd.log.")]
    [switch]$SplunkdLogging,
    [Parameter(Mandatory = $false, HelpMessage="List of DNS zones to ignore.")]
    [string[]]$IgnoredZones = @("microsoft.com","microsoft.com.akadns.net","sophosxl.net"),
    [Parameter(Mandatory = $false, HelpMessage="Keyword to match any DNS event.")]
    [string]$MatchAnyKeyword = "0x0000000000000023"
)

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

#----------------------------------------------------------[Declarations]----------------------------------------------------------
[string]$logName = 'Microsoft-Windows-DNSServer/Analytical'

[string]$scriptname = Split-Path $MyInvocation.MyCommand.Path -Leaf
[System.Collections.ArrayList]$ignoredZonesList = New-Object System.Collections.ArrayList

#-----------------------------------------------------------[Functions]------------------------------------------------------------
function Start-Watchdog {
    param(  
        [Int32]$WaitSeconds,
        [ScriptBlock]$Action = {
            # to splunkd.log
            [Console]::Error.WriteLine(("INFO [{0}:{1}] Script exceeded maximum runtime of {0}.  Terminating PID {1}" -f $WaitSeconds, $PID))

            # to index
            [Console]::WriteLine(("INFO [{0}:{1}] Script exceeded maximum runtime of {0}.  Terminating PID {1}" -f $WaitSeconds, $PID))
            Stop-Process -Id $PID 
        }
    )

    if ($Debug) {
        $Wait = "Start-Sleep -seconds $WaitSeconds"
        $script:Watchdog = [PowerShell]::Create().AddScript($Wait).AddScript($Action)
        $handle = $script:Watchdog.BeginInvoke()
        #  Write-Warning "Watchdog will terminate process $PID in $WaitSeconds seconds unless Stop-Watchdog is called."
    }
    else {
        [Console]::Error.WriteLine(("INFO [{0}:{1}] Debug mode enabled. Watchdog functionality will be disabled." -f $scriptname, $PID))
    }
}

function Stop-Watchdog {
    param()

    if ($null -ne $script:Watchdog) {
        $script:Watchdog.Stop()
        $script:Watchdog.Runspace.Close()
        $script:Watchdog.Dispose()
        Remove-Variable Watchdog -Scope script
    } 
    else {
        Write-Warning 'No Watchdog found.'
    }
}

function BuildRegExPatternFromDomain ([string] $domainBase) {
    if ([string]::IsNullOrWhiteSpace($domainBase)) {
        return [string]::Empty
    }

    return $domainBase.TrimEnd('.').ToLowerInvariant()
}

function Test-IgnoredZone {
    param(
        [string]$Qname,
        [System.Collections.Generic.HashSet[string]]$IgnoredZonesSet
    )

    if ([string]::IsNullOrWhiteSpace($Qname)) {
        return $false
    }

    $normalizedQname = $Qname.Trim().TrimEnd('.').ToLowerInvariant()
    if ($IgnoredZonesSet.Contains($normalizedQname)) {
        return $true
    }

    foreach ($ignoredZone in $IgnoredZonesSet) {
        if ($normalizedQname.EndsWith(".$ignoredZone", [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

function Copy-DnsLog {
    param(
        [Parameter(Mandatory=$true, HelpMessage="Specify the source log file path.")]
        [string]$Source,
        [Parameter(Mandatory=$true, HelpMessage="Specify the destination log file path.")]
        [string]$Destination
    )

    # Start a stopwatch to measure the time the log is paused
    $swLogPaused = [Diagnostics.Stopwatch]::StartNew()

    # Clone and clear the active log
    $script:logSize = if ($null -ne $eventlogSettings.Filesize) {
        $eventlogSettings.Filesize
    }
    else {
        (Get-Item -Path $Source).Length
    }
    
    $script:eventlogSettings.IsEnabled = $false
    $script:eventlogSettings.SaveChanges()

    # Copy the current log to the backup location
    Copy-Item $Source -Destination $Destination -Force

    # Important: 
    # It is not required to clear the log manually, Windows will handle it when the log is disabled and re-enabled
    # try {
    #         # Keep the existing logs instead of clearing them
    #         [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($eventlogSettings.LogName)
    # }
    # catch  [System.Management.Automation.MethodException] { 
    #     # Eat this exception. It says "The process cannot access the file because it is being used by another process" but it lies, the log is cleared.
    # }

    # Enable the event log again
    $script:eventlogSettings.IsEnabled = $true
    $script:eventlogSettings.SaveChanges()

    # Modify ETW Trace Provider to only log QUERY_RECEIVED, RECURSE_RESPONSE_IN and RESPONSE_SUCCESS Events. This have to be done after every log restart...
    try {
        Set-EtwTraceProvider -Guid '{EB79061A-A566-4698-9119-3ED2807060E7}' -SessionName 'EventLog-Microsoft-Windows-DNSServer-Analytical' -MatchAnyKeyword $script:MatchAnyKeyword -ErrorAction Stop
    }
    catch {
        #[Console]::Error.WriteLine(("INFO [{0}:{1}] Failed to modify ETW Trace Provider." -f $scriptname, $PID)) 
    }

    $swLogPaused.Stop()

    # Return the elapsed time in milliseconds that the log was paused
    return $swLogPaused.ElapsedMilliseconds
}


#-----------------------------------------------------------[Execution]------------------------------------------------------------

if($SplunkdLogging) {
    [Console]::Error.WriteLine(("INFO [{0}:{1}] Starting" -f $scriptname, $PID))
}

# Start the watchdog to ensure the script does not run longer than the maximum allowed runtime
Start-Watchdog $MaxRuntimeSecs

if($SplunkdLogging) {
    [Console]::Error.WriteLine(("INFO [{0}:{1}] Started a watchdog thread to terminate this script if it does not finish within {2}s." -f $scriptname, $PID, $MaxRuntimeSecs))
}

if($SplunkdLogging) {
    [Console]::Error.WriteLine(("INFO [{0}:{1}] Collecting local DNS zones" -f $scriptname, $PID))
}

# Build the whitelist/ignore list for records
foreach ($domain in $IgnoredZones) {
    $ignoredZonesList.Add( (BuildRegexPatternFromDomain($domain))) | Out-Null
}

Get-DnsServerZone | ForEach-Object{
    $ignoredZonesList.Add( (BuildRegexPatternFromDomain($_.ZoneName))) | Out-Null
}

# compile a fast in-memory lookup for ignored domains
$ignoredZonesSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($ignoredZone in $ignoredZonesList) {
    $ignoredZonesSet.Add($ignoredZone.Trim('.').ToLowerInvariant()) | Out-Null
}

if($SplunkdLogging) {
    [Console]::Error.WriteLine(("INFO [{0}:{1}] Get the Event Log Settings" -f $scriptname,$PID))
}

$eventlogSettings = Get-WinEvent -ListLog $logName
$prov = Get-WinEvent -ListProvider $eventlogSettings.OwningProviderName
$logFilePath = [System.Environment]::ExpandEnvironmentVariables($eventlogSettings.LogFilePath)  # expand the variables in the file path
$logFile = Get-Item -Path $logFilePath
$logBkpPath = Join-Path -Path $env:TEMP -ChildPath ("{0}-PID{1}{2}" -f $logFile.BaseName, $PID, $logFile.Extension) # Generate a unique file path for this proc using the PID

# Ingest the templates and discover the QNAME positions for each
$NSPREFIX = "evt"
$nsm = New-Object -TypeName System.Xml.XmlNamespaceManager(New-Object System.Xml.NameTable)
$nsm.AddNamespace($NSPREFIX,'http://schemas.microsoft.com/win/2004/08/events')
$filterQnameNode = "/{0}:template/{0}:data[@name='QNAME']" -f $NSPREFIX

if($SplunkdLogging) {
    [Console]::Error.WriteLine(("INFO [{0}:{1}] Begin processing event log message templates" -f $scriptname,$PID))
}

# create a sparse lookup for template metadata. There are no four-digit event IDs so won't need more than 999 slots
[hashtable]$messageTypes = @{}

# Process each event template to extract the QNAME position and prepare message templates for parsing
$prov.Events | ForEach-Object {
    # Get the message template (human-readable, to-be parsed by Splunk)
    $description = $_.Description -replace ";\s+PacketData=%\d+", ""  # remove packetdata  (for now,  too complicated to parse)
    $description = $description -replace "%(?<token>\d{1,2})", "{`${token}}"   # convert for PS-based tokens

    # Find the "slot" holding QNAME in this format/template
    $doc = [xml] $_.Template

    $qnameNodePos = $null
    # If the QNAME node exists
    if ($qname = $doc.SelectSingleNode($filterQnameNode,$nsm) ) {
        # Record the position for later evaluation
        $qnameNodePos = $doc.CreateNavigator().Evaluate( "count($filterQnameNode/preceding-sibling::*)",$nsm)        
    }

    $messageTypes[[int]$_.Id] = [pscustomobject] @{
        Template = $description
        QNAMEPos = $qnameNodePos
    }
}

if($SplunkdLogging) {
    [Console]::Error.WriteLine(("INFO [{0}:{1}] Clone and clear the active log" -f $scriptname,$PID))
}

# Copy the active DNS log to a backup location
$logPausedMs = Copy-DnsLog -Source $logFilePath -Destination $logBkpPath

# Now process the backed-up log data
$ignoredRecs = 0
$emittedRecs = 0
$swRetrievalTime = [Diagnostics.Stopwatch]::StartNew()
$query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($logBkpPath,[System.Diagnostics.Eventing.Reader.PathType]::FilePath, $FilterXPath);
$reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)
$logStart = $null

if ($SplunkdLogging)
{  [Console]::Error.WriteLine(("INFO [{0}:{1}] Process the events." -f $scriptname,$PID))  }

while ($null -ne ($record = $reader.ReadEvent())) # Do not use Get-WinEvent to avoid performance overhead of FormatDescription()
{
    if ($null -eq $logStart) {
        $logStart = $record.TimeCreated
    }
    $logEnd = $record.TimeCreated   # optimize - continuous updating may be inefficient

    $eventId = [int]$record.Id
    $templateInfo = $messageTypes[$eventId]
    if ($null -eq $templateInfo) {
        continue
    }

    # domain of the current record
    $qname = [string]$record.psbase.Properties[$templateInfo.QNAMEPos].value
    if (Test-IgnoredZone -Qname $qname -IgnoredZonesSet $ignoredZonesSet) {
        $ignoredRecs++
        continue
    }

    # convert the raw data to a the format, without relying on EventLogRecord.FormatDescription () 
    $propVals = @($null)
    foreach ($prop in $record.psbase.Properties) {
        $propVals += [string]$prop.value
    }

    $record | Add-Member -Force -MemberType NoteProperty -Name Message -Value ($templateInfo.Template -f $propVals)
    $record | Format-List
    $emittedRecs++
}

# Added if statement to handle exception: New-TimeSpan : Cannot bind parameter 'Start' to the target. Exception setting "Start": "Cannot convert null to type "System.DateTime".
if ($logStart) {
	$LoggedTimespanSecs = (New-TimeSpan -Start $logStart -End $logEnd).TotalSeconds
}

$swRetrievalTime.Stop()
$reader.Dispose()
if ($null -eq $LoggedTimespanSecs) { 
    $LoggedTimespanSecs = -1 
}

if ($SplunkdLogging) {
    [Console]::Error.WriteLine(("INFO [{0}:{1}] Removing the copy of the log at {2}" -f $scriptname,$PID,$logBkpPath))
}

# Delete the backup copy of the log file
Remove-Item -Path $logBkpPath -Force


if ($SplunkdLogging) {
    [Console]::Error.WriteLine(("INFO [{0}:{1}] Writing the formatted events to STDOUT" -f $scriptname,$PID))
}

# Performance benchmarking only
# The individual records were already emitted above for Splunk parsing.
# $recordStream[0] | fl TimeCreated
# $recordStream[-1] | fl TimeCreated

if($SplunkdLogging)
{  [Console]::Error.WriteLine(("INFO [{0}:{1}] Writing performance data to STDOUT" -f $scriptname,$PID))  }

# Emit some performance stats
[pscustomobject]@{
    LogPausedMs = $logPausedMs
    DataRetrievalMs = $swRetrievalTime.ElapsedMilliseconds
    LogFileMaxBytes = $eventlogSettings.MaximumSizeInBytes
    LogFileCurBytes = $logSize
    LoggedRecs = $emittedRecs
    IgnoredRecs = $ignoredRecs
    LogTimespanSecs = $LoggedTimespanSecs
    ScriptRunSecs = (New-TimeSpan -Start (Get-Process -Id $pid).StartTime  -End (Get-Date)).TotalSeconds
} | Format-List


# Stop the watchdog timer before exiting the script
Stop-Watchdog

if ($SplunkdLogging) {
    [Console]::Error.WriteLine(("INFO [{0}:{1}] Log processing complete and watchdog stopped. Exiting" -f $scriptname, $PID))
}

#--------------------------------------------------------------[End]---------------------------------------------------------------
