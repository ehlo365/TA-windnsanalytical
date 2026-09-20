<#
.SYNOPSIS
    Retrieves DNS analytics from the Windows DNS Server analytical log.
    This script collects and processes DNS events from the analytical log, applying filters and ignoring specified zones.

.DESCRIPTION
    This script is designed to facilitate the collection and analysis of DNS events from the Windows DNS Server analytical log. It supports filtering events using XPath expressions and allows ignoring specific DNS zones to reduce noise in the collected data.

    [Console]::WriteLine(...) events are written to the standard output stream, and stored in the `dns` index in Splunk.
    [Console]::Error.WriteLine(...) events are written to the standard error stream and captured into the splunkd.log file, and ultimately sent to the `_internal` index in Splunk.


.PARAMETER MaxRuntimeSecs
    Maximum runtime for the script in seconds, after which it will be terminated. Default is 55 seconds.

.PARAMETER FilterXPath
    XPath filter to select specific DNS events from the analytical log. This should be a valid XPath expression and match the events logged in init_dns_analytics.ps1.

.PARAMETER SplunkdLogging
    Enable logging to splunkd.log.

.PARAMETER IgnoredZones
    List of DNS zones to ignore (in addition to the static ignored zones). This helps reduce noise from known domains that are not of interest.

.PARAMETER MatchAnyKeyword
    Keyword to match any DNS event. This allows filtering events based on a specific keyword.

.EXAMPLE
    .\get_dns_analytics.ps1 *> $null
    Suppress all screen output. This redirects both standard output and error output to $null.

.EXAMPLE
    .\get_dns_analytics.ps1 -SplunkdLogging 1> $null 2> .\dns-analytics-debug.log
    Redirect standard output (event records) to $null and error output (timing and debug information) to a debug log file. Recommended for debugging purposes.
    
    To display the diagnostics afterward:
    Get-Content .\dns-analytics-debug.log

.EXAMPLE
    .\get_dns_analytics.ps1 -SplunkdLogging 1> $null
    Redirect standard output (event records) to $null and enable logging to splunkd.log (stderr visible while stdout is discarded).
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, HelpMessage="Maximum runtime for the script in seconds, after which it will be terminated.")]
    [int]$MaxRuntimeSecs = 55,
    [Parameter(Mandatory = $false, HelpMessage="XPath filter to select specific DNS events from the analytical log. This should be a valid XPath expression and match the events logged in init_dns_analytics.ps1")]
    [string]$FilterXPath = "*[System[EventID=256 or EventID=257] and EventData[Data[@Name='InterfaceIP']!='127.0.0.1' and Data[@Name='InterfaceIP']!='::1']]",
    [Parameter(Mandatory = $false, HelpMessage="Enable logging to splunkd.log.")]
    [switch]$SplunkdLogging,
    [Parameter(Mandatory = $false, HelpMessage="List of DNS zones to ignore.")]
    [string[]]$IgnoredZones,
    [Parameter(Mandatory = $false, HelpMessage="Keyword to match any DNS event.")]
    [string]$MatchAnyKeyword = "0x0000000000000003"
)

#---------------------------------------------------------[Initialisations]--------------------------------------------------------
$stopWatch = New-Object System.Diagnostics.Stopwatch
$stopWatch.Start()

#----------------------------------------------------------[Declarations]----------------------------------------------------------
[string]$logName = 'Microsoft-Windows-DNSServer/Analytical'
[string]$scriptname = Split-Path $MyInvocation.MyCommand.Path -Leaf
[string[]]$ignoredZonesStatic = @("microsoft.com", "microsoft.com.akadns.net", "sophosxl.net")

#-----------------------------------------------------------[Functions]------------------------------------------------------------
function Start-Watchdog {
    param(  
        [Int32]$WaitSeconds,
        [ScriptBlock]$Action = {
            # to splunkd.log
            [Console]::Error.WriteLine(("INFO [{0}:{1}] Script exceeded maximum runtime of {0}. Terminating PID {1}" -f $WaitSeconds, $PID))

            # to index
            [Console]::WriteLine(("INFO [{0}:{1}] Script exceeded maximum runtime of {0}. Terminating PID {1}" -f $WaitSeconds, $PID))
            Stop-Process -Id $PID 
        }
    )

    # Disable watchdog in debug mode. If watchdog is enabled, it will terminate the script after the specified wait time automatically.
    if ($Debug) {
        [Console]::Error.WriteLine(("INFO [{0}:{1}] Debug mode enabled. Watchdog functionality will be disabled." -f $scriptname, $PID))
    }
    else {
        $Wait = "Start-Sleep -seconds $WaitSeconds"
        $script:Watchdog = [PowerShell]::Create().AddScript($Wait).AddScript($Action)
        $handle = $script:Watchdog.BeginInvoke()
        #  Write-Warning "Watchdog will terminate process $PID in $WaitSeconds seconds unless Stop-Watchdog is called."

        if($SplunkdLogging) {
            [Console]::Error.WriteLine(("INFO [{0}:{1}] Started a watchdog thread to terminate this script if it does not finish within {2}s." -f $scriptname, $PID, $MaxRuntimeSecs))
        }
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

function NormalizeZoneName ([string] $domainBase) {
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

function Write-SplunkRecord {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$InputObject
    )

    $timeCreated = $null
    if ($null -ne $InputObject.PSObject.Properties['TimeCreated']) {
        $timeCreated = [string]$InputObject.TimeCreated
        $timeCreated = $timeCreated -replace "`r?`n", ' '
        $timeCreated = $timeCreated -replace "\s+", ' '
        $timeCreated = $timeCreated.Trim()
    }

    $providerName = $null
    if ($null -ne $InputObject.PSObject.Properties['ProviderName']) {
        $providerName = [string]$InputObject.ProviderName
        $providerName = $providerName -replace "`r?`n", ' '
        $providerName = $providerName -replace "\s+", ' '
        $providerName = $providerName.Trim()
    }

    $levelDisplayName = $null
    if ($null -ne $InputObject.PSObject.Properties['LevelDisplayName']) {
        $levelDisplayName = [string]$InputObject.LevelDisplayName
        $levelDisplayName = $levelDisplayName -replace "`r?`n", ' '
        $levelDisplayName = $levelDisplayName -replace "\s+", ' '
        $levelDisplayName = $levelDisplayName.Trim()
    }

    $eventId = $null
    if ($null -ne $InputObject.PSObject.Properties['Id']) {
        $eventId = [string]$InputObject.Id
        $eventId = $eventId -replace "`r?`n", ' '
        $eventId = $eventId -replace "\s+", ' '
        $eventId = $eventId.Trim()
    }

    $message = $null
    if ($null -ne $InputObject.PSObject.Properties['Message']) {
        $message = [string]$InputObject.Message
        $message = $message -replace "`r?`n", ' '
        $message = $message -replace "\s*;\s*(?=[A-Z][A-Z0-9_]+\s*=)", '; '
        $message = $message -replace "\r?\n\s*;", '; '
        $message = $message -replace "\s+", ' '
        $message = $message -replace 'Zone=\.\.?Cache', 'Zone=Cache'
        $message = $message.Trim()
    }

    $recordParts = @()
    if ($timeCreated) { $recordParts += "TimeCreated : $timeCreated" }
    if ($providerName) { $recordParts += "ProviderName : $providerName" }
    if ($levelDisplayName) { $recordParts += "LevelDisplayName : $levelDisplayName" }
    if ($eventId) { $recordParts += "Id : $eventId" }
    if ($message) { $recordParts += "Message : $message" }

    if (-not $recordParts) {
        Write-Output 'Message : no data'
        return
    }

    $recordText = ($recordParts -join '; ')
    Write-Output $recordText
}

function Copy-DnsLog {
    param(
        [Parameter(Mandatory=$true, HelpMessage="Specify the source log file path.")]
        [ValidateNotNullOrEmpty()]
        [string]$Source,
        [Parameter(Mandatory=$true, HelpMessage="Specify the destination log file path.")]
        [ValidateNotNullOrEmpty()]
        [string]$Destination,
        [Parameter(Mandatory=$true, HelpMessage="Specify the Event Log configuration.")]
        [Object]$EventLogConfiguration
    )

    # Pause the log to safely copy it without losing any entries
    $EventLogConfiguration.IsEnabled = $false
    $EventLogConfiguration.SaveChanges()

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

    # Enable the event log again. Windows will handle the clearing of the log automatically.
    $EventLogConfiguration.IsEnabled = $true
    $EventLogConfiguration.SaveChanges()

    # Modify ETW Trace Provider to only log QUERY_RECEIVED, RECURSE_RESPONSE_IN and RESPONSE_SUCCESS Events. This have to be done after every log restart...
    try {
        Set-EtwTraceProvider -Guid '{EB79061A-A566-4698-9119-3ED2807060E7}' -SessionName 'EventLog-Microsoft-Windows-DNSServer-Analytical' -MatchAnyKeyword $script:MatchAnyKeyword -ErrorAction Stop
    }
    catch {
        #[Console]::Error.WriteLine(("INFO [{0}:{1}] Failed to modify ETW Trace Provider." -f $scriptname, $PID)) 
    }
}

#-----------------------------------------------------------[Execution]------------------------------------------------------------
if ($SplunkdLogging) {
    [Console]::Error.WriteLine(("INFO [{0}:{1}] Starting" -f $scriptname, $PID))
}

# Start the watchdog to ensure the script does not run longer than the maximum allowed runtime
Start-Watchdog $MaxRuntimeSecs

# --------------------------------------------------------
# DNS Server Zone Collection
# --------------------------------------------------------
$swDnsZoneCollection = [Diagnostics.Stopwatch]::StartNew()

if($SplunkdLogging) {
    [Console]::Error.WriteLine(("INFO [{0}:{1}] Collecting local DNS zones" -f $scriptname, $PID))
}

# Build the ignore set directly to avoid the redundant ArrayList pass-through.
$ignoredZonesSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($domain in $IgnoredZones) {
    $ignoredZonesSet.Add((NormalizeZoneName -domainBase $domain)) | Out-Null
}

foreach ($domain in $ignoredZonesStatic) {
    $ignoredZonesSet.Add((NormalizeZoneName -domainBase $domain)) | Out-Null
}

Get-DnsServerZone | ForEach-Object {
    $ignoredZonesSet.Add((NormalizeZoneName -domainBase $_.ZoneName)) | Out-Null
}

$swDnsZoneCollection.Stop()

# --------------------------------------------------------
# Event Log Settings Retrieval
# --------------------------------------------------------
$swEventLogSettings = [Diagnostics.Stopwatch]::StartNew()

if($SplunkdLogging) {
    [Console]::Error.WriteLine(("INFO [{0}:{1}] Get the Event Log Settings" -f $scriptname, $PID))
}

# Get the Event Log settings for the specified log name
$eventlogSettings = Get-WinEvent -ListLog $logName
$prov = Get-WinEvent -ListProvider $eventlogSettings.OwningProviderName

# Get the log file path and prepare a backup path for this process
$logFilePath = [System.Environment]::ExpandEnvironmentVariables($eventlogSettings.LogFilePath)  # expand the variables in the file path
$logFile = Get-Item -Path $logFilePath
$logBkpPath = Join-Path -Path $env:TEMP -ChildPath ("{0}-PID{1}{2}" -f $logFile.BaseName, $PID, $logFile.Extension) # Generate a unique file path for this proc using the PID
$swEventLogSettings.Stop()

# --------------------------------------------------------
# Event Log Message Template Processing
# --------------------------------------------------------
$swEventLogMessageTemplateProcessing = [Diagnostics.Stopwatch]::StartNew()

if($SplunkdLogging) {
    [Console]::Error.WriteLine(("INFO [{0}:{1}] Begin processing event log message templates" -f $scriptname,$PID))
}

# Ingest the templates and discover the QNAME positions for each
$NSPREFIX = "evt"
$nsm = New-Object -TypeName System.Xml.XmlNamespaceManager(New-Object System.Xml.NameTable)
$nsm.AddNamespace($NSPREFIX,'http://schemas.microsoft.com/win/2004/08/events')
$filterQnameNode = "/{0}:template/{0}:data[@name='QNAME']" -f $NSPREFIX

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
$swEventLogMessageTemplateProcessing.Stop()

# --------------------------------------------------------
# Clone and Clear the Active DNS Log
# --------------------------------------------------------
# Start a stopwatch to measure the time the log is paused
$swLogPaused = [Diagnostics.Stopwatch]::StartNew()

if($SplunkdLogging) {
    [Console]::Error.WriteLine(("INFO [{0}:{1}] Clone and clear the active log" -f $scriptname,$PID))
}

# Copy the active DNS log to a backup location
Copy-DnsLog -Source $logFilePath -Destination $logBkpPath -EventLogConfiguration $eventlogSettings

$swLogPaused.Stop()

# --------------------------------------------------------
# Process the backed-up DNS log data
# --------------------------------------------------------
[int]$ignoredRecs = 0
[int]$emittedRecs = 0
$firstRecordTimestamp = $null
$lastRecordTimestamp = $null

$swDnsLogReader = [Diagnostics.Stopwatch]::StartNew()
$query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($logBkpPath,[System.Diagnostics.Eventing.Reader.PathType]::FilePath, $FilterXPath);
$reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)

if ($SplunkdLogging)
{  [Console]::Error.WriteLine(("INFO [{0}:{1}] Process the events." -f $scriptname,$PID))  }

while ($null -ne ($record = $reader.ReadEvent())) # Do not use Get-WinEvent to avoid performance overhead of FormatDescription()
{
    $recordTime = $record.TimeCreated

    # Initialize the start time of the log processing if not already set
    if ($null -eq $firstRecordTimestamp) {
        $firstRecordTimestamp = $recordTime
    }

    # Update the end time of the log processing with the current record's timestamp, effectively marking the latest processed event.
    $lastRecordTimestamp = $recordTime

    $eventId = [int]$record.Id
    $templateInfo = $messageTypes[$eventId]
    if ($null -eq $templateInfo) {
        continue
    }

    # Domain of the current record
    $qname = [string]$record.psbase.Properties[$templateInfo.QNAMEPos].value
    if (Test-IgnoredZone -Qname $qname -IgnoredZonesSet $ignoredZonesSet) {
        $ignoredRecs++
        continue
    }

    # Convert the raw data to a the format, without relying on EventLogRecord.FormatDescription () 
    $propVals = @($null)
    foreach ($prop in $record.psbase.Properties) {
        $propVals += [string]$prop.value
    }

    # Format the message for the current record using the template and property values
    $record | Add-Member -Force -MemberType NoteProperty -Name Message -Value ($templateInfo.Template -f $propVals)

    # Emit the formatted record to Splunk
    Write-SplunkRecord -InputObject $record
    $emittedRecs++
}

# Only calculate timespan if the log start time is available (matching events > 0). While processing an empty log, $firstRecordTimestamp will be $null, which would cause New-TimeSpan to throw an exception.
if ($null -ne $firstRecordTimestamp) {
	$LoggedTimespanSecs = (New-TimeSpan -Start $firstRecordTimestamp -End $lastRecordTimestamp).TotalSeconds
}

# Dispose the EventLogReader
$reader.Dispose()

if ($null -eq $LoggedTimespanSecs) { 
    $LoggedTimespanSecs = -1 
}

$swDnsLogReader.Stop()

# --------------------------------------------------------
# Backup log removal section
# --------------------------------------------------------
$swDeleteDnsBackupLog = [Diagnostics.Stopwatch]::StartNew()

if ($SplunkdLogging) {
    [Console]::Error.WriteLine(("INFO [{0}:{1}] Removing the copy of the log at {2}" -f $scriptname, $PID, $logBkpPath))
}

# Delete the backup copy of the log file
Remove-Item -Path $logBkpPath -Force

$swDeleteDnsBackupLog.Stop()

# --------------------------------------------------------
# Performance benchmarking section
# --------------------------------------------------------
if ($SplunkdLogging)
{  [Console]::Error.WriteLine(("INFO [{0}:{1}] Writing performance data to STDOUT" -f $scriptname, $PID))  }

$stopWatch.Stop()

# Collect performance statistics into a custom object for later reporting
$stats = [pscustomobject]@{
    # Performance benchmarking for various sections of the script
    DnsZoneCollectionMs = $swDnsZoneCollection.ElapsedMilliseconds
    EventLogSettingsMs = $swEventLogSettings.ElapsedMilliseconds
    EventLogMessageTemplateProcessingMs = $swEventLogMessageTemplateProcessing.ElapsedMilliseconds
    LogPausedMs = $swLogPaused.ElapsedMilliseconds
    DataRetrievalMs = $swDnsLogReader.ElapsedMilliseconds
    DeleteDnsBackupLogMs = $swDeleteDnsBackupLog.ElapsedMilliseconds
    TotalElapsedMs = $stopWatch.ElapsedMilliseconds
    # Event log size statistics. Force explicit Int64 type casting to strip any formatting bugs
    LogFileMaxBytes = [int64]$eventlogSettings.MaximumSizeInBytes
    LogFileCurBytes = [int64]$eventlogSettings.FileSize
    # Record timestamps and timespan
    FirstLoggedTimeSecs = $firstRecordTimestamp
    LastLoggedTimeSecs = $lastRecordTimestamp
    LogTimespanSecs = $LoggedTimespanSecs
    # Logged and ignored record counts
    LoggedRecs = $emittedRecs
    IgnoredRecs = $ignoredRecs
    # Additional script run statistics
    ScriptRunSecs = (New-TimeSpan -Start (Get-Process -Id $pid).StartTime -End (Get-Date)).TotalSeconds
}

# Emit performance statistics to the standard output stream (as in previous version of the script)
$formattedStats = (($stats.PSObject.Properties | ForEach-Object {
    "{0}={1}" -f $_.Name, $_.Value
}) -join '; ')

$statsMessage = "INFO [{0}:{1}] {2}" -f $scriptname, $PID, $formattedStats
[Console]::WriteLine($statsMessage)

# Emit performance statistics to the console if Splunkd logging is enabled
if ($SplunkdLogging) {
    [Console]::Error.WriteLine($statsMessage)
    # Write error message to the error stream in addition to the standard error stream
    Write-Error $statsMessage
}

#--------------------------------------------------------------[End]---------------------------------------------------------------
# Stop the watchdog timer before exiting the script
Stop-Watchdog

if ($SplunkdLogging) {
    [Console]::Error.WriteLine(("INFO [{0}:{1}] Log processing complete and watchdog stopped. Exiting" -f $scriptname, $PID))
}
