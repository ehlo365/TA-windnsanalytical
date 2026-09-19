# TA-windnsanalytical
Forked from Hugh Kelley's archived GitHub repository (https://github.com/hkelley/TA-windnsanalytical) and his Add-On for Windows DNS Analytical Logging (https://splunkbase.splunk.com/app/4300).

Modifications to the originals:
* Fixed bad regex warning in `props.conf`
* Messages was wrapped after 80 characters in Splunk.
* Data reduction to speed up processing:
  * Modified DNS Analytical ETW Trace provider to log only the required events (reduce number of events to search through).

## Filtering events
### /bin/init_dns_analytics.ps1
Events are logged to Analytic log (Microsoft-Windows-DNSServer/Analytical), which is an Event Tracing for Windows (ETV) file that Splunk can't read.

To avoid logging all possible events to the analytical log, calculate the sum of the bitmask values that you actually need to be logged. To see available keywords that can be filtered on, execute the following command:
```powershell
logman query providers "Microsoft-Windows-DNSServer"
```

Examples:
| Value | Keyword | Analytic Event ID |
| :--- | :--- | :--- |
| 0x0000000000000001 | QUERY_RECEIVED | 256 |
| 0x0000000000000002 | RESPONSE_SUCCESS | 257 |
| 0x0000000000000020 | RECURSE_RESPONSE_IN | 261 |

To log `QUERY_RECEIVED`, `RESPONSE_SUCCESS` and `RECURSE_RESPONSE_IN` events to the ETW file, specify `0x0000000000000023` in the `$MatchAnyKeyword` parameter.

To log `QUERY_RECEIVED` and `RESPONSE_SUCCESS`, specify `0x0000000000000003` instead.

### /bin/get_dns_analytics.ps1
In the `$FilterXPath` parameter, specify which Event ID's that should be logged to Splunk. The Event ID's should normally match the keywords specified in `init_dns_analytics.ps1`. By default DNS queries from localhost (127.0.0.1) is excluded in the XPath expression.

Example:
To fetch `QUERY_RECEIVED`, `RESPONSE_SUCCESS` and `RECURSE_RESPONSE_IN` events, specify Event ID 256, 257 and 261. See [/lookups/win_dns_eventid.csv](/lookups/win_dns_eventid.csv) for additional information.



## Original readme
Based on Jake Walter's Windows DNS Analytical Log App (https://splunkbase.splunk.com/app/2937/  - Version 1.0  Oct. 26, 2015  Initial release).

Subsequent modifications to the original:
* additional tagging for compatibility with Splunk ES DNS data model
* performance improvements in log collection  (Do not use Get-WinEvent to avoid performance overhead of FormatDescription() method)
* data reduction:
** no raw packet data returned
** local and low-risk (defined in the script) names/zones are ignored
* limited performance metrics are returned


(ORIGINAL) ABOUT

The Technology Addon for Windows DNS Analytical logs is designed to be used with Windows DNS servers running on Windows Server 2012 R2 and later. Microsoft has documented a new and recommended method for logging DNS requests using "audit and analytical event logging" as described in this TechNet article:

https://technet.microsoft.com/en-us/library/dn800669.aspx

Analytical logs are written to an event trace log (ETL) and are not able to be read via Splunk's native Windows log monitor. A Powershell script is included that reads the ETL every minute

Lookup tables provide additional data on Windows Event IDs:

https://technet.microsoft.com/en-us/library/dn800669.aspx#analytic

And DNS Resource Record Types:

http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4

INSTALLATION

Install the TA on the target Windows domain controllers, changing DISABLED = 1 to DISABLED = 0 in inputs.conf.

The TA will modify the log rotation settings and initially clear the existing whenever the Splunk UF starts.

Install the TA on search heads and indexers, as needed.

