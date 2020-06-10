<#

.SYNOPSIS

Created by: https://ingogegenwarth.wordpress.com/
Version:    42 ("What do you get if you multiply six by nine?")
Changed:    10.06.2020

.LINK
https://ingogegenwarth.wordpress.com/2015/02/14/troubleshooting-exchange-with-logparseriis-logs-1/
https://ingogegenwarth.wordpress.com/2015/03/03/troubleshooting-exchange-with-logparseriis-logs-2/
https://ingogegenwarth.wordpress.com/2017/03/13/hunteasbug/
https://ingogegenwarth.wordpress.com/2017/06/15/iisstats-update
http://blogs.technet.com/b/exchange/archive/2012/01/31/a-script-to-troubleshoot-issues-with-exchange-activesync.aspx
http://blogs.technet.com/b/exchange/archive/2013/06/17/log-parser-studio-2-2-is-now-available.aspx
http://technet.microsoft.com/library/bb201675(v=exchg.141).aspx
http://support.microsoft.com/kb/943891
http://support2.microsoft.com/kb/820729
http://msdn.microsoft.com/en-us/library/dd299441(v=exchg.80).aspx

.DESCRIPTION

The Get-IISStats.ps1 script is enumerating all CAS servers in the current or given AD site and parse all IIS log files within the given time range.

As output you will get several CSV files which could be used for analysis.

.PARAMETER UserID

filter for a specific user. Cannot be combined with UserIDs,DeviceID or DeviceIDs

.PARAMETER UserIDs

filter for multiple users. Cannot be combined with UserID,DeviceID or DeviceIDs

.PARAMETER DeviceID

filter for a specific EAS device. Cannot be combined with UserID,UserIDS or DeviceIDs

.PARAMETER DeviceIDs

filter for multiple EAS devices. Cannot be combined with UserID,UserIDS or DeviceID

.PARAMETER StartDate

this is used for filtering the logfiles to be parsed. The format must be yyMMdd. If omitted current date will be used

.PARAMETER EndDate

this is used for filtering the logfiles to be parsed. The format must be yyMMdd. If omitted current date will be used

.PARAMETER LogParser

this is used for the path to LogParser.exe

.PARAMETER ADSite

here you can define in which ADSite is searched for Exchange server. If omitted current AD site will be used

.PARAMETER OutPath

where the output will be found. If omitted $env:temp will be used

.PARAMETER LogFolders

which folders to parse. It must be an UNC path without the server name and could have multiple path comma deliminated

.PARAMETER EASReport

will generate a report based on the give script http://blogs.technet.com/b/exchange/archive/2012/01/31/a-script-to-troubleshoot-issues-with-exchange-activesync.aspx with some minor changes.
Could be combined with UserID. Otherwise it will create a report for all devices.

.PARAMETER EASReportByDeviceType

will generate a report of Devicetypes

.PARAMETER EASErrorReport

creates a report with all EAS errors. Could be combined with UserID.

.PARAMETER EASErrorReportByDeviceType

will generate a report of EAS errors grouped by DeviceType

.PARAMETER HTTPReport

creates a report of all errors from the HTTPERR logs.

.PARAMETER ClientReport

creates a report of all clients and their hits. Note: It's not the number of unique clients!

.PARAMETER ClientBandwidth

creates several files, which could be used for bandwidth analysis. Note: Enhanced IIS logging must be enabled in order to get the transferred bytes (cs-bytes,sc-bytes)!

.PARAMETER EASDetails

if used you will get much more details for EAS traffic. Good for troubleshooting EAS devices. Is set to $true by default when DeviceID or DeviceIDs are given.

.PARAMETER Localpath

if you have log files in a local folder. There is no filtering by date! All files will be analyzed.

.PARAMETER SpecifiedServers

if you want to specify one or more server rather than retrieving from AD.

.PARAMETER AllextendedIISFields

enforce extended IIS log fields '[Bytes received]','[Bytes sent]' and 'Host'

.EXAMPLE 

To generate a report for the current day. 4 queries will be run: Hits with detailed information, Hits per hour, errors and all EAS devices
.\Get-IISStats.ps1

To generate a report of all request from a specific user. Could not be used together with "-deviceid" or "-deviceids".
.\Get-IISStats.ps1 -userid donald

To generate a report of all request from a specific user with EAS specific details. Could not be used together with "-deviceid" or "-deviceids".
.\Get-IISStats.ps1 -userid donald -easdetails

To generate a report of all request from specific users. Could not be used together with "-deviceid" or "-deviceids".
.\Get-IISStats.ps1 -userids trick,track

To generate a report of all request from a specific device. Could not be used together with "-userid" or "-userids".
.\Get-IISStats.ps1 -deviceid binford5000

To generate a report of all request from specific devices. Could not be used together with "-userid" or "-userids".
.\Get-IISStats.ps1 -deviceids binford5000,fluxcapacitor3002

To generate a report of all EAS devices
.\Get-IISStats.ps1 -easreport

To generate a report of EAS devices from a specific user
.\Get-IISStats.ps1 -easreport -userid dagobert

To generate a report of EAS devices for specific users. Could only be used with "-easreport".
.\Get-IISStats.ps1 -easreport -userids daisy,arabella

To generate a report of all EAS errors
.\Get-IISStats.ps1 -easerrorreport

To generate a report of all EAS errors for a dedicated user
.\Get-IISStats.ps1 -easerrorreport -userid goofy

To generate a report of EAS devices from a specific devices. Could only be used with "-easreport".
.\Get-IISStats.ps1 -easreport -deviceids cherry01,pear02

For a specific time range and path to LogParser.exe
.\Get-IISStats.ps1 -startdate yymmdd -enddate yymmdd -Logparser "C:\Temp\Logparser.exe"

To generate a report over all HTTPERR logs
.\Get-IISStats.ps1 -httpreport

.NOTES

You need to run this script in the same AD site where the servers are.

#>

[CmdletBinding(DefaultParameterSetName = "ALL")]

param(

    [parameter( Mandatory=$false, ParameterSetName="ALL")]
    [parameter( Mandatory=$false, ParameterSetName="USER")]
    [parameter( Mandatory=$false, ParameterSetName="EAS")]
    [parameter( Mandatory=$false, ParameterSetName="EASERROR")]
    [parameter( Mandatory=$false, ParameterSetName="EASDETAILS")]
    [parameter( Position=0)]
    [string]$UserID,
    
    [parameter( Mandatory=$false, ParameterSetName="ALL")]
    [parameter( Mandatory=$false, ParameterSetName="USERS")]
    [parameter( Mandatory=$false, ParameterSetName="EASDETAILS")]
    [parameter( Position=1)]
    [array]$UserIDs,
    
    [parameter( Mandatory=$false, ParameterSetName="ALL")]
    [parameter( Mandatory=$false, ParameterSetName="DEVICE")]
    [parameter( Mandatory=$false, ParameterSetName="EASDETAILS")]
    [parameter( Position=2)]
    [string]$DeviceID,
    
    [parameter( Mandatory=$false, ParameterSetName="ALL")]
    [parameter( Mandatory=$false, ParameterSetName="DEVICES")]
    [parameter( Mandatory=$false, ParameterSetName="EASDETAILS")]
    [parameter( Position=3)]
    [array]$DeviceIDs,
    
    [parameter( Mandatory=$false, Position=4)]
    [int]$StartDate="$((get-date).ToString("yyMMdd"))",
    
    [parameter( Mandatory=$false, Position=5)]
    [int]$EndDate="$((get-date).ToString("yyMMdd"))",

    [parameter( Mandatory=$false, Position=6)]
    [ValidateScript({If (Test-Path $_ -PathType leaf) {$True} Else {Throw "Logparser could not be found!"}})]
    [string]$Logparser="C:\Program Files (x86)\Log Parser 2.2\LogParser.exe",

    [parameter( Mandatory=$false, Position=7)]
    [string[]]$ADSite="$(([System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite()).GetDirectoryEntry().Name)",
    
    [parameter( Mandatory=$false, Position=8)]
    [ValidateScript({If (Test-Path $_ -PathType container) {$True} Else {Throw "$_ is not a valid path!"}})]
    [string]$Outpath = $env:temp,

    [parameter( Mandatory=$false, Position=9)]
    [array]$LogFolders=@("C$\inetpub\logs\LogFiles\W3SVC1","C$\inetpub\logs\LogFiles\W3SVC2"),
 
    [parameter( Mandatory=$false, ParameterSetName="ALL")]
    [parameter( Mandatory=$false, ParameterSetName="EASREPORT")]
    [parameter( Mandatory=$false, Position=11)]
    [switch]$EASReport,

    [parameter( Mandatory=$false, ParameterSetName="ALL")]
    [parameter( Mandatory=$false, ParameterSetName="EASReportByDeviceType")]
    [parameter( Mandatory=$false, Position=11)]
    [switch]$EASReportByDeviceType,

    [parameter( Mandatory=$false, ParameterSetName="ALL")]
    [parameter( Mandatory=$false, ParameterSetName="EASERROR")]
    [parameter( Mandatory=$false, Position=12)]
    [switch]$EASErrorReport,

    [parameter( Mandatory=$false, ParameterSetName="ALL")]
    [parameter( Mandatory=$false, ParameterSetName="EASErrorReportByDeviceType")]
    [parameter( Mandatory=$false, Position=13)]
    [switch]$EASErrorReportByDeviceType,

    [parameter( Mandatory=$false, ParameterSetName="HTTP")]
    [parameter( Mandatory=$false, Position=14)]
    [switch]$HTTPReport,

    [parameter( Mandatory=$false, ParameterSetName="HTTP")]
    [parameter( Mandatory=$false, Position=15)]
    [switch]$HTTPReportPerIntervall,

    [parameter( Mandatory=$false, ParameterSetName="HTTP")]
    [parameter( Mandatory=$false, Position=16)]
    [int]$HTTPReportIntervall = "600",

    [parameter( Mandatory=$false, ParameterSetName="CLIENT")]
    [parameter( Mandatory=$false, Position=17)]
    [switch]$ClientReport,

    [parameter( Mandatory=$false, ParameterSetName="CLIENTBANDWIDTH")]
    [parameter( Mandatory=$false, Position=18)]
    [switch]$ClientBandwidth,

    [parameter( Mandatory=$false, ParameterSetName="EASDETAILS")]
    [parameter( Mandatory=$false, Position=19)]
    [switch]$EASDetails,

    [parameter( Mandatory=$false, Position=20)]
    [ValidateScript({If (Test-Path $_ -PathType container) {$True} Else {Throw "$_ is not a valid path!"}})]
    [string]$Localpath,

    [parameter( Mandatory=$false, Position=21)]
    [array]$SpecifiedServers,   

    [parameter( Mandatory=$false, Position=22)]
    [switch]$AllextendedIISFields,

    [parameter( Mandatory=$false, Position=23)]
    [switch]$Exchange2013Only,

    [parameter( Mandatory=$false, Position=24)]
    [switch]$CafeOnly,

    [parameter( Mandatory=$false, Position=25)]
    [switch]$MBOnly,

    [switch]$CustomQuery

)

Begin{
# check for elevated PS
If (! ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Warning "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
    Break
}

If ($CafeOnly -and $MBOnly) {
    Write-Host "Ambigious parameter: Either CafeOnly or MBOnly!" -ForegroundColor Yellow
    break
}

# check if LogParser is in the default path
If (!(Test-Path $Logparser -PathType leaf)) {
    Write-Warning "Logparser could not be found!"
    Break
}

# function to get the Exchangeserver from AD site
Function GetExchServer {
    [CmdLetBinding()]
    #http://technet.microsoft.com/en-us/library/bb123496(v=exchg.80).aspx on the bottom there is a list of values
    param([array]$Roles,[string[]]$ADSites
        )
    Process {
        $valid = @("2","4","16","20","32","36","38","54","64","16385","16439","16423")
        ForEach ($Role in $Roles){
            If (!($valid -contains $Role)) {
                Write-Output "Please use the following numbers: MBX=2,CAS=4,UM=16,HT=32,Edge=64 multirole servers:CAS/HT=36,CAS/MBX/HT=38,CAS/UM=20,E2k13 MBX=54,E2K13 CAS=16385,E2k13 CAS/MBX=16439"
                return
            }
        }
        Function GetADSite {
            param([string]$Name)
            If ($null -eq $Name) {
                [string]$Name = ([System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite()).GetDirectoryEntry().Name
            }
            $FilterADSite = "(&(objectclass=site)(Name=$Name))"
            $RootADSite= ([ADSI]'LDAP://RootDse').configurationNamingContext
            $SearcherADSite = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$RootADSite")
            $SearcherADSite.Filter = "$FilterADSite"
            $SearcherADSite.pagesize = 1000
            $ResultsADSite = $SearcherADSite.FindOne()
            $ResultsADSite
        }
        $Filter = "(&(objectclass=msExchExchangeServer)(|"
        ForEach ($ADSite in $ADSites){
            $Site=''
            $Site = GetADSite -Name $ADSite
            If ($null -eq $Site) {
                Write-Verbose "ADSite $($ADSite) could not be found!"
            }
            Else {
                Write-Verbose "Add ADSite $($ADSite) to filter!"
                $Filter += "(msExchServerSite=$((GetADSite -Name $ADSite).properties.distinguishedname))"
            }
        }
        $Filter += ")(|"
        ForEach ($Role in $Roles){
            $Filter += "(msexchcurrentserverroles=$Role)"
        }
        $Filter += "))"
        $Root= ([ADSI]'LDAP://RootDse').configurationNamingContext
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$Root")
        $Searcher.Filter = "$Filter"
        $Searcher.pagesize = 1000
        $Results = $Searcher.FindAll()
        If ("0" -ne $Results.Count) {
            $Results
        }
        Else {
            Write-Verbose "No server found!"
        }
    }
}

# function to build string for Logparser if multiple userIDs or deviceIDs given
function buildstring {
    param(
    [array]$strings
    )
    ForEach ($string in $strings) {
        $temp += "'" + $string + "';"
    }
    $temp.TrimEnd(";").ToLower()
}

# function to build string for stamp if multiple user- or deviceIDs given
function buildstamp {
    param(
    [array]$strings
    )
    ForEach ($string in $strings) {
        $temp += $string + "_"
    }
    $temp.ToLower()
}

If (([string]::IsNullOrEmpty($Localpath)) -and ([string]::IsNullOrEmpty($SpecifiedServers))) {
    If ($Exchange2013Only) {
        # get CAS servers
        [array]$servers2013 = GetExchServer -Role 54,16385,16439,16423 -ADSites $ADSite
    }
    Else {
        # get CAS servers
        [array]$servers = GetExchServer -Role 4,20,36,38 -ADSites $ADSite
        [array]$servers2013 = GetExchServer -Role 54,16385,16439,16423 -ADSites $ADSite
    }
}

If ($HTTPReport -or $HTTPReportPerIntervall) {
    If ($Localpath) {
        [array]$LogFolders = $localpath
        $ADSite="localfiles"
    }
    Else {
        # default HTTPERR log directory
        [array]$LogFolders = "C$\Windows\System32\LogFiles\HTTPERR" 
    }
}
Else {
    If ($Localpath) {
        [array]$LogFolders = $Localpath
        $ADSite="localfiles"
    }
}   

# set variables
$Path = $null
[array]$LogFiles = $null
$TempPath = $null
[string]$LogsFrom = $null
$outputfiles = $null
$logs = $null
[string]$extendedIISfields=$null

If ($Servers -or $Servers2013) {
    Write-Output "Found the following Exchange 2010 servers:" $($Servers | %{$_.Properties.name})
    Write-Output "Found the following Exchange 2013/2016/2019 servers:" $($Servers2013 | %{$_.Properties.name})
}
ElseIf ($SpecifiedServers) {
    Write-Output "You specified the following servers:" $SpecifiedServers
}
Else {
    If (!($Localpath)) {
        Write-Output "No server found!"
        Break
    }
}
# build folderpath for all servers
If (!($Localpath)) {
	If ($CafeOnly) {
        Write-Verbose "CafeOnly"
        $LogFolders = 'C$\inetpub\logs\LogFiles\W3SVC1'
    }
    ElseIf($MBOnly){
        Write-Verbose "MBOnly"
        $LogFolders = 'C$\inetpub\logs\LogFiles\W3SVC2'
    }
    ForEach ($Server in $SpecifiedServers) {
        ForEach ($Folder in $LogFolders) {
            [array]$TempPath += "\\" + $Server + "\" + $Folder
        }
    }
    ForEach ($Server in $Servers) {
        ForEach ($Folder in $LogFolders) {
            [array]$TempPath += "\\" + $Server.Properties.name + "\" + $Folder
        }
    }
    ForEach ($Server2013 in $Servers2013) {
        ForEach ($Folder in $LogFolders) {
            [array]$TempPath += "\\" + $Server2013.Properties.name + "\" + $Folder
        }
    }
}
Else {
    [array]$TempPath = $localpath
}
# validate all path
Foreach ($Path in $TempPath) { 
    If (Test-Path -LiteralPath $Path) {
        [array]$ValidPath += $Path
    }
}
# get all items in final path
If ($ValidPath) {
    ForEach ($Item in $ValidPath) {
        If (Test-Path -LiteralPath $Item){
            Write-Verbose "Get items from:$($Item)"
            $LogFiles += Get-ChildItem -LiteralPath $Item -Filter "*.log"
        }
    }
}
Else {
    Write-Output "No logs found!"
    Break
}

# check for log type
If (!($HTTPReport -or $HTTPReportPerIntervall)) {
    If (!($Localpath)) {    
        If (($StartDate.ToString().Length -gt 6) -or ($EndDate.ToString().Length -gt 6)) {
            If (($StartDate.ToString().Length -gt 6) -and ($EndDate.ToString().Length -gt 6)) {
                $LogFiles = $LogFiles | ?{$_.name.substring(4,8) -ge $StartDate -and $_.name.substring(4,8) -le $EndDate}
            }
            ElseIf (($StartDate.ToString().Length -gt 6) -and ($EndDate.ToString().Length -eq 6)) {
                $LogFiles = $LogFiles | ?{$_.name.substring(4,8) -ge $StartDate -and $_.name.substring(4,6) -le $EndDate}
            }
            Else {
                $LogFiles = $LogFiles | ?{$_.name.substring(4,6) -ge $StartDate -and $_.name.substring(4,8) -le $EndDate}
            }
        }
        Else {
            $LogFiles = $LogFiles | ?{$_.name.substring(4,6) -ge $startdate -and $_.name.substring(4,6) -le $enddate}
        }
    }
}
ElseIf ($HTTPReport -or $HTTPReportPerIntervall) {
    Write-Verbose "Filter logs..."
    $LogFiles = $LogFiles | Select-Object -Property FullName,@{l="TimeFilter";e={Get-Date $_.LastWriteTimeUtc -Format yyMMdd}} | Where-Object -FilterScript {$_.TimeFilter -ge $StartDate -and $_.TimeFilter -le $EndDate}
}

If ($LogFiles) {
    $LogFiles | %{$Logsfrom += "'" + $_.fullname +"',"}
    $Logsfrom = $Logsfrom.TrimEnd(",")
    Write-Output "Logs to be parsed:"
    $LogFiles |Select-Object -Property fullname|Sort-Object -Property fullname
}
Else {
    Write-Output "No logs found!"
    Break
}

###########################################
# check for extended IIS log fields
Write-Host "Get #Fields from file" ($logsfrom.Split(",") | Select-Object -First 1 ).Replace("'","")
[string]$fields = gc ($logsfrom.Split(",") | Select-Object -First 1 ).Replace("'","") -TotalCount 5 | Where-Object -FilterScript {$_ -like "#Fields*"}

If ($AllextendedIISFields) {
    $extendedIISfields += '[Bytes received],'
    $extendedIISfields += '[Bytes sent],'
    $extendedIISfields += 'Host,'
}
Else {
    If ($fields.contains("cs-bytes")) {
        $extendedIISfields += '[Bytes received],'
    }
    If ($fields.contains("sc-bytes")) {
        $extendedIISfields += '[Bytes sent],'
    }
    If ($fields.contains("cs-host")) {
        $extendedIISfields += 'Host,'
    }
}

}

Process{

If ($HTTPReport) {
    Write-Host -fore yellow "HTTPERRORReport!"
    $stamp = "HTTPErrorReport_" + ($ADSite -join "_") + "_" + $(Get-Date -Format HH-mm-ss)
    $query_HTTPERR = @"
    Select Day,Server,Reason,AppPool,Hits
    USING
    TO_STRING(To_timestamp(date, time),'yyMMdd') AS Day,
    REVERSEDNS(s-ip) AS Server,
    s-reason AS Reason,
    s-queuename AS AppPool,
    COUNT(*) AS Hits
    INTO $outpath\*_$stamp.csv 
    FROM $logsfrom
    WHERE Reason NOT LIKE '%Timer_ConnectionIdle%' AND (Day >= '$startdate' AND Day <= '$enddate')
    Group BY Day,Server,Reason,AppPool
    ORDER BY Hits DESC
"@
    # workaround for limitation of path length, therefore we put the query into a file
    Set-Content -Value $query_HTTPERR -Path $outpath\query.txt -Force
    Write-Output -InputObject "Start query for HTTPErrorReport!"
    & $Logparser file:$outpath\query.txt -i:httperr -o:csv -e:100
    Write-Output -InputObject "Query for HTTPErrorReport done!"

}
ElseIf ($HTTPReportPerIntervall) {
    $stamp = "HTTPErrorReportPerIntervall_" + ($ADSite -join "_") + "_" + $(Get-Date -Format HH-mm-ss)
    $query_HTTPERRPerIntervall = @"
Select Day,TimeUTC,Server,Reason,AppPool,Hits
USING
TO_STRING(To_timestamp(date, time),'yyMMdd') AS Day,
QUANTIZE(time, $HTTPReportIntervall) AS TimeUTC,
REVERSEDNS(s-ip) AS Server,
s-reason AS Reason,
s-queuename AS AppPool,
COUNT(*) AS Hits
INTO $outpath\*_$stamp.csv 
FROM $logsfrom

WHERE Reason NOT LIKE '%Timer_ConnectionIdle%' AND (Day >= '$startdate' AND Day <= '$enddate')
Group BY Day,TimeUTC,Server,Reason,AppPool
ORDER BY TimeUTC ASC
"@
    # workaround for limitation of path length, therefore we put the query into a file
    Set-Content -Value $query_HTTPERRPerIntervall -Path $outpath\query.txt -Force
    Write-Output -InputObject "Start query for HTTPErrorReportPerIntervall!"
    & $Logparser file:$outpath\query.txt -i:httperr -o:csv -e:100
    Write-Output -InputObject "Query for HTTPErrorReportPerIntervall done!"

}
ElseIf ($ClientReport) {
    $stamp = "Clientreport" + "_" + ($ADSite -join "_") + "_" + $(Get-Date -Format HH-mm-ss)
    $query_clientreport = @"
    SELECT DISTINCT Day,Clients,Count(*) AS Hits,RequestURI
    Using
    TO_STRING(To_timestamp(date, time),'yyMMdd') AS Day,
    cs(User-Agent) AS Clients,
    cs-uri-stem AS RequestURI
    INTO    $outpath\*_$stamp.csv
    From 
"@
    $query_clientreport += $logsfrom 
    $query_clientreport += @"
    WHERE Clients >''
    GROUP BY Day,Clients,RequestURI
    ORDER BY Clients ASC
"@
Write-Host "Start query for ClientReport!"
#& $Logparser $query_clientreport -i:iisw3c -o:csv
Set-Content -Value $query_clientreport -Path $Outpath\query.txt -Force
& $Logparser file:$Outpath\query.txt -i:IISW3C -o:csv
Write-Host -Object "Query for ClientReport done!"

}
ElseIf ($ClientBandwidth) {
    # set stamps
    $stamp = "Clientbandwidth" + "_" + ($ADSite -join "_") + "_" + $(Get-Date -Format HH-mm-ss) +"_data"
    $query_clientbandwidth = @"
    SELECT  Day,Hour,VDir,User,EASDeviceId,[KB received],[KB sent],ADD([KB received],[KB sent]) AS [KB Total]
    USING
    TO_STRING(To_timestamp(date, time), 'yyMMdd') AS Day,
    TO_STRING(time, 'HH') AS Hour,
    TO_LOWERCASE(EXTRACT_SUFFIX(cs-username,0,'\\')) AS User,
    EXTRACT_VALUE(cs-uri-query,'DeviceId') AS EASDeviceId,
    EXTRACT_TOKEN(cs-uri-stem,1,'/') AS Vdir,
    DIV(Sum(cs-bytes), 1024) AS [KB received],
    DIV(Sum(sc-bytes), 1024) AS [KB sent]
    INTO $outpath\*_$stamp.csv
    FROM $logsfrom
    WHERE cs-username <> NULL AND cs-username NOT LIKE '%lbhealth%'
    GROUP BY Day,Hour,VDir,User,EASDeviceId
    ORDER BY Hour ASC
"@

Write-Host -Object "Start query for Clientbandwidth!"
#& $Logparser $query_clientbandwidth -i:iisw3c -o:csv
Set-Content -Value $query_clientbandwidth -Path $Outpath\query.txt -Force
& $Logparser file:$Outpath\query.txt -i:IISW3C -o:csv
Write-Host -Object "Query for Clientbandwidth done!"

# run additional queries
# helper to get files
$outputfiles = Get-ChildItem -LiteralPath $outpath -Filter *Clientbandwidth*_data.csv
$outputfiles = $outputfiles | ?{$_.LastWriteTime -gt $((Get-Date).addseconds(-5))}
$outputfiles | %{$logs += $_.fullname +","}
$logs = $logs.TrimEnd(",")

    $query_clientbandwidth_rate = @"
    Select File,Hour,[kB/s KiloBytes/s],[MB/s MegaBytes/s],kbps,Mbps
    Using
    SUM([KB Total]) AS KBTotal,
    DIV(KBTotal,3600) AS [kB/s KiloBytes/s],
    DIV(TO_REAL(DIV(KBTotal,3600)),TO_REAL(1024)) AS [MB/s MegaBytes/s],
    TO_INT(DIV(TO_REAL([kB/s KiloBytes/s]),TO_REAL('0.125'))) AS kbps,
    DIV(TO_REAL(kbps),TO_REAL(1000)) AS Mbps,
    EXTRACT_TOKEN(EXTRACT_TOKEN(EXTRACT_TOKEN(Filename,-1,'\\'),0,'.'),0,'_data') AS File
    INTO $outpath\*_rate.csv
    FROM $logs
    GROUP BY File,Hour
"@

Write-Host -Object "Start query for Clientbandwidth rate!"
#& $Logparser $query_clientbandwidth_rate -i:csv -o:csv
Set-Content -Value $query_clientbandwidth_rate -Path $Outpath\query.txt -Force
& $Logparser file:$Outpath\query.txt -i:IISW3C -o:csv
Write-Host -Object "Query for Clientbandwidth rate done!"

# temporary files
    $query_clientbandwidth_tempusers = @"
    Select Distinct File,Hour,User
    Using
    EXTRACT_TOKEN(EXTRACT_TOKEN(EXTRACT_TOKEN(Filename,-1,'\\'),0,'.'),0,'_data') AS File
    INTO $outpath\*_tempusers.csv
    FROM $logs
    WHERE USER <> NULL
    GROUP BY File,Hour,User
"@

    $query_clientbandwidth_tempeasdevices = @"
    Select Distinct File,Hour,EASDeviceId
    Using
    EXTRACT_TOKEN(EXTRACT_TOKEN(EXTRACT_TOKEN(Filename,-1,'\\'),0,'.'),0,'_data') AS File
    INTO $outpath\*_tempeasdevices.csv
    FROM $logs
    WHERE EASDeviceID <> NULL
    GROUP BY File,Hour,EASDeviceId
"@


Write-Host -Object "Start query for Clientbandwidth tempusers!"
#& $Logparser $query_clientbandwidth_tempusers -i:csv -o:csv
Set-Content -Value $query_clientbandwidth_tempusers -Path $Outpath\query.txt -Force
& $Logparser file:$Outpath\query.txt -i:IISW3C -o:csv
Write-Host -Object "Query for Clientbandwidth tempusers done!"

Write-Host -Object "Start query for Clientbandwidth tempeasdevices!"
#& $Logparser $query_clientbandwidth_tempeasdevices -i:csv -o:csv
Set-Content -Value $query_clientbandwidth_tempeasdevices -Path $Outpath\query.txt -Force
& $Logparser file:$Outpath\query.txt -i:IISW3C -o:csv
Write-Host -Object "Query for Clientbandwidth tempeasdevices done!"

# final files
# helper to get files
$outputfiles = $null
$logs = $null

$outputfiles = Get-ChildItem -LiteralPath $outpath -Filter *_tempusers.csv
$outputfiles | %{$logs += $_.fullname +","}
$logs = $logs.TrimEnd(",")

    $query_clientbandwidth_users = @"
    Select File,Hour,Count(User) As UniqueUsers
    Using
    EXTRACT_TOKEN(EXTRACT_TOKEN(EXTRACT_TOKEN(Filename,-1,'\\'),0,'.'),0,'_tempusers') AS File
    INTO $outpath\*_users.csv
    FROM $logs
    GROUP BY File,Hour
"@

Write-Host -Object "Start query for Clientbandwidth users!"
#& $Logparser $query_clientbandwidth_users -i:csv -o:csv
Set-Content -Value $query_clientbandwidth_users -Path $Outpath\query.txt -Force
& $Logparser file:$Outpath\query.txt -i:IISW3C -o:csv
Write-Host -Object "Query for Clientbandwidth users done!"

$outputfiles = $null
$logs = $null
$outputfiles = Get-ChildItem -LiteralPath $outpath -Filter *_tempeasdevices.csv
$outputfiles | %{$logs += $_.fullname +","}
$logs = $logs.TrimEnd(",")

    $query_clientbandwidth_easdevices = @"
    Select File,Hour,Count(EASDeviceId) As UniqueEASDeviceS
    Using
    EXTRACT_TOKEN(EXTRACT_TOKEN(EXTRACT_TOKEN(Filename,-1,'\\'),0,'.'),0,'_tempeasdevices') AS File
    INTO $outpath\*_easdevices.csv
    FROM $logs
    GROUP BY File,Hour
"@

Write-Host -Object "Start query for Clientbandwidth easdevices!"
#& $Logparser $query_clientbandwidth_easdevices -i:csv -o:csv
Set-Content -Value $query_clientbandwidth_easdevices -Path $Outpath\query.txt -Force
& $Logparser file:$Outpath\query.txt -i:IISW3C -o:csv
Write-Host -Object "Query for Clientbandwidth easdevices done!"

Get-ChildItem -LiteralPath $outpath -Filter *_temp*.csv | Remove-Item -Confirm:$false | Out-Null

}
ElseIf ($EASErrorReportByDeviceType) {
    # set stamps
    If ($userid) {
        $stamp = "EASErrorReportByDeviceType_" +$userid + "_" + ($ADSite -join "_") + "_" + $(Get-Date -Format HH-mm-ss)
    $query_easerror = @"
    Select Day,User,DeviceType,EASError,COUNT(*) AS Hits --,cs-uri-query
"@
    }
    Else {
        $stamp = "EASErrorReportByDeviceType_" + ($ADSite -join "_") + "_" + $(Get-Date -Format HH-mm-ss)
        $query_easerror = @"
    Select Day,DeviceType,EASError,COUNT(*) AS Hits --,cs-uri-query
"@
    }
    $query_easerror += @"
    
    USING
    TO_STRING(To_timestamp(date, time),'yyMMdd') AS Day,
    TO_LOWERCASE (cs-username) AS User,
    EXTRACT_PREFIX( EXTRACT_TOKEN(cs(user-agent),0,'/'),0,'-' ) AS DeviceType1,
    CASE DeviceType1
        WHEN NULL THEN EXTRACT_TOKEN(cs(user-agent),0,'/')
        ELSE DeviceType1
    END AS DeviceType2,
    CASE DeviceType2
        WHEN NULL THEN EXTRACT_PREFIX(EXTRACT_SUFFIX(SUBSTR(EASLog, INDEX_OF(EASLog, 'DevOS:')), 0, 'DevOS:'), 0, '_')
        ELSE DeviceType2
    END AS DeviceType3,
    CASE DeviceType3
        WHEN NULL THEN EXTRACT_VALUE(cs-uri-query,'DeviceType')
        ELSE DeviceType3
    END AS DeviceType,
    EXTRACT_VALUE(cs-uri-query,'Log') AS EASLog,
    EXTRACT_TOKEN(EXTRACT_TOKEN(URLUNESCAPE(SUBSTR (EASLog, ADD (INDEX_OF (EASLog, 'Error:'), 6),INDEX_OF (SUBSTR(EASLog, ADD (INDEX_OF (EASLog, 'Error:'), 6)), '_'))),0,'+'),0,':') AS EASError
    
    INTO $outpath\*_$stamp.csv 
    FROM $logsfrom
"@
    If ($userid) {
    Write-Host -fore yellow "EASErrorReportByDeviceType for UserdID $userid!"
    $query_easerror += @"
    WHERE EASError IS NOT NULL AND User LIKE '%$userid%'
    Group By Day,User,DeviceType,EASError
    ORDER BY Hits DESC
"@
    }
    Else {
    Write-Host -fore yellow "EASErrorReportByDeviceType for all!"
    $query_easerror += @"
    WHERE EASError IS NOT NULL
    Group By Day,DeviceType,EASError
    ORDER BY Hits DESC
"@
    }
Write-Host -Object "Start query for EASErrorReportByDeviceType!"
Set-Content -Value $query_easerror -Path $Outpath\query.txt -Force
& $Logparser file:$Outpath\query.txt -i:IISW3C -o:csv
Write-Host -Object "Query for EASErrorReportByDeviceType done!"

}
ElseIf ($EASErrorReport) {
    # set stamps
    If ($userid) {
        $stamp = "EASErrorReport_" +$userid + "_" + ($ADSite -join "_") + "_" + $(Get-Date -Format HH-mm-ss)
    $query_easerror = @"
    Select Day,Server,User,DeviceId,EASError AS Error,COUNT(*) AS Hits
"@
    }
    Else {
        $stamp = "EASErrorReport_" + ($ADSite -join "_") + "_" + $(Get-Date -Format HH-mm-ss)
        $query_easerror = @"
    Select Day,Server,DeviceID,EASError,COUNT(*) AS Hits
"@
    }
    $query_easerror += @"
    
    USING
    TO_STRING(To_timestamp(date, time),'yyMMdd') AS Day,
    cs-username AS User,
    EXTRACT_VALUE(cs-uri-query,'DeviceId') AS DeviceId,
    EXTRACT_VALUE(cs-uri-query,'Log') AS EASLog,
    EXTRACT_TOKEN(EXTRACT_TOKEN(URLUNESCAPE(SUBSTR (EASLog, ADD (INDEX_OF (EASLog, 'Error:'), 6),INDEX_OF (SUBSTR(EASLog, ADD (INDEX_OF (EASLog, 'Error:'), 6)), '_'))),0,'+'),0,':') AS EASError,
    REVERSEDNS(s-ip) AS Server
    
    INTO $outpath\*_$stamp.csv 
    FROM $logsfrom
"@
    If ($userid) {
    Write-Host -fore yellow "EASErrorReport for UserdID $userid!"
    $query_easerror += @"
    WHERE EASError IS NOT NULL AND cs-username LIKE '%$userid%'
    Group By Day,Server,User,DeviceId,EASError
    ORDER BY Hits DESC
"@
    }
    Else {
    Write-Host -fore yellow "EASErrorReport for all!"
    $query_easerror += @"
    WHERE EASError IS NOT NULL
    Group By Day,Server,DeviceId,EASError
    ORDER BY Hits DESC
"@
    }
Write-Host -Object "Start query for EASErrorReport!"
#& $Logparser $query_easerror -i:iisw3c -o:csv
Set-Content -Value $query_easerror -Path $Outpath\query.txt -Force
& $Logparser file:$Outpath\query.txt -i:IISW3C -o:csv
Write-Host -Object "Query for EASErrorReport done!"

}
ElseIf ($EASReport){
        # set stamps
        If ($userid) {
            $stamp = "EASReport_" +$userid + "_" + ($ADSite -join "_") + "_" + $(Get-Date -Format HH-mm-ss)
        }
        Else {
            $stamp = "EASReport_" + ($ADSite -join "_") + "_" + $(Get-Date -Format HH-mm-ss)
        }
        # queries
        $query_easreport = @"
        SELECT  Day,DeviceId,OverallHits,User,Client,
        SUM(TotalSync) AS SubSeqSync,
        SUM(TotalRecoverSync) AS RecoverSync,
        SUM(TotalInvalidSync) AS InvalidSync,
        SUM(TotalFirstSync) AS FirstSync,
        SUM (MyPing)    AS Ping,
        SUM (MySync)    AS Sync,
        SUM (MyFolderSync)  AS FolderSync,
        SUM (MySendMail)    AS SendMail,
        SUM (MySmartReply)  AS SmartReply,
        SUM (MyMeetingResponse) AS MeetingResponse,
        SUM (MyGetAttachment)   AS GetAttachment,
        SUM (MySmartForward)    AS SmartForward,
        SUM (MyGetHierarchy)    AS GetHierarchy,
        SUM (MyCreateCollection)    AS CreateCollection,
        SUM (MyDeleteCollection)    AS DeleteCollection,
        SUM (MyMoveCollection)  AS MoveCollection,
        SUM (MyFolderCreate)    AS FolderCreate, 
        SUM (MyFolderDelete)    AS FolderDelete,
        SUM (MyFolderUpdate)    AS FolderUpdate,
        SUM (MyMoveItems)   AS MoveItems,
        SUM (MyGetItemEstimate) AS GetItemEstimate,
        SUM (MySearch)  AS Search,
        SUM (MySettings)    AS Settings,
        SUM (MyItemOperations)  AS ItemOperations, 
        SUM (MyProvision)   AS Provision, 
        SUM (MyResolveRecipients)   AS ResolveRecipients,
        SUM (MyValidateCert)    AS ValidateCert,
        SUM (MyDisabledForSyncCnt2) AS UserDisabledForSync,
        SUM (MyOverBudget)  AS OverBudget,
        SUM (MyTooManyJobsQueued)   AS TooManyJobsQueued,
        SUM (MyInvalidContent)  AS InvalidContent,
        SUM (MyServerError) AS ServerError,
        SUM (MyServerErrorRetryLater)   AS ServerErrorRetryLater,
        SUM (MyMailboxQuotaExceeded)    AS MailboxQuotaExceeded,
        SUM (MyDeviceIsBlockedForThisUser)  AS DeviceIsBlockedForThisUser, 
        SUM (MyAccessDenied)    AS AccessDenied,
        SUM (MySyncStateNotFound)   AS SyncStateNotFound,
        SUM (MyDeviceNotFullyProvisionable) AS DeviceNotFullyProvisionable,
        SUM (MyDeviceNotProvisioned)    AS DeviceNotProvisioned,
        SUM (MyItemNotFound)    AS ItemNotFound,
        SUM (MyIIS_5xx) AS IIS_5xx,
        SUM (MyIIS_4xx) AS IIS_4xx,
        SUM (MyIIS_503) AS IIS_503,
        SUM (MyIIS_507) AS IIS_507,
        SUM (MyIIS_409) AS IIS_409,
        SUM (MyIIS_451) AS IIS_451,
        cs-host AS Host
        USING
        TO_STRING(To_timestamp(date, time),'yyMMdd') AS Day,
        COUNT(*) AS OverallHits,
        TO_LOWERCASE (cs-username) AS User,
        TO_LOWERCASE(EXTRACT_SUFFIX(cs-username,0,'\\')) AS User2,
        cs(User-Agent) AS Client,
        cs-uri-stem AS Request,
        cs-uri-query AS RequestDetails,
        TO_LOWERCASE(EXTRACT_VALUE(cs-uri-query,'DeviceId')) AS DeviceId,
        EXTRACT_VALUE(RequestDetails,'Cmd') AS MyCmd,
        EXTRACT_VALUE(cs-uri-query,'Log') AS MyLog,
        SUBSTR (MyLog, ADD (INDEX_OF (MyLog, 'Error:'), 6),
        INDEX_OF (SUBSTR(MyLog, ADD (INDEX_OF (MyLog, 'Error:'), 6)), '_')) AS MyLogError,
        SUBSTR(TO_STRING(sc-status),0,1) AS StatusCode,
        EXTRACT_PREFIX(SUBSTR(MyLog, ADD (INDEX_OF (MyLog, '_St:'), 4)),0,'_') AS MySyncType,
        --detect synctypes
        CASE MYSyncType WHEN 'S' Then 1 ELSE 0 END AS TotalSync,
        CASE MYSyncType WHEN 'R' Then 1 ELSE 0 END AS TotalRecoverSync,
        CASE MYSyncType WHEN 'I' Then 1 ELSE 0 END AS TotalInvalidSync,
        CASE MYSyncType WHEN 'F' Then 1 ELSE 0 END AS TotalFirstSync,
        --detect errors
        CASE MyLogError WHEN 'UserDisabledForSync' THEN 1 ELSE 0 END AS MyDisabledForSyncCnt2,
        CASE MyLogError WHEN 'OverBudget' THEN 1 ELSE 0 END AS MyOverBudget,
        CASE MyLogError WHEN 'TooManyJobsQueued' THEN 1 ELSE 0 END AS MyTooManyJobsQueued,
        CASE MyLogError WHEN 'InvalidContent' THEN 1 ELSE 0 END AS MyInvalidContent,
        CASE MyLogError WHEN 'ServerError' THEN 1 ELSE 0 END AS MyServerError,
        CASE MyLogError WHEN 'ServerErrorRetryLater' THEN 1 ELSE 0 END AS MyServerErrorRetryLater,
        CASE MyLogError WHEN 'MailboxQuotaExceeded' THEN 1 ELSE 0 END AS MyMailboxQuotaExceeded,
        CASE MyLogError WHEN 'DeviceIsBlockedForThisUser' THEN 1 ELSE 0 END AS MyDeviceIsBlockedForThisUser,
        CASE MyLogError WHEN 'AccessDenied' THEN 1 ELSE 0 END AS MyAccessDenied,
        CASE MyLogError WHEN 'SyncStateNotFound' THEN 1 ELSE 0 END AS MySyncStateNotFound,
        CASE MyLogError WHEN 'DeviceNotFullyProvisionable' THEN 1 ELSE 0 END AS MyDeviceNotFullyProvisionable,
        CASE MyLogError WHEN 'DeviceNotProvisioned' THEN 1 ELSE 0 END AS MyDeviceNotProvisioned,
        CASE MyLogError WHEN 'ItemNotFound' THEN 1 ELSE 0 END AS MyItemNotFound,
        -- detect commands
        CASE MyCmd WHEN 'Sync' THEN 1 ELSE 0 END AS MySync,
        CASE MyCmd WHEN 'Ping' THEN 1 ELSE 0 END AS MyPing,
        CASE MyCmd WHEN 'SendMail' THEN 1 ELSE 0 END AS MySendMail,
        CASE MyCmd WHEN 'SmartReply' THEN 1 ELSE 0 END AS MySmartReply,
        CASE MyCmd WHEN 'MeetingResponse' THEN 1 ELSE 0 END AS MyMeetingResponse,
        CASE MyCmd WHEN 'GetAttachment' THEN 1 ELSE 0 END AS MyGetAttachment,
        CASE MyCmd WHEN 'FolderSync' THEN 1 ELSE 0 END AS MyFolderSync,
        CASE MyCmd WHEN 'SmartFoward' THEN 1ELSE 0 END AS MySmartForward,
        CASE MyCmd WHEN 'GetHierarchy' THEN 1 ELSE 0 END AS MyGetHierarchy,
        CASE MyCmd WHEN 'CreateCollection' THEN 1 ELSE 0 END AS MyCreateCollection,
        CASE MyCmd WHEN 'DeleteCollection' THEN 1 ELSE 0 END AS MyDeleteCollection,     
        CASE MyCmd WHEN 'MoveCollection' THEN 1 ELSE 0 END AS MyMoveCollection,
        CASE MyCmd WHEN 'FolderCreate' THEN 1 ELSE 0 END AS MyFolderCreate,
        CASE MyCmd WHEN 'FolderDelete' THEN 1 ELSE 0 END AS MyFolderDelete, 
        CASE MyCmd WHEN 'FolderUpdate' THEN 1 ELSE 0 END AS MyFolderUpdate, 
        CASE MyCmd WHEN 'MoveItems' THEN 1 ELSE 0 END AS MyMoveItems,   
        CASE MyCmd WHEN 'GetItemEstimate' THEN 1 ELSE 0 END AS MyGetItemEstimate,
        CASE MyCmd WHEN 'Search' THEN 1 ELSE 0 END AS MySearch,
        CASE MyCmd WHEN 'Settings' THEN 1 ELSE 0 END AS MySettings,
        CASE MyCmd WHEN 'ItemOperations' THEN 1 ELSE 0 END AS MyItemOperations,
        CASE MyCmd WHEN 'Provision' THEN 1 ELSE 0 END AS MyProvision,
        CASE MyCmd WHEN 'ResolveRecipients' THEN 1 ELSE 0 END AS MyResolveRecipients,
        CASE MyCmd WHEN 'ValidateCert' THEN 1 ELSE 0 END AS MyValidateCert,
        -- detect statuscode
        CASE StatusCode WHEN '5' THEN 1 ELSE 0 END AS MyIIS_5xx, 
        CASE StatusCode WHEN '4' THEN 1 ELSE 0 END AS MyIIS_4xx,
        CASE TO_STRING(sc-status) WHEN '503' THEN 1 ELSE 0 END AS MyIIS_503, 
        CASE TO_STRING(sc-status) WHEN '507' THEN 1 ELSE 0 END AS MyIIS_507, 
        CASE TO_STRING(sc-status) WHEN '409' THEN 1 ELSE 0 END AS MyIIS_409, 
        CASE TO_STRING(sc-status) WHEN '451' THEN 1 ELSE 0 END AS MyIIS_451 
        INTO    $outpath\*_$stamp.csv 
        FROM $logsfrom
"@
        If ($userid) {
            Write-Host -ForegroundColor yellow -Object "EASReport for UserdID $userid!"
            $query_easreport += @"
            
            WHERE (cs-uri-stem LIKE '%microsoft-server-activesync%' AND DeviceId > '') AND User LIKE '%$userid%'
            GROUP BY Day,DeviceID,User,Client,Host
            ORDER BY OverallHits DESC
"@
        }
        ElseIf ($userids) {
            $string = buildstring -strings $userids
            Write-Host -ForegroundColor yellow -Object "EASReport for UserdIDs $string!"
            $query_easreport += @"
            
            WHERE (cs-uri-stem LIKE '%microsoft-server-activesync%' AND DeviceId > '') AND User2 IN ($string)
            GROUP BY Day,DeviceID,User,Client,Host
            ORDER BY OverallHits DESC
"@
        }
        ElseIf ($deviceid) {
            $string = buildstring -strings $deviceid
            Write-Host -ForegroundColor yellow -Object "EASReport for DeviceID $string!"
            $query_easreport += @"
            
            WHERE (cs-uri-stem LIKE '%microsoft-server-activesync%') AND DeviceId LIKE '%$deviceid%'
            GROUP BY Day,DeviceID,User,Client,Host
            ORDER BY OverallHits DESC
"@
        }
        ElseIf ($deviceids) {
            $string = buildstring -strings $deviceids
            Write-Host -ForegroundColor yellow -Object "EASReport for DeviceIDs $string!"
            $query_easreport += @"
            
            WHERE (cs-uri-stem LIKE '%microsoft-server-activesync%') AND DeviceId IN ($string)
            GROUP BY Day,DeviceID,User,Client,Host
            ORDER BY OverallHits DESC
"@
        }
    Else {
        Write-Host -ForegroundColor yellow -Object "EASReport for all!"
        $query_easreport += @"
        WHERE cs-uri-stem LIKE '%microsoft-server-activesync%' AND DeviceId > ''
        GROUP BY Day,DeviceID,User,Client,Host
        ORDER BY OverallHits DESC
"@
    }
    Set-Content -Value $query_easreport -Path $outpath\query.txt -Force
    Write-Host -Object "Start query for EASReport!"
    #& $Logparser $query_easreport -i:IISW3C -o:csv
    Set-Content -Value $query_easreport -Path $Outpath\query.txt -Force
    & $Logparser file:$Outpath\query.txt -i:IISW3C -o:csv
    Write-Host -Object "Query done!"
}
ElseIf ($EASReportByDeviceType){
        # set stamps
        If ($userid) {
            $stamp = "EASReportByDeviceType_" +$userid + "_" + ($ADSite -join "_") + "_" + $(Get-Date -Format HH-mm-ss)
            $query_easreport = @"
            Select Day,User,DeviceType,COUNT(*) AS Hits
"@
        }
        Else {
            $stamp = "EASReportByDeviceType_" + ($ADSite -join "_") + "_" + $(Get-Date -Format HH-mm-ss)
            $query_easreport = @"
            Select Day,DeviceType,COUNT(*) AS Hits
"@
        }
        # queries
        $query_easreport += @"
        
        USING
        TO_STRING(To_timestamp(date, time),'yyMMdd') AS Day,
        TO_LOWERCASE (cs-username) AS User,
        EXTRACT_PREFIX( EXTRACT_TOKEN(cs(user-agent),0,'/'),0,'-' ) AS DeviceType1,
        CASE DeviceType1
            WHEN NULL THEN EXTRACT_TOKEN(cs(user-agent),0,'/')
            ELSE DeviceType1
        END AS DeviceType2,
        CASE DeviceType2
            WHEN NULL THEN EXTRACT_PREFIX(EXTRACT_SUFFIX(SUBSTR(EASLog, INDEX_OF(EASLog, 'DevOS:')), 0, 'DevOS:'), 0, '_')
            ELSE DeviceType2
        END AS DeviceType3,
        CASE DeviceType3
            WHEN NULL THEN EXTRACT_VALUE(cs-uri-query,'DeviceType')
            ELSE DeviceType3
        END AS DeviceType,
        EXTRACT_VALUE(cs-uri-query,'Log') AS EASLog

        INTO    $outpath\*_$stamp.csv 
        FROM $logsfrom
"@
        If ($userid) {
            Write-Host -ForegroundColor yellow -Object "EASReportByDeviceTyp for UserdID $userid!"
            $query_easreport += @"
            
        WHERE (cs-uri-stem LIKE '%microsoft-server-activesync%' AND User LIKE '%$userid%') AND DeviceType IS NOT NULL
        Group By Day,User,DeviceType
        ORDER BY Hits DESC
"@
        }
    Else {
        Write-Host -ForegroundColor yellow -Object "EASReportByDeviceTyp for all!"
        $query_easreport += @"
		WHERE cs-uri-stem LIKE '%microsoft-server-activesync%' AND DeviceType IS NOT NULL
        Group By Day,DeviceType
        ORDER BY Hits DESC
"@
    }
    Set-Content -Value $query_easreport -Path $outpath\query.txt -Force
    Write-Host -Object "Start query for EASReportByDeviceType!"
    Set-Content -Value $query_easreport -Path $Outpath\query.txt -Force
    & $Logparser file:$Outpath\query.txt -i:IISW3C -o:csv
    Write-Host -Object "Query done!"
}
ElseIf ($CustomQuery) {
    $stamp = "CustomQuery" + "_" + ($ADSite -join "_") + "_" + $(Get-Date -Format HH-mm-ss)
    $query_CustomQuery = @"
    SELECT Day,Time AS TimeUTC,ServerIP,ClientIP,User,Client,Request,HttpStatus,sc-status,sc-substatus,Win32StatusDescription,sc-win32-status,[Time taken in MS],RequestDetails
    USING
    TO_STRING(To_timestamp(date, time),'yyMMdd') AS Day,
    s-ip AS ServerIP,
    c-ip AS ClientIP,
    cs-username AS User,
    cs(User-Agent) AS Client,
    cs-uri-stem AS Request,
    cs-uri-query AS RequestDetails,
    STRCAT( TO_STRING(sc-status),STRCAT('.',COALESCE(TO_STRING(sc-substatus), '?'))) AS HttpStatus,
    WIN32_ERROR_DESCRIPTION(sc-win32-status) AS Win32StatusDescription,
    time-taken AS [Time taken in MS]
    
    INTO    $outpath\*_$stamp.csv
    From 
"@
    $query_CustomQuery += $logsfrom 
    $query_CustomQuery += @"
    WHERE ((sc-status <> 200) and (cs-uri-stem LIKE '%microsoft-server-activesync%'))
    GROUP BY Day,TimeUTC,ServerIP,ClientIP,User,Client,Request,HttpStatus,sc-status,sc-substatus,Win32StatusDescription,sc-win32-status,[Time taken in MS],RequestDetails
    ORDER BY TimeUTC
"@

    Write-Host -Object "Start Custom query!"
    #& $Logparser $query_CustomQuery -i:IISW3C -o:csv
    Set-Content -Value $query_CustomQuery -Path $Outpath\query.txt -Force
    & $Logparser file:$Outpath\query.txt -i:IISW3C -o:csv
    Write-Host -Object "Query done!"
}
Else {
    If ($userid -OR $deviceid -OR $userids -OR $deviceids) {
        # set stamps
        If ($userid){
            $stamp = $userid + "_" + ($ADSite -join "_") + "_" + $(Get-Date -Format HH-mm-ss)
        }
        If ($deviceid){
            $stamp = $deviceid + "_" + ($ADSite -join "_") + "_" + $(Get-Date -Format HH-mm-ss)
            $EASDetails=$true
        }
        If ($userids){
            $string = buildstamp -strings $userids
            If ($string.Length -gt 30) {
                $stamp = "multiple_users_" + ($ADSite -join "_") + "_" + $(Get-Date -Format HH-mm-ss)
            }
            Else {
                $stamp = $string + "_" + ($ADSite -join "_") + "_" + $(Get-Date -Format HH-mm-ss)
            }
        }
        If ($deviceids){
            $string = buildstamp -strings $deviceids
            If ($string.Length -gt 30) {
                $stamp = "multiple_devices_" + ($ADSite -join "_") + "_" + $(Get-Date -Format HH-mm-ss)
            }
            Else {
                $stamp = $string + "_" + ($ADSite -join "_") + "_" + $(Get-Date -Format HH-mm-ss)
            }
            $EASDetails=$true
        }
        # queries
        If ($EASDetails) {
        $query_user = @"
        SELECT Day,Time AS TimeUTC,ServerIP,ClientIP,User,Client,Request,DeviceId,HttpStatus,Win32StatusDescription,[Time taken in MS],EASElapsedTime, $extendedIISfields
        EASCmd,EASError,EASSyncType,EASStatus,EASABQStatus,EASClientSyncKey,EASServerSyncKey,EASFolderType,EASFilter,EASServerChanges,EASClientChanges,EASProxy,EASPolicyKey,EASCAFEServer,EASMBXServer,EASHeartBeat,EASFolderCount,EASFolderId,EASDevOS,
        EASLog,EASActivity

"@
        }
        Else {
        $query_user = @"
        SELECT Day,Time AS TimeUTC,ServerIP,ClientIP,User,Client,Request,DeviceId,EASCmd,EASError,HttpStatus,Win32StatusDescription,[Time taken in MS], $extendedIISfields
        RequestDetails
        
"@      
        }
        $query_user += @"
        USING
        TO_STRING(To_timestamp(date, time),'yyMMdd') AS Day,
        s-ip AS ServerIP,
        c-ip AS ClientIP,
        COUNT(*) AS OverallHits,
        cs-username AS User,
        TO_LOWERCASE(EXTRACT_SUFFIX(cs-username,0,'\\')) AS User2,
        cs(User-Agent) AS Client,
        Sum(cs-bytes) AS [Bytes received],
        Sum(sc-bytes) AS [Bytes sent],
        cs-uri-stem AS Request,
        cs-uri-query AS RequestDetails,
        STRCAT( TO_STRING(sc-status),STRCAT('.',COALESCE(TO_STRING(sc-substatus), '?'))) AS HttpStatus,
        --sc-win32-status AS Win32Status,
        WIN32_ERROR_DESCRIPTION(sc-win32-status) AS Win32StatusDescription,
        time-taken AS [Time taken in MS],
        EXTRACT_VALUE(cs-uri-query,'Cmd') AS EASCmd,
        TO_LOWERCASE(EXTRACT_VALUE(cs-uri-query,'DeviceId')) AS DeviceId,
        URLUNESCAPE(EXTRACT_VALUE(cs-uri-query,'Log')) AS EASLog,
        cs-host AS Host,
        EXTRACT_TOKEN(EXTRACT_TOKEN(URLUNESCAPE(SUBSTR (EASLog, ADD (INDEX_OF (EASLog, 'Error:'), 6),INDEX_OF (SUBSTR(EASLog, ADD (INDEX_OF (EASLog, 'Error:'), 6)), '_'))),0,'+'),0,':') AS EASError,
        -- EAS details
        EXTRACT_PREFIX(EXTRACT_SUFFIX(SUBSTR(EASLog, INDEX_OF(EASLog, '_As:')), 0, '_As:'), 0, '_') As EASABQStatus,
        TO_INT(EXTRACT_PREFIX(EXTRACT_SUFFIX(EASLog, 0, '_Sk:'), 0, '_')) As EASClientSyncKey,
        TO_INT(EXTRACT_PREFIX(EXTRACT_SUFFIX(EASLog, 0, '_Sks'), 0, '_')) As EASServerSyncKey2013,
        TO_INT(EXTRACT_PREFIX(EXTRACT_SUFFIX(EASLog, 0, '_Sks:'), 0, '_')) As EASServerSyncKey2016,
        
        CASE EASServerSyncKey2013
            WHEN NULL THEN EASServerSyncKey2016
            ELSE EASServerSyncKey2013
        END AS EASServerSyncKey,

        TO_INT(EXTRACT_PREFIX(EXTRACT_SUFFIX(EASLog, 0, '_Fc'), 0, '_')) As EASFolderCountPre2016,
        TO_INT(EXTRACT_PREFIX(EXTRACT_SUFFIX(EASLog, 0, '_FldrC1:'), 0, '_')) As EASFolderCount2016,
        CASE EASFolderCountPre2016
            WHEN NULL THEN EASFolderCount2016
            ELSE EASFolderCountPre2016
        END AS EASFolderCount,

        EXTRACT_PREFIX(EXTRACT_SUFFIX(SUBSTR(EASLog, INDEX_OF(EASLog, 'Fet:')), 0, 'Fet:'), 0, '_') AS EASElapsedTime,
        TO_INT(EXTRACT_PREFIX(EXTRACT_SUFFIX(EASLog, 0, '_Fid:'), 0, '_')) As EASFolderId,
        EXTRACT_PREFIX(EXTRACT_SUFFIX(SUBSTR(EASLog, INDEX_OF(EASLog, 'Ty:')), 0, 'Ty:'), 0, '_') As EASFolderType,
        TO_INT(EXTRACT_PREFIX(EXTRACT_PREFIX(EXTRACT_SUFFIX(EASLog, 0, '_S'), 0, '_Pk'), 0, '_')) As EAS2k10Status,
        TO_INT(EXTRACT_SUFFIX(EXTRACT_PREFIX(EASLog, 0, '_As:'),0,'_S')) As EAS2k13Status,
        TO_INT(EXTRACT_SUFFIX(EXTRACT_PREFIX(SUBSTR(EASLog, INDEX_OF(EASLog,'SC1:')), 0, '_'),0,'SC1:')) As EAS2k16Status,
        CASE EAS2k10Status
            WHEN NULL THEN EAS2k13Status
            ELSE EAS2k10Status
        END AS TempEASStatus,
        
        CASE TempEASStatus
            WHEN NULL THEN EAS2k16Status
            ELSE TempEASStatus  
        END AS EASStatus,

        EXTRACT_PREFIX(EXTRACT_SUFFIX(SUBSTR(EASLog, INDEX_OF(EASLog, 'Srv:')), 0, 'Srv:'), 0, '_') AS EASServerChanges,
        EXTRACT_PREFIX(EXTRACT_SUFFIX(SUBSTR(EASLog, INDEX_OF(EASLog, 'Cli:')), 0, 'Cli:'), 0, '_') AS EASClientChanges,
        TO_INT(EXTRACT_PREFIX(EXTRACT_SUFFIX(EASLog, 0, '_Hb'), 0, '_')) As EASHeartBeatPre16,
        TO_INT(EXTRACT_PREFIX(EXTRACT_SUFFIX(EASLog, 0, '_Hb:'), 0, '_')) As EASHeartBeat2016,
        CASE EASHeartBeatPre16
            WHEN NULL THEN EASHeartBeat2016
            ELSE EASHeartBeatPre16
        END AS EASHeartBeat,

        TO_INT(EXTRACT_PREFIX(EXTRACT_SUFFIX(EASLog, 0, '_Pk'), 0, '_')) As EASPolicyKeyPre2016,
        TO_INT(EXTRACT_PREFIX(EXTRACT_SUFFIX(EASLog, 0, '_Pk:'), 0, '_')) As EASPolicyKey2016,
        CASE EASPolicyKeyPre2016
            WHEN NULL THEN EASPolicyKey2016
            ELSE EASPolicyKeyPre2016
        END AS EASPolicyKey,

        EXTRACT_SUFFIX(EASLog, 0, '_ActivityContextData:') AS EASActivity,

        TO_INT(EXTRACT_SUFFIX(EXTRACT_PREFIX(SUBSTR(EASLog, INDEX_OF(EASLog,'_Filt')), 1, '_'),0,'_Filt')) As MYFILTER13,
        TO_INT(EXTRACT_SUFFIX(EXTRACT_PREFIX(SUBSTR(EASLog, INDEX_OF(EASLog,'_Filter1:')), 1, '_'),0,'_Filter1:')) As MYFILTER16,
        CASE MYFILTER13
            WHEN NULL THEN MYFILTER16
            ELSE MYFILTER13
        END AS MYFILTER,

        CASE MYFILTER
            WHEN 0 THEN 'No Filter'
            WHEN 1 THEN '1 day'
            WHEN 2 THEN '3 days'
            WHEN 3 THEN '1 week'
            WHEN 4 THEN '2 weeks'
            WHEN 5 THEN '1 month'
            WHEN 6 THEN '3 months'
            WHEN 7 THEN '6 months'
            WHEN 8 THEN 'Incomplete tasks'
            ELSE ''
        END AS EASFilter,
        EXTRACT_PREFIX(SUBSTR(EASLog, ADD (INDEX_OF (EASLog, '_St:'), 4)),0,'_') AS MySyncType,
        CASE MySyncType
            WHEN 'F' THEN 'First Sync'
            WHEN 'S' THEN 'Subsequent sync'
            WHEN 'R' THEN 'Recovery sync'
            WHEN 'I' THEN 'Invalid sync'
            ELSE ''
        END AS EASSyncType,
        EXTRACT_PREFIX(SUBSTR(EASLog, INDEX_OF(EASLog, 'Prx')), 0,'_') AS EASProxy,
        EXTRACT_PREFIX(EXTRACT_SUFFIX(SUBSTR(EASLog, INDEX_OF(EASLog, '_Mbx:')), 0, '_Mbx:'), 0, '_') As EASMBXServer,
        EXTRACT_PREFIX(EXTRACT_SUFFIX(SUBSTR(EASLog, INDEX_OF(EASLog, '_Cafe:')), 0, '_Cafe:'), 0, '_') As EASCAFEServer,
        EXTRACT_PREFIX(EXTRACT_SUFFIX(SUBSTR(EASLog, INDEX_OF(EASLog, 'DevOS:')), 0, 'DevOS:'), 0, '_') As EASDevOS
        
        INTO $outpath\*_Hits_by_$stamp.csv
        FROM $logsfrom
"@
        If ($userid){
            Write-Host -ForegroundColor yellow -Object "Query for user $userid!"
            $query_user += @"
            WHERE User LIKE '%$userid%'
"@
        }
        If ($deviceid){
            Write-Host -ForegroundColor yellow -Object "Query for device $deviceid!"
            $query_user += @"
            WHERE DeviceID LIKE '%$deviceid%' AND cs-uri-stem LIKE '%Microsoft-Server-ActiveSync%'
"@
        }
        If ($userids){
            $string = buildstring -strings $userids
            Write-Host -ForegroundColor yellow -Object "Query for users $string!"
            $query_user += @"
            WHERE User2 IN ($string)
"@
        }
        If ($deviceids){
            $string = buildstring -strings $deviceids
            Write-Host -ForegroundColor yellow -Object "Query for devices $string!"
            $query_user += @"
            WHERE DeviceId IN ($string) AND cs-uri-stem LIKE '%Microsoft-Server-ActiveSync%'
"@
        }
        $query_user += @"
        GROUP BY Day,TimeUTC,ServerIP,ClientIP,User,Client,Request,DeviceId,EASDevOS,EASCmd,EASError,EASLog,HttpStatus,Win32StatusDescription,[Time taken in MS],RequestDetails
        ORDER BY Day ASC
"@

        Write-Host -Object "Start query for a dedicated user or device!"
        #$query_user
        Set-Content -Value $query_user -Path $Outpath\query.txt -Force
        & $Logparser file:$Outpath\query.txt -i:IISW3C -o:csv
        Write-Host -Object "Query done!"
    }
    Else {
        Write-Host -ForegroundColor yellow -Object "All queries for statistics!"
        # build queries
        # query for errors
        $query_errors = @"
        SELECT DISTINCT Day,cs-uri-stem AS Request,HttpStatus,Win32Status,SourceIP,Hits 
        USING
        TO_STRING(To_timestamp(date, time), 'yyMMdd') AS Day,
        STRCAT( TO_STRING(sc-status),STRCAT('.',COALESCE(TO_STRING(sc-substatus), '?'))) AS HttpStatus,
        WIN32_ERROR_DESCRIPTION(sc-win32-status) AS Win32Status,
        c-ip AS SourceIP,
        COUNT(*) AS Hits
        Into $outpath\*_IIS_errors.csv 
        From $logsfrom 
        WHERE (sc-status between 400 and 403) or sc-status = 503
        GROUP BY Day,cs-uri-stem,Httpstatus,Win32Status,SourceIP
        ORDER BY Hits DESC
"@
        # query hits by IP
        $query_hits = @"
        SELECT Day,SourceIP,OverallHits,User,Client,[Bytes received],[Bytes sent],EASRequest
        USING
        TO_STRING(To_timestamp(date, time), 'yyMMdd') AS Day,
        c-ip AS SourceIP,
        COUNT(*) AS OverallHits,
        cs-username AS User,
        cs(User-Agent) AS Client,
        Sum(cs-bytes) AS [Bytes received],
        Sum(sc-bytes) AS [Bytes sent],
        cs-uri-stem AS Request,
        CASE Request 
        WHEN '/Microsoft-Server-ActiveSync/default.eas' 
            THEN 1
            ELSE 0
        END AS EASRequest
        INTO $outpath\*_hits_by_ip.csv 
        FROM $logsfrom 
        GROUP BY Day,SourceIP,User,Client,EASRequest
        ORDER BY OverallHits DESC
"@

        # query hits per hour
        $query_hour = @"
        SELECT  Day,Hour,Hits,SUM(EASRequest) AS EASHits
        USING
        TO_STRING(To_timestamp(date, time), 'yyMMdd') AS Day,
        TO_STRING(time, 'HH') AS Hour,
        COUNT(*) AS Hits,
        cs-uri-stem AS Request,
        CASE Request 
            WHEN '/Microsoft-Server-ActiveSync/default.eas' 
            THEN 1
            ELSE 0
        END AS EASRequest
        INTO $outpath\*_hits_by_hour.csv
        FROM $logsfrom 
        GROUP BY Day,Hour
        ORDER BY Hour ASC
"@

        # query EAS devices
        $query_easdevice = @"
        Select DISTINCT Day,EASDeviceId,UserAgents
        USING
        EXTRACT_VALUE(cs-uri-query,'DeviceId') AS EASDeviceId,
        TO_STRING(To_timestamp(date, time), 'yyMMdd') AS Day,
        cs(User-Agent) AS UserAgents
        INTO $outpath\*_eas_devices.csv
        FROM $logsfrom 
        WHERE cs-uri-stem LIKE '%microsoft-server-activesync%' AND EASDeviceId > ''
"@

        Write-Host -Object "Start query for errors!"
        & $Logparser $query_errors -i:IISW3C -o:csv -e:100
        Write-Host -Object "Query for errors done!"

        Write-Host -Object "Start query for hits per day!"
        & $Logparser $query_hits -i:IISW3C -o:csv -e:100
        Write-Host -Object "Query for hits per day done!"

        Write-Host "Start query for hits per hour!"
        & $Logparser $query_hour -i:IISW3C -o:csv -e:100
        Write-Host -Object "Query for hits per hour done!"

        Write-Host -Object "Start query for EAS devices!"
        & $Logparser $query_easdevice -i:IISW3C -o:csv -e:100
        Write-Host -Object "Query for EAS devices done!"
    }
}
}

End{
    # clean query file
    Get-ChildItem -LiteralPath $Outpath -Filter query.txt | Remove-Item -Confirm:$false | Out-Null
}