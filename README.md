# Get-IISStats
Parse the IIS or HTTPErr logs for given user/s device/s or create some statistical reports.

### Prerequisites

* UNC access to all Exchange servers
* Logparser

### Usage

The script has multiple parameters. Only a few are shown in this example:

```
.\Get-IISStats.ps1 -UserID trick -Outpath C:\Temp\Output -StartDate 141020 -EndDate 141020
```

### About

For more information on this script, as well as usage and examples, see
the related blog articles on [The Clueless Guy]:
https://ingogegenwarth.wordpress.com/2017/06/15/iisstats-update/
https://ingogegenwarth.wordpress.com/2015/02/14/troubleshooting-exchange-with-logparseriis-logs-1/
https://ingogegenwarth.wordpress.com/2015/03/03/troubleshooting-exchange-with-logparseriis-logs-2/

## License

This project is licensed under the MIT License - see the LICENSE.md for details.