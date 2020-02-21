# cylance-api-tools

Collection of several Powershell cmdlets in order to execute certain tasks against the Cylance API.

## Prerequisites

The configured application needs the device privileges "read" and "delete token" as well as the memory protection privilege "read".

## Usage

If necessary, set execution policy and import the module afterwards.

```PowerShell
Set-ExecutionPolicy RemoteSigned -Scope Process
Import-Module .\CylanceApiTools.psd1
```

Alternatively, you may want to install the module to a `$env:PSModulePath`, e.g. `C:\Windows\System32\WindowsPowerShell\v1.0\Modules\CylanceApiTools`.

### Invoke-CylanceDuplicateCleanup

Searches for duplicate devices by hostname and removes all but the last one added.

```PowerShell
Invoke-CylanceDuplicateCleanup -applicationId $appId -applicationSecret $appSecret -tenantId $tenId
```

### Invoke-CylanceInactiveCleanup

Searches for inactive devices and removes those whose last activity was past the specified number of days.

```PowerShell
Invoke-CylanceInactiveCleanup -inactiveDays 75 -applicationId $appId -applicationSecret $appSecret -tenantId $tenId
```

### Show-CylanceMemProtectionEvents

Shows information about the 10 most recent memory protection events. The optional parameter `-count` specifies the amount of events to be fetched (between 1 and a maximum of 200).

```PowerShell
Show-CylanceMemProtectionEvents -count 20 -applicationId $appId -applicationSecret $appSecret -tenantId $tenId
```

### Region

The optional parameter `-region` lets you specify your service endpoint region your organization belongs to. Valid values are `apne1`, `au`, `euc1`, `sae1` and `us`. You can also tab-cycle through these values when typing the command. If the parameter is omitted, North America is used as the default region. For example, if you want to query the european servers:

```PowerShell
... -region "euc1" ...
```

### Environment variables

Furthermore, you can avoid to enter appid, secret and tenant GUIDs directly into the terminal by creating environment variables. Access them e.g. like this:

```PowerShell
... -applicationId $env:appId -applicationSecret $env:appSecret -tenantId $env:tenId ...
```

Additionally, cmdlets will by default look for environment variables named `CylanceApiToolsAppId`, `CylanceApiToolsSecret` and `CylanceApiToolsTenantId` and use their corresponding values (the names can be adapted in the manifest file). If they exist, they will always take precendence over the parameters specified on the command line. Thus, the parameters can be omitted completely and the entire call is much clearer:

```PowerShell
Show-CylanceMemProtectionEvents -count 5
```

## Whitelisting devices

It is possible to whitelist devices by name to except them from deletion. Just create a plain text file containing the hostnames (one item per line) and pass its path using the optional parameter `-whitelistFile`, e.g.

whitelist.txt:
```
HOSTA
HOSTB
FOO
BAR
```

Call:
```PowerShell
Invoke-CylanceDuplicateCleanup -whitelistFile "C:\path\to\whitelist.txt" -applicationId $appId -applicationSecret $appSecret -tenantId $tenId
```

## Device re-registration

If a deleted device is reactivated, it may be in an erroneous state, because the agent has no connection to the management instance. One possible way to solve this problem is the use of SCCM compliance baselines. Here are examples how an automatic re-registration mechanism can be implemented.

### Detection

```PowerShell
$cylanceRegKey = "HKLM:\Software\Cylance\Desktop"
$statusJsonPath = "c:\programdata\cylance\status\status.json"
$lastCommunicatedTimestampThreshold = -75

if (Test-Path -Path $cylanceRegKey) {

    if (Test-Path -Path $statusJsonPath) {
        $lastCommunicatedTimestamp = Get-Date -date (Get-Content -Path $statusJsonPath | ConvertFrom-Json).ProductInfo.last_communicated_timestamp
    }

    if ((Get-ItemProperty -Path $cylanceRegKey -Name "LastStateRestorePoint" -ErrorAction SilentlyContinue) -and ($null -ne $lastCommunicatedTimestamp) -and ($lastCommunicatedTimestamp -gt (Get-Date).AddDays($lastCommunicatedTimestampThreshold))) {
        return $true;
    }
    else {
        return $false;
    }
}
```

### Recovery

```PowerShell
$cylanceRegKey = "HKLM:\Software\Cylance\Desktop"
$installToken = "INSTALL_TOKEN_HERE"

if (Test-Path -Path $cylanceRegKey) {
    if(Get-ItemProperty -Path $cylanceRegKey -Name "LastStateRestorePoint" -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $cylanceRegKey -Name "LastStateRestorePoint" -ErrorAction SilentlyContinue
    }
    Set-ItemProperty -Path $cylanceRegKey -Name "InstallToken" -Value $installToken
}
```
