# cylance-api-tools

Collection of several Powershell cmdlets in order to execute certain tasks against the Cylance API.

## Prerequisites

The configured application needs the device privileges "read" and "delete token".

## Usage

Eventually set execution policy and import the module.

```PowerShell
Set-ExecutionPolicy RemoteSigned -Scope Process
Import-Module .\CylanceApiTools.psd1
```

### Invoke-CylanceDuplicateCleanup

Searches for duplicate devices by hostname and removes all but the last one added.

```PowerShell
Invoke-CylanceDuplicateCleanup -applicationId $appId -applicationSecret $appSecret -tenantId $tenId
```

### Invoke-CylanceInactiveCleanup

Searches for inactive devices and removes those whose last activity was past the specified number of days.

```PowerShell
Invoke-CylanceInactiveCleanup -applicationId $appId -applicationSecret $appSecret -tenantId $tenId -inactiveDays 90
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
