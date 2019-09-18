# cylance-api-tools

Collection of several Powershell cmdlets in order to execute certain tasks against the Cylance API.

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
