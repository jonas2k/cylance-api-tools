function Invoke-CylanceInactiveCleanup {
    Param (
        [parameter(Mandatory = $true)]
        [String]$applicationId,
        [parameter(Mandatory = $true)]
        [String]$applicationSecret,
        [parameter(Mandatory = $true)]
        [String]$tenantId,
        [parameter(Mandatory = $true)]
        [int]$inactiveDays
    )

    $jwtIssuer = $MyInvocation.MyCommand.Module.PrivateData["jwtIssuer"]
    $jwtToken = Get-JwtToken -secret $applicationSecret -tenantId $tenantId -appId $applicationId -expirationSeconds 120 -issuer $jwtIssuer
    $bearerToken = Get-BearerToken -jwtToken $jwtToken

    $headers = @{
        "Accept"        = "application/json"
        "Authorization" = "Bearer $bearerToken"
    }

    $params = @{
        "page"      = 1
        "page_size" = 5000
    }
    
    Write-Host "Checking devices, this may take a while."

    $cylanceApiDevicesUri = $MyInvocation.MyCommand.Module.PrivateData["cylanceApiDevicesUri"]
    $response = Invoke-RestMethod -Method "GET" -Uri $cylanceApiDevicesUri -Body $params -Headers $headers
    $offline = $response.page_items | Where-Object { $null -ne $_.id -and $_.state -eq "Offline" -and (Get-DateIsOutOfRange -inputDate $_.date_first_registered -daysBack 1) }

    [Array]$devicesToBeRemoved = @()
    $daysAgo = (Get-Date).AddDays(-$inactiveDays)

    foreach ($device in $offline) {
        try {
            $fullDevice = Invoke-RestMethod -Method "GET" -Uri ("$cylanceApiDevicesUri/{0}" -f $device.id) -Headers $headers
            if ($null -ne $fullDevice -and $null -eq $fullDevice.date_offline) {
                Write-Host "Skipping $($fullDevice.name) since it seems to be online by now or there is no valid offline date."
            }
            else {
                [datetime]$offlineDate = $fullDevice.date_offline
                if ($offlineDate -lt $daysAgo) {
                    $devicesToBeRemoved += $fullDevice
                }
            }
        }
        catch {
            Write-Error "$($device.name): $($_.Exception.Message)"
        }
    }

    if ($devicesToBeRemoved.Count -gt 0) {
        Write-Host "Devices to be removed:"
        Write-Host ($devicesToBeRemoved | Select-Object name, id, state, date_first_registered, date_offline | Sort-Object -Property date_offline | Format-Table | Out-String)
        $confirmation = Read-UserConfirmation -deviceCount $devicesToBeRemoved.Count

        if ($confirmation -eq 'y') {
            Start-DeviceDeletion -devices $devicesToBeRemoved
        }
        else {
            Write-Host "Aborting."
        }
    }
    else {
        Write-Host "Nothing to do."
    }
}