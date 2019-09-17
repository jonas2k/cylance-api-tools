function Invoke-CylanceDuplicateCleanup {
    Param (
        [parameter(Mandatory = $true)]
        [String]$applicationId,
        [parameter(Mandatory = $true)]
        [String]$applicationSecret,
        [parameter(Mandatory = $true)]
        [String]$tenantId
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
    
    $cylanceApiDevicesUri = $MyInvocation.MyCommand.Module.PrivateData["cylanceApiDevicesUri"]
    $response = Invoke-RestMethod -Method "GET" -Uri $cylanceApiDevicesUri -Body $params -Headers $headers
    $duplicates = $response.page_items | Group-Object -Property "name" | Where-Object { $_.count -ge 2 }

    [Array]$devicesToBeRemoved = @()
    
    foreach ($deviceGroup in $duplicates) {
        $currentDevices = $deviceGroup.Group | ForEach-Object { $_.date_first_registered = [DateTime]$_.date_first_registered; $_ } | Sort-Object date_first_registered | Select-Object -SkipLast 1
        $devicesToBeRemoved += $currentDevices
    }

    if ($devicesToBeRemoved.Count -gt 0) {
        Write-Host "Devices to be removed:"
        Write-Host ($devicesToBeRemoved | Select-Object name, id, date_first_registered | Sort-Object -Property date_first_registered | Format-Table | Out-String)
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