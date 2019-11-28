function Get-JwtToken {
    Param (
        [parameter(Mandatory = $true)]
        [String]$appId,
        [parameter(Mandatory = $true)]
        [String]$secret,
        [parameter(Mandatory = $true)]
        [String]$issuer,
        [parameter(Mandatory = $true)]
        [int]$expirationSeconds,
        [parameter(Mandatory = $true)]
        [String]$tenantId
    )

    $UtcNow = [int32](((Get-Date -Date ((Get-Date).ToUniversalTime()) -UFormat %s -Millisecond 0)) -Replace ("[,\.]\d*", ""))

    [pscustomobject]$claims = @{
        sub = $appId
        iss = $issuer
        jti = (New-Guid).Guid
        exp = $utcNow + $expirationSeconds
        tid = $tenantId
        iat = $utcNow
    }

    [pscustomobject]$jwtHeader = @{
        alg = "HS256"
        typ = "JWT"
    }

    $jwtHeaderJson = $jwtHeader | ConvertTo-Json -Compress
    $jwtPayloadJson = $claims | ConvertTo-Json -Compress

    $jwtHeader = ConvertTo-Base64UrlEncoding $jwtHeaderJson
    $jwtPayload = ConvertTo-Base64UrlEncoding $jwtPayloadJson
    $jwtSignature = Get-HMACSHA256 -Message "${jwtHeader}.${jwtPayload}" -secret $secret

    return "$jwtHeader.$jwtPayload.$jwtSignature"
}

function ConvertTo-Base64UrlEncoding {
    Param(
        [parameter(Mandatory = $true)]
        [Object]$inputData
    )
    if ($inputData -is [String]) {
        $inputData = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($inputData))
    }
    elseif ($inputData -is [byte[]]) {
        $inputData = [Convert]::ToBase64String($inputData)
    }
    return ($inputData.Split("=")[0].Replace("+", "-").Replace("/", "_"))
}

function Get-HMACSHA256 {
    Param(
        [parameter(Mandatory = $true)]
        [String]$message,
        [parameter(Mandatory = $true)]
        [String]$secret
    )
    $hmacsha = New-Object System.Security.Cryptography.HMACSHA256
    $hmacsha.key = [Text.Encoding]::UTF8.GetBytes($secret)
    $messageBytes = [Text.Encoding]::UTF8.GetBytes($message)
    $signatureBytes = $hmacsha.ComputeHash($messageBytes)
    return (ConvertTo-Base64UrlEncoding $signatureBytes)
}

function Get-BearerToken {
    Param (
        [parameter(Mandatory = $true)]
        [String]$applicationId,
        [parameter(Mandatory = $true)]
        [String]$applicationSecret,
        [parameter(Mandatory = $true)]
        [String]$tenantId
    )

    $jwtIssuer = $MyInvocation.MyCommand.Module.PrivateData["jwtIssuer"]
    $expirationSeconds = $MyInvocation.MyCommand.Module.PrivateData["expirationSeconds"]
    $jwtToken = Get-JwtToken -appId $applicationId -secret $applicationSecret -tenantId $tenantId -expirationSeconds $expirationSeconds -issuer $jwtIssuer

    $headers = @{
        "Accept"       = "application/json"
        "Content-Type" = "application/json; charset=utf-8"
    }

    $body = ConvertTo-Json @{ "auth_token" = $jwtToken }
    $cylanceApiAuthUri = $MyInvocation.MyCommand.Module.PrivateData["cylanceApiAuthUri"]
    return (Invoke-RestMethod -Method "POST" -Uri $cylanceApiAuthUri -Body $body -Headers $headers).access_token
}

function Get-Chunks {
    Param(
        [parameter(Mandatory = $true)]
        [int]$chunkSize,
        [parameter(Mandatory = $true)]
        [array]$inputDataArray
    )

    $groupedItems = @()
    $partCount = [math]::Ceiling($inputDataArray.Length / $chunkSize)

    for ($i = 0; $i -lt $partCount; $i++) {
        $start = $i * $chunkSize
        $end = (($i + 1) * $chunkSize) - 1
        $groupedItems += , @($inputDataArray[$start..$end])
    }
    return $groupedItems
}

function Test-DateIsOutOfRange {
    Param(
        [parameter(Mandatory = $true)]
        [datetime]$inputDate,
        [parameter(Mandatory = $true)]
        [int]$daysBack
    )
    return ($inputDate).Date -lt (Get-Date).AddDays(-$daysBack).Date
}

function Get-CylanceDevices {
    Param(
        [parameter(Mandatory = $true)]
        [string]$bearerToken
    )

    $headers = @{
        "Accept"        = "application/json"
        "Authorization" = "Bearer $bearerToken"
    }

    $params = @{
        "page"      = 1
        "page_size" = $MyInvocation.MyCommand.Module.PrivateData["devicePageSize"]
    }

    $cylanceApiDevicesUri = $MyInvocation.MyCommand.Module.PrivateData["cylanceApiDevicesUri"]
    return Invoke-RestMethod -Method "GET" -Uri $cylanceApiDevicesUri -Body $params -Headers $headers
}

function Get-FullCylanceDevice {
    Param(
        [parameter(Mandatory = $true)]
        [array]$device,
        [parameter(Mandatory = $true)]
        [string]$bearerToken
    )

    $headers = @{
        "Accept"        = "application/json"
        "Authorization" = "Bearer $bearerToken"
    }
    $cylanceApiDevicesUri = $MyInvocation.MyCommand.Module.PrivateData["cylanceApiDevicesUri"]
    return Invoke-RestMethod -Method "GET" -Uri ("$cylanceApiDevicesUri/{0}" -f $device.id) -Headers $headers
}

function Remove-WhitelistedDevices {
    Param(
        [parameter(Mandatory = $true)]
        [Array]$whitelistFile,
        [parameter(Mandatory = $true)]
        [Alias("devices")]
        [Array]$devicesToBeRemoved
    )

    [Array]$whitelistedDevices = (Get-Content $whitelistFile |
        ForEach-Object {
            [PSCustomObject]@{
                name = $_
            }
        })

    if ($whitelistedDevices.Count -gt 0) {
        $comparedDevices = Compare-Object -ReferenceObject $devicesToBeRemoved -DifferenceObject $whitelistedDevices -PassThru -Property name -IncludeEqual

        $skippedDevices = $comparedDevices | Where-Object { $_.sideindicator -eq "==" }
        $results = $comparedDevices | Where-Object { $_.sideindicator -eq "<=" }

        if ($skippedDevices.Count -gt 0) {
            Write-Host "Skipping whitelisted device(s) $(($skippedDevices | Select-Object -expand name) -join ",")." -ForegroundColor "Yellow"
        }
    }
    return $results
}

function Read-UserConfirmation {
    Param(
        [parameter(Mandatory = $true)]
        [int]$deviceCount
    )
    Write-Host "I'm about to delete $deviceCount devices. Are you sure? (y/n)" -ForegroundColor "Red"
    return Read-Host
}

function Start-DeviceDeletion {
    Param(
        [parameter(Mandatory = $true)]
        [Alias("devices")]
        [Array]$devicesToBeRemoved
    )
    [Array]$deviceIdsToBeRemoved = @()
    $deviceIdsToBeRemoved += ($($devicesToBeRemoved | Select-Object -Property "id"))
    $groupedDeviceIds = @(Get-Chunks -chunkSize 20 -inputDataArray $deviceIdsToBeRemoved)

    $headers = @{
        "Accept"        = "application/json"
        "Authorization" = "Bearer $bearerToken"
        "Content-Type"  = "application/json; charset=utf-8"
    }

    [int32]$deletedDevicesCount = 0
    foreach ($group in $groupedDeviceIds) {
        $params = ConvertTo-Json @{
            "device_ids" = @($group.id)
        }

        try {
            # Write-Host $params
            $cylanceApiDevicesUri = $MyInvocation.MyCommand.Module.PrivateData["cylanceApiDevicesUri"]
            Invoke-RestMethod -Method "DELETE" -Uri $cylanceApiDevicesUri -Body $params -Headers $headers > $null
            $deletedDevicesCount += $group.Count
        }
        catch {
            Write-Host "$($_.Exception.Message)"
        }
    }
    Write-Host "Deleted $deletedDevicesCount device(s)."

}