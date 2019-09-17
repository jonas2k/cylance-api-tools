function Get-JwtToken {
    Param (
        [parameter(Mandatory = $true)]
        [String]$secret,
        [parameter(Mandatory = $true)]
        [String]$issuer,
        [parameter(Mandatory = $true)]
        [String]$appId,
        [parameter(Mandatory = $true)]
        [String]$tenantId,
        [parameter(Mandatory = $true)]
        [int]$expirationSeconds
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

    [pscustomobject]$h = @{
        alg = "HS256"
        typ = "JWT"
    }

    $h_json = $h | ConvertTo-Json -Compress
    $p_json = $claims | ConvertTo-Json -Compress

    $h = ConvertTo-Base64UrlEncoding $h_json
    $p = ConvertTo-Base64UrlEncoding $p_json
    $s = Get-HMACSHA256 -Message "${h}.${p}" -secret $secret

    return "$h.$p.$s"
}

function ConvertTo-Base64UrlEncoding {
    Param(
        [parameter(Mandatory = $true)]
        [Object]$s
    )
    if ($s -is [String]) {
        $s = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($s))
    }
    elseif ($s -is [byte[]]) {
        $s = [Convert]::ToBase64String($s)
    }
    $s.Split("=")[0].Replace("+", "-").Replace("/", "_")
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
    ConvertTo-Base64UrlEncoding $signatureBytes
}

function Get-BearerToken {
    Param (
        [parameter(Mandatory = $True)]
        [String]$jwtToken
    )

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
        [array]$inputArray
    )

    $groupedItems = @()
    $partCount = [math]::Ceiling($inputArray.Length / $chunkSize)

    for ($i = 0; $i -lt $partCount; $i++) {
        $start = $i * $chunkSize
        $end = (($i + 1) * $chunkSize) - 1
        $groupedItems += , @($inputArray[$start..$end])
    }
    return $groupedItems
}

function Get-DateIsOutOfRange {
    Param(
        [parameter(Mandatory = $true)]
        [datetime]$inputDate,
        [parameter(Mandatory = $true)]
        [int]$daysBack
    )
    return ($inputDate).Date -lt (Get-Date).AddDays(-$daysBack).Date
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
    $groupedDeviceIds = @(Get-Chunks -chunkSize 20 -inputArray $deviceIdsToBeRemoved)

    $headers = @{
        "Accept"        = "application/json"
        "Authorization" = "Bearer $bearerToken"
        "Content-Type"  = "application/json; charset=utf-8"
    }

    foreach ($group in $groupedDeviceIds) {
        $params = ConvertTo-Json @{
            "device_ids" = @($group.id)
        }
        # Write-Host $params
        Invoke-RestMethod -Method "DELETE" -Uri $cylanceApiDevicesUri -Body $params -Headers $headers
    }
    Write-Host "Deleted $($deviceIdsToBeRemoved.Count) devices."
}