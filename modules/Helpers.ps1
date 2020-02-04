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
        [String]$tenantId,
        [parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [String]$region
    )

    $jwtIssuer = $MyInvocation.MyCommand.Module.PrivateData["jwtIssuer"]
    $expirationSeconds = $MyInvocation.MyCommand.Module.PrivateData["expirationSeconds"]
    $jwtToken = Get-JwtToken -appId $applicationId -secret $applicationSecret -tenantId $tenantId -expirationSeconds $expirationSeconds -issuer $jwtIssuer

    $headers = @{
        "Accept"       = "application/json"
        "Content-Type" = "application/json; charset=utf-8"
    }

    $body = ConvertTo-Json @{ "auth_token" = $jwtToken }
    return (Invoke-RestMethod -Method "POST" -Uri $(Get-CylanceApiUri -type "Auth" -region $region) -Body $body -Headers $headers).access_token
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
        [string]$bearerToken,
        [parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [String]$region
    )

    $headers = @{
        "Accept"        = "application/json"
        "Authorization" = "Bearer $bearerToken"
    }

    $params = @{
        "page"      = 1
        "page_size" = $MyInvocation.MyCommand.Module.PrivateData["devicePageSize"]
    }

    return Invoke-RestMethod -Method "GET" -Uri (Get-CylanceApiUri -type "Devices" -region $region) -Body $params -Headers $headers
}

function Get-FullCylanceDevice {
    Param(
        [parameter(Mandatory = $true)]
        [string]$deviceId,
        [parameter(Mandatory = $true)]
        [string]$bearerToken,
        [parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [String]$region
    )

    $headers = @{
        "Accept"        = "application/json"
        "Authorization" = "Bearer $bearerToken"
    }
    return Invoke-RestMethod -Method "GET" -Uri ("$(Get-CylanceApiUri -type "Devices" -region $region)/{0}" -f $deviceId) -Headers $headers
}

function Get-MemProtectionEvents {
    Param(
        [parameter(Mandatory = $true)]
        [ValidateRange(1,200)]
        [int]$count,
        [parameter(Mandatory = $true)]
        [string]$bearerToken,
        [parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [String]$region
    )

    $headers = @{
        "Accept"        = "application/json"
        "Authorization" = "Bearer $bearerToken"
    }

    $params = @{
        "page"      = 1
        "page_size" = $count
    }
    return Invoke-RestMethod -Method "GET" -Uri (Get-CylanceApiUri -type "Mem" -region $region) -Body $params -Headers $headers
}

function Add-MemProtectionActionDescription {
    Param(
        [parameter(ValueFromPipeline)]
        $event
    )

    $memProtectionActions = $MyInvocation.MyCommand.Module.PrivateData["memProtectionActions"]
    if($memProtectionActions.ContainsKey($([int32]$event.action))) {
        $event | Add-Member -NotePropertyName "action_description" -NotePropertyValue $($memProtectionActions.$([int32]$event.action))
    }
}
function Add-MemProtectionViolationTypeDescription {
    Param (
        [parameter(ValueFromPipeline)]
        $event
    )

    $memProtectionViolationTypes = $MyInvocation.MyCommand.Module.PrivateData["memProtectionViolationTypes"]
    if($memProtectionViolationTypes.ContainsKey($([int32]$event.violation_type))) {
        $event | Add-Member -NotePropertyName "violation_type_description" -NotePropertyValue $($memProtectionViolationTypes.$([int32]$event.violation_type))
    }
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
        [Array]$devicesToBeRemoved,
        [parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [String]$region
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
            # For debugging: Write-Host $params
            Invoke-RestMethod -Method "DELETE" -Uri $(Get-CylanceApiUri -type "Devices" -region $region) -Body $params -Headers $headers > $null
            $deletedDevicesCount += $group.Count
        }
        catch {
            Write-Error "$($_.Exception.Message)"
        }
    }
    Write-Host "Deleted $deletedDevicesCount device(s)."
}

function Get-CylanceApiUri {
    Param(
        [parameter(Mandatory = $true)]
        [ValidateSet("Auth", "Devices", "Mem")]
        [Array]$type,
        [parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [Array]$region
    )
    $cylanceApiUri = "{0}{1}" -f $MyInvocation.MyCommand.Module.PrivateData["cylanceApiBaseUri"], $MyInvocation.MyCommand.Module.PrivateData["cylanceApi{0}Suffix" -f $type]
    
    if (![string]::IsNullOrEmpty($region)) {
        $regionKey = ($MyInvocation.MyCommand.Module.PrivateData["cylanceApiRegions"])[$region]
        $cylanceApiUri = $cylanceApiUri.Insert($cylanceApiUri.IndexOf("."), $regionKey)
    }
    return $cylanceApiUri 
}

function Write-Banner {
    $bannerAsciiArt =
    @'
  _____     __                  ___        _ ______          __  
 / ___/_ __/ /__ ____  _______ / _ | ___  (_)_  __/__  ___  / /__
/ /__/ // / / _ `/ _ \/ __/ -_) __ |/ _ \/ / / / / _ \/ _ \/ (_-<
\___/\_, /_/\_,_/_//_/\__/\__/_/ |_/ .__/_/ /_/  \___/\___/_/___/
    /___/                         /_/                            
'@
    Write-Host $bannerAsciiArt -ForegroundColor "Green"
    Write-Host ("{0} v{1} by {2}`n" -f $MyInvocation.MyCommand.Module.Name, $MyInvocation.MyCommand.Module.Version, $MyInvocation.MyCommand.Module.Author) -ForegroundColor "Green"
}

function Write-ExceptionToConsole {
    Write-Host $_.Exception.Message -ForegroundColor "Red"
    if ($null -ne $_.ErrorDetails.Message) {
        Write-Host ($_.ErrorDetails.Message | ConvertFrom-Json).message -ForegroundColor "Red"
    }
}