class AuthenticationData {
    [String]$appId
    [String]$secret
    [String]$tenantId
}

function Get-JwtToken {
    param(
        [parameter(Mandatory = $false)]
        [String]$appId,
        [parameter(Mandatory = $false)]
        [String]$secret,
        [parameter(Mandatory = $true)]
        [String]$issuer,
        [parameter(Mandatory = $true)]
        [int]$expirationSeconds,
        [parameter(Mandatory = $false)]
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
    param(
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
    param(
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
    param(
        [parameter(Mandatory = $false)]
        [String]$applicationId,
        [parameter(Mandatory = $false)]
        [String]$applicationSecret,
        [parameter(Mandatory = $false)]
        [String]$tenantId,
        [parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [String]$region
    )
    $jwtIssuer = $MyInvocation.MyCommand.Module.PrivateData["jwtIssuer"]
    $expirationSeconds = $MyInvocation.MyCommand.Module.PrivateData["expirationSeconds"]

    $authenticationData = [AuthenticationData]@{
        appId    = $appId
        secret   = $applicationSecret
        tenantId = $tenantId
    }

    Find-AuthenticationData -authenticationData $authenticationData
    Test-AuthenticationData -authenticationData $authenticationData

    $jwtToken = Get-JwtToken -appId $authenticationData.appId -secret $authenticationData.secret -tenantId $authenticationData.tenantId -expirationSeconds $expirationSeconds -issuer $jwtIssuer

    $headers = @{
        "Accept"       = "application/json"
        "Content-Type" = "application/json; charset=utf-8"
    }
    $body = ConvertTo-Json @{ "auth_token" = $jwtToken }
    return (Invoke-RestMethod -Method "POST" -Uri $(Get-CylanceApiUri -type "Auth" -region $region) -Body $body -Headers $headers).access_token
}

function Find-AuthenticationData {
    param(
        [parameter(Mandatory = $true)]
        [AuthenticationData]$authenticationData
    )

    $applicationIdFromEnv = [Environment]::GetEnvironmentVariable($MyInvocation.MyCommand.Module.PrivateData["AppIdEnvName"])
    $applicationSecretFromEnv = [Environment]::GetEnvironmentVariable($MyInvocation.MyCommand.Module.PrivateData["SecretEnvName"])
    $tenantIdFromEnv = [Environment]::GetEnvironmentVariable($MyInvocation.MyCommand.Module.PrivateData["TenantIdEnvName"])

    if ($applicationIdFromEnv -and $applicationSecretFromEnv -and $tenantIdFromEnv) {
        $authenticationData.appId = $applicationIdFromEnv
        $authenticationData.secret = $applicationSecretFromEnv
        $authenticationData.tenantId = $tenantIdFromEnv
        Write-HostAs -mode "Info" -message "Using authentication data stored in environment variables."
    }
    else {
        Write-HostAs -mode "Info" -message "Using parameter provided authentication data."
    }
}

function Test-AuthenticationData {
    param(
        [parameter(Mandatory = $true)]
        [AuthenticationData]$authenticationData
    )
    if (-not ($authenticationData.appId -and $authenticationData.secret -and $authenticationData.tenantId)) {
        throw "Missing authentication data, provide them either by environment variables or by parameters."
    }
}

function Get-Chunks {
    param(
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
    param(
        [parameter(Mandatory = $true)]
        [DateTime]$inputDate,
        [parameter(Mandatory = $true)]
        [int]$daysBack
    )
    return ($inputDate).Date -lt (Get-Date).AddDays(-$daysBack).Date
}

function Get-CylanceDevices {
    param(
        [parameter(Mandatory = $true)]
        [String]$bearerToken,
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
        "page_size" = $MyInvocation.MyCommand.Module.PrivateData["maxPageSize"]
    }

    $devicesCylanceApiUri = Get-CylanceApiUri -type "Devices" -region $region
    return (Get-CylanceItems -itemCylanceApiUri $devicesCylanceApiUri -params $params -headers $headers)
}

function Get-CylanceItems {
    param (
        [parameter(Mandatory = $true)]
        [String]$itemCylanceApiUri,
        [parameter(Mandatory = $true)]
        [hashtable]$params,
        [parameter(Mandatory = $true)]
        [hashtable]$headers,
        [parameter(Mandatory = $false)]
        [int]$itemLimit = $null
    )

    $items = New-Object -TypeName "System.Collections.ArrayList"

    $initialResponse = Invoke-RestMethod -Method "GET" -Uri $itemCylanceApiUri -Body $params -Headers $headers
    $items.AddRange($initialResponse.page_items)

    if ($initialResponse.total_pages -gt 1 -and ($items.Count -lt $itemLimit)) {
        for ($i = $params.page + 1; $i -le $initialResponse.total_pages; $i++) {
            $params.page = $i
            $response = Invoke-RestMethod -Method "GET" -Uri $itemCylanceApiUri -Body $params -Headers $headers
            $items.AddRange($response.page_items)

            if ($itemLimit -and ($items.Count -gt $itemLimit)) {
                break
            }
        }
    }
    if ($itemLimit -and ($items.Count -gt $itemLimit)) {
        $items = $items.GetRange(0, $itemLimit)
    }

    if (($null -eq $itemLimit -and $initialResponse.total_number_of_items -ne $items.Count) -or ($null -ne $itemLimit -and $itemLimit -ne $items.Count)) {
        Write-HostAs -mode "Warning" -message "Item count reported by API doesn't match actually returned item count, please proceed with caution."
    }
    return $items
}

function Get-FullCylanceDevice {
    param(
        [parameter(Mandatory = $true)]
        [String]$deviceId,
        [parameter(Mandatory = $true)]
        [String]$bearerToken,
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
    param(
        [parameter(Mandatory = $true)]
        [ValidateRange(1, 1000)]
        [int]$count,
        [parameter(Mandatory = $true)]
        [String]$bearerToken,
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
        "page_size" = $MyInvocation.MyCommand.Module.PrivateData["maxPageSize"]
    }

    $memProtectionCylanceApiUri = Get-CylanceApiUri -type "Mem" -region $region
    return (Get-CylanceItems -itemCylanceApiUri $memProtectionCylanceApiUri -headers $headers -params $params -itemLimit $count)
}

function Add-MemProtectionActionDescription {
    param(
        [parameter(ValueFromPipeline)]
        $memProtectionEvent
    )

    $memProtectionActions = $MyInvocation.MyCommand.Module.PrivateData["memProtectionActions"]
    if ($memProtectionActions.ContainsKey($([int32]$memProtectionEvent.action))) {
        $memProtectionEvent | Add-Member -NotePropertyName "action_description" -NotePropertyValue $($memProtectionActions.$([int32]$evmemProtectionEventent.action))
    }
}
function Add-MemProtectionViolationTypeDescription {
    param(
        [parameter(ValueFromPipeline)]
        $memProtectionEvent
    )

    $memProtectionViolationTypes = $MyInvocation.MyCommand.Module.PrivateData["memProtectionViolationTypes"]
    if ($memProtectionViolationTypes.ContainsKey($([int32]$memProtectionEvent.violation_type))) {
        $memProtectionEvent | Add-Member -NotePropertyName "violation_type_description" -NotePropertyValue $($memProtectionViolationTypes.$([int32]$memProtectionEvent.violation_type))
    }
}

function Remove-WhitelistedDevices {
    param(
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
            Write-HostAs -mode "Warning" -message "Skipping whitelisted device(s) $(($skippedDevices | Select-Object -expand name) -join ", ")."
        }
    }
    return $results
}

function Read-UserConfirmation {
    param(
        [parameter(Mandatory = $true)]
        [int]$deviceCount
    )
    Write-HostAs -mode "Warning" -message "I'm about to delete $deviceCount device(s). Are you sure? (y/n)"
    return Read-Host
}

function Start-DeviceDeletion {
    param(
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
            #DEBUG: Write-Host $params
            Invoke-RestMethod -Method "DELETE" -Uri $(Get-CylanceApiUri -type "Devices" -region $region) -Body $params -Headers $headers > $null
            $deletedDevicesCount += $group.Count
        }
        catch {
            Write-HostAs -mode "Error" -message "$($_.Exception.Message)"
        }
    }
    Write-HostAs -mode "Info" -message "Deleted $deletedDevicesCount device(s)."
}

function Get-CylanceApiUri {
    param(
        [parameter(Mandatory = $true)]
        [ValidateSet("Auth", "Devices", "Mem")]
        [Array]$type,
        [parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [Array]$region
    )
    $cylanceApiUri = "{0}{1}" -f $MyInvocation.MyCommand.Module.PrivateData["cylanceApiBaseUri"], $MyInvocation.MyCommand.Module.PrivateData["cylanceApi{0}Suffix" -f $type]
    
    if (![String]::IsNullOrEmpty($region)) {
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
    Write-HostAs -mode "Error" -message $_.Exception.Message
    if ($null -ne $_.ErrorDetails.Message) {
        Write-HostAs -mode "Error" -message ($_.ErrorDetails.Message | ConvertFrom-Json).message
    }
}

function Write-HostAs {
    param (
        [parameter(Mandatory = $true)]
        [ValidateSet("Info", "Error", "Warning")]
        [String]$mode,
        [parameter(Mandatory = $true)]
        [String]$message
    )
    $outputFormat = $MyInvocation.MyCommand.Module.PrivateData.outputFormats[$mode]
    Write-Host ("{0} {1}" -f $outputFormat.prefix, $message) -ForegroundColor $($outputFormat.color ? $outputFormat.color : $((Get-Host).UI.RawUI.ForegroundColor))
}