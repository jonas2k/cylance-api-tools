function Invoke-CylanceDuplicateCleanup {
    Param (
        [parameter(Mandatory = $true)]
        [String]$applicationId,
        [parameter(Mandatory = $true)]
        [String]$applicationSecret,
        [parameter(Mandatory = $true)]
        [String]$tenantId,
        [parameter(Mandatory = $false)]
        [String]$whitelistFile,
        [parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [ValidateSet("apne1", "au", "euc1", "sae1", "us")]
        [String]$region
    )

    Write-Banner
    try {
        $bearerToken = Get-BearerToken -applicationId $applicationId -applicationSecret $applicationSecret -tenantId $tenantId -region $region
        $response = Get-CylanceDevices -bearerToken $bearerToken -region $region

        $duplicates = $response.page_items | Group-Object -Property "name" | Where-Object { $_.count -ge 2 }

        [Array]$devicesToBeRemoved = @()
    
        foreach ($deviceGroup in $duplicates) {
            $currentDevices = $deviceGroup.Group | ForEach-Object { $_.date_first_registered = [DateTime]$_.date_first_registered; $_ } | Sort-Object date_first_registered | Select-Object -SkipLast 1
            $devicesToBeRemoved += $currentDevices
        }

        if (($devicesToBeRemoved.Count -gt 0) -and ($null -ne $whitelistFile) -and (Test-Path $whitelistFile)) {
            $devicesToBeRemoved = Remove-WhitelistedDevices -whitelistFile $whitelistFile -devices $devicesToBeRemoved
        }

        if ($devicesToBeRemoved.Count -gt 0) {

            [Array]$fullDevicesToBeRemoved = @()
            foreach ($device in $devicesToBeRemoved) {
                try {
                    $fullDevicesToBeRemoved += Get-FullCylanceDevice -device $device -bearerToken $bearerToken -region $region
                }
                catch {
                    Write-Error "Can't get full device details for $($device.name). Adding device without additional information."
                    $fullDevicesToBeRemoved += $device
                }
            }

            Write-Host "Devices to be removed:"
            Write-Host ($fullDevicesToBeRemoved | Select-Object name, id, state, date_first_registered, date_offline, last_logged_in_user, os_version | Sort-Object -Property date_first_registered | Format-Table -Wrap -AutoSize | Out-String)
            $confirmation = Read-UserConfirmation -deviceCount $fullDevicesToBeRemoved.Count

            if ($confirmation -eq 'y') {
                Start-DeviceDeletion -devices $fullDevicesToBeRemoved -region $region
            }
            else {
                Write-Host "Aborting."
            }
        }
        else {
            Write-Host "Nothing to do."
        }
    }
    catch {
        Write-Host $_.Exception.Message -ForegroundColor "Red"
        if ($null -ne $_.ErrorDetails.Message) {
            Write-Host ($_.ErrorDetails.Message | ConvertFrom-Json).message -ForegroundColor "Red"
        }
    }
}