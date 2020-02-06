function Invoke-CylanceInactiveCleanup {
    Param (
        [parameter(Mandatory = $false)]
        [String]$applicationId,
        [parameter(Mandatory = $false)]
        [String]$applicationSecret,
        [parameter(Mandatory = $false)]
        [String]$tenantId,
        [parameter(Mandatory = $true)]
        [int]$inactiveDays,
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
        Write-Host "Checking devices, this may take a while."
        $response = Get-CylanceDevices -bearerToken $bearerToken -region $region

        $offlineDevices = $response.page_items | Where-Object { $null -ne $_.id -and $_.state -eq "Offline" -and (Test-DateIsOutOfRange -inputDate $_.date_first_registered -daysBack 1) }

        [Array]$devicesToBeRemoved = @()
        $daysAgo = (Get-Date).AddDays(-$inactiveDays)

        foreach ($device in $offlineDevices) {
            try {
                $fullDevice = Get-FullCylanceDevice -device $device.id -bearerToken $bearerToken -region $region
                if ($null -ne $fullDevice -and $null -eq $fullDevice.date_offline) {
                    Write-Host "Skipping $($fullDevice.name) since it seems to be online by now or there is no valid offline date."
                }
                else {
                    [DateTime]$offlineDate = $fullDevice.date_offline
                    if ($offlineDate -lt $daysAgo) {
                        $devicesToBeRemoved += $fullDevice
                    }
                }
            }
            catch {
                Write-Error "Can't get full device details for $($device.name)."
                Write-Error "$($device.name): $($_.Exception.Message)"
            }
        }

        if (($devicesToBeRemoved.Count -gt 0) -and ($null -ne $whitelistFile) -and (Test-Path $whitelistFile)) {
            $devicesToBeRemoved = Remove-WhitelistedDevices -whitelistFile $whitelistFile -devices $devicesToBeRemoved
        }

        if ($devicesToBeRemoved.Count -gt 0) {

            Write-Host "Devices to be removed:"
            Write-Host ($devicesToBeRemoved | Select-Object @{Name = 'Name'; Expression = { "$($_.name)" } },
                @{Name = 'ID'; Expression = { "$($_.id)" } },
                @{Name = 'State'; Expression = { "$($_.state)" } },
                @{Name = 'Registration date'; Expression = { ($_.date_first_registered) } },
                @{Name = 'Offline date'; Expression = { ($_.date_offline) } },
                @{Name = 'Last user'; Expression = { "$($_.last_logged_in_user)" } },
                @{Name = 'OS'; Expression = { "$($_.os_version)" } } | Sort-Object -Property date_offline | Format-Table -Wrap -AutoSize | Out-String)
            $confirmation = Read-UserConfirmation -deviceCount $devicesToBeRemoved.Count

            if ($confirmation -eq 'y') {
                Start-DeviceDeletion -devices $devicesToBeRemoved -region $region
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
        Write-ExceptionToConsole($_)
    }
}