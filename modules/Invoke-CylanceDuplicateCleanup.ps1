function Invoke-CylanceDuplicateCleanup {
    param(
        [parameter(Mandatory = $false)]
        [String]$applicationId,
        [parameter(Mandatory = $false)]
        [String]$applicationSecret,
        [parameter(Mandatory = $false)]
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
        Write-HostAs -mode "Info" -message "Checking devices, this may take a while."
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
                    $fullDevicesToBeRemoved += Get-FullCylanceDevice -device $device.id -bearerToken $bearerToken -region $region
                }
                catch {
                    Write-HostAs -mode "Error" -message "Can't get full device details for $($device.name). Adding device without additional information."
                    $fullDevicesToBeRemoved += $device
                }
            }

            Write-HostAs -mode "Info" -message "Devices to be removed:"
            Write-Host ($fullDevicesToBeRemoved | Select-Object @{Name = 'Name'; Expression = { "$($_.name)" } },
                @{Name = 'ID'; Expression = { "$($_.id)" } },
                @{Name = 'State'; Expression = { "$($_.state)" } },
                @{Name = 'Registration date'; Expression = { ($_.date_first_registered) } },
                @{Name = 'Offline date'; Expression = { ($_.date_offline) } },
                @{Name = 'Last user'; Expression = { "$($_.last_logged_in_user)" } },
                @{Name = 'OS'; Expression = { "$($_.os_version)" } } | Sort-Object -Property date_first_registered | Format-Table -Wrap -AutoSize | Out-String)
            $confirmation = Read-UserConfirmation -deviceCount $fullDevicesToBeRemoved.Count

            if ($confirmation -eq 'y') {
                Start-DeviceDeletion -devices $fullDevicesToBeRemoved -region $region
            }
            else {
                Write-HostAs -mode "Info" -message "Aborting."
            }
        }
        else {
            Write-HostAs -mode "Info" -message "Nothing to do."
        }
    }
    catch {
        Write-ExceptionToConsole($_)
    }
}