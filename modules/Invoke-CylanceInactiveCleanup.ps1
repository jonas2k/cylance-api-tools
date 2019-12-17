function Invoke-CylanceInactiveCleanup {
    Param (
        [parameter(Mandatory = $true)]
        [String]$applicationId,
        [parameter(Mandatory = $true)]
        [String]$applicationSecret,
        [parameter(Mandatory = $true)]
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

    try {
        $bearerToken = Get-BearerToken -applicationId $applicationId -applicationSecret $applicationSecret -tenantId $tenantId -region $region
        Write-Host "Checking devices, this may take a while."
        $response = Get-CylanceDevices -bearerToken $bearerToken -region $region

        $offlineDevices = $response.page_items | Where-Object { $null -ne $_.id -and $_.state -eq "Offline" -and (Test-DateIsOutOfRange -inputDate $_.date_first_registered -daysBack 1) }

        [Array]$devicesToBeRemoved = @()
        $daysAgo = (Get-Date).AddDays(-$inactiveDays)

        foreach ($device in $offlineDevices) {
            try {
                $fullDevice = Get-FullCylanceDevice -device $device -bearerToken $bearerToken -region $region
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
                Write-Error "Can't get full device details for $($device.name)."
                Write-Error "$($device.name): $($_.Exception.Message)"
            }
        }

        if (($devicesToBeRemoved.Count -gt 0) -and ($null -ne $whitelistFile) -and (Test-Path $whitelistFile)) {
            $devicesToBeRemoved = Remove-WhitelistedDevices -whitelistFile $whitelistFile -devices $devicesToBeRemoved
        }

        if ($devicesToBeRemoved.Count -gt 0) {

            Write-Host "Devices to be removed:"
            Write-Host ($devicesToBeRemoved | Select-Object name, id, state, date_first_registered, date_offline, last_logged_in_user, os_version | Sort-Object -Property date_offline | Format-Table -Wrap -AutoSize | Out-String)
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
        Write-Host $_.Exception.Message -ForegroundColor "Red"
        if ($null -ne $_.ErrorDetails.Message) {
            Write-Host ($_.ErrorDetails.Message | ConvertFrom-Json).message -ForegroundColor "Red"
        }
    }
}