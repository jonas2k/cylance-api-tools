function Invoke-CylanceDuplicateCleanup {
    Param (
        [parameter(Mandatory = $true)]
        [String]$applicationId,
        [parameter(Mandatory = $true)]
        [String]$applicationSecret,
        [parameter(Mandatory = $true)]
        [String]$tenantId
    )

    $bearerToken = Get-BearerToken -applicationId $applicationId -applicationSecret $applicationSecret -tenantId $tenantId
    $response = Get-CylanceDevices -bearerToken $bearerToken

    $duplicates = $response.page_items | Group-Object -Property "name" | Where-Object { $_.count -ge 2 }

    [Array]$devicesToBeRemoved = @()
    
    foreach ($deviceGroup in $duplicates) {
        $currentDevices = $deviceGroup.Group | ForEach-Object { $_.date_first_registered = [DateTime]$_.date_first_registered; $_ } | Sort-Object date_first_registered | Select-Object -SkipLast 1
        $devicesToBeRemoved += $currentDevices
    }

    if ($devicesToBeRemoved.Count -gt 0) {

        [Array]$fullDevicesToBeRemoved = @()
        foreach ($device in $devicesToBeRemoved) {
            try {
                $fullDevicesToBeRemoved += Get-FullCylanceDevice -device $device -bearerToken $bearerToken
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
            Start-DeviceDeletion -devices $fullDevicesToBeRemoved
        }
        else {
            Write-Host "Aborting."
        }
    }
    else {
        Write-Host "Nothing to do."
    }
}