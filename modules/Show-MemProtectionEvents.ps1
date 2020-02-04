function Show-MemProtectionEvents {
    Param (
        [parameter(Mandatory = $true)]
        [String]$applicationId,
        [parameter(Mandatory = $true)]
        [String]$applicationSecret,
        [parameter(Mandatory = $true)]
        [String]$tenantId,
        [parameter(Mandatory = $false)]
        [ValidateRange(1,200)]
        [int]$count = 10,
        [parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [ValidateSet("apne1", "au", "euc1", "sae1", "us")]
        [String]$region
    )

    Write-Banner
    try {
        $bearerToken = Get-BearerToken -applicationId $applicationId -applicationSecret $applicationSecret -tenantId $tenantId -region $region
        Write-Host "Fetching data, this may take a while."
        $response = Get-MemProtectionEvents -count $count -bearerToken $bearerToken -region $region
        $memProtectionEvents = $response.page_items | ForEach-Object { $_.created = [DateTime]$_.created; $_ }

        foreach ($event in $memProtectionEvents) {
            try {
                $fullDevice = Get-FullCylanceDevice -device $event.device_id -bearerToken $bearerToken -region $region
                $event | Add-Member -NotePropertyName "device_name" -NotePropertyValue $fullDevice.name
                $event | Add-Member -NotePropertyName "device_policy" -NotePropertyValue $fullDevice.policy.name
            }
            catch {
                Write-Error "Can't get full device details for $($device.name)."
                Write-Error "$($device.name): $($_.Exception.Message)"
            }
            $event | Add-MemProtectionActionDescription
            $event | Add-MemProtectionViolationTypeDescription
        }

        if($memProtectionEvents.Count -gt 0) {
            Write-Host ($memProtectionEvents | Select-Object @{Name = 'Image'; Expression = { "$($_.image_name) ($($_.process_id))" }},
                @{Name = 'User'; Expression = { "$($_.user_name)" } },
                @{Name = 'Device'; Expression = { "$($_.device_name)" } },
                @{Name = 'Device policy'; Expression = { "$($_.device_policy)" } },
                @{Name = 'Violation type'; Expression = { "$($_.violation_type_description)" } },
                @{Name = 'Action'; Expression = { "$($_.action_description)" } },
                @{Name = 'Created'; Expression = { $_.created } } | Format-Table -Wrap -AutoSize | Out-String)
        } else {
            Write-Host "No memory protection events were found."
        }
    }
    catch {
        Write-ExceptionToConsole($_)
    }
}