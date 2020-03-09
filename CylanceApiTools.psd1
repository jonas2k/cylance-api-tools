﻿# Module manifest for module "CylanceApiTools"
# Generated by: jonas2k
# Generated on: 13.09.2019

@{

    # Script module or binary module file associated with this manifest.
    # RootModule = ''

    # Version number of this module.
    ModuleVersion        = '1.4'

    # Supported PSEditions
    CompatiblePSEditions = @("Core")

    # ID used to uniquely identify this module
    GUID                 = '7068880d-6941-4386-910a-bde17ba2d4f2'

    # Author of this module
    Author               = 'jonas2k'

    # Company or vendor of this module
    # CompanyName = 'Unknown'

    # Copyright statement for this module
    # Copyright = '(c) jonas2k. All rights reserved.'

    # Description of the functionality provided by this module
    Description          = 'Collection of several Powershell cmdlets in order to execute certain tasks against the Cylance API.'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion    = '7.0'

    # Name of the PowerShell host required by this module
    # PowerShellHostName = ''

    # Minimum version of the PowerShell host required by this module
    # PowerShellHostVersion = ''

    # Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    # DotNetFrameworkVersion = ''

    # Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    # CLRVersion = ''

    # Processor architecture (None, X86, Amd64) required by this module
    # ProcessorArchitecture = ''

    # Modules that must be imported into the global environment prior to importing this module
    # RequiredModules = @()

    # Assemblies that must be loaded prior to importing this module
    # RequiredAssemblies = @()

    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
    # ScriptsToProcess = @()

    # Type files (.ps1xml) to be loaded when importing this module
    # TypesToProcess = @()

    # Format files (.ps1xml) to be loaded when importing this module
    # FormatsToProcess = @()

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    NestedModules        = @(".\modules\Invoke-CylanceDuplicateCleanup.ps1",
        ".\modules\Invoke-CylanceInactiveCleanup.ps1",
        ".\modules\Show-CylanceMemProtectionEvents.ps1",
        ".\modules\Helpers.ps1")

    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport    = @("Invoke-CylanceDuplicateCleanup", "Invoke-CylanceInactiveCleanup", "Show-CylanceMemProtectionEvents")

    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport      = @()

    # Variables to export from this module
    VariablesToExport    = @()

    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport      = @()

    # DSC resources to export from this module
    # DscResourcesToExport = @()

    # List of all modules packaged with this module
    # ModuleList = @()

    # List of all files packaged with this module
    # FileList = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData          = @{
        AppIdEnvName                = "CylanceApiToolsAppId"
        SecretEnvName               = "CylanceApiToolsSecret"
        TenantIdEnvName             = "CylanceApiToolsTenantId"
        jwtIssuer                   = "http://cylance.com"
        cylanceApiBaseUri           = "https://protectapi.cylance.com/"
        cylanceApiDevicesSuffix     = "devices/v2"
        cylanceApiAuthSuffix        = "auth/v2/token"
        cylanceApiMemSuffix         = "memoryprotection/v2"
        cylanceApiRegions           = @{apne1 = "-apne1"; au = "-au"; euc1 = "-euc1"; sae1 = "-sae1"; us = ".us" }
        devicePageSize              = 10000
        expirationSeconds           = 120
        memProtectionActions        = @{
            0 = "None";
            1 = "Warning";
            2 = "Block";
            3 = "Terminate";
        }
        memProtectionViolationTypes = @{
            1  = "Stack Pivot";
            2  = "Stack Protect";
            3  = "Overwrite Code";
            4  = "Remote Allocation of Memory";
            5  = "Remote Mapping of Memory";
            6  = "Remote Write to Memory";
            7  = "Remote Write PE to Memory";
            8  = "Remote Overwrite Code";
            9  = "Remote Unmap of Memory";
            10 = "Remote Thread Creation";
            11 = "Remote APC Scheduled";
            12 = "LSASS Read";
            13 = "RAM Scraping";
            22 = "Zero Allocate";
            23 = "DYLD Injection";
            24 = "Malicious Payload";
        }
        outputFormats               = @{
            "Info"    = @{ prefix = "[*]"; color = "" };
            "Warning" = @{ prefix = "[!]"; color = "Yellow" };
            "Error"   = @{ prefix = "[x]"; color = "Red" }
        }
        PSData                      = @{

            # Tags applied to this module. These help with module discovery in online galleries.
            # Tags = @()

            # A URL to the license for this module.
            LicenseUri = 'https://github.com/jonas2k/cylance-api-tools/blob/master/LICENSE'

            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/jonas2k/cylance-api-tools'

            # A URL to an icon representing this module.
            # IconUri = ''

            # ReleaseNotes of this module
            # ReleaseNotes = ''

        } # End of PSData hashtable

    } # End of PrivateData hashtable

    # HelpInfo URI of this module
    # HelpInfoURI = ''

    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    # DefaultCommandPrefix = ''

}