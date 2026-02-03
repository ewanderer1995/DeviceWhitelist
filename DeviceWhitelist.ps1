# Self-elevating script - will request admin privileges if needed
<#
.SYNOPSIS
    Windows Device Whitelisting Script
    Blocks unauthorized devices while allowing whitelisted ones.

.DESCRIPTION
    This script manages device installation policies on Windows 10/11.
    It blocks USB, CD/DVD, Bluetooth, and Wireless devices by default,
    while allowing system devices, keyboards, mice, touchscreens, and Ethernet.
    
    Users can manually whitelist devices by Device Instance Path or Hardware ID.

.NOTES
    Author: Ow Wai Kian
    Version: 1.0
    Requires: Windows 10/11, Administrator privileges
    
    WARNING: Improper use can prevent device connectivity. 
             A recovery option is included.

.EXAMPLE
    .\DeviceWhitelist.ps1 -Action Enable
    Enables device restrictions with default whitelist

.EXAMPLE
    .\DeviceWhitelist.ps1 -Action AddDevice -DeviceId "USB\VID_1234&PID_5678"
    Adds a specific device to the whitelist

.EXAMPLE
    .\DeviceWhitelist.ps1 -Action ListDevices
    Lists all connected devices with their IDs
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("Enable", "Disable", "AddDevice", "RemoveDevice", "ListWhitelist", "ListDevices", "Status", "Menu")]
    [string]$Action = "Menu",
    
    [Parameter(Mandatory = $false)]
    [string]$DeviceId = "",
    
    [Parameter(Mandatory = $false)]
    [string]$DeviceInstancePath = ""
)

#region Constants and Configuration

# Registry paths for Device Installation Restrictions
$RegBasePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
$RegDenyClasses = "$RegBasePath\DenyDeviceClasses"
$RegAllowClasses = "$RegBasePath\AllowDeviceClasses"
$RegAllowIds = "$RegBasePath\AllowDeviceIDs"

# Custom whitelist storage
$CustomWhitelistPath = "HKLM:\SOFTWARE\DeviceWhitelist\AllowedDevices"

# Device Class GUIDs - TO BLOCK
$BlockedClasses = @{
    "USB_Controller"   = "{36fc9e60-c465-11cf-8056-444553540000}"
    "USB_Device"       = "{88bae032-5a81-49f0-bc3d-a4ff138216d6}"
    "CD_DVD_Drive"     = "{4d36e965-e325-11ce-bfc1-08002be10318}"
    "Bluetooth"        = "{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}"
    "Bluetooth_LE"     = "{6bdd1fc1-810f-11d0-bec7-08002be2092f}"
    "Portable_Devices" = "{eec5ad98-8080-425f-922a-dabf3de3f69a}"
    "WPD"              = "{6ac27878-a6fa-4155-ba85-f98f491d4f33}"
    "SD_Host"          = "{a0a588a4-c46f-4b37-b7ea-c82fe89870c6}"
    "Infrared"         = "{6bdd1fc5-810f-11d0-bec7-08002be2092f}"
    "Image_Scanner"    = "{6bdd1fc6-810f-11d0-bec7-08002be2092f}"
    "Modem"            = "{4d36e96d-e325-11ce-bfc1-08002be10318}"
    "PCMCIA"           = "{4d36e977-e325-11ce-bfc1-08002be10318}"
    "SmartCard_Reader" = "{50dd5230-ba8a-11d1-bf5d-0000f805f530}"
}

# Device Class GUIDs - TO ALLOW (System Critical)
$AllowedClasses = @{
    "System"            = "{4d36e97d-e325-11ce-bfc1-08002be10318}"
    "Computer"          = "{4d36e966-e325-11ce-bfc1-08002be10318}"
    "Processor"         = "{50127dc3-0f36-415e-a6cc-4cb3be910b65}"
    "Keyboard"          = "{4d36e96b-e325-11ce-bfc1-08002be10318}"
    "Mouse"             = "{4d36e96f-e325-11ce-bfc1-08002be10318}"
    "HID"               = "{745a17a0-74d3-11d0-b6fe-00a0c90f57da}"
    "Monitor"           = "{4d36e96e-e325-11ce-bfc1-08002be10318}"
    "Display_Adapter"   = "{4d36e968-e325-11ce-bfc1-08002be10318}"
    "Volume"            = "{71a27cdd-812a-11d0-bec7-08002be2092f}"
    "DiskDrive"         = "{4d36e967-e325-11ce-bfc1-08002be10318}"
    "HDC"               = "{4d36e96a-e325-11ce-bfc1-08002be10318}"
    "SCSIAdapter"       = "{4d36e97b-e325-11ce-bfc1-08002be10318}"
    "Net"               = "{4d36e972-e325-11ce-bfc1-08002be10318}"  # Includes Ethernet
    "Battery"           = "{72631e54-78a4-11d0-bcf7-00aa00b7b32a}"
    "Firmware"          = "{f2e7dd72-6468-4e36-b6f1-6488f42c1b52}"
    "SecurityDevices"   = "{d94ee5d8-d189-4994-83d2-f68d7d41b0e6}"
    "SoftwareComponent" = "{5c4c3332-344d-483c-8739-259e934c9cc8}"
    "Extension"         = "{e2f84ce7-8efa-411c-aa69-97454ca4cb57}"
    "BIOS"              = "{d94ee5d8-d189-4994-83d2-f68d7d41b0e6}"
    "PrintQueue"        = "{1ed2bbf9-11f0-4084-b21f-ad83a8e6dcdc}"
    "TouchScreen"       = "{4d36e96b-e325-11ce-bfc1-08002be10318}"  # Often uses HID
}

#endregion

#region Helper Functions

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

function Write-Banner {
    Clear-Host
    Write-ColorOutput @"
+====================================================================+
|           WINDOWS DEVICE WHITELISTING MANAGER v1.0                 |
|                      For Windows 10/11                             |
+====================================================================+
|  WARNING: This script modifies device installation policies.       |
|           Run with care. Requires Administrator privileges.        |
+====================================================================+
"@ -Color Cyan
}

function Test-AdminPrivileges {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Request-Elevation {
    <#
    .SYNOPSIS
        Restarts the current script with elevated privileges.
    #>
    
    # Build the argument list to pass to the elevated process
    $scriptPath = $PSCommandPath
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
    
    # Add original parameters if provided
    if ($Action -and $Action -ne "Menu") {
        $arguments += " -Action $Action"
    }
    if ($DeviceId) {
        $arguments += " -DeviceId `"$DeviceId`""
    }
    if ($DeviceInstancePath) {
        $arguments += " -DeviceInstancePath `"$DeviceInstancePath`""
    }
    
    try {
        # Start new elevated PowerShell process
        $process = Start-Process -FilePath "powershell.exe" -ArgumentList $arguments -Verb RunAs -PassThru
        
        # Wait for the elevated process to complete
        $process.WaitForExit()
        
        # Exit the current non-elevated process
        exit $process.ExitCode
    }
    catch {
        Write-ColorOutput "`n[ERROR] Failed to elevate privileges." -Color Red
        Write-ColorOutput "User may have cancelled the UAC prompt." -Color Yellow
        exit 1
    }
}

function Initialize-RegistryPath {
    param([string]$Path)
    
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
        Write-ColorOutput "  Created registry path: $Path" -Color Gray
    }
}

function Update-GroupPolicy {
    <#
    .SYNOPSIS
        Refreshes Group Policy to ensure gpedit.msc reflects registry changes.
    #>
    Write-ColorOutput "`n  Refreshing Group Policy to apply changes..." -Color Gray
    try {
        # Use gpupdate to refresh computer policies (device installation policies are computer-level)
        $gpupdateResult = Start-Process -FilePath "gpupdate.exe" -ArgumentList "/target:computer /force" -Wait -PassThru -NoNewWindow
        
        if ($gpupdateResult.ExitCode -eq 0) {
            Write-ColorOutput "  Group Policy refreshed successfully." -Color Green
            Write-ColorOutput "  Changes should now be visible in gpedit.msc" -Color Green
        }
        else {
            Write-ColorOutput "  Group Policy refresh completed with warnings." -Color Yellow
        }
    }
    catch {
        Write-ColorOutput "  Could not refresh Group Policy: $($_.Exception.Message)" -Color Yellow
        Write-ColorOutput "  You may need to run 'gpupdate /force' manually or restart." -Color Yellow
    }
}

function Get-AllConnectedDevices {
    # Get basic device info quickly (without Hardware IDs to avoid slow per-device calls)
    $devices = Get-PnpDevice | Where-Object { $_.Status -eq "OK" } | Select-Object `
        FriendlyName, Class, InstanceId, Status
    
    return $devices
}

function Get-DeviceInfo {
    param([string]$DeviceIdentifier)
    
    # Try to find by Instance ID first
    $device = Get-PnpDevice | Where-Object { $_.InstanceId -eq $DeviceIdentifier } | Select-Object -First 1
    
    if (-not $device) {
        # Try to find by Hardware ID
        $device = Get-PnpDevice | Where-Object { 
            $hwIds = (Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName DEVPKEY_Device_HardwareIds -ErrorAction SilentlyContinue).Data
            $hwIds -contains $DeviceIdentifier
        } | Select-Object -First 1
    }
    
    return $device
}

#endregion

#region Core Functions

function Enable-DeviceRestrictions {
    Write-ColorOutput "`n[ENABLING DEVICE RESTRICTIONS]" -Color Yellow
    Write-ColorOutput "================================" -Color Yellow
    
    # Create backup of current settings
    Write-ColorOutput "`n  Creating backup of current settings..." -Color Gray
    $backupPath = "$env:TEMP\DevicePolicy_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"
    
    try {
        if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall") {
            reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall" $backupPath /y 2>$null
            Write-ColorOutput "  Backup saved to: $backupPath" -Color Green
        }
    }
    catch {
        Write-ColorOutput "  Could not create backup (settings may be new)" -Color Gray
    }
    
    # Ensure registry paths exist
    Write-ColorOutput "`n  Creating registry structure..." -Color Gray
    Initialize-RegistryPath $RegBasePath
    Initialize-RegistryPath $RegDenyClasses
    Initialize-RegistryPath $RegAllowClasses
    Initialize-RegistryPath $RegAllowIds
    Initialize-RegistryPath $CustomWhitelistPath
    
    # Enable device installation restrictions
    Write-ColorOutput "`n  Enabling restriction policies..." -Color Gray
    
    # Deny all devices not described by other policy settings
    Set-ItemProperty -Path $RegBasePath -Name "DenyUnspecified" -Value 1 -Type DWord -Force
    
    # Enable deny by device class
    Set-ItemProperty -Path $RegBasePath -Name "DenyDeviceClasses" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $RegBasePath -Name "DenyDeviceClassesRetroactive" -Value 0 -Type DWord -Force
    
    # Enable allow by device class
    Set-ItemProperty -Path $RegBasePath -Name "AllowDeviceClasses" -Value 1 -Type DWord -Force
    
    # Enable allow by device ID (for custom whitelist)
    Set-ItemProperty -Path $RegBasePath -Name "AllowDeviceIDs" -Value 1 -Type DWord -Force
    
    # Add blocked device classes
    Write-ColorOutput "`n  Adding blocked device classes:" -Color Gray
    $index = 1
    foreach ($class in $BlockedClasses.GetEnumerator()) {
        Set-ItemProperty -Path $RegDenyClasses -Name "$index" -Value $class.Value -Type String -Force
        Write-ColorOutput "    [$index] $($class.Key): $($class.Value)" -Color Red
        $index++
    }
    
    # Add allowed device classes
    Write-ColorOutput "`n  Adding allowed device classes:" -Color Gray
    $index = 1
    foreach ($class in $AllowedClasses.GetEnumerator()) {
        Set-ItemProperty -Path $RegAllowClasses -Name "$index" -Value $class.Value -Type String -Force
        Write-ColorOutput "    [$index] $($class.Key): $($class.Value)" -Color Green
        $index++
    }
    
    # Apply custom whitelist
    Set-CustomWhitelist
    
    # Refresh Group Policy so gpedit.msc shows changes
    Update-GroupPolicy
    
    Write-ColorOutput "`n  [SUCCESS] Device restrictions enabled!" -Color Green
    Write-ColorOutput "`n  NOTE: Some changes may require a system restart to take full effect." -Color Yellow
    Write-ColorOutput "  NOTE: Already connected devices may continue to work until unplugged." -Color Yellow
    
    return $true
}

function Disable-DeviceRestrictions {
    Write-ColorOutput "`n[DISABLING DEVICE RESTRICTIONS]" -Color Yellow
    Write-ColorOutput "=================================" -Color Yellow
    
    if (Test-Path $RegBasePath) {
        # Remove restriction settings
        Set-ItemProperty -Path $RegBasePath -Name "DenyUnspecified" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $RegBasePath -Name "DenyDeviceClasses" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $RegBasePath -Name "DenyDeviceClassesRetroactive" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $RegBasePath -Name "AllowDeviceClasses" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $RegBasePath -Name "AllowDeviceIDs" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        
        # Remove deny classes
        if (Test-Path $RegDenyClasses) {
            Remove-Item -Path $RegDenyClasses -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        # Remove allow classes
        if (Test-Path $RegAllowClasses) {
            Remove-Item -Path $RegAllowClasses -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        # Remove allow IDs
        if (Test-Path $RegAllowIds) {
            Remove-Item -Path $RegAllowIds -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        # Refresh Group Policy so gpedit.msc shows changes
        Update-GroupPolicy
        
        Write-ColorOutput "`n  [SUCCESS] Device restrictions disabled!" -Color Green
        Write-ColorOutput "  All devices can now be installed freely." -Color Yellow
        Write-ColorOutput "  NOTE: Custom whitelist preserved for future use." -Color Gray
    }
    else {
        Write-ColorOutput "`n  Device restrictions were not enabled." -Color Gray
    }
    
    return $true
}

function Add-DeviceToWhitelist {
    param(
        [string]$Identifier
    )
    
    if ([string]::IsNullOrWhiteSpace($Identifier)) {
        Write-ColorOutput "`n  [ERROR] No device identifier provided!" -Color Red
        return $false
    }
    
    Write-ColorOutput "`n[ADDING DEVICE TO WHITELIST]" -Color Yellow
    Write-ColorOutput "=============================" -Color Yellow
    
    # Get device info
    $device = Get-DeviceInfo -DeviceIdentifier $Identifier
    
    if ($device) {
        Write-ColorOutput "`n  Device found:" -Color Green
        Write-ColorOutput "    Name: $($device.FriendlyName)" -Color White
        Write-ColorOutput "    Class: $($device.Class)" -Color White
        Write-ColorOutput "    Instance ID: $($device.InstanceId)" -Color White
    }
    else {
        Write-ColorOutput "`n  Device not currently connected, but will be added anyway." -Color Yellow
    }
    
    # Ensure registry path exists
    Initialize-RegistryPath $CustomWhitelistPath
    Initialize-RegistryPath $RegAllowIds
    
    # Generate unique key name
    $existingItems = Get-Item -Path $CustomWhitelistPath -ErrorAction SilentlyContinue | 
    Select-Object -ExpandProperty Property -ErrorAction SilentlyContinue
    
    $nextIndex = 1
    if ($existingItems) {
        $maxIndex = ($existingItems | ForEach-Object { [int]$_ } | Measure-Object -Maximum).Maximum
        $nextIndex = $maxIndex + 1
    }
    
    # Add to custom whitelist
    Set-ItemProperty -Path $CustomWhitelistPath -Name "$nextIndex" -Value $Identifier -Type String -Force
    Write-ColorOutput "`n  Added to custom whitelist: $Identifier" -Color Green
    
    # Apply to active policy if enabled
    if (Test-Path $RegBasePath) {
        $denyEnabled = Get-ItemProperty -Path $RegBasePath -Name "DenyDeviceClasses" -ErrorAction SilentlyContinue
        if ($denyEnabled.DenyDeviceClasses -eq 1) {
            # Add to allow IDs
            $existingAllowIds = Get-Item -Path $RegAllowIds -ErrorAction SilentlyContinue | 
            Select-Object -ExpandProperty Property -ErrorAction SilentlyContinue
            
            $nextAllowIndex = 1
            if ($existingAllowIds) {
                $maxAllowIndex = ($existingAllowIds | ForEach-Object { [int]$_ } | Measure-Object -Maximum).Maximum
                $nextAllowIndex = $maxAllowIndex + 1
            }
            
            Set-ItemProperty -Path $RegAllowIds -Name "$nextAllowIndex" -Value $Identifier -Type String -Force
            Write-ColorOutput "  Added to active policy allow list" -Color Green
            
            # Refresh Group Policy so gpedit.msc shows changes
            Update-GroupPolicy
        }
    }
    
    Write-ColorOutput "`n  [SUCCESS] Device whitelisted!" -Color Green
    return $true
}

function Remove-DeviceFromWhitelist {
    param(
        [string]$Identifier
    )
    
    if ([string]::IsNullOrWhiteSpace($Identifier)) {
        Write-ColorOutput "`n  [ERROR] No device identifier provided!" -Color Red
        return $false
    }
    
    Write-ColorOutput "`n[REMOVING DEVICE FROM WHITELIST]" -Color Yellow
    Write-ColorOutput "=================================" -Color Yellow
    
    $found = $false
    
    # Remove from custom whitelist
    if (Test-Path $CustomWhitelistPath) {
        $properties = Get-Item -Path $CustomWhitelistPath | Select-Object -ExpandProperty Property
        
        foreach ($prop in $properties) {
            $value = Get-ItemPropertyValue -Path $CustomWhitelistPath -Name $prop -ErrorAction SilentlyContinue
            if ($value -eq $Identifier) {
                Remove-ItemProperty -Path $CustomWhitelistPath -Name $prop -Force
                Write-ColorOutput "  Removed from custom whitelist" -Color Green
                $found = $true
            }
        }
    }
    
    # Remove from active allow IDs
    if (Test-Path $RegAllowIds) {
        $properties = Get-Item -Path $RegAllowIds -ErrorAction SilentlyContinue | 
        Select-Object -ExpandProperty Property -ErrorAction SilentlyContinue
        
        if ($properties) {
            foreach ($prop in $properties) {
                $value = Get-ItemPropertyValue -Path $RegAllowIds -Name $prop -ErrorAction SilentlyContinue
                if ($value -eq $Identifier) {
                    Remove-ItemProperty -Path $RegAllowIds -Name $prop -Force
                    Write-ColorOutput "  Removed from active policy" -Color Green
                    $found = $true
                }
            }
        }
    }
    
    if ($found) {
        # Refresh Group Policy so gpedit.msc shows changes
        Update-GroupPolicy
        
        Write-ColorOutput "`n  [SUCCESS] Device removed from whitelist!" -Color Green
    }
    else {
        Write-ColorOutput "`n  [INFO] Device was not in the whitelist." -Color Yellow
    }
    
    return $true
}

function Set-CustomWhitelist {
    Write-ColorOutput "`n  Applying custom whitelist to policy..." -Color Gray
    
    if (-not (Test-Path $CustomWhitelistPath)) {
        Write-ColorOutput "    No custom whitelist entries found." -Color Gray
        return
    }
    
    Initialize-RegistryPath $RegAllowIds
    
    $properties = Get-Item -Path $CustomWhitelistPath -ErrorAction SilentlyContinue | 
    Select-Object -ExpandProperty Property -ErrorAction SilentlyContinue
    
    if ($properties) {
        $index = 1
        foreach ($prop in $properties) {
            $value = Get-ItemPropertyValue -Path $CustomWhitelistPath -Name $prop -ErrorAction SilentlyContinue
            if ($value) {
                Set-ItemProperty -Path $RegAllowIds -Name "$index" -Value $value -Type String -Force
                Write-ColorOutput "    [$index] $value" -Color Cyan
                $index++
            }
        }
        Write-ColorOutput "    Applied $($index - 1) custom whitelist entries" -Color Green
    }
    else {
        Write-ColorOutput "    No custom whitelist entries found." -Color Gray
    }
}

function Show-Whitelist {
    Write-ColorOutput "`n[CURRENT WHITELIST]" -Color Yellow
    Write-ColorOutput "===================" -Color Yellow
    
    Write-ColorOutput "`n  DEFAULT ALLOWED DEVICE CLASSES:" -Color Cyan
    foreach ($class in $AllowedClasses.GetEnumerator() | Sort-Object Name) {
        Write-ColorOutput "    * $($class.Key): $($class.Value)" -Color White
    }
    
    Write-ColorOutput "`n  CUSTOM WHITELISTED DEVICES:" -Color Cyan
    
    if (Test-Path $CustomWhitelistPath) {
        $properties = Get-Item -Path $CustomWhitelistPath -ErrorAction SilentlyContinue | 
        Select-Object -ExpandProperty Property -ErrorAction SilentlyContinue
        
        if ($properties) {
            foreach ($prop in $properties) {
                $value = Get-ItemPropertyValue -Path $CustomWhitelistPath -Name $prop -ErrorAction SilentlyContinue
                if ($value) {
                    # Try to get device friendly name
                    $device = Get-DeviceInfo -DeviceIdentifier $value
                    $displayName = if ($device) { "$($device.FriendlyName) ($value)" } else { $value }
                    Write-ColorOutput "    [$prop] $displayName" -Color White
                }
            }
        }
        else {
            Write-ColorOutput "    (No custom entries)" -Color Gray
        }
    }
    else {
        Write-ColorOutput "    (No custom entries)" -Color Gray
    }
    
    Write-ColorOutput "`n  BLOCKED DEVICE CLASSES:" -Color Red
    foreach ($class in $BlockedClasses.GetEnumerator() | Sort-Object Name) {
        Write-ColorOutput "    x $($class.Key): $($class.Value)" -Color Red
    }
}

function Show-ConnectedDevices {
    Write-ColorOutput "`n[CONNECTED DEVICES]" -Color Yellow
    Write-ColorOutput "===================" -Color Yellow
    Write-ColorOutput "  Loading devices..." -Color Gray
    
    $devices = Get-AllConnectedDevices | Sort-Object Class, FriendlyName
    
    Write-ColorOutput "  Use the Instance ID to whitelist devices.`n" -Color Gray
    
    # Define column widths
    $classWidth = 20
    $nameWidth = 40
    
    # Print table header
    $header = "  {0,-$classWidth} {1,-$nameWidth} {2}" -f "CLASS", "DEVICE NAME", "INSTANCE ID"
    $separator = "  " + ("-" * $classWidth) + " " + ("-" * $nameWidth) + " " + ("-" * 50)
    
    Write-ColorOutput $header -Color Cyan
    Write-ColorOutput $separator -Color Gray
    
    # Print each device row
    foreach ($device in $devices) {
        $class = if ($device.Class.Length -gt $classWidth) { 
            $device.Class.Substring(0, $classWidth - 3) + "..." 
        }
        else { 
            $device.Class 
        }
        
        $name = if ($device.FriendlyName.Length -gt $nameWidth) { 
            $device.FriendlyName.Substring(0, $nameWidth - 3) + "..." 
        }
        else { 
            $device.FriendlyName 
        }
        
        $row = "  {0,-$classWidth} {1,-$nameWidth} {2}" -f $class, $name, $device.InstanceId
        Write-ColorOutput $row -Color White
    }
    
    Write-ColorOutput $separator -Color Gray
    Write-ColorOutput "  Total devices: $($devices.Count)" -Color Yellow
}

function Show-RestrictionStatus {
    Write-ColorOutput "`n[RESTRICTION STATUS]" -Color Yellow
    Write-ColorOutput "====================" -Color Yellow
    
    if (-not (Test-Path $RegBasePath)) {
        Write-ColorOutput "`n  Status: NOT CONFIGURED" -Color Gray
        Write-ColorOutput "  Device restrictions have not been enabled." -Color Gray
        return
    }
    
    $settings = Get-ItemProperty -Path $RegBasePath -ErrorAction SilentlyContinue
    
    $denyUnspecified = if ($settings.DenyUnspecified -eq 1) { "ENABLED" } else { "DISABLED" }
    $denyClasses = if ($settings.DenyDeviceClasses -eq 1) { "ENABLED" } else { "DISABLED" }
    $allowClasses = if ($settings.AllowDeviceClasses -eq 1) { "ENABLED" } else { "DISABLED" }
    $allowIds = if ($settings.AllowDeviceIDs -eq 1) { "ENABLED" } else { "DISABLED" }
    
    $statusColor = if ($settings.DenyDeviceClasses -eq 1) { "Green" } else { "Red" }
    
    Write-ColorOutput "`n  Overall Status: $(if ($settings.DenyDeviceClasses -eq 1) { 'ACTIVE' } else { 'INACTIVE' })" -Color $statusColor
    Write-ColorOutput "`n  Policy Settings:" -Color White
    Write-ColorOutput "    Deny Unspecified:    $denyUnspecified" -Color $(if ($denyUnspecified -eq "ENABLED") { "Green" } else { "Gray" })
    Write-ColorOutput "    Deny Device Classes: $denyClasses" -Color $(if ($denyClasses -eq "ENABLED") { "Green" } else { "Gray" })
    Write-ColorOutput "    Allow Device Classes: $allowClasses" -Color $(if ($allowClasses -eq "ENABLED") { "Green" } else { "Gray" })
    Write-ColorOutput "    Allow Device IDs:    $allowIds" -Color $(if ($allowIds -eq "ENABLED") { "Green" } else { "Gray" })
    
    # Count blocked and allowed
    $blockedCount = 0
    $allowedCount = 0
    $customCount = 0
    
    if (Test-Path $RegDenyClasses) {
        $blockedCount = (Get-Item -Path $RegDenyClasses | Select-Object -ExpandProperty Property -ErrorAction SilentlyContinue | Measure-Object).Count
    }
    
    if (Test-Path $RegAllowClasses) {
        $allowedCount = (Get-Item -Path $RegAllowClasses | Select-Object -ExpandProperty Property -ErrorAction SilentlyContinue | Measure-Object).Count
    }
    
    if (Test-Path $CustomWhitelistPath) {
        $customCount = (Get-Item -Path $CustomWhitelistPath | Select-Object -ExpandProperty Property -ErrorAction SilentlyContinue | Measure-Object).Count
    }
    
    Write-ColorOutput "`n  Statistics:" -Color White
    Write-ColorOutput "    Blocked device classes: $blockedCount" -Color Red
    Write-ColorOutput "    Allowed device classes: $allowedCount" -Color Green
    Write-ColorOutput "    Custom whitelisted:     $customCount" -Color Cyan
}

function Show-InteractiveMenu {
    while ($true) {
        Write-Banner
        Show-RestrictionStatus
        
        Write-ColorOutput "`n[MENU OPTIONS]" -Color Yellow
        Write-ColorOutput "==============" -Color Yellow
        Write-ColorOutput "  1. Enable Device Restrictions" -Color White
        Write-ColorOutput "  2. Disable Device Restrictions" -Color White
        Write-ColorOutput "  3. Add Device to Whitelist" -Color White
        Write-ColorOutput "  4. Remove Device from Whitelist" -Color White
        Write-ColorOutput "  5. View Whitelist" -Color White
        Write-ColorOutput "  6. View Connected Devices" -Color White
        Write-ColorOutput "  7. View Status" -Color White
        Write-ColorOutput "  8. Exit" -Color White
        
        Write-Host ""
        $choice = Read-Host "  Enter your choice (1-8)"
        
        switch ($choice) {
            "1" {
                Write-ColorOutput "`n  Are you sure you want to enable device restrictions?" -Color Yellow
                Write-ColorOutput "  This will block USB, CD/DVD, Bluetooth, and Wireless devices." -Color Yellow
                $confirm = Read-Host "  Type 'YES' to confirm"
                if ($confirm -eq "YES") {
                    Enable-DeviceRestrictions
                }
                else {
                    Write-ColorOutput "  Operation cancelled." -Color Gray
                }
                Read-Host "`n  Press Enter to continue"
            }
            "2" {
                Write-ColorOutput "`n  Are you sure you want to disable all device restrictions?" -Color Yellow
                $confirm = Read-Host "  Type 'YES' to confirm"
                if ($confirm -eq "YES") {
                    Disable-DeviceRestrictions
                }
                else {
                    Write-ColorOutput "  Operation cancelled." -Color Gray
                }
                Read-Host "`n  Press Enter to continue"
            }
            "3" {
                Show-ConnectedDevices
                Write-ColorOutput "`n  Enter the Device Instance Path or Hardware ID to whitelist:" -Color Cyan
                $deviceId = Read-Host "  Device ID"
                if (-not [string]::IsNullOrWhiteSpace($deviceId)) {
                    Add-DeviceToWhitelist -Identifier $deviceId
                }
                Read-Host "`n  Press Enter to continue"
            }
            "4" {
                Show-Whitelist
                Write-ColorOutput "`n  Enter the Device Instance Path or Hardware ID to remove:" -Color Cyan
                $deviceId = Read-Host "  Device ID"
                if (-not [string]::IsNullOrWhiteSpace($deviceId)) {
                    Remove-DeviceFromWhitelist -Identifier $deviceId
                }
                Read-Host "`n  Press Enter to continue"
            }
            "5" {
                Show-Whitelist
                Read-Host "`n  Press Enter to continue"
            }
            "6" {
                Show-ConnectedDevices
                Read-Host "`n  Press Enter to continue"
            }
            "7" {
                Show-RestrictionStatus
                Read-Host "`n  Press Enter to continue"
            }
            "8" {
                Write-ColorOutput "`n  Goodbye!" -Color Cyan
                return
            }
            default {
                Write-ColorOutput "`n  Invalid option. Please try again." -Color Red
                Start-Sleep -Seconds 1
            }
        }
    }
}

#endregion

#region Main Execution

# Check for admin privileges and self-elevate if needed
if (-not (Test-AdminPrivileges)) {
    Write-Host "`nThis script requires Administrator privileges." -ForegroundColor Yellow
    Write-Host "Requesting elevation..." -ForegroundColor Cyan
    Request-Elevation
}

# Process action
switch ($Action) {
    "Enable" {
        Write-Banner
        Enable-DeviceRestrictions
    }
    "Disable" {
        Write-Banner
        Disable-DeviceRestrictions
    }
    "AddDevice" {
        Write-Banner
        $id = if ($DeviceInstancePath) { $DeviceInstancePath } else { $DeviceId }
        Add-DeviceToWhitelist -Identifier $id
    }
    "RemoveDevice" {
        Write-Banner
        $id = if ($DeviceInstancePath) { $DeviceInstancePath } else { $DeviceId }
        Remove-DeviceFromWhitelist -Identifier $id
    }
    "ListWhitelist" {
        Write-Banner
        Show-Whitelist
    }
    "ListDevices" {
        Write-Banner
        Show-ConnectedDevices
    }
    "Status" {
        Write-Banner
        Show-RestrictionStatus
    }
    "Menu" {
        Show-InteractiveMenu
    }
}

#endregion
