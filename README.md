# Device Whitelisting Manager

A PowerShell-based device control solution for Windows 10/11 that blocks unauthorized devices while allowing whitelisted ones.

## ⚠️ Important Warning

This script modifies Windows device installation policies via the registry. **Improper use can prevent keyboard, mouse, or other essential devices from working.** 

- Always test in a controlled environment first
- Keep the `Disable` option readily available
- A backup is automatically created when enabling restrictions

---

## Features

### Default Blocked Devices
- USB Controllers and USB Devices
- CD/DVD Drives
- Bluetooth Devices
- Portable Devices (WPD)
- SD Card Readers
- Infrared Devices
- Image Scanners
- Modems
- PCMCIA Cards
- Smart Card Readers

### Default Allowed Devices
- System Devices
- Computer (motherboard/chipset)
- Processors
- Keyboards
- Mice
- Human Interface Devices (HID) - includes touchscreens
- Monitors
- Display Adapters
- Disk Drives (internal)
- Hard Disk Controllers
- SCSI Adapters
- Network Adapters (Ethernet included)
- Battery
- Firmware
- Security Devices

### Custom Whitelisting
- Whitelist specific devices by **Device Instance Path**
- Whitelist specific devices by **Hardware ID**
- Remove devices from whitelist when no longer needed
- Persistent whitelist storage (survives disable/enable cycles)

---

## Installation

1. Copy both files to a secure location:
   - `DeviceWhitelist.ps1`
   - `DeviceWhitelist.bat`

2. **No installation required** - runs directly

---

## Usage

### Interactive Menu (Recommended)

Double-click `DeviceWhitelist.bat` or run:
```powershell
.\DeviceWhitelist.ps1
```

The interactive menu provides a user-friendly interface for all operations.

### Command Line

#### Batch File (Auto-elevates to Admin)
```batch
DeviceWhitelist.bat                          # Interactive menu
DeviceWhitelist.bat /enable                  # Enable restrictions
DeviceWhitelist.bat /disable                 # Disable restrictions
DeviceWhitelist.bat /add "DEVICE_ID"         # Add device to whitelist
DeviceWhitelist.bat /remove "DEVICE_ID"      # Remove from whitelist
DeviceWhitelist.bat /list                    # View whitelist
DeviceWhitelist.bat /devices                 # View connected devices
DeviceWhitelist.bat /status                  # View current status
```

#### PowerShell (Must run as Administrator)
```powershell
.\DeviceWhitelist.ps1 -Action Enable
.\DeviceWhitelist.ps1 -Action Disable
.\DeviceWhitelist.ps1 -Action AddDevice -DeviceId "USB\VID_1234&PID_5678\ABC123"
.\DeviceWhitelist.ps1 -Action AddDevice -DeviceInstancePath "USB\VID_1234&PID_5678\ABC123"
.\DeviceWhitelist.ps1 -Action RemoveDevice -DeviceId "USB\VID_1234&PID_5678\ABC123"
.\DeviceWhitelist.ps1 -Action ListWhitelist
.\DeviceWhitelist.ps1 -Action ListDevices
.\DeviceWhitelist.ps1 -Action Status
```

---

## How to Whitelist a Device

### Step 1: Find the Device ID
1. Run the script and choose option **6 (View Connected Devices)**
2. Or run: `.\DeviceWhitelist.ps1 -Action ListDevices`
3. Find your device in the list and copy its **Instance ID** or **Hardware ID**

Example output:
```
[USB]
  • SanDisk Ultra USB 3.0
    Instance ID: USB\VID_0781&PID_5583\4C530001234567890
    Hardware ID: USB\VID_0781&PID_5583
```

### Step 2: Add to Whitelist
Using the Instance ID (specific device):
```powershell
.\DeviceWhitelist.ps1 -Action AddDevice -DeviceId "USB\VID_0781&PID_5583\4C530001234567890"
```

Using the Hardware ID (all devices of this model):
```powershell
.\DeviceWhitelist.ps1 -Action AddDevice -DeviceId "USB\VID_0781&PID_5583"
```

---

## Technical Details

### Registry Locations

| Path | Purpose |
|------|---------|
| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions` | Main policy settings |
| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses` | Blocked device classes |
| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\AllowDeviceClasses` | Allowed device classes |
| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\AllowDeviceIDs` | Allowed specific devices |
| `HKLM:\SOFTWARE\DeviceWhitelist\AllowedDevices` | Custom whitelist storage |

### How It Works

1. **DenyDeviceClasses** blocks entire categories of devices by their class GUID
2. **AllowDeviceClasses** creates exceptions for entire device classes
3. **AllowDeviceIDs** creates exceptions for specific devices by Instance ID or Hardware ID
4. The custom whitelist is persisted separately and reapplied when enabling restrictions

---

## Troubleshooting

### Keyboard/Mouse Not Working After Enable
1. If you can access the system, run `DeviceWhitelist.bat /disable`
2. If locked out:
   - Boot into Safe Mode
   - Open Registry Editor
   - Navigate to `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions`
   - Set `DenyDeviceClasses` to `0`
   - Reboot

### Device Still Blocked After Whitelisting
1. Ensure you're using the correct ID format
2. Try both Instance ID and Hardware ID
3. Unplug and replug the device
4. A system restart may be required

### Finding Device IDs in Device Manager
1. Open Device Manager
2. Right-click on the device → Properties
3. Go to Details tab
4. Select "Hardware Ids" or "Device Instance Path" from the dropdown

---

## Security Considerations

1. **Run only from secure location** - Protect the script from unauthorized modification
2. **Limit access** - Only administrators should have access to the script
3. **Audit changes** - The script creates backups before enabling restrictions
4. **Test first** - Always test in a non-production environment
5. **Document whitelisted devices** - Keep records of why devices were whitelisted

---

## Requirements

- Windows 10 or Windows 11
- PowerShell 5.1 or higher
- Administrator privileges

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
