@echo off
:: Windows Device Whitelisting Script Launcher
:: This batch file launches the PowerShell script with admin privileges

title Windows Device Whitelisting Manager

:: Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo.
    echo ========================================
    echo  ADMINISTRATOR PRIVILEGES REQUIRED
    echo ========================================
    echo.
    echo This script requires Administrator privileges.
    echo Attempting to restart with elevated privileges...
    echo.
    
    :: Relaunch as admin (handle empty arguments)
    if "%~1"=="" (
        powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    ) else (
        powershell -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
    )
    exit /b
)

:: Get the directory where this batch file is located
set "SCRIPT_DIR=%~dp0"

:: Check if PowerShell script exists
if not exist "%SCRIPT_DIR%DeviceWhitelist.ps1" (
    echo.
    echo ERROR: DeviceWhitelist.ps1 not found in %SCRIPT_DIR%
    echo Please ensure the PowerShell script is in the same directory.
    echo.
    pause
    exit /b 1
)

:: Parse arguments
set "ACTION=Menu"
set "DEVICE_ID="

if "%~1"=="/enable" set "ACTION=Enable"
if "%~1"=="/disable" set "ACTION=Disable"
if "%~1"=="/add" (
    set "ACTION=AddDevice"
    set "DEVICE_ID=%~2"
)
if "%~1"=="/remove" (
    set "ACTION=RemoveDevice"
    set "DEVICE_ID=%~2"
)
if "%~1"=="/list" set "ACTION=ListWhitelist"
if "%~1"=="/devices" set "ACTION=ListDevices"
if "%~1"=="/status" set "ACTION=Status"
if "%~1"=="/?" goto :help
if "%~1"=="/help" goto :help

:: Launch PowerShell script
if "%DEVICE_ID%"=="" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%DeviceWhitelist.ps1" -Action %ACTION%
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%DeviceWhitelist.ps1" -Action %ACTION% -DeviceId "%DEVICE_ID%"
)

pause
exit /b

:help
echo.
echo ========================================
echo  WINDOWS DEVICE WHITELISTING MANAGER
echo ========================================
echo.
echo Usage: DeviceWhitelist.bat [option] [device_id]
echo.
echo Options:
echo   (no option)    Launch interactive menu
echo   /enable        Enable device restrictions
echo   /disable       Disable device restrictions
echo   /add [id]      Add device to whitelist
echo   /remove [id]   Remove device from whitelist
echo   /list          Show current whitelist
echo   /devices       Show connected devices
echo   /status        Show restriction status
echo   /? or /help    Show this help
echo.
echo Examples:
echo   DeviceWhitelist.bat
echo   DeviceWhitelist.bat /enable
echo   DeviceWhitelist.bat /add "USB\VID_1234&PID_5678\1234567890"
echo   DeviceWhitelist.bat /devices
echo.
pause
exit /b
