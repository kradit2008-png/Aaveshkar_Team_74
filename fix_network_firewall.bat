@echo off
title Configure Windows Firewall for Cross-Device Network Access
color 0a

:: Self-elevation to Administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [i] Administrator privileges required. Requesting UAC elevation...
    powershell -Command "Start-Process -FilePath '%~dpnx0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"

echo ===============================================================
echo   IDENTITY SHIELD - NETWORK FIREWALL AUTO-CONFIGURATOR
echo ===============================================================
echo.

echo [*] 1. Adding Windows Firewall Inbound Rule for Port 3000 (Node.js)...
netsh advfirewall firewall delete rule name="Identity Shield Node Server (Port 3000)" >nul 2>&1
netsh advfirewall firewall add rule name="Identity Shield Node Server (Port 3000)" dir=in action=allow protocol=TCP localport=3000 profile=any >nul
if %errorlevel% equ 0 (
    echo    [OK] Inbound rule created for Port 3000.
) else (
    echo    [!] Failed to create rule for Port 3000.
)

echo [*] 2. Adding Windows Firewall Inbound Rule for Port 5000 (Python)...
netsh advfirewall firewall delete rule name="Identity Shield Python Server (Port 5000)" >nul 2>&1
netsh advfirewall firewall add rule name="Identity Shield Python Server (Port 5000)" dir=in action=allow protocol=TCP localport=5000 profile=any >nul
if %errorlevel% equ 0 (
    echo    [OK] Inbound rule created for Port 5000.
) else (
    echo    [!] Failed to create rule for Port 5000.
)

echo [*] 3. Changing Wi-Fi Network Profile from Public to Private...
powershell -Command "Get-NetConnectionProfile -InterfaceAlias 'Wi-Fi*' | Set-NetConnectionProfile -NetworkCategory Private" >nul 2>&1
if %errorlevel% equ 0 (
    echo    [OK] Wi-Fi network set to Private (allows local device communication).
) else (
    echo    [!] Could not change network category automatically.
)

echo.
echo ===============================================================
echo   FIREWALL & NETWORK CONFIGURATION COMPLETE!
echo ===============================================================
echo.
echo You can now connect from your phone or other device at:
echo.
echo   >>> http://10.17.29.72:3000 <<<
echo.
echo Press any key to close this window.
pause >nul
