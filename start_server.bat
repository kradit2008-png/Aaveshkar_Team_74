@echo off
title Identity Shield - Node.js Network Server
color 0b
cd /d "%~dp0"

echo ===============================================================
echo   IDENTITY SHIELD - NODE.JS CROSS-DEVICE NETWORK SERVER
echo ===============================================================
echo.

:: Detect Node.js binary in PATH or standard install paths
where node >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set "NODE_BIN=node"
) else (
    if exist "C:\Program Files\nodejs\node.exe" (
        set "NODE_BIN=C:\Program Files\nodejs\node.exe"
        set "PATH=C:\Program Files\nodejs;%PATH%"
    ) else if exist "%LOCALAPPDATA%\Programs\nodejs\node.exe" (
        set "NODE_BIN=%LOCALAPPDATA%\Programs\nodejs\node.exe"
        set "PATH=%LOCALAPPDATA%\Programs\nodejs;%PATH%"
    ) else (
        color 0c
        echo [ERROR] Node.js was not found on your system!
        echo Please install Node.js from https://nodejs.org or via winget:
        echo   winget install OpenJS.NodeJS.LTS
        echo.
        pause
        exit /b 1
    )
)

echo [OK] Node.js detected:
"%NODE_BIN%" --version
echo.
echo Starting server on all network interfaces (0.0.0.0:3000)...
echo.
echo [!] NOTE: If your phone cannot open http://10.17.29.72:3000, run:
echo     fix_network_firewall.bat
echo     (This allows Port 3000 through Windows Firewall)
echo.

:: Automatically open browser after 2 seconds
start /b "" cmd /c "timeout /t 2 /nobreak >nul & start http://localhost:3000"

:server_loop
"%NODE_BIN%" server.js
echo.
echo [!] Server exited. Auto-restarting in 1 second (Press Ctrl+C to abort)...
timeout /t 1 /nobreak >nul
goto server_loop
