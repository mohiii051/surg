@echo off
setlocal EnableExtensions
cd /d "%~dp0"
echo SURGE DIAGNOSTICS
echo =================
where dotnet
if errorlevel 1 echo [ERROR] dotnet was not found in PATH.
echo.
echo [1] Client build:
dotnet build "%~dp0SurgeApp.csproj" -c Release
echo.
echo [2] Server build:
dotnet build "%~dp0Surge.LicenseServer\Surge.LicenseServer.csproj" -c Release
echo.
echo [3] Admin build:
dotnet build "%~dp0Surge.AdminPanel\Surge.AdminPanel.csproj" -c Release
echo.
echo [4] Admin startup log:
if exist "%LOCALAPPDATA%\Surge\AdminPanel-startup.log" type "%LOCALAPPDATA%\Surge\AdminPanel-startup.log" else echo No AdminPanel startup log found.
echo.
pause
