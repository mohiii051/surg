@echo off
REM Surge v19.4.1 - Linux server-side publish (License Server + Server Control)
setlocal
cd /d "%~dp0"

echo === Surge.LicenseServer (linux-x64) ===
dotnet publish Surge.LicenseServer\Surge.LicenseServer.csproj ^
  -c Release -r linux-x64 --self-contained false ^
  -p:Deterministic=true -p:ContinuousIntegrationBuild=true ^
  -o publish\server
if errorlevel 1 goto :fail

echo === Surge.ServerControl (linux-x64) ===
dotnet publish Surge.ServerControl\Surge.ServerControl.csproj ^
  -c Release -r linux-x64 --self-contained false ^
  -p:Deterministic=true -p:ContinuousIntegrationBuild=true ^
  -o publish\control
if errorlevel 1 goto :fail

echo.
echo PUBLISH SUCCESS (v19.4.1) - copy publish\server to /opt/surge/server and publish\control to /opt/surge/control
goto :eof

:fail
echo PUBLISH FAILED
exit /b 1
