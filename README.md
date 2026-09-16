# Surge v19.4.1

Clean source tree for the Surge WPF client, license server, and administrator panel.

## Projects
- `SurgeApp.csproj` — Windows WPF client.
- `Surge.LicenseServer/Surge.LicenseServer.csproj` — ASP.NET Core license server.
- `Surge.AdminPanel/Surge.AdminPanel.csproj` — Windows WPF admin console.

## Build
Build each project independently:

```powershell
dotnet build .\SurgeApp.csproj -c Release
dotnet build .\Surge.LicenseServer\Surge.LicenseServer.csproj -c Release
dotnet build .\Surge.AdminPanel\Surge.AdminPanel.csproj -c Release
```

## Publish and run
Run `Publish-Surge-v19.4.1.cmd`. The publish folders are created under `publish\`.

Then use:
- `Start-Surge-LicenseServer.cmd` — starts the server and keeps the console visible.
- `Start-Surge-Client.cmd` — starts the client.
- `Start-Surge-AdminPanel.cmd` — starts the admin panel.
- `Start-Surge-Diagnostics.cmd` — runs all builds and shows the admin startup log.

If an EXE closes immediately, do not guess: run the corresponding Start script from an existing CMD window. The launchers keep publish/build failures visible.

## Server environment
Production should set `SURGE_ADMIN_USER`, `SURGE_ADMIN_PASSWORD`, `SURGE_LICENSE_SECRET`, and `SURGE_JWT_SECRET`. The example credentials in scripts are for local testing only.


## Windows startup
The desktop client requests Administrator permission from its manifest before startup. This avoids restarting the application after login and losing the authenticated UI state.
