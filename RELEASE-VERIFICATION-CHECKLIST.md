# Surge v19.4.1 — Release Verification Checklist

This repository is source-complete but runtime verification must be performed on the target Windows PC and VPS.

## Windows
- [ ] `dotnet --version` reports an installed .NET 8 SDK compatible with `global.json`.
- [ ] Client Debug build succeeds with 0 errors.
- [ ] Admin Panel Debug build succeeds with 0 errors.
- [ ] Client login window appears on startup.
- [ ] Admin Panel login succeeds.
- [ ] Users, Devices, Licenses, Logs and Backup grids display actual cell values (not only row counts).
- [ ] Visual Studio Output contains no `BindingExpression` errors.

## VPS
- [ ] `/api/health` returns HTTP 200 over HTTPS.
- [ ] `http://95.38.233.67/` presents a publicly trusted certificate for the IP.
- [ ] 5077 and 5078 are not reachable externally.
- [ ] License Server binds to 127.0.0.1:5077.
- [ ] Server Control binds to 127.0.0.1:5078.
- [ ] Nginx config passes `nginx -t`.
- [ ] Certificate renewal succeeds and triggers an Nginx reload only after a successful config test.
- [ ] `SURGE_CONTROL_SECRET` matches between License Server and Server Control environment files.
- [ ] sudoers permits only the required `surge-license.service` start/stop/restart commands.

## License / HWID
- [ ] First device login succeeds.
- [ ] Same account on another PC is rejected before token issuance.
- [ ] Same license on another PC is rejected.
- [ ] Copied DeviceId with a different hardware fingerprint is rejected.
- [ ] Sign out does not release the device or license.
- [ ] Admin release works and is audited.
