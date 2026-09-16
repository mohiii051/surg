# Hardware fingerprint migration (v19.2 → v19.4)

**Read this before you ship the v19.4 client.** It is the one change in this set that can lock
paying users out of licences they already own.

## What changed

`HardwareFingerprintService` no longer spawns `powershell.exe`. It reads the same five values
natively through WMI. The canonical string that gets hashed is deliberately identical in shape:

```
CPU | BOARD-UUID | DISK-SERIAL | TPM | MACHINE-GUID
```

Same order, same `Trim().ToUpperInvariant()` normalisation, same `missing` / `unavailable` /
`unsupported` sentinels. On the large majority of machines the resulting SHA-256 is byte-identical
to what v19.2 produced, and nothing needs to happen.

## Where it can still differ

| Component | Risk | Why |
|---|---|---|
| CPU, Board UUID, MachineGuid | Very low | Identical values from the identical WMI classes. |
| Disk serial | Low | v19.2 took `Select-Object -First 1` (WMI enumeration order). v19.4 takes the lowest `Index`. These agree in practice, but not by contract. |
| TPM | Low–moderate | v19.2 ran `Get-Tpm`, which needs elevation and a working TPM stack. v19.4 queries `Win32_Tpm` in `root\CIMV2\Security\MicrosoftTpm`. A machine where one succeeded and the other fails will produce `True`/`False` vs `unavailable`. |
| MachineGuid | Low | v19.4 explicitly opens the 64-bit registry view. This is a *correctness fix*, but on a 32-bit host it changes the value. |

A machine that shifts will be refused at `POST /api/devices/register` with
`"Hardware fingerprint conflict."` and the user cannot use the product.

## The migration window

`Program.cs` accepts a **time-boxed rebind**, disabled by default:

```
SURGE_HWID_REBIND_UNTIL_UTC=2026-10-15T00:00:00Z
```

While that timestamp is in the future, a fingerprint mismatch is accepted **only if the device's
ECDSA public key still matches the stored one**. That key lives in `DeviceIdentityService`, is
generated once per install, and is sealed with DPAPI under `CurrentUser`. Presenting it proves the
request comes from the same Windows account on the same machine — which is a stronger claim than
the fingerprint itself was making. Any licence locked to the device has its
`HardwareFingerprintHash` carried across in the same transaction, and the event is written to the
audit log as `Hardware Fingerprint Rebound`.

Requests that fail the public-key check are rejected exactly as before. The window does not weaken
the one-device policy; it only allows a device that can already prove its identity
cryptographically to update a hash that changed underneath it.

## Suggested rollout

1. Deploy the server first, with `SURGE_HWID_REBIND_UNTIL_UTC` set ~30 days out.
2. Ship the v19.4 client.
3. Watch `Hardware Fingerprint Rebound` in the admin audit log. That count is your real-world
   drift rate — if it is near zero, the compatibility work held.
4. After the window closes, remove the variable. Anyone who missed it is handled by the existing
   **Release HWID** admin action, which already works for this case.

## If you would rather not open the window at all

Leave `SURGE_HWID_REBIND_UNTIL_UTC` unset. Affected users then contact support and an administrator
clicks **Release HWID** on their device. That is entirely workable at small scale; it does not scale
to a large install base hitting it at once on release day.
