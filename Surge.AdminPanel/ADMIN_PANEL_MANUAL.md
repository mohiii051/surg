# Surge Admin Panel 19.4.1 — Operator Manual

This panel is the privileged control surface for Surge. Keep it restricted to the administrator workstation.

## Core operations

### Devices
Select a device and use:
- **Block / Unblock** — prevent/allow that device.
- **Release HWID** — unbinds all licenses locked to that device and marks the device inactive. This is the deliberate administrator override.
- **Copy HWID / Device ID** — copies the selected identifier to the clipboard.


### User password management
- Passwords are never stored in plaintext and cannot be recovered from the server.
- **Reset password** generates a new random temporary password, invalidates the user's active refresh-token sessions, shows the new password once, and copies it to the clipboard.
- The Users grid displays the account email and a masked password state, not the recoverable old password.

### Licenses
- **Create license** — creates a one-device PRO license.
- **Copy key** — copies a full key only when the current admin session has its plaintext (newly created or rotated key).
- **Rotate key** — replaces the key immediately. Existing masked keys cannot be reconstructed because the server stores a hash, not plaintext. Rotation is the recovery path for an old key.
- **Revoke** — permanently bans the selected license until an administrator later extends it; the current key stops activating.
- **Expire** — makes the license expired immediately.
- **Extend** — extends by the number entered in `Extend days` (1–3650).
- **Release device** — removes the license's current device/HWID lock without affecting other licenses.

## Safety rules
- Sign out never releases a device or license.
- Device/HWID release and license release are administrator-only actions.
- Confirmations are shown for destructive operations.
- All state-changing actions are audited by the server.
- Do not distribute this panel to customers.

## Network model
The current no-domain staging deployment uses:

`Admin Panel -> http://95.38.233.67/api/admin/* -> Nginx -> 127.0.0.1:5077`

Server Control remains on the private loopback path through the License Server.
