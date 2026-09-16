Surge Server Control

This small root service exposes authenticated start/stop/restart/status operations for surge-license.service.
It is required because a stopped license server cannot receive its own Start request.

Security: protect TCP 5078 with your firewall and keep the Admin token private.
The service validates the same token.secret and SURGE_ADMIN_USER used by the license server.
