# Security & Privacy Policy

`hookpeek` is a local-first developer tool designed to capture, inspect, and replay webhooks locally during development and debugging. Because webhooks may carry sensitive information, `hookpeek` enforces strict security defaults.

## Secure by Default

1. **Loopback Only:**
   - The listener binds exclusively to `127.0.0.1` by default.
   - Binding to `0.0.0.0` or any non-loopback network interface requires the explicit `--allow-public-bind` flag.

2. **Loopback-Only Replay Target:**
   - The `replay` command defaults strictly to loopback targets (`127.0.0.1`, `localhost`, `::1`).
   - Replaying requests to remote or third-party servers requires the explicit `--allow-remote` flag to prevent accidental external webhook flooding or unintended SSRF.

3. **Disabled Redirects on Replay:**
   - The HTTP client used for replaying requests disables automatic redirect following, preventing target restriction bypasses.

4. **Credential and Signature Sanitization:**
   - Common sensitive headers (`Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key`, and provider webhook signatures) are automatically redacted to `[REDACTED]` upon storage.
   - They are never stored in plaintext in event files. When replaying, developers can supply fresh dev credentials via `--header`.

5. **Terminal Redaction in Inspect:**
   - The `inspect` command redacts common secret keys (`password`, `token`, `secret`, `api_key`, `access_token`) in formatted terminal previews.

6. **Restricted File Permissions:**
   - Event files and data directories are created with restrictive permissions (`0700` for directories, `0600` for event files) on supported Unix/POSIX systems.

7. **URL Sanitization:**
   - Replay targets strictly require `http` or `https` schemes without embedded user credentials (`user:pass@host`).

## Raw Body Storage Trade-off

To ensure that replayed webhooks remain byte-for-byte accurate for debugging and reproduction, raw request payloads are stored locally in base64 format.

- Developers are responsible for securing their local storage directory.
- Never commit the local events storage directory into version control.
- `hookpeek` includes `events/` and temporary files in its default `.gitignore`.
- Run `hookpeek prune` regularly to discard historical events.

## Internet Tunnels

`hookpeek` does not provide an integrated public tunnel. When using external tunneling software (e.g. ngrok, cloudflared, tailscale) to expose `hookpeek` to internet webhook providers, ensure you configure authentication and TLS properly on the tunnel endpoint.
