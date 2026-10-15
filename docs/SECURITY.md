# Security & Privacy Policy

`hookpeek` is a local-first developer tool designed to capture, inspect, and replay webhooks locally during development and debugging. Because webhooks may carry sensitive information, `hookpeek` enforces strict security defaults.

## Secure by Default

1. **Loopback Only:**
   - The listener binds exclusively to `127.0.0.1` by default.
   - Binding to `0.0.0.0` or any non-loopback network interface requires the explicit `--allow-public-bind` flag.
   - The inspector UI and `/api/*` remain loopback-client only even when capture uses `--allow-public-bind`. Inspector browsers must use the same local origin; other origins and remote peers are denied. Webhook capture endpoints remain accessible on the configured listener.

2. **Loopback-Only Replay Target:**
   - The `replay` command defaults strictly to loopback targets (`127.0.0.1`, `localhost`, `::1`).
   - Replaying requests to remote or third-party servers requires the explicit `--allow-remote` flag to prevent accidental external webhook flooding or unintended SSRF.

3. **Disabled Redirects on Replay:**
   - The HTTP client used for replaying requests disables automatic redirect following, preventing target restriction bypasses.

4. **Credential and Signature Sanitization:**
   - Common sensitive headers (`Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key`, and signature/HMAC headers) are automatically redacted to `[REDACTED]` in event files and inspector/API responses.
   - Incoming signatures are stored separately as plaintext in a private `signatures/` directory (files `0600`) so local HMAC verification can work. This directory must be protected like the raw payload storage. Signature sidecars are removed on prune; regular replay does not reuse them, but immediate live forwarding sends original incoming headers. Supply fresh dev credentials with `--header` for later replay.

5. **Terminal Redaction in Inspect:**
   - The `inspect` command redacts common secret keys (`password`, `token`, `secret`, `api_key`, `access_token`) in formatted terminal previews.

6. **Restricted File Permissions:**
   - Event files, signature sidecars, and data directories are created with restrictive permissions (`0700` for directories, `0600` for files) on supported Unix/POSIX systems.

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
