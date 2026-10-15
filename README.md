# hookpeek

> Capture, inspect, and replay webhooks locally.

[![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://img.shields.io/badge/CI-Passing-brightgreen?style=flat&logo=github-actions)](https://github.com/farulwananda/hookpeek/actions)

`hookpeek` is a lightweight, local-first developer tool written in Go to capture incoming webhook requests, inspect metadata and raw payloads, store history locally on disk, and replay selected requests to your development application.

Built for backend developers integrating third-party callbacks (Stripe, GitHub, Shopify, payment gateways, custom webhooks) who need reproducible requests without writing throwaway debugging endpoints.

---

## Features

- **Local HTTP Receiver:** Capture `POST`, `PUT`, and `PATCH` webhook calls on `/hooks/<name>` with a single command.
- **Live Realtime Forwarding:** Automatically forward incoming webhooks in real time to your development server via `--forward-to`.
- **Accurate Replay:** Resend captured requests to your development app with exact method and raw payload bytes preserved.
- **Interactive Web Inspector:** Bundled same-origin local UI with live Server-Sent Events (SSE) streaming and 1-click replay (the page's Tailwind and font assets currently load from external CDNs).
- **Instant cURL Generator:** Turn any captured webhook into a ready-to-run `curl` command with `hookpeek curl`.
- **Payload Diffing:** Compare two captured payloads side by side to diagnose webhook payload discrepancies.
- **HMAC Signature Verifier:** Debug and test HMAC-SHA256, SHA1, and SHA512 signatures with custom secrets and headers.
- **Search & Filtering:** Search through stored webhooks by ID, path, headers, or body payload content.
- **Secure by Default:** Binds to `127.0.0.1` only. Replays default strictly to loopback targets to prevent unintentional SSRF.
- **Automatic Header Sanitization:** Redacts `Authorization`, `Cookie`, API keys, and webhook signatures in event JSON; original signature headers are kept only in private sidecar files for local verification.
- **Atomic File Storage:** Persists events as JSON files safely without databases, background daemons, or Docker.

---

## Installation

### Using Go

```bash
go install github.com/farulwananda/hookpeek/cmd/hookpeek@latest
```

### From Source

```bash
git clone https://github.com/farulwananda/hookpeek.git
cd hookpeek
go build -o hookpeek ./cmd/hookpeek
```

---

## Quick Start

### 1. Start Local Webhook Receiver

```bash
hookpeek listen --port 8787
```

Output:
```text
hookpeek: listener active on http://127.0.0.1:8787
Send webhooks to http://127.0.0.1:8787/hooks/<name>
Storage: /Users/username/Library/Application Support/hookpeek/events
Press Ctrl+C to stop.
```

### 2. Send a Test Webhook

In another terminal, send a webhook request:

```bash
curl -i -X POST http://127.0.0.1:8787/hooks/orders \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer secret-auth-token" \
  -H "X-Event: order.paid" \
  -d '{"order_id": "ORD-12345", "amount": 250000, "customer": "Alex"}'
```

The listener captures the webhook and responds with `202 Accepted`:
```json
{
  "id": "16bae9e957e11edba45fd617f9389db3",
  "captured": true
}
```

### 3. List Captured Requests

```bash
hookpeek list
```

Output:
```text
ID                                TIME (UTC)            METHOD  PATH           SIZE
16bae9e957e11edba45fd617f9389db3  2026-10-15T01:22:52Z  POST    /hooks/orders  64 B

Showing 1 event(s)
```

Export list as clean JSON:
```bash
hookpeek list --format json
```

### 4. Inspect Request Details & Body

```bash
hookpeek inspect 16bae9e957e11edba45fd617f9389db3
```

Output:
```text
EVENT ID:     16bae9e957e11edba45fd617f9389db3
CAPTURED AT:  2026-10-15T01:22:52.313569Z
METHOD:       POST
PATH:         /hooks/orders
CONTENT-TYPE: application/json
BODY SIZE:    64 B (64 bytes)
BODY SHA256:  6dae50bb27d305579b1cb691fd90c5a1a420b95141d89e148359b1638fab28c4

--- HEADERS ---
Accept: */*
Authorization: [REDACTED]
Content-Type: application/json
User-Agent: curl/8.7.1
X-Event: order.paid

--- PAYLOAD ---
{
  "amount": 250000,
  "customer": "Alex",
  "order_id": "ORD-12345"
}
```

### 5. Replay Request to Your Development Server

Run your local application (e.g. at `http://127.0.0.1:3000`), then replay the webhook:

```bash
hookpeek replay 16bae9e957e11edba45fd617f9389db3 \
  --to http://127.0.0.1:3000/api/webhooks/orders \
  --header "Authorization: Bearer my-development-token"
```

Preview without sending (Dry Run):
```bash
hookpeek replay 16bae9e957e11edba45fd617f9389db3 \
  --to http://127.0.0.1:3000/api/webhooks/orders \
  --dry-run
```

### 6. Prune Old Events

```bash
# Delete events older than 7 days
hookpeek prune --older-than 7d

# Keep only the 50 newest events
hookpeek prune --keep-last 50

# Preview deletion count without deleting
hookpeek prune --older-than 7d --dry-run
```

### 7. Realtime Webhook Forwarding

Automatically proxy incoming webhooks to your local dev app as they arrive, attaching any custom headers required:

```bash
hookpeek listen --forward-to http://127.0.0.1:3000/api/webhook \
  --header "Authorization: Bearer dev-secret" \
  --header "X-Api-Key: my-dev-key"
```

### 8. Generate cURL Command

Convert a captured webhook event into a POSIX-shell-quoted `curl` command (bodies containing NUL bytes cannot be represented as shell arguments):

```bash
hookpeek curl 16bae9e957e11edba45fd617f9389db3 --to http://127.0.0.1:3000/api/webhook
```

### 9. Launch Apple-Style Web Live Inspector

Open the bundled private live dashboard in your browser with real-time SSE streaming, payload inspector, and 1-click replay. It works regardless of the CLI's current working directory:

```bash
hookpeek web
# Or start the listener with UI auto-open:
hookpeek listen --ui
```

The inspector and `/api/*` endpoints accept loopback clients only (even with `--allow-public-bind`); browser requests must come from the same local origin. Webhook capture at `/hooks/*` remains available on the configured listener. Local scripts without an `Origin` header can still use the API.

### 10. Compare Payloads (Diff)

See the exact differences between two webhook payloads:

```bash
hookpeek diff <event-id-1> <event-id-2>
```

### 11. Verify HMAC Webhook Signatures

Test and debug webhook signatures with custom shared secrets and headers:

```bash
hookpeek verify <event-id> --secret "whsec_my_secret" --header "X-Hub-Signature-256"
```

Incoming signature headers are redacted from captured event JSON and inspector output. Their original values are saved separately in a private `signatures/` directory for local `hookpeek verify`; old events without a private signature remain unverifiable if they were captured with a redacted signature. Legacy events containing unredacted signature headers can still be verified, but inspector/API output masks them.

### 12. Search & Filter Webhook History

Search by keyword in path, headers, or payload text:

```bash
hookpeek list --search "ORD-12345"
hookpeek list --path "/hooks/orders" --method POST
```

---

## CLI Reference

### `hookpeek listen`

Starts the local webhook receiver.

```text
Flags:
  --host string          Host address to bind (default "127.0.0.1")
  --port int             Port to listen on (default 8787)
  --max-body int         Maximum request body size in bytes (default 1048576)
  --allow-public-bind    Permit binding to 0.0.0.0 or non-loopback addresses
  --data-dir string      Custom storage directory for captured events
```

### `hookpeek list`

Lists captured webhook events sorted newest first.

```text
Flags:
  --limit int            Maximum number of events to show (default 20, 0 = all)
  --format string        Output format: 'table' or 'json' (default "table")
  --data-dir string      Custom storage directory
```

### `hookpeek inspect <event-id>`

Displays metadata, sanitized headers, and decoded payload preview for a specific event.

```text
Flags:
  --format string        Output format: 'text' or 'json' (default "text")
  --data-dir string      Custom storage directory
```

### `hookpeek replay <event-id> --to <url>`

Replays a captured webhook request to the specified target URL.

```text
Flags:
  --to string            Target URL to send request to (required)
  --allow-remote         Permit replaying to non-loopback remote endpoints
  --header string        Custom header to override or add (can be repeated)
  --dry-run              Display request details without sending over the network
  --timeout duration     Request timeout (default 15s)
  --format string        Output format: 'text' or 'json' (default "text")
  --data-dir string      Custom storage directory
```

### `hookpeek prune`

Cleans up stored event files based on age or retention limit.

```text
Flags:
  --older-than duration  Delete events older than duration (e.g. 7d, 24h)
  --keep-last int        Preserve at least N newest events
  --dry-run              Preview number of events that would be deleted
  --data-dir string      Custom storage directory
```

---

## Security & Privacy

- **Loopback Enforcement:** Binds exclusively to `127.0.0.1` by default. Binding to `0.0.0.0` requires `--allow-public-bind`.
- **Target Guards:** Replays are restricted to `localhost`/loopback targets unless explicitly bypassed with `--allow-remote`.
- **Redirects Disabled:** Automatic HTTP redirect following is disabled on replay to prevent SSRF bypasses.
- **Credential Masking:** Headers such as `Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key`, and webhook signatures are masked to `[REDACTED]` in event JSON, CLI inspect, and the web inspector. Original signature headers alone are stored in private `0600` sidecar files for local HMAC verification and deleted on prune; they are not served by the API. Live forwarding sends original request headers, while later replay uses redacted stored headers.
- **Permission Hardening:** Storage directories and event/signature files use restricted permissions (`0700` and `0600`) on supported systems.

For full details, see [docs/SECURITY.md](docs/SECURITY.md).

---

## License

This project is licensed under the [MIT License](LICENSE).
