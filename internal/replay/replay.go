package replay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/farulwananda/hookpeek/internal/event"
)

var hopByHopHeaders = map[string]struct{}{
	"connection":          {},
	"proxy-connection":    {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"te":                  {},
	"trailer":             {},
	"trailers":            {},
	"transfer-encoding":   {},
	"upgrade":             {},
	"host":                {},
	"content-length":      {},
}

// Config holds options for replaying an event.
type Config struct {
	TargetURL                 string
	AllowRemote               bool
	CustomHeaders             []string
	DryRun                    bool
	Timeout                   time.Duration
	ForwardOriginalSignatures bool // only for ephemeral live forwarding, never stored replay
	MaxResponseSize           int64
	Client                    *http.Client
}

// Result holds the details and outcome of a replay execution.
type Result struct {
	EventID          string              `json:"event_id"`
	TargetURL        string              `json:"target_url"`
	Method           string              `json:"method"`
	OutboundHeaders  map[string][]string `json:"outbound_headers"`
	DryRun           bool                `json:"dry_run"`
	ResponseStatus   int                 `json:"response_status,omitempty"`
	ResponseDuration int64               `json:"response_duration_ms,omitempty"`
	ResponseBody     string              `json:"response_body_preview,omitempty"`
	Error            string              `json:"error,omitempty"`
}

// ValidateTargetURL validates the target URL and checks the loopback guard.
func ValidateTargetURL(rawTarget string, allowRemote bool) (*url.URL, error) {
	trimmed := strings.TrimSpace(rawTarget)
	if trimmed == "" {
		return nil, errors.New("target URL cannot be empty")
	}

	u, err := url.ParseRequestURI(trimmed)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL %q: %w", trimmed, err)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("invalid scheme %q: only http and https are allowed", u.Scheme)
	}

	if u.User != nil {
		return nil, errors.New("embedded credentials (userinfo) in target URL are rejected for security")
	}

	host := u.Hostname()
	if host == "" {
		return nil, errors.New("target URL missing hostname")
	}

	// Loopback guard
	if !isLoopbackHost(host) && !allowRemote {
		return nil, fmt.Errorf("target host %q is not loopback; pass --allow-remote to permit remote replays", host)
	}

	return u, nil
}

// Replay sends a stored webhook event to a target endpoint.
func Replay(ctx context.Context, ev *event.Event, cfg Config) (*Result, error) {
	if ev == nil {
		return nil, errors.New("event cannot be nil")
	}

	targetURL, err := ValidateTargetURL(cfg.TargetURL, cfg.AllowRemote)
	if err != nil {
		return nil, err
	}

	rawBody, err := ev.DecodeBody()
	if err != nil {
		return nil, fmt.Errorf("failed to decode stored body: %w", err)
	}

	// Prepare outbound headers
	outboundHeader := make(http.Header)
	storedHeaders := ev.Headers
	if !cfg.ForwardOriginalSignatures {
		storedHeaders = event.SanitizeHeaders(http.Header(ev.Headers))
	}
	for k, vals := range storedHeaders {
		lowerK := strings.ToLower(k)
		if _, isHop := hopByHopHeaders[lowerK]; isHop || (event.IsSignatureHeader(k) && !cfg.ForwardOriginalSignatures) {
			continue
		}
		for _, v := range vals {
			if v == "[REDACTED]" {
				continue // Do not forward stored redaction placeholders
			}
			outboundHeader.Add(k, v)
		}
	}

	// Apply custom header overrides
	for _, rawH := range cfg.CustomHeaders {
		parts := strings.SplitN(rawH, ":", 2)
		if len(parts) == 2 {
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			if k != "" {
				outboundHeader.Set(k, v)
			}
		}
	}

	res := &Result{
		EventID:         ev.ID,
		TargetURL:       targetURL.String(),
		Method:          ev.Method,
		OutboundHeaders: outboundHeader,
		DryRun:          cfg.DryRun,
	}

	if cfg.DryRun {
		return res, nil
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	client := cfg.Client
	if client == nil {
		client = &http.Client{
			Timeout: timeout,
			// Do NOT automatically follow redirects to maintain target boundary security
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, ev.Method, targetURL.String(), bytes.NewReader(rawBody))
	if err != nil {
		res.Error = err.Error()
		return res, fmt.Errorf("failed creating replay request: %w", err)
	}
	req.Header = outboundHeader

	maxResp := cfg.MaxResponseSize
	if maxResp <= 0 {
		maxResp = 4096 // 4 KiB default preview
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		res.ResponseDuration = time.Since(start).Milliseconds()
		res.Error = err.Error()
		return res, fmt.Errorf("replay request failed: %w", err)
	}
	defer resp.Body.Close()

	res.ResponseDuration = time.Since(start).Milliseconds()
	res.ResponseStatus = resp.StatusCode

	respBodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxResp+1))
	if int64(len(respBodyBytes)) > maxResp {
		res.ResponseBody = string(respBodyBytes[:maxResp]) + "\n... [response truncated]"
	} else {
		res.ResponseBody = string(respBodyBytes)
	}

	return res, nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

// GenerateCURL produces a copy-pasteable curl command string for a captured event.
func GenerateCURL(ev *event.Event, targetURL string, customHeaders []string) (string, error) {
	if ev == nil {
		return "", errors.New("event cannot be nil")
	}

	target := strings.TrimSpace(targetURL)
	if target == "" {
		target = "http://127.0.0.1:3000" + ev.Path
		if ev.RawQuery != "" {
			target += "?" + ev.RawQuery
		}
	}

	parts := []string{"curl -X " + shellQuote(ev.Method)}

	// Headers
	for k, vals := range event.SanitizeHeaders(http.Header(ev.Headers)) {
		lowerK := strings.ToLower(k)
		if _, isHop := hopByHopHeaders[lowerK]; isHop || event.IsSignatureHeader(k) {
			continue
		}
		for _, v := range vals {
			if v == "[REDACTED]" {
				continue
			}
			parts = append(parts, "-H", shellQuote(k+": "+v))
		}
	}

	for _, rawH := range customHeaders {
		trimmed := strings.TrimSpace(rawH)
		if trimmed != "" {
			parts = append(parts, "-H", shellQuote(trimmed))
		}
	}

	// Body
	rawBody, err := ev.DecodeBody()
	if err != nil {
		return "", fmt.Errorf("failed to decode body: %w", err)
	}
	if bytes.IndexByte(rawBody, 0) >= 0 {
		return "", errors.New("cannot represent a NUL byte in a POSIX shell argument")
	}
	if len(rawBody) > 0 {
		// stdin avoids curl's special interpretation of leading @ as a file.
		parts = append(parts, "--data-binary", "@-")
	}
	parts = append(parts, "--", shellQuote(target))
	command := strings.Join(parts, " \\\n  ")
	if len(rawBody) > 0 {
		return "printf '%s' " + shellQuote(string(rawBody)) + " | " + command, nil
	}
	return command, nil
}

// POSIX single-quoted literals never evaluate $, backticks, or backslashes.
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}
