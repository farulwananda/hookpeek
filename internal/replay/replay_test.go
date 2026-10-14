package replay

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/farulwananda/hookpeek/internal/event"
)

func TestReplay_Success(t *testing.T) {
	var receivedMethod string
	var receivedBody string
	var receivedAuth string
	var receivedCustom string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		b, _ := io.ReadAll(r.Body)
		receivedBody = string(b)
		receivedAuth = r.Header.Get("Authorization")
		receivedCustom = r.Header.Get("X-Custom")

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"received":true}`))
	}))
	defer ts.Close()

	ev := &event.Event{
		SchemaVersion: 1,
		ID:            "0123456789abcdef0123456789abcdef",
		Method:        "POST",
		Path:          "/hooks/test",
		Headers: map[string][]string{
			"Content-Type":  {"application/json"},
			"Authorization": {"[REDACTED]"},
			"X-Custom":      {"old-value"},
		},
		BodyBase64: "eyJmb28iOiJiYXIifQ==", // {"foo":"bar"}
		BodySize:   13,
	}

	cfg := Config{
		TargetURL: ts.URL + "/api/webhook",
		CustomHeaders: []string{
			"Authorization: Bearer dev-token-123",
			"X-Custom: new-value",
		},
		Client: ts.Client(),
	}

	res, err := Replay(context.Background(), ev, cfg)
	if err != nil {
		t.Fatalf("Replay unexpected error: %v", err)
	}

	if res.ResponseStatus != http.StatusOK {
		t.Errorf("status = %d, want 200", res.ResponseStatus)
	}
	if receivedMethod != "POST" {
		t.Errorf("method = %s, want POST", receivedMethod)
	}
	if receivedBody != `{"foo":"bar"}` {
		t.Errorf("body = %s, want {\"foo\":\"bar\"}", receivedBody)
	}
	if receivedAuth != "Bearer dev-token-123" {
		t.Errorf("auth = %s, want 'Bearer dev-token-123'", receivedAuth)
	}
	if receivedCustom != "new-value" {
		t.Errorf("custom header = %s, want 'new-value'", receivedCustom)
	}
}

func TestReplay_RemoteGuard(t *testing.T) {
	ev := &event.Event{
		ID:         "0123456789abcdef0123456789abcdef",
		Method:     "POST",
		BodyBase64: "",
	}

	// Remote target without flag -> rejected
	_, err := Replay(context.Background(), ev, Config{
		TargetURL:   "https://api.example.com/webhook",
		AllowRemote: false,
		DryRun:      true,
	})
	if err == nil || !strings.Contains(err.Error(), "not loopback") {
		t.Errorf("expected remote target rejection, got: %v", err)
	}

	// Remote target with flag -> allowed
	res, err := Replay(context.Background(), ev, Config{
		TargetURL:   "https://api.example.com/webhook",
		AllowRemote: true,
		DryRun:      true,
	})
	if err != nil {
		t.Errorf("unexpected error with --allow-remote: %v", err)
	}
	if !res.DryRun {
		t.Errorf("expected dry-run=true")
	}
}

func TestReplay_RedirectNotFollowed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/malicious", http.StatusFound)
	}))
	defer ts.Close()

	ev := &event.Event{
		ID:         "0123456789abcdef0123456789abcdef",
		Method:     "POST",
		BodyBase64: "",
	}

	res, err := Replay(context.Background(), ev, Config{
		TargetURL: ts.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Redirect should be returned as status 302 without following!
	if res.ResponseStatus != http.StatusFound {
		t.Errorf("expected 302 Found, got %d", res.ResponseStatus)
	}
}

func TestValidateTargetURL_Rejections(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr string
	}{
		{"empty", "", "cannot be empty"},
		{"invalid scheme", "ftp://localhost/hook", "only http and https are allowed"},
		{"embedded credentials", "http://user:pass@localhost/hook", "embedded credentials"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateTargetURL(tc.target, false)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("ValidateTargetURL(%q) error = %v, want substring %q", tc.target, err, tc.wantErr)
			}
		})
	}
}
