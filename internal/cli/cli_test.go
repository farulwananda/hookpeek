package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/farulwananda/hookpeek/internal/event"
	"github.com/farulwananda/hookpeek/internal/storage"
)

func createCapturedEvent(t *testing.T, store *storage.Store, id, path, body string) *event.Event {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, "http://localhost"+path, nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer secret")
	ev, _ := event.New(req, []byte(body), time.Now())
	ev.ID = id
	if err := store.Save(ev); err != nil {
		t.Fatalf("failed to save event: %v", err)
	}
	return ev
}

func TestCLI_HelpAndVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--help"}, &stdout, &stderr)
	if code != ExitSuccess {
		t.Errorf("expected 0, got %d", code)
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Errorf("stdout missing usage: %s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"version"}, &stdout, &stderr)
	if code != ExitSuccess {
		t.Errorf("expected 0, got %d", code)
	}
	if !strings.Contains(stdout.String(), "v1.0.0") {
		t.Errorf("stdout missing version: %s", stdout.String())
	}
}

func TestCLI_ListAndInspect(t *testing.T) {
	tempDir := t.TempDir()
	store, _ := storage.NewStore(tempDir)

	ev := createCapturedEvent(t, store, "0123456789abcdef0123456789abcdef", "/hooks/orders", `{"order_id":"ORD-1"}`)

	// List Table
	var stdout, stderr bytes.Buffer
	code := Run([]string{"list", "--data-dir", tempDir}, &stdout, &stderr)
	if code != ExitSuccess {
		t.Fatalf("list failed with %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), ev.ID) || !strings.Contains(stdout.String(), "/hooks/orders") {
		t.Errorf("list output missing event: %s", stdout.String())
	}

	// List JSON
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"list", "--format", "json", "--data-dir", tempDir}, &stdout, &stderr)
	if code != ExitSuccess {
		t.Fatalf("list json failed: %s", stderr.String())
	}
	var listedEvents []*event.Event
	if err := json.Unmarshal(stdout.Bytes(), &listedEvents); err != nil {
		t.Fatalf("failed parsing list json: %v", err)
	}
	if len(listedEvents) != 1 || listedEvents[0].ID != ev.ID {
		t.Errorf("unexpected list json output: %+v", listedEvents)
	}

	// Inspect Text
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"inspect", ev.ID, "--data-dir", tempDir}, &stdout, &stderr)
	if code != ExitSuccess {
		t.Fatalf("inspect failed: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "EVENT ID:") || !strings.Contains(stdout.String(), "ORD-1") {
		t.Errorf("inspect missing details: %s", stdout.String())
	}

	// Inspect JSON
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"inspect", ev.ID, "--format", "json", "--data-dir", tempDir}, &stdout, &stderr)
	if code != ExitSuccess {
		t.Fatalf("inspect json failed: %s", stderr.String())
	}
	var inspectedEvent event.Event
	if err := json.Unmarshal(stdout.Bytes(), &inspectedEvent); err != nil {
		t.Fatalf("failed parsing inspect json: %v", err)
	}
	if inspectedEvent.ID != ev.ID {
		t.Errorf("inspected ID = %s, want %s", inspectedEvent.ID, ev.ID)
	}
}

func TestCLI_Replay(t *testing.T) {
	tempDir := t.TempDir()
	store, _ := storage.NewStore(tempDir)

	ev := createCapturedEvent(t, store, "0123456789abcdef0123456789abcdef", "/hooks/payments", `{"payment":"ok"}`)

	var receivedBody string
	var receivedAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		receivedBody = string(b)
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success":true}`))
	}))
	defer ts.Close()

	// Dry Run
	var stdout, stderr bytes.Buffer
	code := Run([]string{"replay", ev.ID, "--to", ts.URL, "--dry-run", "--data-dir", tempDir}, &stdout, &stderr)
	if code != ExitSuccess {
		t.Fatalf("replay dry-run failed: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "[DRY-RUN]") {
		t.Errorf("expected dry-run banner in stdout: %s", stdout.String())
	}

	// Actual Replay with custom header
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{
		"replay", ev.ID,
		"--to", ts.URL,
		"--header", "Authorization: Bearer dev-token-xyz",
		"--data-dir", tempDir,
	}, &stdout, &stderr)

	if code != ExitSuccess {
		t.Fatalf("replay failed: %s", stderr.String())
	}
	if receivedBody != `{"payment":"ok"}` {
		t.Errorf("target received body = %s, want {\"payment\":\"ok\"}", receivedBody)
	}
	if receivedAuth != "Bearer dev-token-xyz" {
		t.Errorf("target received auth = %s, want 'Bearer dev-token-xyz'", receivedAuth)
	}
}

func TestCLI_Prune(t *testing.T) {
	tempDir := t.TempDir()
	store, _ := storage.NewStore(tempDir)

	for i := range 5 {
		createCapturedEvent(t, store, fmt.Sprintf("%032x", i+1), "/hooks/test", "{}")
	}

	var stdout, stderr bytes.Buffer
	code := Run([]string{"prune", "--keep-last", "2", "--data-dir", tempDir}, &stdout, &stderr)
	if code != ExitSuccess {
		t.Fatalf("prune failed: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "Pruned 3 event(s)") {
		t.Errorf("unexpected prune stdout: %s", stdout.String())
	}

	remaining, _ := store.List(0)
	if len(remaining) != 2 {
		t.Errorf("expected 2 remaining, got %d", len(remaining))
	}
}

func TestParseDuration(t *testing.T) {
	d, err := parseDuration("7d")
	if err != nil || d != 7*24*time.Hour {
		t.Errorf("parseDuration(7d) = %v, err=%v", d, err)
	}
	d, err = parseDuration("12h")
	if err != nil || d != 12*time.Hour {
		t.Errorf("parseDuration(12h) = %v, err=%v", d, err)
	}
}
