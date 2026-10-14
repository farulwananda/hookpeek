package capture

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/farulwananda/hookpeek/internal/storage"
)

func setupTestServer(t *testing.T, maxBody int64) (*Server, *storage.Store) {
	t.Helper()
	tempDir := t.TempDir()
	store, err := storage.NewStore(tempDir)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	srv, err := NewServer(Config{
		Host:         "127.0.0.1",
		Port:         8787,
		MaxBodyBytes: maxBody,
		Store:        store,
		Logger:       ioDiscard{},
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	return srv, store
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }

func TestServer_Healthz(t *testing.T) {
	srv, _ := setupTestServer(t, 1024)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var res HealthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to parse json: %v", err)
	}
	if res.Status != "ok" {
		t.Errorf("status = %q, want 'ok'", res.Status)
	}

	// Method not allowed on healthz
	reqPost := httptest.NewRequest(http.MethodPost, "/healthz", nil)
	recPost := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recPost, reqPost)
	if recPost.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 on POST /healthz, got %d", recPost.Code)
	}
}

func TestServer_CaptureSuccess(t *testing.T) {
	srv, store := setupTestServer(t, 1024*1024)

	bodyPayload := `{"order_id":"ORD-999","amount":150000}`
	req := httptest.NewRequest(http.MethodPost, "/hooks/payments?source=gateway", strings.NewReader(bodyPayload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Webhook-Event", "payment.success")
	req.Header.Set("Authorization", "Bearer top-secret")

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted, got %d. Body: %s", rec.Code, rec.Body.String())
	}

	var resp CaptureResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if !resp.Captured || resp.ID == "" {
		t.Fatalf("invalid capture response: %+v", resp)
	}

	// Verify saved in storage
	ev, err := store.Get(resp.ID)
	if err != nil {
		t.Fatalf("event not found in storage: %v", err)
	}

	if ev.Path != "/hooks/payments" || ev.RawQuery != "source=gateway" {
		t.Errorf("path/query mismatch: %s?%s", ev.Path, ev.RawQuery)
	}
	if ev.Headers["Authorization"][0] != "[REDACTED]" {
		t.Errorf("Authorization header was not redacted: %v", ev.Headers["Authorization"])
	}

	decoded, _ := ev.DecodeBody()
	if !bytes.Equal(decoded, []byte(bodyPayload)) {
		t.Errorf("saved body mismatch: got %s, want %s", string(decoded), bodyPayload)
	}
}

func TestServer_MethodNotAllowed(t *testing.T) {
	srv, _ := setupTestServer(t, 1024)

	req := httptest.NewRequest(http.MethodGet, "/hooks/demo", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
	if rec.Header().Get("Allow") != "POST, PUT, PATCH" {
		t.Errorf("Allow header = %q, want 'POST, PUT, PATCH'", rec.Header().Get("Allow"))
	}
}

func TestServer_NotFound(t *testing.T) {
	srv, _ := setupTestServer(t, 1024)

	req := httptest.NewRequest(http.MethodPost, "/random/path", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestServer_PayloadTooLarge(t *testing.T) {
	srv, store := setupTestServer(t, 50) // Max 50 bytes

	bigPayload := strings.Repeat("A", 100) // 100 bytes
	req := httptest.NewRequest(http.MethodPost, "/hooks/big", strings.NewReader(bigPayload))
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413, got %d", rec.Code)
	}

	// Verify no events were saved
	events, _ := store.List(0)
	if len(events) != 0 {
		t.Errorf("expected 0 events in store, got %d", len(events))
	}
}

func TestServer_NonLoopbackSecurityGuard(t *testing.T) {
	tempDir := t.TempDir()
	store, _ := storage.NewStore(tempDir)

	// Attempt non-loopback without flag -> should fail
	_, err := NewServer(Config{
		Host:            "0.0.0.0",
		AllowPublicBind: false,
		Store:           store,
	})
	if err == nil {
		t.Fatal("expected error binding to 0.0.0.0 without --allow-public-bind, got nil")
	}

	// With flag -> should succeed
	srv, err := NewServer(Config{
		Host:            "0.0.0.0",
		AllowPublicBind: true,
		Store:           store,
	})
	if err != nil {
		t.Fatalf("unexpected error with --allow-public-bind: %v", err)
	}
	if srv == nil {
		t.Fatal("expected non-nil server")
	}
}

func TestServer_GracefulShutdown(t *testing.T) {
	tempDir := t.TempDir()
	store, _ := storage.NewStore(tempDir)

	srv, err := NewServer(Config{
		Host:  "127.0.0.1",
		Port:  0, // Ephemeral port
		Store: store,
	})
	if err != nil {
		t.Fatalf("failed creating server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errChan := make(chan error, 1)

	go func() {
		errChan <- srv.Start(ctx)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel() // Trigger graceful shutdown

	select {
	case err := <-errChan:
		if err != nil {
			t.Fatalf("expected nil error on clean shutdown, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server failed to shutdown within 2 seconds")
	}
}
