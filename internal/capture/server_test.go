package capture

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/farulwananda/hookpeek/internal/storage"
	"github.com/farulwananda/hookpeek/internal/verify"
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

func TestInspectorLocalOriginAndEmbeddedUI(t *testing.T) {
	srv, _ := setupTestServer(t, 1024)
	oldDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldDir) })

	for _, path := range []string{"/ui", "/api/events", "/api/curl?id=missing", "/api/events/stream", "/api/replay"} {
		t.Run(path, func(t *testing.T) {
			method := http.MethodGet
			if path == "/api/replay" {
				method = http.MethodPost
			}
			for _, tc := range []struct {
				name, peer, host, origin string
				forbidden                bool
			}{
				{"hostile origin", "127.0.0.1:4000", "127.0.0.1:8787", "https://evil.example", true},
				{"hostile host", "127.0.0.1:4000", "evil.example:8787", "", true},
				{"remote peer", "192.0.2.5:4000", "127.0.0.1:8787", "", true},
				{"local CLI", "127.0.0.1:4000", "127.0.0.1:8787", "", false},
				{"same-origin browser", "127.0.0.1:4000", "127.0.0.1:8787", "http://127.0.0.1:8787", false},
			} {
				if path == "/api/events/stream" && !tc.forbidden {
					continue // an accepted stream is tested with a real HTTP connection below
				}
				t.Run(tc.name, func(t *testing.T) {
					req := httptest.NewRequest(method, "http://"+tc.host+path, strings.NewReader("{}"))
					req.RemoteAddr = tc.peer
					if tc.origin != "" {
						req.Header.Set("Origin", tc.origin)
					}
					rec := httptest.NewRecorder()
					srv.Handler().ServeHTTP(rec, req)
					if tc.forbidden && rec.Code != http.StatusForbidden {
						t.Fatalf("got %d, want 403", rec.Code)
					}
					if !tc.forbidden && rec.Code == http.StatusForbidden {
						t.Fatalf("local request rejected: %s", rec.Body.String())
					}
					if rec.Header().Get("Access-Control-Allow-Origin") != "" {
						t.Fatal("wildcard CORS exposed")
					}
					if path == "/ui" && !tc.forbidden && !strings.Contains(rec.Body.String(), "eventList") {
						t.Fatal("embedded inspector unavailable away from repo")
					}
				})
			}
		})
	}
	preflight := httptest.NewRequest(http.MethodOptions, "http://127.0.0.1:8787/api/replay", nil)
	preflight.RemoteAddr = "127.0.0.1:4000"
	preflight.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, preflight)
	if rec.Code != http.StatusForbidden || rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("cross-origin replay preflight accepted: %d %v", rec.Code, rec.Header())
	}
}

func TestCapture_SignaturePrivateAndLiveForward(t *testing.T) {
	received := make(chan http.Header, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(Config{Store: store, ForwardTo: target.URL, Logger: ioDiscard{}})
	if err != nil {
		t.Fatal(err)
	}
	source := httptest.NewServer(srv.Handler())
	defer source.Close()
	body := `{"event":"signed"}`
	mac := hmac.New(sha256.New, []byte("secret"))
	_, _ = mac.Write([]byte(body))
	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	req, err := http.NewRequest(http.MethodPost, source.URL+"/hooks/signed", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-My-Signature", signature)
	req.Header.Set("Authorization", "Bearer private")
	resp, err := source.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("capture returned %d", resp.StatusCode)
	}
	var captured CaptureResponse
	if err := json.NewDecoder(resp.Body).Decode(&captured); err != nil {
		t.Fatal(err)
	}
	select {
	case headers := <-received:
		if headers.Get("X-My-Signature") != signature || headers.Get("Authorization") != "Bearer private" {
			t.Fatalf("live forwarded headers were redacted: %v", headers)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("live forward never arrived")
	}
	ev, err := store.Get(captured.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ev.GetHeader("X-My-Signature") != "[REDACTED]" || ev.GetHeader("Authorization") != "[REDACTED]" {
		t.Fatal("stored event contains sensitive headers")
	}
	private, err := store.GetSignatureHeaders(ev.ID)
	if err != nil {
		t.Fatal(err)
	}
	result, err := verify.Verify(ev, verify.Options{Secret: "secret", HeaderName: "X-My-Signature", SignatureHeaders: private})
	if err != nil || !result.Matched {
		t.Fatalf("private signature did not verify: %+v, %v", result, err)
	}
	if strings.Contains(result.ReceivedHeaderValue, signature) {
		t.Fatal("verification result leaked signature")
	}
	res, err := source.Client().Get(source.URL + "/api/events")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil || strings.Contains(string(data), signature) || strings.Contains(string(data), "Bearer private") {
		t.Fatalf("inspector leaked secret: %s, %v", data, err)
	}
}

func TestInspectorSSEStreamsRedactedEvent(t *testing.T) {
	srv, _ := setupTestServer(t, 1024)
	source := httptest.NewServer(srv.Handler())
	defer source.Close()
	request, err := http.NewRequest(http.MethodGet, source.URL+"/api/events/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", source.URL)
	client := &http.Client{Timeout: 3 * time.Second}
	stream, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Body.Close()
	if stream.StatusCode != http.StatusOK || stream.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("local stream unavailable or CORS enabled: %d %v", stream.StatusCode, stream.Header)
	}
	capture, err := http.NewRequest(http.MethodPost, source.URL+"/hooks/sse", strings.NewReader(`{"hello":true}`))
	if err != nil {
		t.Fatal(err)
	}
	capture.Header.Set("X-Hub-Signature-256", "secret-signature")
	res, err := client.Do(capture)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	line, err := bufio.NewReader(stream.Body).ReadString('\n')
	if err != nil || !strings.Contains(line, `"path":"/hooks/sse"`) ||
		strings.Contains(line, "secret-signature") || !strings.Contains(line, "[REDACTED]") {
		t.Fatalf("stream did not deliver redacted event: %q, %v", line, err)
	}
}

func TestInspectorMasksLegacySignatureFiles(t *testing.T) {
	srv, store := setupTestServer(t, 1024)
	ev := map[string]any{
		"id":          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"captured_at": time.Now().UTC().Format(time.RFC3339Nano),
		"method":      "POST", "path": "/hooks/old",
		"headers": map[string][]string{"X-Hub-Signature-256": {"sha256=old-private"}},
	}
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.EventsDir(), ev["id"].(string)+".json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/events", "/api/curl?id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"} {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8787"+path, nil)
		req.RemoteAddr = "127.0.0.1:4200"
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "old-private") {
			t.Fatalf("legacy signature exposed by %s: %d %s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestInspectorAPIReplayAndCURL(t *testing.T) {
	srv, _ := setupTestServer(t, 1024)
	received := make(chan string, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received <- r.Method + " " + string(body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("received"))
	}))
	defer target.Close()
	capture := httptest.NewRequest(http.MethodPost, "/hooks/demo?source=test", strings.NewReader(`{"ok":true}`))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, capture)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("capture status %d", rec.Code)
	}
	var event CaptureResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(apiReplayPayload{EventID: event.ID, TargetURL: target.URL})
	replayReq := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8787/api/replay", bytes.NewReader(payload))
	replayReq.RemoteAddr = "127.0.0.1:4200"
	replayReq.Header.Set("Origin", "http://127.0.0.1:8787")
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, replayReq)
	got := <-received
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"response_status":201`) ||
		got != `POST {"ok":true}` {
		t.Fatalf("inspector replay failed: %d %s; received %q", rec.Code, rec.Body.String(), got)
	}
	curlReq := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8787/api/curl?id="+event.ID+"&to="+url.QueryEscape(target.URL), nil)
	curlReq.RemoteAddr = "127.0.0.1:4200"
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, curlReq)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), target.URL) ||
		!strings.Contains(rec.Body.String(), `{"ok":true}`) {
		t.Fatalf("inspector curl failed: %d %s", rec.Code, rec.Body.String())
	}
}
