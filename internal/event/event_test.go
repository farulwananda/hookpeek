package event

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestEvent_CreationAndSanitization(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "http://localhost/hooks/orders?source=web", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer super-secret-token")
	req.Header.Set("X-API-Key", "my-api-key-123")
	req.Header.Set("X-Custom-Header", "allowed-value")

	body := []byte(`{"order_id": 123, "password": "hidden", "token": "secret123", "items": ["book"]}`)
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

	ev, err := New(req, body, now)
	if err != nil {
		t.Fatalf("unexpected error creating event: %v", err)
	}

	if err := ValidateID(ev.ID); err != nil {
		t.Errorf("invalid ID generated: %v", err)
	}
	if ev.SchemaVersion != 1 {
		t.Errorf("expected schema version 1, got %d", ev.SchemaVersion)
	}
	if ev.Method != "POST" {
		t.Errorf("expected POST, got %s", ev.Method)
	}
	if ev.Path != "/hooks/orders" {
		t.Errorf("expected /hooks/orders, got %s", ev.Path)
	}
	if ev.RawQuery != "source=web" {
		t.Errorf("expected source=web, got %s", ev.RawQuery)
	}

	// Verify Header Redaction
	if ev.GetHeader("Authorization") != "[REDACTED]" {
		t.Errorf("expected Authorization to be redacted, got %v", ev.GetHeader("Authorization"))
	}
	if ev.GetHeader("X-API-Key") != "[REDACTED]" {
		t.Errorf("expected X-API-Key to be redacted, got %v", ev.GetHeader("X-API-Key"))
	}
	if ev.GetHeader("X-Custom-Header") != "allowed-value" {
		t.Errorf("expected X-Custom-Header to be preserved, got %v", ev.GetHeader("X-Custom-Header"))
	}

	// Verify Body Decoding
	decoded, err := ev.DecodeBody()
	if err != nil {
		t.Fatalf("failed to decode body: %v", err)
	}
	if !bytes.Equal(decoded, body) {
		t.Errorf("decoded body does not match original bytes")
	}

	// Verify JSON preview redaction
	preview, isText := ev.RedactedTextPreview()
	if !isText {
		t.Errorf("expected isText to be true for JSON body")
	}
	if strings.Contains(preview, "hidden") {
		t.Errorf("preview contains unredacted password: %s", preview)
	}
	if strings.Contains(preview, "secret123") {
		t.Errorf("preview contains unredacted token: %s", preview)
	}
	if !strings.Contains(preview, "[REDACTED]") {
		t.Errorf("preview missing [REDACTED] label: %s", preview)
	}
	if !strings.Contains(preview, "book") {
		t.Errorf("preview missing non-sensitive value 'book': %s", preview)
	}
}

func TestEvent_BinaryBody(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "http://localhost/hooks/binary", nil)
	binaryData := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0x00}

	ev, err := New(req, binaryData, time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	preview, isText := ev.RedactedTextPreview()
	if isText {
		t.Errorf("expected isText=false for binary data, got true")
	}
	if !strings.Contains(preview, "binary payload") {
		t.Errorf("preview expected binary payload summary, got %s", preview)
	}
}

func TestValidateID(t *testing.T) {
	if err := ValidateID("5b4c8f0d6a7e92c103b4d5e6f709a8bc"); err != nil {
		t.Errorf("expected valid ID, got %v", err)
	}
	if err := ValidateID("../invalid"); err == nil {
		t.Errorf("expected error on path traversal ID, got nil")
	}
	if err := ValidateID("short"); err == nil {
		t.Errorf("expected error on short ID, got nil")
	}
}
