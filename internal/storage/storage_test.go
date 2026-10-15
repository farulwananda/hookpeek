package storage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/farulwananda/hookpeek/internal/event"
)

func createTestEvent(id string, captured time.Time) *event.Event {
	return &event.Event{
		SchemaVersion: 1,
		ID:            id,
		CapturedAt:    captured.UTC().Format(time.RFC3339Nano),
		Method:        "POST",
		Path:          "/hooks/test",
		ContentType:   "application/json",
		Headers:       map[string][]string{"X-Test": {"val"}},
		BodyBase64:    "e30=",
		BodySize:      2,
		BodySHA256:    "dummy",
	}
}

func TestStore_SaveAndGet(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ev := createTestEvent("0123456789abcdef0123456789abcdef", time.Now())
	if err := store.Save(ev); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Verify file exists
	path := filepath.Join(store.EventsDir(), ev.ID+".json")
	if _, err := os.Stat(path); err != nil {
		t.Errorf("event file does not exist: %v", err)
	}

	// Get
	got, err := store.Get(ev.ID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.ID != ev.ID || got.Path != ev.Path {
		t.Errorf("got %+v, want %+v", got, ev)
	}

	// Non-existent ID
	_, err = store.Get("fedcba9876543210fedcba9876543210")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}

	// Invalid ID
	_, err = store.Get("../traversal")
	if err == nil {
		t.Errorf("expected error for path traversal, got nil")
	}
}

func TestStore_ListAndOrder(t *testing.T) {
	tempDir := t.TempDir()
	store, _ := NewStore(tempDir)

	now := time.Now()
	ev1 := createTestEvent("11111111111111111111111111111111", now.Add(-2*time.Hour))
	ev2 := createTestEvent("22222222222222222222222222222222", now.Add(-10*time.Minute))
	ev3 := createTestEvent("33333333333333333333333333333333", now.Add(-1*time.Minute))

	_ = store.Save(ev1)
	_ = store.Save(ev2)
	_ = store.Save(ev3)

	events, err := store.List(0)
	if err != nil {
		t.Fatalf("List error: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("got %d events, want 3", len(events))
	}

	// Newest first order
	if events[0].ID != ev3.ID || events[1].ID != ev2.ID || events[2].ID != ev1.ID {
		t.Errorf("unexpected order: [%s, %s, %s]", events[0].ID, events[1].ID, events[2].ID)
	}

	// Limit test
	limited, _ := store.List(2)
	if len(limited) != 2 {
		t.Errorf("limit 2 got %d", len(limited))
	}
}

func TestStore_Prune(t *testing.T) {
	tempDir := t.TempDir()
	store, _ := NewStore(tempDir)

	now := time.Now()
	// 5 events, oldest is 10 days old, newest is 1 hour old
	offsets := []time.Duration{
		1 * time.Hour,
		5 * time.Hour,
		72 * time.Hour,
		96 * time.Hour,
		120 * time.Hour,
	}
	for i, offset := range offsets {
		ev := createTestEvent(fmt.Sprintf("%032x", i+1), now.Add(-offset))
		_ = store.Save(ev)
	}

	// Dry run prune older than 2 days
	dryCount, err := store.Prune(48*time.Hour, 0, true)
	if err != nil {
		t.Fatalf("prune dry run failed: %v", err)
	}
	if dryCount != 3 {
		t.Errorf("dry run count = %d, want 3", dryCount)
	}

	// Actual prune with keepLast 2
	pruned, err := store.Prune(0, 2, false)
	if err != nil {
		t.Fatalf("prune failed: %v", err)
	}
	if pruned != 3 {
		t.Errorf("pruned = %d, want 3", pruned)
	}

	remaining, _ := store.List(0)
	if len(remaining) != 2 {
		t.Errorf("remaining = %d, want 2", len(remaining))
	}
}

func TestStore_PrivateSignaturesPruned(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ev := createTestEvent("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", time.Now().Add(-time.Hour))
	ev.Headers["X-Hub-Signature-256"] = []string{"sha256=private"}
	if err := store.SaveWithSignatures(ev, map[string][]string{
		"X-Hub-Signature-256": {"sha256=private"},
		"Authorization":       {"Bearer never-save"},
	}); err != nil {
		t.Fatal(err)
	}
	eventJSON, err := os.ReadFile(filepath.Join(store.EventsDir(), ev.ID+".json"))
	if err != nil || strings.Contains(string(eventJSON), "sha256=private") {
		t.Fatalf("event JSON leaked signature: %v, %s", err, eventJSON)
	}
	signPath := filepath.Join(store.BaseDir(), "signatures", ev.ID+".json")
	stat, err := os.Stat(signPath)
	if err != nil {
		t.Fatal(err)
	}
	if stat.Mode().Perm()&0077 != 0 {
		t.Fatalf("signature sidecar is accessible to other users: %v", stat.Mode())
	}
	headers, err := store.GetSignatureHeaders(ev.ID)
	if err != nil || headers["X-Hub-Signature-256"][0] != "sha256=private" || len(headers) != 1 {
		t.Fatalf("private signature storage mismatch: %v, %v", headers, err)
	}
	if _, err := store.Prune(0, 0, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(signPath); !os.IsNotExist(err) {
		t.Fatalf("pruned event retained signature: %v", err)
	}
}
