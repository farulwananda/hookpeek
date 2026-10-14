package diff

import (
	"strings"
	"testing"

	"github.com/farulwananda/hookpeek/internal/event"
)

func TestCompare_Identical(t *testing.T) {
	ev1 := &event.Event{
		ID:         "11111111111111111111111111111111",
		Method:     "POST",
		Path:       "/hooks/orders",
		BodySHA256: "same-hash",
	}
	ev2 := &event.Event{
		ID:         "22222222222222222222222222222222",
		Method:     "POST",
		Path:       "/hooks/orders",
		BodySHA256: "same-hash",
	}

	report := Compare(ev1, ev2)
	if !strings.Contains(report, "identical") {
		t.Errorf("expected identical notice, got: %s", report)
	}
}

func TestCompare_JSONDiff(t *testing.T) {
	ev1 := &event.Event{
		ID:          "11111111111111111111111111111111",
		Method:      "POST",
		Path:        "/hooks/orders",
		ContentType: "application/json",
		BodyBase64:  "eyJzdGF0dXMiOiAicGVuZGluZyJ9", // {"status": "pending"}
		BodySHA256:  "hash1",
	}
	ev2 := &event.Event{
		ID:          "22222222222222222222222222222222",
		Method:      "POST",
		Path:        "/hooks/orders",
		ContentType: "application/json",
		BodyBase64:  "eyJzdGF0dXMiOiAiY29tcGxldGVkIn0=", // {"status": "completed"}
		BodySHA256:  "hash2",
	}

	report := Compare(ev1, ev2)
	if !strings.Contains(report, "pending") || !strings.Contains(report, "completed") {
		t.Errorf("diff output missing changes: %s", report)
	}
}
