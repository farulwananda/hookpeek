package verify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/farulwananda/hookpeek/internal/event"
)

func TestVerify_ValidSHA256(t *testing.T) {
	secret := "whsec_test_secret_key"
	body := []byte(`{"event":"order.completed","amount":500}`)

	// Compute expected signature
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	sigHex := hex.EncodeToString(mac.Sum(nil))

	ev := &event.Event{
		ID:         "11111111111111111111111111111111",
		BodyBase64: "eyJldmVudCI6Im9yZGVyLmNvbXBsZXRlZCIsImFtb3VudCI6NTAwfQ==",
		Headers: map[string][]string{
			"X-Custom-Signature": {"sha256=" + sigHex},
		},
	}

	res, err := Verify(ev, Options{
		Secret:     secret,
		HeaderName: "X-Custom-Signature",
		Algorithm:  "sha256",
	})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !res.Matched {
		t.Errorf("expected signature to match, computed: %s, received: %s", res.ComputedHex, res.ReceivedHeaderValue)
	}
}

func TestVerify_Mismatch(t *testing.T) {
	ev := &event.Event{
		ID:         "11111111111111111111111111111111",
		BodyBase64: "eyJldmVudCI6InRlc3QifQ==",
		Headers: map[string][]string{
			"X-Custom-Signature": {"invalid-signature"},
		},
	}

	res, err := Verify(ev, Options{
		Secret:     "secret123",
		HeaderName: "X-Custom-Signature",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Matched {
		t.Errorf("expected mismatch, but got matched=true")
	}
}
