package verify

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strings"

	"github.com/farulwananda/hookpeek/internal/event"
)

var autoSignatureHeaders = []string{
	"stripe-signature",
	"x-hub-signature-256",
	"x-hub-signature",
	"x-signature",
	"x-signature-sha256",
	"x-webhook-signature",
	"x-shopify-hmac-sha256",
	"x-razorpay-signature",
	"x-paystack-signature",
}

// Options configures HMAC verification.
type Options struct {
	Secret     string
	HeaderName string
	Algorithm  string // "sha256" (default), "sha1", "sha512"
}

// Result holds the verification outcome.
type Result struct {
	EventID             string `json:"event_id"`
	HeaderName          string `json:"header_name"`
	ReceivedHeaderValue string `json:"received_header_value"`
	Algorithm           string `json:"algorithm"`
	ComputedHex         string `json:"computed_hex"`
	ComputedBase64      string `json:"computed_base64"`
	Matched             bool   `json:"matched"`
}

// Verify computes HMAC over the event raw body and compares against the signature header.
func Verify(ev *event.Event, opts Options) (*Result, error) {
	if ev == nil {
		return nil, errors.New("event cannot be nil")
	}

	secret := strings.TrimSpace(opts.Secret)
	if secret == "" {
		return nil, errors.New("secret key cannot be empty")
	}

	algo := strings.ToLower(strings.TrimSpace(opts.Algorithm))
	if algo == "" {
		algo = "sha256"
	}

	var hashFn func() hash.Hash
	switch algo {
	case "sha256":
		hashFn = sha256.New
	case "sha1":
		hashFn = sha1.New
	case "sha512":
		hashFn = sha512.New
	default:
		return nil, fmt.Errorf("unsupported algorithm %q: must be sha256, sha1, or sha512", algo)
	}

	rawBody, err := ev.DecodeBody()
	if err != nil {
		return nil, fmt.Errorf("failed to decode event body: %w", err)
	}

	// Compute HMAC
	mac := hmac.New(hashFn, []byte(secret))
	mac.Write(rawBody)
	macSum := mac.Sum(nil)

	computedHex := hex.EncodeToString(macSum)
	computedBase64 := base64.StdEncoding.EncodeToString(macSum)

	// Determine header to check
	targetHeader := strings.TrimSpace(opts.HeaderName)
	var headerVal string

	if targetHeader != "" {
		headerVal = ev.GetHeader(targetHeader)
	} else {
		// Auto-detect common signature headers
		for _, candidate := range autoSignatureHeaders {
			if val := ev.GetHeader(candidate); val != "" {
				targetHeader = candidate
				headerVal = val
				break
			}
		}
	}

	if targetHeader == "" {
		targetHeader = "X-Signature"
	}

	matched := false
	if headerVal != "" && headerVal != "[REDACTED]" {
		lowerVal := strings.ToLower(headerVal)
		if strings.Contains(lowerVal, computedHex) || strings.Contains(headerVal, computedBase64) {
			matched = true
		}
	}

	return &Result{
		EventID:             ev.ID,
		HeaderName:          targetHeader,
		ReceivedHeaderValue: headerVal,
		Algorithm:           algo,
		ComputedHex:         computedHex,
		ComputedBase64:      computedBase64,
		Matched:             matched,
	}, nil
}
