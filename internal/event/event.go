package event

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const SchemaVersion = 1

var idRegex = regexp.MustCompile(`^[a-f0-9]{32}$`)

var sensitiveHeaders = map[string]struct{}{
	"authorization":           {},
	"cookie":                  {},
	"set-cookie":              {},
	"x-api-key":               {},
	"apikey":                  {},
	"x-auth-token":            {},
	"x-hub-signature":         {},
	"x-hub-signature-256":     {},
	"stripe-signature":        {},
	"webhook-signature":       {},
	"x-signature":             {},
	"x-webhook-signature":     {},
	"x-razorpay-signature":    {},
	"x-shopify-hmac-sha256":   {},
	"x-signature-sha256":      {},
	"x-paystack-signature":    {},
	"paypal-transmission-sig": {},
}

var sensitiveJSONKeys = map[string]struct{}{
	"password":      {},
	"token":         {},
	"secret":        {},
	"api_key":       {},
	"apikey":        {},
	"access_token":  {},
	"refresh_token": {},
	"client_secret": {},
	"private_key":   {},
	"cvv":           {},
	"card_number":   {},
}

// Event represents a captured webhook request.
type Event struct {
	SchemaVersion int                 `json:"schema_version"`
	ID            string              `json:"id"`
	CapturedAt    string              `json:"captured_at"`
	Method        string              `json:"method"`
	Path          string              `json:"path"`
	RawQuery      string              `json:"raw_query"`
	ContentType   string              `json:"content_type"`
	Headers       map[string][]string `json:"headers"`
	BodyBase64    string              `json:"body_base64"`
	BodySize      int64               `json:"body_size"`
	BodySHA256    string              `json:"body_sha256"`
}

// New creates and initializes an Event from an incoming HTTP request and raw body bytes.
func New(req *http.Request, rawBody []byte, now time.Time) (*Event, error) {
	id, err := GenerateID()
	if err != nil {
		return nil, fmt.Errorf("could not generate event ID: %w", err)
	}

	sanitizedHeaders := SanitizeHeaders(req.Header)

	sha := sha256.Sum256(rawBody)
	shaHex := hex.EncodeToString(sha[:])

	return &Event{
		SchemaVersion: SchemaVersion,
		ID:            id,
		CapturedAt:    now.UTC().Format(time.RFC3339Nano),
		Method:        req.Method,
		Path:          req.URL.Path,
		RawQuery:      req.URL.RawQuery,
		ContentType:   req.Header.Get("Content-Type"),
		Headers:       sanitizedHeaders,
		BodyBase64:    base64.StdEncoding.EncodeToString(rawBody),
		BodySize:      int64(len(rawBody)),
		BodySHA256:    shaHex,
	}, nil
}

// GenerateID produces a cryptographically secure 16-byte hex ID (32 chars).
func GenerateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ValidateID ensures an ID is strictly 32 lowercase hex characters.
func ValidateID(id string) error {
	id = strings.TrimSpace(id)
	if !idRegex.MatchString(id) {
		return fmt.Errorf("invalid event ID format %q: expected 32 lowercase hex characters", id)
	}
	return nil
}

// SanitizeHeaders redacts credentials and sensitive signature headers.
func SanitizeHeaders(headers http.Header) map[string][]string {
	result := make(map[string][]string, len(headers))
	for k, v := range headers {
		lowerK := strings.ToLower(k)
		if _, isSensitive := sensitiveHeaders[lowerK]; isSensitive {
			result[k] = []string{"[REDACTED]"}
		} else {
			cp := make([]string, len(v))
			copy(cp, v)
			result[k] = cp
		}
	}
	return result
}

// HeaderValues returns the values for a given header name, case-insensitively.
func (e *Event) HeaderValues(name string) []string {
	lower := strings.ToLower(name)
	for k, v := range e.Headers {
		if strings.ToLower(k) == lower {
			return v
		}
	}
	return nil
}

// GetHeader returns the first value for a given header name, case-insensitively.
func (e *Event) GetHeader(name string) string {
	vals := e.HeaderValues(name)
	if len(vals) > 0 {
		return vals[0]
	}
	return ""
}

// DecodeBody decodes the base64 stored body back into raw bytes.
func (e *Event) DecodeBody() ([]byte, error) {
	if e.BodyBase64 == "" {
		return []byte{}, nil
	}
	return base64.StdEncoding.DecodeString(e.BodyBase64)
}

// IsTextPayload returns true if the content-type or bytes appear to be textual data.
func (e *Event) IsTextPayload(rawBody []byte) bool {
	ct := strings.ToLower(e.ContentType)
	if strings.Contains(ct, "json") ||
		strings.Contains(ct, "xml") ||
		strings.Contains(ct, "text") ||
		strings.Contains(ct, "x-www-form-urlencoded") {
		return true
	}
	return utf8.Valid(rawBody) && !bytes.ContainsRune(rawBody, 0)
}

// RedactedTextPreview returns a preview of the body with common secrets masked in JSON.
func (e *Event) RedactedTextPreview() (string, bool) {
	raw, err := e.DecodeBody()
	if err != nil {
		return "[corrupt body data]", false
	}
	if len(raw) == 0 {
		return "[empty body]", true
	}

	if !e.IsTextPayload(raw) {
		return fmt.Sprintf("[binary payload: %d bytes, sha256:%s]", e.BodySize, e.BodySHA256[:12]), false
	}

	// Try parsing JSON for intelligent key-based redaction
	var parsed any
	if err := json.Unmarshal(raw, &parsed); err == nil {
		redactedObj := redactJSONAny(parsed)
		if pretty, err := json.MarshalIndent(redactedObj, "", "  "); err == nil {
			return string(pretty), true
		}
	}

	// Fallback to raw text
	return string(raw), true
}

func redactJSONAny(v any) any {
	switch val := v.(type) {
	case map[string]any:
		res := make(map[string]any, len(val))
		for k, child := range val {
			lowerK := strings.ToLower(k)
			if _, isSensitive := sensitiveJSONKeys[lowerK]; isSensitive {
				res[k] = "[REDACTED]"
			} else {
				res[k] = redactJSONAny(child)
			}
		}
		return res
	case []any:
		res := make([]any, len(val))
		for i, child := range val {
			res[i] = redactJSONAny(child)
		}
		return res
	default:
		return val
	}
}
