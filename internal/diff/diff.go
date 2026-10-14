package diff

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/farulwananda/hookpeek/internal/event"
)

// Compare produces a structured diff report between two events.
func Compare(ev1, ev2 *event.Event) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("Comparing Event 1 (%s) <-> Event 2 (%s)\n", ev1.ID, ev2.ID))
	b.WriteString(strings.Repeat("=", 60) + "\n")

	// Metadata diff
	if ev1.Method != ev2.Method {
		b.WriteString(fmt.Sprintf("Method:       - %s\n              + %s\n", ev1.Method, ev2.Method))
	} else {
		b.WriteString(fmt.Sprintf("Method:       %s\n", ev1.Method))
	}

	if ev1.Path != ev2.Path {
		b.WriteString(fmt.Sprintf("Path:         - %s\n              + %s\n", ev1.Path, ev2.Path))
	} else {
		b.WriteString(fmt.Sprintf("Path:         %s\n", ev1.Path))
	}

	if ev1.RawQuery != ev2.RawQuery {
		b.WriteString(fmt.Sprintf("Query:        - %s\n              + %s\n", ev1.RawQuery, ev2.RawQuery))
	}

	if ev1.ContentType != ev2.ContentType {
		b.WriteString(fmt.Sprintf("Content-Type: - %s\n              + %s\n", ev1.ContentType, ev2.ContentType))
	}

	// Body diff
	b.WriteString("\n--- PAYLOAD DIFF ---\n")
	body1, _ := ev1.DecodeBody()
	body2, _ := ev2.DecodeBody()

	if ev1.BodySHA256 == ev2.BodySHA256 {
		b.WriteString("[Payloads are byte-for-byte identical]\n")
		return b.String()
	}

	// Attempt JSON formatted diff
	var json1, json2 any
	err1 := json.Unmarshal(body1, &json1)
	err2 := json.Unmarshal(body2, &json2)

	if err1 == nil && err2 == nil {
		pretty1, _ := json.MarshalIndent(json1, "", "  ")
		pretty2, _ := json.MarshalIndent(json2, "", "  ")
		diffLines := computeLineDiff(string(pretty1), string(pretty2))
		b.WriteString(diffLines)
		return b.String()
	}

	// Plain text diff fallback
	if ev1.IsTextPayload(body1) && ev2.IsTextPayload(body2) {
		diffLines := computeLineDiff(string(body1), string(body2))
		b.WriteString(diffLines)
		return b.String()
	}

	// Binary summary
	b.WriteString(fmt.Sprintf("Binary payloads differ:\n  Event 1: %d bytes (sha256:%s)\n  Event 2: %d bytes (sha256:%s)\n",
		ev1.BodySize, ev1.BodySHA256[:12], ev2.BodySize, ev2.BodySHA256[:12]))

	return b.String()
}

func computeLineDiff(text1, text2 string) string {
	lines1 := strings.Split(text1, "\n")
	lines2 := strings.Split(text2, "\n")

	set1 := make(map[string]int)
	for _, l := range lines1 {
		set1[l]++
	}

	set2 := make(map[string]int)
	for _, l := range lines2 {
		set2[l]++
	}

	var sb strings.Builder

	// Unified comparison
	maxLines := len(lines1)
	if len(lines2) > maxLines {
		maxLines = len(lines2)
	}

	for i := range maxLines {
		var l1, l2 string
		hasL1 := i < len(lines1)
		hasL2 := i < len(lines2)

		if hasL1 {
			l1 = lines1[i]
		}
		if hasL2 {
			l2 = lines2[i]
		}

		if hasL1 && hasL2 && l1 == l2 {
			sb.WriteString("  " + l1 + "\n")
		} else {
			if hasL1 && set2[l1] == 0 {
				sb.WriteString("- " + l1 + "\n")
			}
			if hasL2 && set1[l2] == 0 {
				sb.WriteString("+ " + l2 + "\n")
			}
		}
	}

	return sb.String()
}
