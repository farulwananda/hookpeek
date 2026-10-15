package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/farulwananda/hookpeek/internal/capture"
	"github.com/farulwananda/hookpeek/internal/diff"
	"github.com/farulwananda/hookpeek/internal/event"
	"github.com/farulwananda/hookpeek/internal/replay"
	"github.com/farulwananda/hookpeek/internal/storage"
	"github.com/farulwananda/hookpeek/internal/verify"
)

const (
	Version     = "v1.0.0"
	ExitSuccess = 0
	ExitFailure = 1
	ExitUsage   = 2
)

const rootHelp = `hookpeek - Capture, inspect, and replay webhooks locally.

Usage:
  hookpeek <command> [flags] [arguments]

  listen     Start local HTTP receiver to capture incoming webhooks
  list       List captured webhook events with search and filtering
  inspect    Display full details and body of a captured webhook event
  replay     Resend a captured webhook request to a local target URL
  curl       Generate copy-pasteable cURL command for an event
  diff       Compare two captured webhook payloads side by side
  verify     Verify HMAC webhook signatures against a shared secret
  web        Launch the Apple-style Web Live Inspector
  prune      Delete older webhook event files based on retention rules
  version    Show hookpeek version
Flags (listen):
  --host string          Host address to bind (default "127.0.0.1")
  --port int             Port to listen on (default 8787)
  --max-body int         Maximum request body size in bytes (default 1048576)
  --allow-public-bind    Permit binding to 0.0.0.0 or non-loopback addresses
  --forward-to string    Auto-forward incoming webhooks in real time to target URL
  --header string        Custom header to attach when forwarding webhooks (repeatable)
  --ui                   Launch the Web Inspector in browser on start
  --allow-remote         Permit forwarding to non-loopback endpoints
  --data-dir string      Custom storage directory for captured events

Flags (list):
  --limit int            Maximum number of events to show (default 20, 0 = all)
  --format string        Output format: 'table' or 'json' (default "table")
  --data-dir string      Custom storage directory

Flags (inspect):
  --format string        Output format: 'text' or 'json' (default "text")
  --data-dir string      Custom storage directory

Flags (replay):
  --to string            Target URL to send request to (required)
  --allow-remote         Permit replaying to non-loopback remote endpoints
  --header string        Custom header to override or add (can be used multiple times)
  --dry-run              Display the request without sending it
  --timeout duration     Request timeout (default 15s)
  --format string        Output format: 'text' or 'json' (default "text")
  --data-dir string      Custom storage directory

Flags (prune):
  --older-than duration  Delete events older than duration (e.g. 7d, 24h)
  --keep-last int        Preserve at least N newest events
  --dry-run              Display number of events that would be deleted
  --data-dir string      Custom storage directory

Examples:
  hookpeek listen --port 8787
  hookpeek list --limit 10
  hookpeek inspect <event-id>
  hookpeek replay <event-id> --to http://127.0.0.1:3000/webhooks/orders
  hookpeek replay <event-id> --to http://127.0.0.1:3000/webhooks/orders --header "Authorization: Bearer dev-token"
  hookpeek prune --older-than 7d
`

type arrayFlags []string

func (a *arrayFlags) String() string {
	return strings.Join(*a, ", ")
}

func (a *arrayFlags) Set(value string) error {
	*a = append(*a, value)
	return nil
}

// Run executes the CLI application and returns an exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, rootHelp)
		return ExitUsage
	}

	cmd := args[0]
	switch cmd {
	case "-h", "--help", "help":
		fmt.Fprint(stdout, rootHelp)
		return ExitSuccess
	case "-v", "--version", "version":
		fmt.Fprintf(stdout, "hookpeek %s\n", Version)
		return ExitSuccess
	case "listen":
		return runListen(args[1:], stdout, stderr)
	case "list":
		return runList(args[1:], stdout, stderr)
	case "inspect":
		return runInspect(args[1:], stdout, stderr)
	case "replay":
		return runReplay(args[1:], stdout, stderr)
	case "curl":
		return runCurl(args[1:], stdout, stderr)
	case "diff":
		return runDiff(args[1:], stdout, stderr)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "web", "ui":
		return runWeb(args[1:], stdout, stderr)
	case "prune":
		return runPrune(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "hookpeek: unknown command %q\nRun 'hookpeek --help' for usage.\n", cmd)
		return ExitUsage
	}
}

func getStore(customDir string) (*storage.Store, error) {
	dataDir, err := storage.ResolveDataDir(customDir)
	if err != nil {
		return nil, err
	}
	return storage.NewStore(dataDir)
}

func runListen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("listen", flag.ContinueOnError)
	fs.SetOutput(stderr)

	host := fs.String("host", capture.DefaultHost, "Host address to bind")
	port := fs.Int("port", capture.DefaultPort, "Port to listen on")
	maxBody := fs.Int64("max-body", capture.DefaultMaxBodySize, "Maximum request body size in bytes")
	allowPublic := fs.Bool("allow-public-bind", false, "Permit binding to non-loopback addresses")
	forwardTo := fs.String("forward-to", "", "Auto-forward incoming webhooks in real time to target URL")
	var forwardHeaders arrayFlags
	fs.Var(&forwardHeaders, "header", "Custom header to attach when forwarding webhooks (can be repeated)")
	allowRemote := fs.Bool("allow-remote", false, "Permit forwarding to non-loopback endpoints")
	launchUI := fs.Bool("ui", false, "Open the Web Live Inspector in default browser")
	dataDir := fs.String("data-dir", "", "Custom storage directory")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitSuccess
		}
		return ExitUsage
	}

	store, err := getStore(*dataDir)
	if err != nil {
		fmt.Fprintf(stderr, "hookpeek listen: failed initializing storage: %v\n", err)
		return ExitFailure
	}

	srv, err := capture.NewServer(capture.Config{
		Host:            *host,
		Port:            *port,
		MaxBodyBytes:    *maxBody,
		AllowPublicBind: *allowPublic,
		Store:           store,
		Logger:          stdout,
		ForwardTo:       *forwardTo,
		ForwardHeaders:  forwardHeaders,
		AllowRemote:     *allowRemote,
	})
	if err != nil {
		fmt.Fprintf(stderr, "hookpeek listen: %v\n", err)
		return ExitFailure
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(stdout, "hookpeek: listener active on http://%s:%d\n", *host, *port)
	fmt.Fprintf(stdout, "Send webhooks to http://%s:%d/hooks/<name>\n", *host, *port)
	fmt.Fprintf(stdout, "Storage: %s\n", store.EventsDir())
	if *forwardTo != "" {
		fmt.Fprintf(stdout, "Forwarding: -> %s\n", *forwardTo)
	}
	fmt.Fprintln(stdout, "Press Ctrl+C to stop.")
	if *launchUI {
		go openBrowser(fmt.Sprintf("http://%s:%d/ui", *host, *port))
	}

	if err := srv.Start(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(stderr, "hookpeek listen: server error: %v\n", err)
		return ExitFailure
	}

	fmt.Fprintln(stdout, "\nhookpeek: server stopped.")
	return ExitSuccess
}

func runList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(stderr)

	limit := fs.Int("limit", 20, "Maximum number of events to show (0 = all)")
	search := fs.String("search", "", "Search keywords in ID, path, query, headers, or body")
	pathFilter := fs.String("path", "", "Filter events by path substring")
	methodFilter := fs.String("method", "", "Filter events by HTTP method (e.g. POST, PUT, PATCH)")
	format := fs.String("format", "table", "Output format: 'table' or 'json'")
	dataDir := fs.String("data-dir", "", "Custom storage directory")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitSuccess
		}
		return ExitUsage
	}

	if *format != "table" && *format != "json" {
		fmt.Fprintf(stderr, "hookpeek list: invalid format %q, must be 'table' or 'json'\n", *format)
		return ExitUsage
	}

	store, err := getStore(*dataDir)
	if err != nil {
		fmt.Fprintf(stderr, "hookpeek list: failed initializing storage: %v\n", err)
		return ExitFailure
	}

	events, err := store.Find(storage.FilterOptions{
		Limit:  *limit,
		Search: *search,
		Path:   *pathFilter,
		Method: *methodFilter,
	})
	if err != nil {
		fmt.Fprintf(stderr, "hookpeek list: failed to list events: %v\n", err)
		return ExitFailure
	}
	for _, ev := range events {
		ev.Headers = event.SanitizeHeaders(http.Header(ev.Headers))
	}

	if *format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(events); err != nil {
			fmt.Fprintf(stderr, "hookpeek list: failed formatting JSON: %v\n", err)
			return ExitFailure
		}
		return ExitSuccess
	}

	if len(events) == 0 {
		fmt.Fprintln(stdout, "No webhook events captured yet.")
		return ExitSuccess
	}

	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tTIME (UTC)\tMETHOD\tPATH\tSIZE")
	for _, ev := range events {
		timeStr := ev.CapturedAt
		if t, err := time.Parse(time.RFC3339Nano, ev.CapturedAt); err == nil {
			timeStr = t.UTC().Format("2006-01-02T15:04:05Z")
		}
		sizeStr := formatBytes(ev.BodySize)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", ev.ID, timeStr, ev.Method, ev.Path, sizeStr)
	}
	tw.Flush()

	fmt.Fprintf(stdout, "\nShowing %d event(s)\n", len(events))
	return ExitSuccess
}

func runInspect(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(stderr)

	format := fs.String("format", "text", "Output format: 'text' or 'json'")
	dataDir := fs.String("data-dir", "", "Custom storage directory")

	positionals, err := parseFlagsAndPositionals(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitSuccess
		}
		return ExitUsage
	}

	if len(positionals) == 0 {
		fmt.Fprintln(stderr, "hookpeek inspect: missing event ID argument")
		return ExitUsage
	}

	store, err := getStore(*dataDir)
	if err != nil {
		fmt.Fprintf(stderr, "hookpeek inspect: failed initializing storage: %v\n", err)
		return ExitFailure
	}

	ev, err := store.Get(positionals[0])
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			fmt.Fprintf(stderr, "hookpeek inspect: event %q not found\n", positionals[0])
			return ExitFailure
		}
		fmt.Fprintf(stderr, "hookpeek inspect: %v\n", err)
		return ExitFailure
	}
	ev.Headers = event.SanitizeHeaders(http.Header(ev.Headers))

	if *format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(ev); err != nil {
			fmt.Fprintf(stderr, "hookpeek inspect: failed formatting JSON: %v\n", err)
			return ExitFailure
		}
		return ExitSuccess
	}

	fmt.Fprintf(stdout, "EVENT ID:     %s\n", ev.ID)
	fmt.Fprintf(stdout, "CAPTURED AT:  %s\n", ev.CapturedAt)
	fmt.Fprintf(stdout, "METHOD:       %s\n", ev.Method)
	fmt.Fprintf(stdout, "PATH:         %s\n", ev.Path)
	if ev.RawQuery != "" {
		fmt.Fprintf(stdout, "QUERY:        %s\n", ev.RawQuery)
	}
	if ev.ContentType != "" {
		fmt.Fprintf(stdout, "CONTENT-TYPE: %s\n", ev.ContentType)
	}
	fmt.Fprintf(stdout, "BODY SIZE:    %s (%d bytes)\n", formatBytes(ev.BodySize), ev.BodySize)
	fmt.Fprintf(stdout, "BODY SHA256:  %s\n", ev.BodySHA256)

	fmt.Fprintln(stdout, "\n--- HEADERS ---")
	for k, vals := range ev.Headers {
		for _, v := range vals {
			fmt.Fprintf(stdout, "%s: %s\n", k, v)
		}
	}

	preview, _ := ev.RedactedTextPreview()
	fmt.Fprintln(stdout, "\n--- PAYLOAD ---")
	fmt.Fprintln(stdout, preview)

	return ExitSuccess
}

func runReplay(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	fs.SetOutput(stderr)

	targetURL := fs.String("to", "", "Target URL to send webhook request to (required)")
	allowRemote := fs.Bool("allow-remote", false, "Permit replaying to non-loopback remote endpoints")
	var customHeaders arrayFlags
	fs.Var(&customHeaders, "header", "Custom header to override or add (can be repeated)")
	dryRun := fs.Bool("dry-run", false, "Display request details without sending over the network")
	timeout := fs.Duration("timeout", 15*time.Second, "Replay request timeout")
	format := fs.String("format", "text", "Output format: 'text' or 'json'")
	dataDir := fs.String("data-dir", "", "Custom storage directory")

	positionals, err := parseFlagsAndPositionals(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitSuccess
		}
		return ExitUsage
	}

	if *targetURL == "" {
		fmt.Fprintln(stderr, "hookpeek replay: --to target URL flag is required")
		return ExitUsage
	}

	if len(positionals) == 0 {
		fmt.Fprintln(stderr, "hookpeek replay: missing event ID argument")
		return ExitUsage
	}

	store, err := getStore(*dataDir)
	if err != nil {
		fmt.Fprintf(stderr, "hookpeek replay: failed initializing storage: %v\n", err)
		return ExitFailure
	}

	ev, err := store.Get(positionals[0])
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			fmt.Fprintf(stderr, "hookpeek replay: event %q not found\n", positionals[0])
			return ExitFailure
		}
		fmt.Fprintf(stderr, "hookpeek replay: %v\n", err)
		return ExitFailure
	}

	ctx := context.Background()
	result, err := replay.Replay(ctx, ev, replay.Config{
		TargetURL:     *targetURL,
		AllowRemote:   *allowRemote,
		CustomHeaders: customHeaders,
		DryRun:        *dryRun,
		Timeout:       *timeout,
	})
	if err != nil {
		fmt.Fprintf(stderr, "hookpeek replay: %v\n", err)
		return ExitFailure
	}

	if *format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(result)
		if result.ResponseStatus >= 400 {
			return ExitFailure
		}
		return ExitSuccess
	}

	if result.DryRun {
		fmt.Fprintln(stdout, "[DRY-RUN] Replay Request Summary:")
		fmt.Fprintf(stdout, "Target:  %s\n", result.TargetURL)
		fmt.Fprintf(stdout, "Method:  %s\n", result.Method)
		fmt.Fprintln(stdout, "Headers:")
		for k, vals := range result.OutboundHeaders {
			for _, v := range vals {
				fmt.Fprintf(stdout, "  %s: %s\n", k, v)
			}
		}
		fmt.Fprintf(stdout, "Body:    %s (%d bytes)\n", formatBytes(ev.BodySize), ev.BodySize)
		return ExitSuccess
	}

	fmt.Fprintf(stdout, "Replayed event %s to %s\n", result.EventID, result.TargetURL)
	fmt.Fprintf(stdout, "Status:   %d %s\n", result.ResponseStatus, http.StatusText(result.ResponseStatus))
	fmt.Fprintf(stdout, "Duration: %d ms\n", result.ResponseDuration)
	if result.ResponseBody != "" {
		fmt.Fprintln(stdout, "\nResponse Preview:")
		fmt.Fprintln(stdout, result.ResponseBody)
	}

	if result.ResponseStatus >= 400 {
		return ExitFailure
	}
	return ExitSuccess
}

func runPrune(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("prune", flag.ContinueOnError)
	fs.SetOutput(stderr)

	olderThanStr := fs.String("older-than", "", "Delete events older than duration (e.g. 7d, 24h)")
	keepLast := fs.Int("keep-last", 0, "Preserve at least N newest events")
	dryRun := fs.Bool("dry-run", false, "Preview number of events that would be deleted")
	dataDir := fs.String("data-dir", "", "Custom storage directory")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitSuccess
		}
		return ExitUsage
	}

	var olderThan time.Duration
	if *olderThanStr != "" {
		dur, err := parseDuration(*olderThanStr)
		if err != nil {
			fmt.Fprintf(stderr, "hookpeek prune: invalid --older-than value %q: %v\n", *olderThanStr, err)
			return ExitUsage
		}
		olderThan = dur
	}

	if olderThan == 0 && *keepLast <= 0 {
		fmt.Fprintln(stderr, "hookpeek prune: must specify --older-than and/or --keep-last")
		return ExitUsage
	}

	store, err := getStore(*dataDir)
	if err != nil {
		fmt.Fprintf(stderr, "hookpeek prune: failed initializing storage: %v\n", err)
		return ExitFailure
	}

	count, err := store.Prune(olderThan, *keepLast, *dryRun)
	if err != nil {
		fmt.Fprintf(stderr, "hookpeek prune: %v\n", err)
		return ExitFailure
	}

	if *dryRun {
		fmt.Fprintf(stdout, "[DRY-RUN] Would delete %d event(s).\n", count)
	} else {
		fmt.Fprintf(stdout, "Pruned %d event(s).\n", count)
	}

	return ExitSuccess
}
func runCurl(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("curl", flag.ContinueOnError)
	fs.SetOutput(stderr)

	targetURL := fs.String("to", "", "Target destination URL (defaults to http://127.0.0.1:3000<path>)")
	var customHeaders arrayFlags
	fs.Var(&customHeaders, "header", "Custom header to append or override (can be repeated)")
	dataDir := fs.String("data-dir", "", "Custom storage directory")

	positionals, err := parseFlagsAndPositionals(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitSuccess
		}
		return ExitUsage
	}

	if len(positionals) == 0 {
		fmt.Fprintln(stderr, "hookpeek curl: missing event ID argument")
		return ExitUsage
	}

	store, err := getStore(*dataDir)
	if err != nil {
		fmt.Fprintf(stderr, "hookpeek curl: failed initializing storage: %v\n", err)
		return ExitFailure
	}

	ev, err := store.Get(positionals[0])
	if err != nil {
		fmt.Fprintf(stderr, "hookpeek curl: %v\n", err)
		return ExitFailure
	}

	cmd, err := replay.GenerateCURL(ev, *targetURL, customHeaders)
	if err != nil {
		fmt.Fprintf(stderr, "hookpeek curl: %v\n", err)
		return ExitFailure
	}

	fmt.Fprintln(stdout, cmd)
	return ExitSuccess
}

func runDiff(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(stderr)

	dataDir := fs.String("data-dir", "", "Custom storage directory")

	positionals, err := parseFlagsAndPositionals(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitSuccess
		}
		return ExitUsage
	}

	if len(positionals) < 2 {
		fmt.Fprintln(stderr, "hookpeek diff: requires two event IDs to compare (usage: hookpeek diff <id1> <id2>)")
		return ExitUsage
	}

	store, err := getStore(*dataDir)
	if err != nil {
		fmt.Fprintf(stderr, "hookpeek diff: failed initializing storage: %v\n", err)
		return ExitFailure
	}

	ev1, err := store.Get(positionals[0])
	if err != nil {
		fmt.Fprintf(stderr, "hookpeek diff: event 1 error: %v\n", err)
		return ExitFailure
	}

	ev2, err := store.Get(positionals[1])
	if err != nil {
		fmt.Fprintf(stderr, "hookpeek diff: event 2 error: %v\n", err)
		return ExitFailure
	}

	out := diff.Compare(ev1, ev2)
	fmt.Fprint(stdout, out)
	return ExitSuccess
}

func runVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)

	secret := fs.String("secret", "", "Secret key used to compute HMAC (required)")
	headerName := fs.String("header", "", "Signature header name (auto-detected if omitted)")
	algo := fs.String("algo", "sha256", "HMAC algorithm: 'sha256', 'sha1', or 'sha512'")
	format := fs.String("format", "text", "Output format: 'text' or 'json'")
	dataDir := fs.String("data-dir", "", "Custom storage directory")

	positionals, err := parseFlagsAndPositionals(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitSuccess
		}
		return ExitUsage
	}

	if len(positionals) == 0 {
		fmt.Fprintln(stderr, "hookpeek verify: missing event ID argument")
		return ExitUsage
	}

	if *secret == "" {
		fmt.Fprintln(stderr, "hookpeek verify: --secret flag is required")
		return ExitUsage
	}

	store, err := getStore(*dataDir)
	if err != nil {
		fmt.Fprintf(stderr, "hookpeek verify: failed initializing storage: %v\n", err)
		return ExitFailure
	}

	ev, err := store.Get(positionals[0])
	if err != nil {
		fmt.Fprintf(stderr, "hookpeek verify: %v\n", err)
		return ExitFailure
	}
	signatures, err := store.GetSignatureHeaders(ev.ID)
	if err != nil {
		fmt.Fprintf(stderr, "hookpeek verify: %v\n", err)
		return ExitFailure
	}

	res, err := verify.Verify(ev, verify.Options{
		Secret:           *secret,
		HeaderName:       *headerName,
		Algorithm:        *algo,
		SignatureHeaders: signatures,
	})
	if err != nil {
		fmt.Fprintf(stderr, "hookpeek verify: %v\n", err)
		return ExitFailure
	}

	if *format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
		if !res.Matched {
			return ExitFailure
		}
		return ExitSuccess
	}

	fmt.Fprintf(stdout, "EVENT ID:     %s\n", res.EventID)
	fmt.Fprintf(stdout, "HEADER:       %s\n", res.HeaderName)
	fmt.Fprintf(stdout, "ALGORITHM:    %s\n", strings.ToUpper(res.Algorithm))
	fmt.Fprintf(stdout, "RECEIVED:     %s\n", res.ReceivedHeaderValue)
	fmt.Fprintf(stdout, "COMPUTED:     %s\n", res.ComputedHex)

	if res.Matched {
		fmt.Fprintln(stdout, "\nSTATUS:       VALID (HMAC signature matches payload)")
		return ExitSuccess
	}

	fmt.Fprintln(stdout, "\nSTATUS:       MISMATCH (HMAC signature does not match payload)")
	return ExitFailure
}

func runWeb(args []string, stdout, stderr io.Writer) int {
	argsWithUI := append([]string{"--ui"}, args...)
	return runListen(argsWithUI, stdout, stderr)
}

func openBrowser(target string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", target)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", target)
	default:
		cmd = exec.Command("xdg-open", target)
	}
	_ = cmd.Start()
}

func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if strings.HasSuffix(s, "d") {
		daysStr := strings.TrimSuffix(s, "d")
		days, err := strconv.Atoi(daysStr)
		if err != nil {
			return 0, err
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

func formatBytes(b int64) string {
	if b < 1024 {
		return fmt.Sprintf("%d B", b)
	}
	if b < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
}

func parseFlagsAndPositionals(fs *flag.FlagSet, args []string) ([]string, error) {
	var flagArgs []string
	var positionals []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			if !strings.Contains(arg, "=") {
				flagName := strings.TrimLeft(arg, "-")
				fl := fs.Lookup(flagName)
				isBool := false
				if fl != nil {
					if bf, ok := fl.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
						isBool = true
					}
				}
				if !isBool && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
					flagArgs = append(flagArgs, args[i+1])
					i++
				}
			}
		} else {
			positionals = append(positionals, arg)
		}
	}

	if err := fs.Parse(flagArgs); err != nil {
		return nil, err
	}
	return positionals, nil
}
