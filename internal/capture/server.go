package capture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/farulwananda/hookpeek/internal/event"
	"github.com/farulwananda/hookpeek/internal/storage"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DefaultHost        = "127.0.0.1"
	DefaultPort        = 8787
	DefaultMaxBodySize = 1024 * 1024 // 1 MiB
	MaxConcurrent      = 32
)

// Config defines the configuration for the webhook capture server.
type Config struct {
	Host            string
	Port            int
	MaxBodyBytes    int64
	AllowPublicBind bool
	Store           *storage.Store
	NowFunc         func() time.Time
	Logger          io.Writer
}

// Server handles listening for and capturing incoming webhooks.
type Server struct {
	cfg        Config
	store      *storage.Store
	httpServer *http.Server
	semaphore  chan struct{}
	mu         sync.Mutex
	addr       string
}

// CaptureResponse is returned upon successful webhook persistence.
type CaptureResponse struct {
	ID       string `json:"id"`
	Captured bool   `json:"captured"`
}

// HealthResponse is returned by /healthz.
type HealthResponse struct {
	Status string `json:"status"`
}

// ErrorResponse represents standard JSON error payloads.
type ErrorResponse struct {
	Error string `json:"error"`
}

// NewServer creates a new capture Server.
func NewServer(cfg Config) (*Server, error) {
	host := strings.TrimSpace(cfg.Host)
	if host == "" {
		host = DefaultHost
	}

	// Loopback enforcement
	if !isLoopback(host) && !cfg.AllowPublicBind {
		return nil, fmt.Errorf("binding to non-loopback address %q is rejected for security; pass --allow-public-bind to override", host)
	}

	port := cfg.Port
	if port <= 0 {
		port = DefaultPort
	}

	maxBody := cfg.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = DefaultMaxBodySize
	}

	if cfg.Store == nil {
		return nil, errors.New("storage Store is required")
	}

	nowFunc := cfg.NowFunc
	if nowFunc == nil {
		nowFunc = time.Now
	}

	logger := cfg.Logger
	if logger == nil {
		logger = os.Stderr
	}

	s := &Server{
		cfg: Config{
			Host:            host,
			Port:            port,
			MaxBodyBytes:    maxBody,
			AllowPublicBind: cfg.AllowPublicBind,
			Store:           cfg.Store,
			NowFunc:         nowFunc,
			Logger:          logger,
		},
		store:     cfg.Store,
		semaphore: make(chan struct{}, MaxConcurrent),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/hooks/", s.handleCapture)
	mux.HandleFunc("/", s.handleNotFound)
	s.httpServer = &http.Server{
		Addr:              net.JoinHostPort(host, strconv.Itoa(port)),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1024 * 1024,
	}

	return s, nil
}

// Start runs the server on a net.Listener (blocking until ctx cancelled or Close).
func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.httpServer.Addr)
	if err != nil {
		return fmt.Errorf("failed to bind to %s: %w", s.httpServer.Addr, err)
	}

	s.mu.Lock()
	s.addr = ln.Addr().String()
	s.mu.Unlock()

	errChan := make(chan error, 1)
	go func() {
		if err := s.httpServer.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errChan <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(shutdownCtx)
	case err := <-errChan:
		return err
	}
}

// Addr returns the bound network address.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.addr != "" {
		return s.addr
	}
	return s.httpServer.Addr
}

// Handler returns the http.Handler for direct testing with httptest.
func (s *Server) Handler() http.Handler {
	return s.httpServer.Handler
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, HealthResponse{Status: "ok"})
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "endpoint not found; send webhooks to /hooks/<name>"})
}

func (s *Server) handleCapture(w http.ResponseWriter, r *http.Request) {
	// 1. Allowed methods: POST, PUT, PATCH
	method := r.Method
	if method != http.MethodPost && method != http.MethodPut && method != http.MethodPatch {
		w.Header().Set("Allow", "POST, PUT, PATCH")
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed; only POST, PUT, and PATCH are supported"})
		return
	}

	// 2. Concurrency limiting
	select {
	case s.semaphore <- struct{}{}:
		defer func() { <-s.semaphore }()
	default:
		w.Header().Set("Retry-After", "1")
		writeJSON(w, http.StatusServiceUnavailable, ErrorResponse{Error: "concurrent capture limit reached; try again shortly"})
		return
	}

	// 3. Size-guarded body reading
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) || strings.Contains(strings.ToLower(err.Error()), "too large") {
			writeJSON(w, http.StatusRequestEntityTooLarge, ErrorResponse{
				Error: fmt.Sprintf("payload exceeds maximum limit of %d bytes", s.cfg.MaxBodyBytes),
			})
			return
		}
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "failed reading request body"})
		return
	}

	// 4. Construct Event model
	now := s.cfg.NowFunc()
	ev, err := event.New(r, body, now)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed initializing event"})
		return
	}

	// 5. Persist to storage
	if err := s.store.Save(ev); err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed persisting event"})
		return
	}

	// Log capture non-sensitively
	if s.cfg.Logger != nil {
		fmt.Fprintf(s.cfg.Logger, "[%s] CAPTURED %s %s (%d B) -> id:%s\n",
			now.Format("15:04:05"), ev.Method, ev.Path, ev.BodySize, ev.ID)
	}

	// 6. Respond 202 Accepted
	writeJSON(w, http.StatusAccepted, CaptureResponse{
		ID:       ev.ID,
		Captured: true,
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}
