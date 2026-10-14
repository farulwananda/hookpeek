package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/farulwananda/hookpeek/internal/event"
)

var ErrNotFound = errors.New("event not found")

// Store manages local filesystem persistence for webhook events.
type Store struct {
	baseDir   string
	eventsDir string
}

// ResolveDataDir determines the platform-appropriate data directory.
func ResolveDataDir(customDir string) (string, error) {
	if customDir != "" {
		return filepath.Clean(customDir), nil
	}

	if env := os.Getenv("HOOKPEEK_DATA_DIR"); env != "" {
		return filepath.Clean(env), nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return ".hookpeek", nil
	}

	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "hookpeek"), nil
	case "windows":
		if appData := os.Getenv("LOCALAPPDATA"); appData != "" {
			return filepath.Join(appData, "hookpeek"), nil
		}
		return filepath.Join(home, "AppData", "Local", "hookpeek"), nil
	default: // Linux / BSD / Unix
		if xdgState := os.Getenv("XDG_STATE_HOME"); xdgState != "" {
			return filepath.Join(xdgState, "hookpeek"), nil
		}
		return filepath.Join(home, ".local", "state", "hookpeek"), nil
	}
}

// NewStore initializes Store, creating necessary directories with 0700 permissions.
func NewStore(dir string) (*Store, error) {
	cleanDir := filepath.Clean(dir)
	eventsDir := filepath.Join(cleanDir, "events")

	if err := os.MkdirAll(eventsDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create events directory %q: %w", eventsDir, err)
	}

	return &Store{
		baseDir:   cleanDir,
		eventsDir: eventsDir,
	}, nil
}

// BaseDir returns the root storage directory.
func (s *Store) BaseDir() string {
	return s.baseDir
}

// EventsDir returns the directory where event JSON files are located.
func (s *Store) EventsDir() string {
	return s.eventsDir
}

// Save atomically writes an event to the filesystem.
func (s *Store) Save(ev *event.Event) error {
	if err := event.ValidateID(ev.ID); err != nil {
		return err
	}

	data, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize event %s: %w", ev.ID, err)
	}

	finalPath := filepath.Join(s.eventsDir, ev.ID+".json")
	tmpFile, err := os.CreateTemp(s.eventsDir, fmt.Sprintf("tmp_%s_*.json", ev.ID))
	if err != nil {
		return fmt.Errorf("failed to create temporary event file: %w", err)
	}
	tmpPath := tmpFile.Name()

	// Ensure cleanup if any step fails
	success := false
	defer func() {
		if !success {
			_ = tmpFile.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmpFile.Chmod(0600); err != nil {
		// Non-fatal on filesystems that don't support Unix permissions
	}

	if _, err := tmpFile.Write(data); err != nil {
		return fmt.Errorf("failed writing event payload: %w", err)
	}

	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("failed syncing event payload: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed closing temp event file: %w", err)
	}

	if err := os.Rename(tmpPath, finalPath); err != nil {
		return fmt.Errorf("failed atomically renaming event file: %w", err)
	}

	success = true
	return nil
}

// Get retrieves a single event by ID.
func (s *Store) Get(id string) (*event.Event, error) {
	if err := event.ValidateID(id); err != nil {
		return nil, err
	}

	path := filepath.Join(s.eventsDir, id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed reading event %s: %w", id, err)
	}

	var ev event.Event
	if err := json.Unmarshal(data, &ev); err != nil {
		return nil, fmt.Errorf("corrupt event data in %s: %w", path, err)
	}

	return &ev, nil
}

// FilterOptions defines search and filtering criteria for events.
type FilterOptions struct {
	Limit  int
	Search string
	Path   string
	Method string
}

// Find queries events based on filtering options, returning them sorted newest first.
func (s *Store) Find(opts FilterOptions) ([]*event.Event, error) {
	entries, err := os.ReadDir(s.eventsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read events directory: %w", err)
	}

	searchQuery := strings.ToLower(strings.TrimSpace(opts.Search))
	filterPath := strings.ToLower(strings.TrimSpace(opts.Path))
	filterMethod := strings.ToUpper(strings.TrimSpace(opts.Method))

	var events []*event.Event
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || strings.HasPrefix(entry.Name(), "tmp_") {
			continue
		}

		path := filepath.Join(s.eventsDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		var ev event.Event
		if err := json.Unmarshal(data, &ev); err != nil {
			continue
		}

		// Filter by Method
		if filterMethod != "" && strings.ToUpper(ev.Method) != filterMethod {
			continue
		}

		// Filter by Path
		if filterPath != "" && !strings.Contains(strings.ToLower(ev.Path), filterPath) {
			continue
		}

		// Filter by Search Query
		if searchQuery != "" {
			matched := false
			if strings.Contains(strings.ToLower(ev.ID), searchQuery) ||
				strings.Contains(strings.ToLower(ev.Path), searchQuery) ||
				strings.Contains(strings.ToLower(ev.RawQuery), searchQuery) {
				matched = true
			}
			if !matched {
				for k, vals := range ev.Headers {
					if strings.Contains(strings.ToLower(k), searchQuery) {
						matched = true
						break
					}
					for _, v := range vals {
						if strings.Contains(strings.ToLower(v), searchQuery) {
							matched = true
							break
						}
					}
					if matched {
						break
					}
				}
			}
			if !matched {
				if raw, err := ev.DecodeBody(); err == nil && len(raw) > 0 {
					if strings.Contains(strings.ToLower(string(raw)), searchQuery) {
						matched = true
					}
				}
			}
			if !matched {
				continue
			}
		}

		events = append(events, &ev)
	}

	// Sort newest first
	sort.Slice(events, func(i, j int) bool {
		return events[i].CapturedAt > events[j].CapturedAt
	})

	if opts.Limit > 0 && len(events) > opts.Limit {
		events = events[:opts.Limit]
	}

	return events, nil
}

// List loads all events sorted descending by CapturedAt (newest first).
func (s *Store) List(limit int) ([]*event.Event, error) {
	return s.Find(FilterOptions{Limit: limit})
}

// Prune removes old events based on retention criteria.
func (s *Store) Prune(olderThan time.Duration, keepLast int, dryRun bool) (int, error) {
	allEvents, err := s.List(0)
	if err != nil {
		return 0, err
	}

	now := time.Now().UTC()
	var toDelete []*event.Event

	for i, ev := range allEvents {
		// If keepLast is specified, protect the first keepLast newest events
		if keepLast > 0 && i < keepLast {
			continue
		}

		if olderThan > 0 {
			captured, err := time.Parse(time.RFC3339Nano, ev.CapturedAt)
			if err != nil {
				captured, err = time.Parse(time.RFC3339, ev.CapturedAt)
			}
			if err == nil && now.Sub(captured) < olderThan {
				continue
			}
		}

		toDelete = append(toDelete, ev)
	}

	if dryRun {
		return len(toDelete), nil
	}

	deletedCount := 0
	for _, ev := range toDelete {
		path := filepath.Join(s.eventsDir, ev.ID+".json")
		if err := os.Remove(path); err == nil {
			deletedCount++
		}
	}

	return deletedCount, nil
}
