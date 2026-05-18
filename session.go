package gowireshark

import (
	"fmt"
	"sync"

	"github.com/pkg/errors"
)

// Query holds per-call parameters that may vary between uses of a Session.
type Query struct {
	Filter string
}

type cacheKey struct {
	filter string
	page   int
	size   int
}

type sessionCache struct {
	mu     sync.RWMutex
	counts map[string]int
	pages  map[cacheKey]*pageCacheEntry
}

type pageCacheEntry struct {
	frames  []*FrameData
	hasMore bool
}

func newSessionCache() *sessionCache {
	return &sessionCache{
		counts: make(map[string]int),
		pages:  make(map[cacheKey]*pageCacheEntry),
	}
}

func (c *sessionCache) getCount(filter string) (int, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.counts[filter]
	return v, ok
}

func (c *sessionCache) setCount(filter string, count int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counts[filter] = count
}

func (c *sessionCache) getPage(filter string, page, size int) (*pageCacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.pages[cacheKey{filter, page, size}]
	return v, ok
}

func (c *sessionCache) setPage(filter string, page, size int, frames []*FrameData, hasMore bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pages[cacheKey{filter, page, size}] = &pageCacheEntry{frames: frames, hasMore: hasMore}
}

func (c *sessionCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counts = make(map[string]int)
	c.pages = make(map[cacheKey]*pageCacheEntry)
}

var (
	// ErrSessionClosed reports use of a session after Close.
	ErrSessionClosed = errors.New("session is closed")
	// ErrSessionActive reports an attempt to open a second process-wide session.
	ErrSessionActive = errors.New("another session is already active")
)

var (
	activeSessionMu sync.Mutex
	activeSession   *Session
)

// Session provides serial, reusable access to a single pcap file.
// OpenSession builds a frame offset index and holds the Wireshark dissection
// configuration for reuse. Sequential operations reset the underlying reader
// before scanning again.
//
// Sessions are not safe for concurrent use by multiple goroutines. Because
// libwireshark exposes process-global capture state, only one active Session may
// exist in the process at a time.
type Session struct {
	conf       *config
	cache      *sessionCache
	frameCount int
	closed     bool
}

// OpenSession opens a pcap file, applies options to the Wireshark session,
// builds the frame offset index, and returns a reusable Session.
//
// Options that affect session-wide dissection (TLS keys, registry, follow
// taps, etc.) are applied once here. Per-call display filters belong in Query.
func OpenSession(path string, opts ...Option) (*Session, error) {
	if !fileExists(path) {
		return nil, errors.Wrapf(ErrFileNotFound, "cannot open %q", path)
	}

	activeSessionMu.Lock()
	if activeSession != nil {
		activeSessionMu.Unlock()
		return nil, ErrSessionActive
	}

	conf := newConfig(opts...)

	s := &Session{
		conf:  conf,
		cache: newSessionCache(),
	}

	epanMu.Lock()

	_, err := initCapFile(path, opts...)
	if err != nil {
		epanMu.Unlock()
		activeSessionMu.Unlock()
		return nil, err
	}

	count, err := sessionBuildIndex()
	if err != nil {
		sessionDoClose()
		epanMu.Unlock()
		activeSessionMu.Unlock()
		return nil, err
	}
	s.frameCount = count

	epanMu.Unlock()
	activeSession = s
	activeSessionMu.Unlock()

	return s, nil
}

// Close releases Wireshark resources and clears cached results.
// After Close, all methods return ErrSessionClosed.
// Calling Close on an already-closed session is safe (no-op).
func (s *Session) Close() error {
	activeSessionMu.Lock()
	defer activeSessionMu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true

	s.cache.clear()

	epanMu.Lock()
	sessionFreeIndex()
	sessionDoClose()
	epanMu.Unlock()

	if activeSession == s {
		activeSession = nil
	}

	return nil
}

func (s *Session) checkClosed() error {
	if s.closed {
		return ErrSessionClosed
	}
	return nil
}

// FrameCount returns the number of frames selected by the query filter.
//
// Without a filter this is O(1) — it returns the count from the offset index
// built during OpenSession. With a filter, libwireshark must re-scan;
// results are cached by filter.
func (s *Session) FrameCount(q Query) (int, error) {
	if err := s.checkClosed(); err != nil {
		return 0, err
	}

	if q.Filter == "" {
		return s.frameCount, nil
	}

	if err := ValidateFilter(q.Filter); err != nil {
		return 0, err
	}

	if v, ok := s.cache.getCount(q.Filter); ok {
		return v, nil
	}

	epanMu.Lock()
	if err := sessionResetReadPosition(); err != nil {
		epanMu.Unlock()
		return 0, err
	}
	count := sessionCountFrames(q.Filter)
	epanMu.Unlock()

	s.cache.setCount(q.Filter, count)
	return count, nil
}

// FramesPage fetches a specific page of frames selected by the query filter.
// Results are cached by (filter, page, size).
func (s *Session) FramesPage(q Query, page, size int) ([]*FrameData, bool, error) {
	if err := s.checkClosed(); err != nil {
		return nil, false, err
	}

	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 10
	}

	if e, ok := s.cache.getPage(q.Filter, page, size); ok {
		return e.frames, e.hasMore, nil
	}

	epanMu.Lock()
	if err := sessionResetReadPosition(); err != nil {
		epanMu.Unlock()
		return nil, false, err
	}
	frames, hasMore, err := framesPageFromConf(s.conf, q.Filter, page, size, s.parseOpts()...)
	epanMu.Unlock()
	if err != nil {
		return nil, false, err
	}

	s.cache.setPage(q.Filter, page, size, frames, hasMore)
	return frames, hasMore, nil
}

// WalkFrames walks all frames matched by the query filter, calling walkFn for each.
// The FrameData passed to walkFn is only valid during the call; do not retain it.
// WalkFrames results are not cached.
func (s *Session) WalkFrames(q Query, walkFn func(*FrameData) error) error {
	if err := s.checkClosed(); err != nil {
		return err
	}

	epanMu.Lock()
	if err := sessionResetReadPosition(); err != nil {
		epanMu.Unlock()
		return err
	}
	err := walkFramesFromConf(s.conf, q.Filter, walkFn, s.parseOpts()...)
	epanMu.Unlock()
	return err
}

// FollowStream extracts payloads for TCP or UDP packets selected by the query filter.
// FollowStream results are not cached.
func (s *Session) FollowStream(q Query, proto string) (*FollowResult, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
	}
	if proto != "tcp" && proto != "udp" {
		return nil, fmt.Errorf("unsupported protocol: %q (must be \"tcp\" or \"udp\")", proto)
	}

	epanMu.Lock()
	if err := sessionResetReadPosition(); err != nil {
		epanMu.Unlock()
		return nil, err
	}
	res, err := followStreamFromConf(q.Filter, proto)
	epanMu.Unlock()
	return res, err
}

// TotalFrames returns the unfiltered frame count from the index built at open time.
func (s *Session) TotalFrames() int {
	return s.frameCount
}

func (s *Session) parseOpts() []Option {
	opts := []Option{
		WithIgnoreErrors(s.conf.IgnoreErrors),
		WithDebug(s.conf.Debug),
	}
	if s.conf.Registry != nil {
		opts = append(opts, WithRegistry(s.conf.Registry))
	}
	return opts
}
