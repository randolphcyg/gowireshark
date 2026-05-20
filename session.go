package gowireshark

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
	mu      sync.RWMutex
	counts  map[string]int
	pages   map[cacheKey]*pageCacheEntry
	streams map[string][]StreamSummary
	experts map[string][]ExpertInfo
	follows map[followCacheKey]*FollowResult
}

type pageCacheEntry struct {
	frames  []*FrameData
	hasMore bool
}

type followCacheKey struct {
	filter string
	proto  string
}

func newSessionCache() *sessionCache {
	return &sessionCache{
		counts:  make(map[string]int),
		pages:   make(map[cacheKey]*pageCacheEntry),
		streams: make(map[string][]StreamSummary),
		experts: make(map[string][]ExpertInfo),
		follows: make(map[followCacheKey]*FollowResult),
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
	if !ok {
		return nil, false
	}
	cp := make([]*FrameData, len(v.frames))
	copy(cp, v.frames)
	return &pageCacheEntry{frames: cp, hasMore: v.hasMore}, true
}

func (c *sessionCache) setPage(filter string, page, size int, frames []*FrameData, hasMore bool) {
	cp := make([]*FrameData, len(frames))
	copy(cp, frames)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pages[cacheKey{filter, page, size}] = &pageCacheEntry{frames: cp, hasMore: hasMore}
}

func (c *sessionCache) getStreams(filter string) ([]StreamSummary, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.streams[filter]
	if !ok {
		return nil, false
	}
	cp := make([]StreamSummary, len(v))
	copy(cp, v)
	return cp, true
}

func (c *sessionCache) setStreams(filter string, streams []StreamSummary) {
	cp := make([]StreamSummary, len(streams))
	copy(cp, streams)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.streams[filter] = cp
}

func (c *sessionCache) getExpertInfos(filter string) ([]ExpertInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.experts[filter]
	if !ok {
		return nil, false
	}
	cp := make([]ExpertInfo, len(v))
	copy(cp, v)
	return cp, true
}

func (c *sessionCache) setExpertInfos(filter string, infos []ExpertInfo) {
	cp := make([]ExpertInfo, len(infos))
	copy(cp, infos)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.experts[filter] = cp
}

func (c *sessionCache) getFollowStream(filter, proto string) (*FollowResult, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.follows[followCacheKey{filter, proto}]
	if !ok {
		return nil, false
	}
	cp := &FollowResult{
		Payloads:    make([]FollowPayload, len(v.Payloads)),
		ClientNode:  v.ClientNode,
		ServerNode:  v.ServerNode,
		ClientBytes: v.ClientBytes,
		ServerBytes: v.ServerBytes,
		PacketCount: v.PacketCount,
	}
	for i, p := range v.Payloads {
		bytesCopy := make([]byte, len(p.Bytes))
		copy(bytesCopy, p.Bytes)
		cp.Payloads[i] = FollowPayload{Dir: p.Dir, HexData: p.HexData, Bytes: bytesCopy}
	}
	return cp, true
}

func (c *sessionCache) setFollowStream(filter, proto string, r *FollowResult) {
	cp := &FollowResult{
		Payloads:    make([]FollowPayload, len(r.Payloads)),
		ClientNode:  r.ClientNode,
		ServerNode:  r.ServerNode,
		ClientBytes: r.ClientBytes,
		ServerBytes: r.ServerBytes,
		PacketCount: r.PacketCount,
	}
	for i, p := range r.Payloads {
		bytesCopy := make([]byte, len(p.Bytes))
		copy(bytesCopy, p.Bytes)
		cp.Payloads[i] = FollowPayload{Dir: p.Dir, HexData: p.HexData, Bytes: bytesCopy}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.follows[followCacheKey{filter, proto}] = cp
}

func (c *sessionCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counts = make(map[string]int)
	c.pages = make(map[cacheKey]*pageCacheEntry)
	c.streams = make(map[string][]StreamSummary)
	c.experts = make(map[string][]ExpertInfo)
	c.follows = make(map[followCacheKey]*FollowResult)
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
// Results are cached by (filter, proto).
func (s *Session) FollowStream(q Query, proto string) (*FollowResult, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
	}
	if proto != "tcp" && proto != "udp" {
		return nil, errors.Wrapf(ErrUnsupportedProtocol, "%q (must be \"tcp\" or \"udp\")", proto)
	}

	if v, ok := s.cache.getFollowStream(q.Filter, proto); ok {
		return v, nil
	}

	epanMu.Lock()
	if err := sessionResetReadPosition(); err != nil {
		epanMu.Unlock()
		return nil, err
	}
	res, err := followStreamFromConf(q.Filter, proto)
	epanMu.Unlock()
	if err != nil {
		return nil, err
	}

	s.cache.setFollowStream(q.Filter, proto, res)
	return res, nil
}

// TotalFrames returns the unfiltered frame count from the index built at open time.
func (s *Session) TotalFrames() int {
	return s.frameCount
}

func (s *Session) parseOpts() []Option {
	opts := []Option{
		WithIgnoreErrors(s.conf.IgnoreErrors),
		WithDebug(s.conf.Debug),
		WithParseMode(s.conf.ParseMode),
	}
	if s.conf.Registry != nil {
		opts = append(opts, WithRegistry(s.conf.Registry))
	}
	if len(s.conf.SelectedLayers) > 0 {
		opts = append(opts, WithSelectedLayers(s.conf.SelectedLayers))
	}
	return opts
}

// FrameByIndex returns one parsed frame by its 1-based frame number using the
// already-open session.
func (s *Session) FrameByIndex(frameIdx int) (*FrameData, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
	}
	epanMu.Lock()
	defer epanMu.Unlock()
	if err := sessionResetReadPosition(); err != nil {
		return nil, err
	}
	return frameByIndexFromActiveConf(s.conf, frameIdx, s.parseOpts()...)
}

// FramesByIndices returns parsed frames for sorted unique 1-based frame numbers
// using the already-open session.
func (s *Session) FramesByIndices(frameIdxs []int) ([]*FrameData, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
	}
	epanMu.Lock()
	if err := sessionResetReadPosition(); err != nil {
		epanMu.Unlock()
		return nil, err
	}
	frames, err := framesByIndicesFromConf(s.conf, frameIdxs, s.parseOpts()...)
	epanMu.Unlock()
	return frames, err
}

// HexDataByIndex returns the hex dump for one 1-based frame number using the
// already-open session.
func (s *Session) HexDataByIndex(frameIdx int) (*HexData, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
	}
	epanMu.Lock()
	defer epanMu.Unlock()
	if err := sessionResetReadPosition(); err != nil {
		return nil, err
	}
	return hexDataByIndexFromActive(frameIdx)
}

// Streams returns TCP/UDP stream aggregates with real Wireshark stream IDs
// (tcp.stream / udp.stream). ConversationID is a hash of the sorted 5-tuple for
// internal matching; StreamID is the protocol-level stream identifier that can be
// used directly in display filters like "tcp.stream eq N".
// StreamID is -1 when the stream ID could not be resolved from the capture.
// Results are cached by query filter.
func (s *Session) Streams(q Query) ([]StreamSummary, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
	}

	if v, ok := s.cache.getStreams(q.Filter); ok {
		return v, nil
	}

	var all []StreamSummary

	tcpConvs, tcpErr := s.TapConversations("tcp", q)
	if tcpErr == nil {
		all = append(all, tapConvsToStreams(tcpConvs, "tcp")...)
	}

	udpConvs, udpErr := s.TapConversations("udp", q)
	if udpErr == nil {
		all = append(all, tapConvsToStreams(udpConvs, "udp")...)
	}

	if len(all) == 0 && (tcpErr != nil || udpErr != nil) {
		return nil, combineErrors(tcpErr, udpErr)
	}

	fillStreamIDs(s, q, all)

	slices.SortFunc(all, func(a, b StreamSummary) int {
		if a.Protocol != b.Protocol {
			return strings.Compare(a.Protocol, b.Protocol)
		}
		return a.ConversationID - b.ConversationID
	})

	s.cache.setStreams(q.Filter, all)
	return all, nil
}

// Conversations returns directional 5-tuple aggregates for this session's capture.
func (s *Session) Conversations(q Query) ([]ConversationSummary, error) {
	acc := newTrafficAccumulator()
	if err := s.WalkFrames(q, func(f *FrameData) error { acc.addFrame(f); return nil }); err != nil {
		return nil, err
	}
	return acc.conversations(), nil
}

// WriteFrames writes selected frames as NDJSON using this session's capture.
func (s *Session) WriteFrames(q Query, w io.Writer) (int, error) {
	if err := s.checkClosed(); err != nil {
		return 0, err
	}
	epanMu.Lock()
	if err := sessionResetReadPosition(); err != nil {
		epanMu.Unlock()
		return 0, err
	}
	count, err := writeFramesFromConf(s.conf, q.Filter, w)
	epanMu.Unlock()
	return count, err
}

// WriteFramesPage writes one page of selected frames as NDJSON using this session's capture.
func (s *Session) WriteFramesPage(q Query, page, size int, w io.Writer) (int, bool, error) {
	if err := s.checkClosed(); err != nil {
		return 0, false, err
	}
	epanMu.Lock()
	if err := sessionResetReadPosition(); err != nil {
		epanMu.Unlock()
		return 0, false, err
	}
	count, hasMore, err := writeFramesPageFromConf(s.conf, q.Filter, page, size, w)
	epanMu.Unlock()
	return count, hasMore, err
}

// TapConversations returns Wireshark conversation statistics for this session's capture.
func (s *Session) TapConversations(convType string, q Query) ([]TapConversation, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
	}
	epanMu.Lock()
	if err := sessionResetReadPosition(); err != nil {
		epanMu.Unlock()
		return nil, err
	}
	res, err := tapConversationsFromActive(convType, q.Filter)
	epanMu.Unlock()
	return res, err
}

// TapEndpoints returns Wireshark endpoint statistics for this session's capture.
func (s *Session) TapEndpoints(endpointType string, q Query) ([]TapEndpoint, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
	}
	epanMu.Lock()
	if err := sessionResetReadPosition(); err != nil {
		epanMu.Unlock()
		return nil, err
	}
	res, err := tapEndpointsFromActive(endpointType, q.Filter)
	epanMu.Unlock()
	return res, err
}

// ExportObjects returns Wireshark export objects for this session's capture.
func (s *Session) ExportObjects(protocol string, q Query) ([]ExportObject, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
	}
	epanMu.Lock()
	if err := sessionResetReadPosition(); err != nil {
		epanMu.Unlock()
		return nil, err
	}
	res, err := exportObjectsFromActive(protocol, q.Filter)
	epanMu.Unlock()
	return res, err
}

// WriteExportObject writes the payload of one export object to w for this session's capture.
func (s *Session) WriteExportObject(protocol string, packetNum int, w io.Writer, q Query) error {
	if err := s.checkClosed(); err != nil {
		return err
	}
	epanMu.Lock()
	if err := sessionResetReadPosition(); err != nil {
		epanMu.Unlock()
		return err
	}
	err := writeExportObjectFromActive(protocol, packetNum, q.Filter, w)
	epanMu.Unlock()
	return err
}

// WriteExportObjects writes all export objects for a protocol to dir for this session's capture.
func (s *Session) WriteExportObjects(protocol string, dir string, q Query) ([]ExportObject, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
	}

	objs, err := s.ExportObjects(protocol, q)
	if err != nil {
		return nil, err
	}
	if len(objs) == 0 {
		return nil, nil
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	out := make([]ExportObject, 0, len(objs))
	usedNames := map[string]int{}

	for _, obj := range objs {
		filename := obj.Filename
		if filename == "" {
			filename = fmt.Sprintf("%s_%d.bin", protocol, obj.PacketNum)
		}
		filename = sanitizeFilename(filename)

		usedNames[filename]++
		if n := usedNames[filename]; n > 1 {
			ext := filepath.Ext(filename)
			base := filename[:len(filename)-len(ext)]
			filename = fmt.Sprintf("%s_%d%s", base, n, ext)
		}

		fullPath := filepath.Join(dir, filename)
		f, fErr := os.Create(fullPath)
		if fErr != nil {
			return out, fErr
		}
		wErr := s.WriteExportObject(protocol, obj.PacketNum, f, q)
		f.Close()
		if wErr != nil {
			os.Remove(fullPath)
			return out, wErr
		}
		out = append(out, obj)
	}
	return out, nil
}

// ServiceResponseTimes returns Wireshark SRT statistics for this session's capture.
func (s *Session) ServiceResponseTimes(protocol string, q Query) ([]SRTSummary, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
	}
	epanMu.Lock()
	if err := sessionResetReadPosition(); err != nil {
		epanMu.Unlock()
		return nil, err
	}
	res, err := serviceResponseTimesFromActive(protocol, q.Filter)
	epanMu.Unlock()
	return res, err
}

func combineErrors(a, b error) error {
	if a != nil && b != nil {
		return errors.Wrapf(a, "also: %v", b)
	}
	if a != nil {
		return a
	}
	return b
}
