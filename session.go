package gowireshark

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bytedance/sonic"
	"github.com/pkg/errors"
)

// Query is STABLE.
type Query struct {
	Filter string
}

var (
	ErrSessionClosed = errors.New("session is closed")
)

var sessionGate = make(chan struct{}, 1)

func init() {
	sessionGate <- struct{}{}
}

func acquireSessionGate(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-sessionGate:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func releaseSessionGate() {
	select {
	case sessionGate <- struct{}{}:
	default:
	}
}

// Session is STABLE.
// Session holds an open libwireshark capture file and optional in-memory caches.
//
// Stability: stable — the exported Session type and its methods form the
// primary warm-session API. The struct fields are unexported and may change.
//
// Concurrency: NOT safe for concurrent use. At most one Session may be open
// per process (enforced by sessionGate). See package doc for the full contract.
type Session struct {
	conf              *config
	cache             *sessionCache
	frameCount        int
	closed            atomic.Bool
	path              string
	mu                sync.RWMutex
	readPositionDirty atomic.Bool
}

func OpenSessionContext(ctx context.Context, path string, opts ...Option) (*Session, error) {
	if !fileExists(path) {
		return nil, errors.Wrapf(ErrFileNotFound, "cannot open %q", path)
	}

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err := acquireSessionGate(ctx); err != nil {
		return nil, err
	}

	conf := newConfig(opts...)

	s := &Session{
		conf:  conf,
		cache: newSessionCache(conf.SessionCache),
		path:  path,
	}

	epanMu.Lock()

	_, err := initCapFile(path, opts...)
	if err != nil {
		epanMu.Unlock()
		releaseSessionGate()
		return nil, err
	}

	count, err := sessionBuildIndex()
	if err != nil {
		sessionDoClose()
		epanMu.Unlock()
		releaseSessionGate()
		return nil, err
	}
	s.frameCount = count
	s.readPositionDirty.Store(true)

	epanMu.Unlock()

	return s, nil
}

func (s *Session) Close() error {
	s.mu.Lock()
	if s.closed.Load() {
		s.mu.Unlock()
		return nil
	}
	s.closed.Store(true)

	s.cache.clear()

	epanMu.Lock()
	sessionFreeIndex()
	sessionDoClose()
	epanMu.Unlock()

	s.mu.Unlock()

	releaseSessionGate()

	return nil
}

func (s *Session) resetReadPosition() error {
	if !s.readPositionDirty.Load() {
		return nil
	}
	s.readPositionDirty.Store(false)
	return sessionResetReadPosition()
}

func (s *Session) FrameCount(q Query) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.frameCountLocked(q)
}

func (s *Session) frameCountLocked(q Query) (int, error) {
	if s.closed.Load() {
		return 0, ErrSessionClosed
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
	if err := s.resetReadPosition(); err != nil {
		epanMu.Unlock()
		return 0, err
	}
	count := sessionCountFrames(q.Filter)
	epanMu.Unlock()
	s.readPositionDirty.Store(true)

	s.cache.setCount(q.Filter, count)
	return count, nil
}

func (s *Session) FrameNumbers(q Query) ([]int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.frameNumbersLocked(q)
}

func (s *Session) frameNumbersLocked(q Query) ([]int, error) {
	if s.closed.Load() {
		return nil, ErrSessionClosed
	}

	if q.Filter == "" {
		fc := s.frameCount
		numbers := make([]int, fc)
		for i := range numbers {
			numbers[i] = i + 1
		}
		return numbers, nil
	}

	if err := ValidateFilter(q.Filter); err != nil {
		return nil, err
	}

	if v, ok := s.cache.getNumbers(q.Filter); ok {
		return v, nil
	}

	epanMu.Lock()
	if err := s.resetReadPosition(); err != nil {
		epanMu.Unlock()
		return nil, err
	}
	numbers, err := sessionGetFrameNumbers(q.Filter)
	epanMu.Unlock()
	s.readPositionDirty.Store(true)
	if err != nil {
		return nil, err
	}

	s.cache.setNumbers(q.Filter, numbers)
	return numbers, nil
}

func (s *Session) FramesPage(q Query, page, size int) ([]*FrameData, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return nil, false, ErrSessionClosed
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
	if err := s.resetReadPosition(); err != nil {
		epanMu.Unlock()
		return nil, false, err
	}
	frames, hasMore, err := framesPageFromConf(s.conf, q.Filter, page, size, s.parseOpts()...)
	epanMu.Unlock()
	s.readPositionDirty.Store(true)
	if err != nil {
		return nil, false, err
	}

	s.cache.setPage(q.Filter, page, size, frames, hasMore)
	return frames, hasMore, nil
}

func (s *Session) WalkFrames(q Query, walkFn func(*FrameData) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.walkFramesLocked(q, walkFn)
}

func (s *Session) walkFramesLocked(q Query, walkFn func(*FrameData) error) error {
	if s.closed.Load() {
		return ErrSessionClosed
	}

	epanMu.Lock()
	if err := s.resetReadPosition(); err != nil {
		epanMu.Unlock()
		return err
	}
	err := walkFramesFromConf(s.conf, q.Filter, walkFn, s.parseOpts()...)
	epanMu.Unlock()
	s.readPositionDirty.Store(true)
	return err
}

func (s *Session) FollowStream(q Query, proto string) (*FollowResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return nil, ErrSessionClosed
	}
	if proto != "tcp" && proto != "udp" {
		return nil, errors.Wrapf(ErrUnsupportedProtocol, "%q (must be \"tcp\" or \"udp\")", proto)
	}

	if v, ok := s.cache.getFollowStream(q.Filter, proto); ok {
		return v, nil
	}

	epanMu.Lock()
	if err := s.resetReadPosition(); err != nil {
		epanMu.Unlock()
		return nil, err
	}
	res, err := followStreamFromConf(q.Filter, proto)
	epanMu.Unlock()
	s.readPositionDirty.Store(true)
	if err != nil {
		return nil, err
	}

	s.cache.setFollowStream(q.Filter, proto, res)
	return res, nil
}

func (s *Session) TotalFrames() int {
	s.mu.RLock()
	fc := s.frameCount
	s.mu.RUnlock()
	return fc
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

func (s *Session) Frames(frameNums []int) ([]*FrameData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return nil, ErrSessionClosed
	}
	epanMu.Lock()
	if err := s.resetReadPosition(); err != nil {
		epanMu.Unlock()
		return nil, err
	}
	frames, err := framesByIndicesFromConf(s.conf, frameNums, s.parseOpts()...)
	epanMu.Unlock()
	s.readPositionDirty.Store(true)
	return frames, err
}

func (s *Session) HexData(frameNum int) (*HexData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return nil, ErrSessionClosed
	}
	epanMu.Lock()
	defer epanMu.Unlock()
	if err := s.resetReadPosition(); err != nil {
		return nil, err
	}
	hd, err := hexDataByIndexFromActive(frameNum)
	if err != nil {
		return nil, err
	}
	s.readPositionDirty.Store(true)
	return hd, nil
}

func (s *Session) Streams(q Query) ([]StreamSummary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return nil, ErrSessionClosed
	}

	if v, ok := s.cache.getStreams(q.Filter); ok {
		return v, nil
	}

	acc := newTrafficAccumulator()
	if err := s.conversationsFastLocked(q, acc); err != nil {
		return nil, err
	}
	all := acc.streams()

	s.cache.setStreams(q.Filter, all)
	return all, nil
}

func (s *Session) Conversations(q Query) ([]ConversationSummary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return nil, ErrSessionClosed
	}
	acc := newTrafficAccumulator()
	if err := s.conversationsFastLocked(q, acc); err != nil {
		s.readPositionDirty.Store(true)
		return nil, err
	}
	return acc.conversations(), nil
}

func (s *Session) conversationsFastLocked(q Query, acc *trafficAccumulator) error {
	epanMu.Lock()
	defer epanMu.Unlock()
	if err := s.resetReadPosition(); err != nil {
		return err
	}
	var parseErr error
	globalFrameSink = func(jsonBytes []byte) bool {
		var row map[string]string
		if err := sonic.Unmarshal(jsonBytes, &row); err != nil {
			parseErr = err
			return false
		}
		acc.addRow(row)
		return true
	}
	defer cleanupGlobalState()
	fields := []string{"frame.len", "frame.time_epoch", "frame.protocols",
		"ip.src", "ip.dst",
		"tcp.srcport", "tcp.dstport", "tcp.stream",
		"udp.srcport", "udp.dstport", "udp.stream"}
	if err := sessionWalkFieldsFast(q.Filter, fields); err != nil {
		return err
	}
	s.readPositionDirty.Store(true)
	if parseErr != nil {
		return parseErr
	}
	return nil
}

type timelineRow struct {
	T  string `json:"t"`
	L  int    `json:"l"`
	S  string `json:"s,omitempty"`
	D  string `json:"d,omitempty"`
	TS int    `json:"ts,omitempty"`
	US int    `json:"us,omitempty"`
	P  string `json:"p,omitempty"`
}

func (s *Session) TimelineBy(q Query, bucket time.Duration) ([]TimelineBucket, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return nil, ErrSessionClosed
	}

	if bucket <= 0 {
		bucket = time.Minute
	}

	epanMu.Lock()
	if err := s.resetReadPosition(); err != nil {
		epanMu.Unlock()
		return nil, err
	}
	rawJSON, err := sessionGetTimelineJSON(q.Filter)
	epanMu.Unlock()
	s.readPositionDirty.Store(true)
	if err != nil {
		return nil, err
	}

	var rows []timelineRow
	if err := sonic.Unmarshal([]byte(rawJSON), &rows); err != nil {
		return nil, errors.Wrap(err, "parse timeline JSON")
	}

	buckets := map[int64]*TimelineBucket{}
	bucketSec := int64(bucket / time.Second)
	if bucketSec <= 0 {
		bucketSec = 1
	}

	for _, row := range rows {
		if row.T == "" || row.L <= 0 {
			continue
		}
		epoch, parseErr := strconv.ParseFloat(row.T, 64)
		if parseErr != nil {
			t, err := time.Parse(time.RFC3339Nano, row.T)
			if err != nil {
				continue
			}
			epoch = float64(t.UnixNano()) / 1e9
		}
		if epoch <= 0 {
			continue
		}
		sec := int64(epoch)
		start := sec - (sec % bucketSec)

		b := buckets[start]
		if b == nil {
			b = &TimelineBucket{StartEpoch: start, EndEpoch: start + bucketSec, Protocols: map[string]int{}}
			buckets[start] = b
		}
		b.FrameCount++
		b.ByteCount += int64(row.L)

		for _, proto := range protocolList(row.P) {
			b.Protocols[proto]++
		}
	}

	out := make([]TimelineBucket, 0, len(buckets))
	for _, b := range buckets {
		out = append(out, *b)
	}
	slices.SortFunc(out, func(a, b TimelineBucket) int { return int(a.StartEpoch - b.StartEpoch) })
	return out, nil
}

func (s *Session) WriteFrames(q Query, w io.Writer) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.writeFramesLocked(q, w)
}

func (s *Session) writeFramesLocked(q Query, w io.Writer) (int, error) {
	if s.closed.Load() {
		return 0, ErrSessionClosed
	}
	epanMu.Lock()
	if err := s.resetReadPosition(); err != nil {
		epanMu.Unlock()
		return 0, err
	}
	count, err := writeFramesFromConf(s.conf, q.Filter, w)
	epanMu.Unlock()
	s.readPositionDirty.Store(true)
	return count, err
}

func (s *Session) WriteFramesPage(q Query, page, size int, w io.Writer) (int, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return 0, false, ErrSessionClosed
	}
	epanMu.Lock()
	if err := s.resetReadPosition(); err != nil {
		epanMu.Unlock()
		return 0, false, err
	}
	count, hasMore, err := writeFramesPageFromConf(s.conf, q.Filter, page, size, w)
	epanMu.Unlock()
	s.readPositionDirty.Store(true)
	return count, hasMore, err
}

func (s *Session) TapConversations(convType string, q Query) ([]TapConversation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tapConversationsLocked(convType, q)
}

func (s *Session) tapConversationsLocked(convType string, q Query) ([]TapConversation, error) {
	if s.closed.Load() {
		return nil, ErrSessionClosed
	}
	epanMu.Lock()
	if err := s.resetReadPosition(); err != nil {
		epanMu.Unlock()
		return nil, err
	}
	res, err := tapConversationsFromActive(convType, q.Filter)
	epanMu.Unlock()
	s.readPositionDirty.Store(true)
	return res, err
}

func (s *Session) TapEndpoints(endpointType string, q Query) ([]TapEndpoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return nil, ErrSessionClosed
	}
	epanMu.Lock()
	if err := s.resetReadPosition(); err != nil {
		epanMu.Unlock()
		return nil, err
	}
	res, err := tapEndpointsFromActive(endpointType, q.Filter)
	epanMu.Unlock()
	s.readPositionDirty.Store(true)
	return res, err
}

func (s *Session) ExportObjects(protocol string, q Query) ([]ExportObject, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.exportObjectsLocked(protocol, q)
}

func (s *Session) exportObjectsLocked(protocol string, q Query) ([]ExportObject, error) {
	if s.closed.Load() {
		return nil, ErrSessionClosed
	}
	epanMu.Lock()
	if err := s.resetReadPosition(); err != nil {
		epanMu.Unlock()
		return nil, err
	}
	res, err := exportObjectsFromActive(protocol, q.Filter)
	epanMu.Unlock()
	s.readPositionDirty.Store(true)
	return res, err
}

func (s *Session) WriteExportObject(protocol string, packetNum int, w io.Writer, q Query) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.writeExportObjectLocked(protocol, packetNum, w, q)
}

func (s *Session) writeExportObjectLocked(protocol string, packetNum int, w io.Writer, q Query) error {
	if s.closed.Load() {
		return ErrSessionClosed
	}
	epanMu.Lock()
	if err := s.resetReadPosition(); err != nil {
		epanMu.Unlock()
		return err
	}
	err := writeExportObjectFromActive(protocol, packetNum, q.Filter, w)
	epanMu.Unlock()
	s.readPositionDirty.Store(true)
	return err
}

func (s *Session) WriteExportObjects(protocol string, dir string, q Query) ([]ExportObject, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return nil, ErrSessionClosed
	}

	objs, err := s.exportObjectsLocked(protocol, q)
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
		wErr := s.writeExportObjectLocked(protocol, obj.PacketNum, f, q)
		f.Close()
		if wErr != nil {
			os.Remove(fullPath)
			return out, wErr
		}
		out = append(out, obj)
	}
	return out, nil
}

func (s *Session) ServiceResponseTimes(protocol string, q Query) ([]SRTSummary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return nil, ErrSessionClosed
	}
	epanMu.Lock()
	if err := s.resetReadPosition(); err != nil {
		epanMu.Unlock()
		return nil, err
	}
	res, err := serviceResponseTimesFromActive(protocol, q.Filter)
	epanMu.Unlock()
	s.readPositionDirty.Store(true)
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

func (s *Session) ProtocolHierarchy(q Query) ([]ProtocolHierarchyEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return nil, ErrSessionClosed
	}
	epanMu.Lock()
	if err := s.resetReadPosition(); err != nil {
		epanMu.Unlock()
		return nil, err
	}
	res, err := protocolHierarchyFromActive(q.Filter)
	epanMu.Unlock()
	s.readPositionDirty.Store(true)
	return res, err
}

func (s *Session) IOStats(q Query, interval time.Duration) ([]IOStatBucket, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return nil, ErrSessionClosed
	}
	epanMu.Lock()
	if err := s.resetReadPosition(); err != nil {
		epanMu.Unlock()
		return nil, err
	}
	res, err := ioStatsFromActive(q.Filter, interval.Seconds())
	epanMu.Unlock()
	s.readPositionDirty.Store(true)
	return res, err
}

func (s *Session) WriteDissection(w io.Writer, format OutputFormat, q Query, opts ...Option) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return 0, ErrSessionClosed
	}
	return s.writeDissection(w, format, q, opts...)
}

func (s *Session) resolveSelector(selector FrameSelector) ([]int, error) {
	set := map[int]bool{}
	for _, idx := range selector.Indices {
		if idx < 1 {
			return nil, errors.Wrapf(ErrInvalidFrameNumber, "%d", idx)
		}
		set[idx] = true
	}
	if selector.Range.Start != 0 || selector.Range.End != 0 {
		if selector.Range.Start < 1 || selector.Range.End < selector.Range.Start {
			return nil, errors.Wrapf(ErrInvalidFrameNumber, "range %d-%d", selector.Range.Start, selector.Range.End)
		}
		for i := selector.Range.Start; i <= selector.Range.End; i++ {
			set[i] = true
		}
	}
	if selector.Filter != "" {
		if err := ValidateFilter(selector.Filter); err != nil {
			return nil, err
		}
		numbers, err := s.frameNumbersLocked(Query{Filter: selector.Filter})
		if err != nil {
			return nil, err
		}
		for _, n := range numbers {
			set[n] = true
		}
	}
	if len(set) == 0 {
		return nil, ErrEmptySelection
	}
	out := make([]int, 0, len(set))
	for idx := range set {
		out = append(out, idx)
	}
	slices.Sort(out)
	return out, nil
}

func (s *Session) WritePcapSlice(w io.Writer, selector FrameSelector) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return 0, ErrSessionClosed
	}
	indices, err := s.resolveSelector(selector)
	if err != nil {
		return 0, err
	}
	return writePcapSliceByIndices(s.path, w, indices)
}

func (s *Session) WritePcapSliceWithOptions(w io.Writer, selector FrameSelector, sliceOpts PcapSliceOptions) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return 0, ErrSessionClosed
	}
	if !validPcapSliceOutputFormat(sliceOpts.OutputFormat) {
		return 0, &OutputFormatError{Format: string(sliceOpts.OutputFormat), Message: "pcap slice output format"}
	}
	indices, err := s.resolveSelector(selector)
	if err != nil {
		return 0, err
	}
	return writePcapSliceByIndicesWithOptions(s.path, w, indices, sliceOpts)
}
