package gowireshark

import "sync"

// cacheKey identifies one cached page of frames.
type cacheKey struct {
	filter string
	page   int
	size   int
}

// sessionCache holds optional in-memory caches for one Session to avoid
// re-dissecting the same capture for repeated queries.
type sessionCache struct {
	mu           sync.RWMutex
	opts         SessionCacheOptions
	counts       map[string]int
	numbers      map[string][]int
	frameIndexes map[string]*FrameIndex
	pages        map[cacheKey]*pageCacheEntry
	pageOrder    []cacheKey
	streams      map[string][]StreamSummary
	experts      map[string][]ExpertInfo
	follows      map[followCacheKey]*FollowResult
}

type pageCacheEntry struct {
	frames  []*FrameData
	hasMore bool
}

type followCacheKey struct {
	filter string
	proto  string
}

func newSessionCache(opts SessionCacheOptions) *sessionCache {
	return &sessionCache{
		opts:         opts,
		counts:       make(map[string]int),
		numbers:      make(map[string][]int),
		frameIndexes: make(map[string]*FrameIndex),
		pages:        make(map[cacheKey]*pageCacheEntry),
		streams:      make(map[string][]StreamSummary),
		experts:      make(map[string][]ExpertInfo),
		follows:      make(map[followCacheKey]*FollowResult),
	}
}

func (c *sessionCache) getCount(filter string) (int, bool) {
	if c.opts.Disable {
		return 0, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.counts[filter]
	return v, ok
}

func (c *sessionCache) setCount(filter string, count int) {
	if c.opts.Disable {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counts[filter] = count
}

func (c *sessionCache) getNumbers(filter string) ([]int, bool) {
	if c.opts.Disable {
		return nil, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.numbers[filter]
	if !ok {
		return nil, false
	}
	cp := make([]int, len(v))
	copy(cp, v)
	return cp, true
}

func (c *sessionCache) setNumbers(filter string, numbers []int) {
	if c.opts.Disable {
		return
	}
	cp := make([]int, len(numbers))
	copy(cp, numbers)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.numbers[filter] = cp
}

func (c *sessionCache) getFrameIndex(filter string) (*FrameIndex, bool) {
	if c.opts.Disable {
		return nil, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	idx, ok := c.frameIndexes[filter]
	if !ok {
		return nil, false
	}
	cp := make([]int, len(idx.FrameNumbers))
	copy(cp, idx.FrameNumbers)
	return &FrameIndex{
		FrameNumbers: cp,
		Filter:       idx.Filter,
		TotalFrames:  idx.TotalFrames,
	}, true
}

func (c *sessionCache) setFrameIndex(filter string, idx *FrameIndex) {
	if c.opts.Disable {
		return
	}
	cp := make([]int, len(idx.FrameNumbers))
	copy(cp, idx.FrameNumbers)
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.frameIndexes) >= c.opts.MaxIndexCount && c.opts.MaxIndexCount > 0 {
		for k := range c.frameIndexes {
			delete(c.frameIndexes, k)
			break
		}
	}
	c.frameIndexes[filter] = &FrameIndex{
		FrameNumbers: cp,
		Filter:       idx.Filter,
		TotalFrames:  idx.TotalFrames,
	}
}

func (c *sessionCache) getPage(filter string, page, size int) (*pageCacheEntry, bool) {
	if c.opts.Disable {
		return nil, false
	}
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
	if c.opts.Disable {
		return
	}
	cp := make([]*FrameData, len(frames))
	copy(cp, frames)
	c.mu.Lock()
	defer c.mu.Unlock()
	key := cacheKey{filter, page, size}
	_, exists := c.pages[key]
	c.pages[key] = &pageCacheEntry{frames: cp, hasMore: hasMore}
	if !exists {
		c.pageOrder = append(c.pageOrder, key)
		if c.opts.MaxPages > 0 && len(c.pageOrder) > c.opts.MaxPages {
			evict := c.pageOrder[0]
			c.pageOrder = c.pageOrder[1:]
			delete(c.pages, evict)
		}
	}
}

func (c *sessionCache) getStreams(filter string) ([]StreamSummary, bool) {
	if c.opts.Disable {
		return nil, false
	}
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
	if c.opts.Disable {
		return
	}
	cp := make([]StreamSummary, len(streams))
	copy(cp, streams)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.streams[filter] = cp
}

func (c *sessionCache) getExpertInfos(filter string) ([]ExpertInfo, bool) {
	if c.opts.Disable {
		return nil, false
	}
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
	if c.opts.Disable {
		return
	}
	cp := make([]ExpertInfo, len(infos))
	copy(cp, infos)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.experts[filter] = cp
}

func (c *sessionCache) getFollowStream(filter, proto string) (*FollowResult, bool) {
	if c.opts.Disable {
		return nil, false
	}
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
	if c.opts.Disable {
		return
	}
	if c.opts.MaxFollowBytes > 0 {
		totalBytes := r.ClientBytes + r.ServerBytes
		if int64(totalBytes) > c.opts.MaxFollowBytes {
			return
		}
	}
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
	c.numbers = make(map[string][]int)
	c.frameIndexes = make(map[string]*FrameIndex)
	c.pages = make(map[cacheKey]*pageCacheEntry)
	c.pageOrder = nil
	c.streams = make(map[string][]StreamSummary)
	c.experts = make(map[string][]ExpertInfo)
	c.follows = make(map[followCacheKey]*FollowResult)
}
