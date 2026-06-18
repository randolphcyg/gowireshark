package gowireshark

// FrameIndex is STABLE.
type FrameIndex struct {
	FrameNumbers []int
	Filter       string
	TotalFrames  int
}

func (s *Session) FrameIndex(q Query) (*FrameIndex, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return nil, ErrSessionClosed
	}

	if v, ok := s.cache.getFrameIndex(q.Filter); ok {
		return v, nil
	}

	idx, err := s.buildFrameIndexLocked(q)
	if err != nil {
		return nil, err
	}
	return idx, nil
}

func (s *Session) BuildFrameIndex(q Query) (*FrameIndex, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.buildFrameIndexLocked(q)
}

func (s *Session) buildFrameIndexLocked(q Query) (*FrameIndex, error) {
	if s.closed.Load() {
		return nil, ErrSessionClosed
	}

	if q.Filter != "" {
		if err := ValidateFilter(q.Filter); err != nil {
			return nil, err
		}
	}

	numbers, err := s.frameNumbersLocked(q)
	if err != nil {
		return nil, err
	}

	idx := &FrameIndex{
		FrameNumbers: numbers,
		Filter:       q.Filter,
		TotalFrames:  s.frameCount,
	}
	s.cache.setFrameIndex(q.Filter, idx)
	return idx, nil
}

func (s *Session) Frame(num int) (*FrameData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return nil, ErrSessionClosed
	}
	if num < 1 || num > s.frameCount {
		return nil, ErrInvalidFrameNumber
	}
	epanMu.Lock()
	defer epanMu.Unlock()
	if err := s.resetReadPosition(); err != nil {
		return nil, err
	}
	fd, err := frameByIndexFromActiveConf(s.conf, num, s.parseOpts()...)
	if err != nil {
		return nil, err
	}
	s.readPositionDirty.Store(true)
	return fd, nil
}
