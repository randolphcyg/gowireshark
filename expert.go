package gowireshark

import "context"

type ExpertInfo struct {
	FrameNumber int    `json:"frameNumber"`
	Severity    string `json:"severity,omitempty"`
	Group       string `json:"group,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	Summary     string `json:"summary,omitempty"`
	Field       string `json:"field,omitempty"`
	Name        string `json:"name,omitempty"`
	Message     string `json:"message,omitempty"`
}

// ExpertInfos returns Expert Info records for frames matched by opts.
func ExpertInfos(path string, opts ...Option) ([]ExpertInfo, error) {
	return ExpertInfosContext(context.Background(), path, opts...)
}

// ExpertInfosContext returns Expert Info records using the provided context for
// session acquisition.
func ExpertInfosContext(ctx context.Context, path string, opts ...Option) ([]ExpertInfo, error) {
	s, err := OpenSessionContext(ctx, path, opts...)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return s.ExpertInfos(Query{Filter: extractFilter(opts)})
}

// ExpertInfos returns Expert Info records for frames matched by q.
// Results are cached by query filter.
func (s *Session) ExpertInfos(q Query) ([]ExpertInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return nil, ErrSessionClosed
	}
	if q.Filter != "" {
		if err := ValidateFilter(q.Filter); err != nil {
			return nil, err
		}
	}

	if v, ok := s.cache.getExpertInfos(q.Filter); ok {
		return v, nil
	}

	epanMu.Lock()
	defer epanMu.Unlock()

	if err := s.resetReadPosition(); err != nil {
		return nil, err
	}
	infos, err := expertInfosFromActive(q.Filter)
	if err != nil {
		return nil, err
	}

	s.cache.setExpertInfos(q.Filter, infos)
	return infos, nil
}

func expertInfosFromActive(filter string) ([]ExpertInfo, error) {
	return getExpertInfosBatch(filter)
}
