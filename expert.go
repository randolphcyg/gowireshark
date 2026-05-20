package gowireshark

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
	epanMu.Lock()
	defer epanMu.Unlock()

	conf, err := initCapFile(path, opts...)
	if err != nil {
		return nil, err
	}
	if conf.DisplayFilter != "" {
		if err := ValidateFilter(conf.DisplayFilter); err != nil {
			return nil, err
		}
	}
	return expertInfosFromActive(conf.DisplayFilter)
}

// ExpertInfos returns Expert Info records for frames matched by q.
// Results are cached by query filter.
func (s *Session) ExpertInfos(q Query) ([]ExpertInfo, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
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

	if err := sessionResetReadPosition(); err != nil {
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
