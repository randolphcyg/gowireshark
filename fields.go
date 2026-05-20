package gowireshark

type FieldRow map[string]string

// FieldsRows returns only the requested fields for every frame in the capture.
//
// Each FieldRow is a map from field name (e.g. "ip.src", "tcp.stream") to string
// value. This avoids the overhead of constructing FrameData and BaseLayers but
// still generates a complete frame JSON per frame in C before Go-side field
// extraction. The field extraction is semantically correct but not equivalent to
// tshark's native -T fields fast path.
func FieldsRows(path string, fields []string, opts ...Option) ([]FieldRow, error) {
	s, err := OpenSession(path, opts...)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	return s.FieldsRows(Query{Filter: extractFilter(opts)}, fields)
}

func (s *Session) FieldsRows(q Query, fields []string) ([]FieldRow, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
	}

	epanMu.Lock()
	defer epanMu.Unlock()

	if err := sessionResetReadPosition(); err != nil {
		return nil, err
	}

	var rows []FieldRow
	var walkErr error

	globalFrameSink = func(jsonBytes []byte) bool {
		selected, err := selectOutputFields(jsonBytes, fields)
		if err != nil {
			walkErr = err
			return false
		}
		row := make(FieldRow, len(selected))
		for k, v := range selected {
			row[k] = formatFieldValue(v)
		}
		rows = append(rows, row)
		return true
	}
	defer func() { globalFrameSink = nil }()

	if err := sessionWalkAllFramesJSON(q.Filter); err != nil {
		return nil, err
	}
	if walkErr != nil {
		return nil, walkErr
	}
	return rows, nil
}