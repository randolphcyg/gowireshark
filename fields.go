package gowireshark

import (
	"context"

	"github.com/bytedance/sonic"
	"github.com/pkg/errors"
)

type FieldRow map[string]string

type FieldOccurrence string

const (
	OccurrenceFirst FieldOccurrence = "first"
	OccurrenceLast  FieldOccurrence = "last"
	OccurrenceAll   FieldOccurrence = "all"
)

type FieldRowValues struct {
	FrameNumber int
	Values      map[string][]string
}

func normalizeScalarFieldOccurrence(occurrence FieldOccurrence) (FieldOccurrence, error) {
	switch occurrence {
	case "", OccurrenceFirst:
		return OccurrenceFirst, nil
	case OccurrenceLast:
		return OccurrenceLast, nil
	case OccurrenceAll:
		return "", errors.Wrap(ErrUnsupportedFieldOccurrence, "OccurrenceAll requires FieldsRowsValues")
	default:
		return "", errors.Wrapf(ErrUnsupportedFieldOccurrence, "unknown field occurrence %q", occurrence)
	}
}

func FieldsRows(path string, fields []string, opts ...Option) ([]FieldRow, error) {
	return FieldsRowsContext(context.Background(), path, fields, opts...)
}

func FieldsRowsValues(path string, fields []string, opts ...Option) ([]FieldRowValues, error) {
	return FieldsRowsValuesContext(context.Background(), path, fields, opts...)
}

func FieldsRowsValuesContext(ctx context.Context, path string, fields []string, opts ...Option) ([]FieldRowValues, error) {
	s, err := OpenSessionContext(ctx, path, opts...)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return s.FieldsRowsValues(Query{Filter: extractFilter(opts)}, fields)
}

func (s *Session) FieldsRows(q Query, fields []string, opts ...Option) ([]FieldRow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return nil, ErrSessionClosed
	}
	conf := newConfig(opts...)
	occurrence, err := normalizeScalarFieldOccurrence(conf.FieldOccurrence)
	if err != nil {
		return nil, errors.Wrap(err, "FieldsRows")
	}

	if err := ValidateFilter(q.Filter); err != nil {
		return nil, err
	}

	epanMu.Lock()
	defer epanMu.Unlock()

	if err := s.resetReadPosition(); err != nil {
		return nil, err
	}

	occ := 0
	if occurrence == OccurrenceLast {
		occ = 1
	}

	rows, err := fieldsRowsOccurrenceFast(q.Filter, fields, occ)
	if err != nil {
		return nil, err
	}
	s.readPositionDirty.Store(true)
	return rows, nil
}

func fieldsRowsOccurrenceFast(filter string, fields []string, occurrence int) ([]FieldRow, error) {
	var rows []FieldRow
	var parseErr error

	globalFrameSink = func(jsonBytes []byte) bool {
		var row map[string]string
		if err := sonic.Unmarshal(jsonBytes, &row); err != nil {
			parseErr = err
			return false
		}
		rows = append(rows, row)
		return true
	}
	defer cleanupGlobalState()

	if err := sessionWalkFieldsOccurrence(filter, fields, occurrence); err != nil {
		return nil, err
	}
	if parseErr != nil {
		return nil, parseErr
	}
	return rows, nil
}

func (s *Session) FieldsRowsValues(q Query, fields []string) ([]FieldRowValues, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return nil, ErrSessionClosed
	}

	if err := ValidateFilter(q.Filter); err != nil {
		return nil, err
	}

	epanMu.Lock()
	defer epanMu.Unlock()

	if err := s.resetReadPosition(); err != nil {
		return nil, err
	}

	rows, err := fieldsRowsAllFast(q.Filter, fields)
	if err != nil {
		return nil, err
	}
	s.readPositionDirty.Store(true)
	return rows, nil
}

func fieldsRowsAllFast(filter string, fields []string) ([]FieldRowValues, error) {
	var rows []FieldRowValues
	var parseErr error

	globalFrameSink = func(jsonBytes []byte) bool {
		var rawWithNum struct {
			FrameNumber int            `json:"_frame"`
			Values      map[string]any `json:"_values"`
		}
		if err := sonic.Unmarshal(jsonBytes, &rawWithNum); err != nil {
			parseErr = err
			return false
		}
		row := FieldRowValues{
			FrameNumber: rawWithNum.FrameNumber,
			Values:      make(map[string][]string, len(rawWithNum.Values)),
		}
		for field, val := range rawWithNum.Values {
			switch v := val.(type) {
			case []any:
				strs := make([]string, len(v))
				for i, item := range v {
					strs[i] = formatFieldValue(item)
				}
				row.Values[field] = strs
			case string:
				row.Values[field] = []string{v}
			default:
				row.Values[field] = []string{formatFieldValue(val)}
			}
		}
		rows = append(rows, row)
		return true
	}
	defer cleanupGlobalState()

	if err := sessionWalkFieldsOccurrence(filter, fields, 2); err != nil {
		return nil, err
	}
	if parseErr != nil {
		return nil, parseErr
	}
	return rows, nil
}
