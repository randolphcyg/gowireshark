package gowireshark

import (
	"fmt"
	"io"
	"strings"

	"github.com/pkg/errors"
)

// TsharkOutputFormat maps to tshark -T flags.
type TsharkOutputFormat string

const (
	OutputJSON    TsharkOutputFormat = "json"
	OutputJSONRaw TsharkOutputFormat = "jsonraw"
	OutputFields  TsharkOutputFormat = "fields"
	OutputPDML    TsharkOutputFormat = "pdml"
	OutputPSML    TsharkOutputFormat = "psml"
	OutputText    TsharkOutputFormat = "text"
)

// FieldOutputOptions controls field-level output (tshark -e / -E flags).
type FieldOutputOptions struct {
	Fields     []string
	Separator  string
	Header     bool
	Quote      bool
	Occurrence string
}

// WriteDissection writes frame dissections from path to w in the requested
// output format, applying field options when format is OutputFields.
//
// OutputFields mode generates complete frame JSON per frame in C before
// Go-side field selection. This is not equivalent to tshark's native
// -T fields fast path. For programmatic field extraction use FieldsRows.
func WriteDissection(path string, w io.Writer, format TsharkOutputFormat, opts ...Option) (int, error) {
	s, err := OpenSession(path, opts...)
	if err != nil {
		return 0, err
	}
	defer s.Close()
	return s.writeDissection(w, format, Query{Filter: extractFilter(opts)}, opts...)
}

func (s *Session) writeDissection(w io.Writer, format TsharkOutputFormat, q Query, opts ...Option) (int, error) {
	conf := newConfig(opts...)

	switch format {
	case OutputJSON, OutputJSONRaw:
		return s.writeNDJSON(w, q)
	case OutputFields:
		return s.writeFields(w, q, conf)
	case OutputText:
		return s.writeText(w, q)
	case OutputPDML:
		return 0, errors.New("PDML output not yet implemented (requires C-level pdml writer)")
	case OutputPSML:
		return 0, errors.New("PSML output not yet implemented (requires C-level psml writer)")
	default:
		return 0, errors.Errorf("unknown output format: %q", format)
	}
}

func (s *Session) writeNDJSON(w io.Writer, q Query) (int, error) {
	count, err := s.WriteFrames(q, w)
	if err != nil {
		return count, err
	}
	return count, nil
}

func (s *Session) writeFields(w io.Writer, q Query, conf *config) (int, error) {
	fo := conf.FieldOutput
	if len(fo.Fields) == 0 {
		return 0, errors.New("field output requires at least one field in FieldOutputOptions.Fields")
	}

	sep := fo.Separator
	if sep == "" {
		sep = "\t"
	}

	count := 0
	if fo.Header {
		if _, err := w.Write([]byte(strings.Join(fo.Fields, sep) + "\n")); err != nil {
			return 0, err
		}
	}

	var writeErr error
	globalFrameSink = func(jsonBytes []byte) bool {
		selected, fErr := selectOutputFields(jsonBytes, fo.Fields)
		if fErr != nil {
			writeErr = fErr
			return false
		}
		parts := make([]string, len(fo.Fields))
		for i, field := range fo.Fields {
			if v, ok := selected[field]; ok {
				val := formatFieldValue(v)
				if fo.Quote {
					val = fmt.Sprintf("%q", val)[1 : len(val)-1]
				}
				parts[i] = val
			}
		}
		line := strings.Join(parts, sep) + "\n"
		if _, wErr := w.Write([]byte(line)); wErr != nil {
			writeErr = wErr
			return false
		}
		count++
		return true
	}
	defer func() { globalFrameSink = nil }()

	epanMu.Lock()
	if err := sessionResetReadPosition(); err != nil {
		epanMu.Unlock()
		return count, err
	}
	sessionWalkAllFramesJSON(q.Filter)
	epanMu.Unlock()

	if writeErr != nil {
		return count, writeErr
	}
	return count, nil
}

func formatFieldValue(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return fmt.Sprintf("%v", x)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", x)
	}
}

func (s *Session) writeText(w io.Writer, q Query) (int, error) {
	return 0, errors.New("text output not yet implemented (requires column-based formatting)")
}

// WithFieldOutput sets field-level output options for use with WriteDissection
// in OutputFields mode.
func WithFieldOutput(fo FieldOutputOptions) Option {
	return func(c *config) {
		c.FieldOutput = fo
	}
}