package gowireshark

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/bytedance/sonic"
	"github.com/pkg/errors"
)

// OutputFormat is STABLE.
// OutputFormat controls how frame dissection is rendered.
type OutputFormat string

const (
	// PDML, PSML, and Text use the SDK renderer — they are not byte-for-byte tshark equivalents.
	//
	// OutputPDML is the most expensive format: it walks every frame through the
	// full FrameData materialisation path before rendering. For large captures
	// prefer WriteFrames / WriteFramesJSONL or IterFrameJSON instead.
	OutputJSON    OutputFormat = "json"
	OutputJSONRaw OutputFormat = "jsonraw"
	OutputFields  OutputFormat = "fields"
	OutputPDML    OutputFormat = "pdml"
	OutputPSML    OutputFormat = "psml"
	OutputText    OutputFormat = "text"
)

// FieldOutputOptions is STABLE.
// FieldOutputOptions controls field-level output (tshark -e / -E flags).
type FieldOutputOptions struct {
	Fields     []string
	Separator  string
	Header     bool
	Quote      bool
	Occurrence FieldOccurrence
}

// WriteDissection writes frame dissections from path to w in the requested
// output format, applying field options when format is OutputFields.
//
// OutputFields mode uses a C-level field-only fast path that extracts only
// the requested fields without generating the full frame JSON proto tree.
// For programmatic field extraction use FieldsRows.
func WriteDissection(path string, w io.Writer, format OutputFormat, opts ...Option) (int, error) {
	return WriteDissectionContext(context.Background(), path, w, format, opts...)
}

func (s *Session) writeDissection(w io.Writer, format OutputFormat, q Query, opts ...Option) (int, error) {
	conf := newConfig(opts...)

	switch format {
	case OutputJSON, OutputJSONRaw:
		return s.writeNDJSON(w, q)
	case OutputFields:
		return s.writeFields(w, q, conf)
	case OutputText:
		return s.writeText(w, q)
	case OutputPDML:
		return s.writePDML(w, q)
	case OutputPSML:
		return s.writePSML(w, q)
	default:
		return 0, &OutputFormatError{Format: string(format), Message: "unknown dissection output format"}
	}
}

func (s *Session) writeNDJSON(w io.Writer, q Query) (int, error) {
	count, err := s.writeFramesLocked(q, w)
	if err != nil {
		return count, err
	}
	return count, nil
}

func (s *Session) writeFields(w io.Writer, q Query, conf *config) (int, error) {
	fo := conf.FieldOutput
	if len(fo.Fields) == 0 {
		return 0, errors.Wrap(ErrInvalidField, "field output requires at least one field in FieldOutputOptions.Fields")
	}

	if err := ValidateFilter(q.Filter); err != nil {
		return 0, err
	}

	sep := fo.Separator
	if sep == "" {
		sep = "\t"
	}

	if fo.Header {
		if _, err := w.Write([]byte(strings.Join(fo.Fields, sep) + "\n")); err != nil {
			return 0, err
		}
	}

	epanMu.Lock()
	if err := s.resetReadPosition(); err != nil {
		epanMu.Unlock()
		return 0, err
	}

	count, writeErr := writeFieldsFast(q.Filter, fo, sep, w)
	epanMu.Unlock()
	s.readPositionDirty.Store(true)

	if writeErr != nil {
		return count, writeErr
	}
	return count, nil
}

func writeFieldsFast(filter string, fo FieldOutputOptions, sep string, w io.Writer) (int, error) {
	occurrence, err := normalizeScalarFieldOccurrence(fo.Occurrence)
	if err != nil {
		return 0, errors.Wrap(err, "OutputFields")
	}

	count := 0
	var writeErr error

	occ := 0
	if occurrence == OccurrenceLast {
		occ = 1
	}

	globalFrameSink = func(jsonBytes []byte) bool {
		var row map[string]string
		if uErr := sonic.Unmarshal(jsonBytes, &row); uErr != nil {
			writeErr = uErr
			return false
		}
		parts := make([]string, len(fo.Fields))
		for i, field := range fo.Fields {
			if val, ok := row[field]; ok {
				if fo.Quote {
					val = strconv.Quote(val)
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
	defer cleanupGlobalState()

	if err := sessionWalkFieldsOccurrence(filter, fo.Fields, occ); err != nil {
		return count, err
	}
	return count, writeErr
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

// WithFieldOutput sets field-level output options for use with WriteDissection
// in OutputFields mode.
func WithFieldOutput(fo FieldOutputOptions) Option {
	return func(c *config) {
		c.FieldOutput = fo
	}
}
