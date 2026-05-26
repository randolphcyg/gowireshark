package gowireshark

import (
	stderrors "errors"
	"testing"
)

func TestStructuredErrorsSupportIsAndAs(t *testing.T) {
	errs := []struct {
		name   string
		err    error
		target error
		as     any
	}{
		{
			name:   "display filter",
			err:    &DisplayFilterError{Filter: "frame.number ==", Message: "syntax error"},
			target: ErrInvalidDisplayFilter,
			as:     new(*DisplayFilterError),
		},
		{
			name:   "field",
			err:    &FieldError{Field: "not.real", Message: "unknown field"},
			target: ErrInvalidField,
			as:     new(*FieldError),
		},
		{
			name:   "field occurrence",
			err:    ErrUnsupportedFieldOccurrence,
			target: ErrUnsupportedFieldOccurrence,
			as:     nil,
		},
		{
			name:   "decode as",
			err:    &DecodeAsError{Table: "not.real", Message: "table not registered"},
			target: ErrDecodeAsUnsupported,
			as:     new(*DecodeAsError),
		},
		{
			name:   "output format",
			err:    &OutputFormatError{Format: "bogus", Message: "unknown"},
			target: ErrUnsupportedOutputFormat,
			as:     new(*OutputFormatError),
		},
		{
			name:   "wiretap",
			err:    &WiretapError{Operation: "pcap slice", Code: -1, Err: ErrReadCaptureFile},
			target: ErrReadCaptureFile,
			as:     new(*WiretapError),
		},
	}

	for _, tc := range errs {
		t.Run(tc.name, func(t *testing.T) {
			if !stderrors.Is(tc.err, tc.target) {
				t.Fatalf("errors.Is(%v, %v) = false", tc.err, tc.target)
			}
			if tc.as != nil && !stderrors.As(tc.err, tc.as) {
				t.Fatalf("errors.As(%T) = false", tc.as)
			}
		})
	}
}
