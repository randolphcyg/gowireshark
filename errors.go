package gowireshark

import (
	"fmt"

	"github.com/pkg/errors"
)

var (
	ErrInvalidDisplayFilter       = errors.New("invalid display filter")
	ErrInvalidFrameNumber         = errors.New("invalid frame number")
	ErrUnsupportedProtocol        = errors.New("unsupported protocol")
	ErrEmptySelection             = errors.New("empty frame selection")
	ErrInvalidField               = errors.New("invalid field")
	ErrUnsupportedFieldOccurrence = errors.New("unsupported field occurrence")
	ErrInvalidPreference          = errors.New("invalid preference")
	ErrInvalidProfile             = errors.New("invalid profile")
	ErrDecodeAsUnsupported        = errors.New("decode-as operation not supported for the given table or selector")
	ErrUnsupportedOutputFormat    = errors.New("unsupported output format")
)

type DisplayFilterError struct {
	Filter  string
	Message string
}

func (e *DisplayFilterError) Error() string {
	return fmt.Sprintf("display filter %q is invalid: %s", e.Filter, e.Message)
}

func (e *DisplayFilterError) Is(target error) bool {
	return target == ErrInvalidDisplayFilter
}

type FieldError struct {
	Field   string
	Message string
}

func (e *FieldError) Error() string {
	return fmt.Sprintf("field %q is invalid: %s", e.Field, e.Message)
}

func (e *FieldError) Is(target error) bool {
	return target == ErrInvalidField
}

type DecodeAsError struct {
	Table    string
	Selector string
	Protocol string
	Message  string
}

func (e *DecodeAsError) Error() string {
	return fmt.Sprintf("decode-as %q -> %q on %q: %s", e.Selector, e.Protocol, e.Table, e.Message)
}

func (e *DecodeAsError) Is(target error) bool {
	return target == ErrDecodeAsUnsupported
}

type OutputFormatError struct {
	Format  string
	Message string
}

func (e *OutputFormatError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("output format %q is unsupported: %s", e.Format, e.Message)
	}
	return fmt.Sprintf("output format %q is unsupported", e.Format)
}

func (e *OutputFormatError) Is(target error) bool {
	return target == ErrUnsupportedOutputFormat
}

type WiretapError struct {
	Operation string
	Code      int
	Message   string
	Err       error
}

func (e *WiretapError) Error() string {
	operation := e.Operation
	if operation == "" {
		operation = "wiretap"
	}
	msg := e.Message
	if msg == "" && e.Err != nil {
		msg = e.Err.Error()
	}
	if e.Code != 0 {
		return fmt.Sprintf("%s failed with code %d: %s", operation, e.Code, msg)
	}
	return fmt.Sprintf("%s failed: %s", operation, msg)
}

func (e *WiretapError) Unwrap() error {
	return e.Err
}
