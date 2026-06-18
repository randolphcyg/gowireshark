package gowireshark

/*
#include "bridge.h"
#include "offline.h"
*/
import "C"

import (
	"strconv"
	"strings"
	"unsafe"
)

// ValidateFilter validates a Wireshark display filter string. Returns nil if
// the filter is valid or empty, or a *DisplayFilterError describing the
// syntax error otherwise.
func ValidateFilter(filter string) error {
	if filter == "" {
		return nil
	}
	cFilter := C.CString(filter)
	defer C.free(unsafe.Pointer(cFilter))
	cErrMsg := C.validate_filter(cFilter)
	if cErrMsg != nil {
		defer C.free_c_string(cErrMsg)
		return &DisplayFilterError{Filter: filter, Message: cString(cErrMsg)}
	}
	return nil
}

// FilterValidationResult contains detailed display filter validation info.
type FilterValidationResult struct {
	Valid  bool     `json:"valid"`
	Error  string   `json:"error,omitempty"`
	Fields []string `json:"fields,omitempty"`
}

func extractFilterFields(filter string) []string {
	seen := map[string]bool{}
	var fields []string

	start := -1
	for i := 0; i < len(filter); i++ {
		c := filter[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '.' {
			if start < 0 {
				start = i
			}
		} else {
			if start >= 0 {
				tok := filter[start:i]
				start = -1
				if isValidFilterFieldToken(tok) && !seen[tok] {
					seen[tok] = true
					fields = append(fields, tok)
				}
			}
		}
	}
	if start >= 0 {
		tok := filter[start:]
		if isValidFilterFieldToken(tok) && !seen[tok] {
			fields = append(fields, tok)
		}
	}
	return fields
}

func isValidFilterFieldToken(tok string) bool {
	if len(tok) == 0 || tok[0] == '.' || tok[len(tok)-1] == '.' {
		return false
	}
	if !strings.ContainsRune(tok, '.') {
		return false
	}
	if looksLikeIPv4(tok) {
		return false
	}
	if ValidateField(tok) != nil {
		return false
	}
	return true
}

func looksLikeIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

// ValidateDisplayFilterDetailed validates a display filter and returns structured feedback.
func ValidateDisplayFilterDetailed(filter string) (*FilterValidationResult, error) {
	if filter == "" {
		return &FilterValidationResult{Valid: true}, nil
	}

	fields := extractFilterFields(filter)

	cFilter := C.CString(filter)
	defer C.free(unsafe.Pointer(cFilter))

	cErrMsg := C.validate_filter(cFilter)
	if cErrMsg != nil {
		defer C.free_c_string(cErrMsg)
		return &FilterValidationResult{
			Valid:  false,
			Error:  cString(cErrMsg),
			Fields: fields,
		}, nil
	}
	return &FilterValidationResult{Valid: true, Fields: fields}, nil
}

// extractFilter returns the DisplayFilter configured via WithDisplayFilter,
// or "" when none was set.
func extractFilter(opts []Option) string {
	return newConfig(opts...).DisplayFilter
}
