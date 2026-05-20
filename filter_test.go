package gowireshark

import (
	"strings"
	"testing"
)

func TestValidateDisplayFilterDetailed_Valid(t *testing.T) {
	result, err := ValidateDisplayFilterDetailed("tcp.stream == 1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Valid {
		t.Fatalf("expected valid filter, got error: %s", result.Error)
	}
}

func TestValidateDisplayFilterDetailed_Invalid(t *testing.T) {
	result, err := ValidateDisplayFilterDetailed("tcp.stream ==")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Valid {
		t.Fatal("expected invalid filter")
	}
	if result.Error == "" {
		t.Fatal("expected error message for invalid filter")
	}
	t.Logf("filter error: %s", result.Error)
}

func TestValidateDisplayFilterDetailed_Empty(t *testing.T) {
	result, err := ValidateDisplayFilterDetailed("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Valid {
		t.Fatal("empty filter should be valid")
	}
}

func TestValidateDisplayFilterDetailed_Complex(t *testing.T) {
	result, err := ValidateDisplayFilterDetailed("ip.src == 192.168.1.1 && tcp.port == 80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Valid {
		t.Fatalf("expected valid complex filter, got error: %s", result.Error)
	}
}

func TestValidateDisplayFilterDetailed_NonExistentField(t *testing.T) {
	result, err := ValidateDisplayFilterDetailed("bogus.dne.field == 42")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Valid {
		t.Fatal("expected invalid filter for non-existent field")
	}
	t.Logf("filter error: %s", result.Error)
}

func TestSuggestFields_IPPrefix(t *testing.T) {
	fields, err := SuggestFields("ip.", 20)
	if err != nil {
		t.Fatalf("SuggestFields: %v", err)
	}
	if len(fields) == 0 {
		t.Fatal("expected at least one field with prefix 'ip.'")
	}
	if len(fields) > 20 {
		t.Fatalf("expected at most 20 fields, got %d", len(fields))
	}

	for _, f := range fields {
		if !strings.HasPrefix(strings.ToLower(f.Abbrev), "ip.") {
			t.Fatalf("field abbrev %q does not start with 'ip.'", f.Abbrev)
		}
	}
	t.Logf("found %d fields with ip. prefix", len(fields))
}

func TestSuggestFields_NoMatch(t *testing.T) {
	fields, err := SuggestFields("zzz.no.such.field.prefix", 10)
	if err != nil {
		t.Fatalf("SuggestFields: %v", err)
	}
	if len(fields) != 0 {
		t.Fatalf("expected 0 fields for non-existent prefix, got %d", len(fields))
	}
}

func TestSuggestFields_Limit(t *testing.T) {
	fields5, err := SuggestFields("frame.", 5)
	if err != nil {
		t.Fatalf("SuggestFields: %v", err)
	}
	if len(fields5) > 5 {
		t.Fatalf("limit=5 returned %d fields", len(fields5))
	}

	fieldsUnlimited, err := SuggestFields("frame.", 0)
	if err != nil {
		t.Fatalf("SuggestFields: %v", err)
	}
	if len(fieldsUnlimited) < len(fields5) {
		t.Fatalf("unlimited results (%d) should be >= limited results (%d)",
			len(fieldsUnlimited), len(fields5))
	}
}

func TestSuggestFields_CaseInsensitive(t *testing.T) {
	lower, err := SuggestFields("tcp.stream", 1)
	if err != nil {
		t.Fatalf("SuggestFields lowercase: %v", err)
	}
	upper, err := SuggestFields("TCP.STREAM", 1)
	if err != nil {
		t.Fatalf("SuggestFields uppercase: %v", err)
	}
	if len(lower) != len(upper) {
		t.Fatalf("case should not matter: lower=%d upper=%d", len(lower), len(upper))
	}
	if len(lower) > 0 && lower[0].Name != upper[0].Name {
		t.Fatalf("case-insensitive returned different results: %q vs %q",
			lower[0].Name, upper[0].Name)
	}
}