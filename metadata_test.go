package gowireshark

import (
	"context"
	stderrors "errors"
	"testing"
)

func TestFieldMetadata(t *testing.T) {
	if err := ValidateField("tcp.stream"); err != nil {
		t.Fatalf("ValidateField(tcp.stream): %v", err)
	}
	if err := ValidateField("definitely.not.a.real.field"); !stderrors.Is(err, ErrInvalidField) {
		t.Fatalf("ValidateField(invalid) error=%v, want ErrInvalidField", err)
	}

	field, err := FieldInfo("frame.number")
	if err != nil {
		t.Fatalf("FieldInfo(frame.number): %v", err)
	}
	if field.Abbrev != "frame.number" || field.Type == "" {
		t.Fatalf("unexpected field info: %#v", field)
	}

	fields, err := RuntimeFields(context.Background())
	if err != nil {
		t.Fatalf("Fields: %v", err)
	}
	for _, want := range []string{"frame.number", "ip.src", "tcp.stream"} {
		found := false
		for _, got := range fields {
			if got.Abbrev == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("Fields missing %s", want)
		}
	}
}

func TestProtocolsMetadata(t *testing.T) {
	protocols, err := RuntimeProtocols(context.Background())
	if err != nil {
		t.Fatalf("Protocols: %v", err)
	}
	for _, want := range []string{"frame", "tcp"} {
		found := false
		for _, got := range protocols {
			if got.FilterName == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("Protocols missing %s", want)
		}
	}
}

func TestRuntimeVersionCompat(t *testing.T) {
	v, err := RuntimeVersion(context.Background())
	if err != nil {
		t.Fatalf("RuntimeVersion: %v", err)
	}
	if v.Version == "" {
		t.Fatal("expected non-empty version string")
	}
	t.Logf("version: %s", v.Version)
}

func TestRuntimeVersion(t *testing.T) {
	v, err := RuntimeVersion(context.Background())
	if err != nil {
		t.Fatalf("RuntimeVersion: %v", err)
	}
	if v.Version == "" {
		t.Fatal("expected non-empty runtime version string")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := RuntimeVersion(ctx); err == nil {
		t.Fatal("expected canceled context error")
	}
}

func TestProfiles(t *testing.T) {
	profiles, err := RuntimeProfiles(context.Background())
	if err != nil {
		t.Fatalf("Profiles: %v", err)
	}
	t.Logf("found %d profiles", len(profiles))
	for _, p := range profiles {
		if p == "" {
			t.Fatal("profile name should not be empty")
		}
	}
}

func TestDecodeAsTables(t *testing.T) {
	tables, err := RuntimeDecodeAsTables(context.Background())
	if err != nil {
		t.Fatalf("DecodeAsTables: %v", err)
	}
	if len(tables) == 0 {
		t.Fatal("expected at least one decode-as table")
	}
	for _, tbl := range tables {
		if tbl.Name == "" {
			t.Fatal("unexpected empty table name")
		}
		if tbl.TableName == "" {
			t.Fatal("unexpected empty table name for " + tbl.Name)
		}
	}
	t.Logf("found %d decode-as tables", len(tables))
}

func TestDecodeAsChoices(t *testing.T) {
	choices, err := RuntimeDecodeAsChoices(context.Background(), "tcp.port")
	if err != nil {
		t.Fatalf("DecodeAsChoices tcp.port: %v", err)
	}
	if len(choices) == 0 {
		t.Fatal("expected at least one choice for tcp.port")
	}
	t.Logf("tcp.port choices: %v", choices)
}

func TestDecodeAsChoices_InvalidTable(t *testing.T) {
	_, err := RuntimeDecodeAsChoices(context.Background(), "nonexistent.table")
	if !stderrors.Is(err, ErrDecodeAsUnsupported) {
		t.Fatalf("DecodeAsChoices invalid table error=%v, want ErrDecodeAsUnsupported", err)
	}
	var decodeErr *DecodeAsError
	if !stderrors.As(err, &decodeErr) {
		t.Fatalf("DecodeAsChoices invalid table error type=%T, want DecodeAsError", err)
	}
	if decodeErr.Table != "nonexistent.table" {
		t.Fatalf("DecodeAsError table: want nonexistent.table got %q", decodeErr.Table)
	}
}

func TestTapTypes(t *testing.T) {
	taps := RuntimeTapTypes(context.Background())
	t.Logf("found %d tap types: %v", len(taps), taps)
	for _, tap := range taps {
		if tap == "" {
			t.Fatal("tap type should not be empty")
		}
	}
}

func TestPreferences(t *testing.T) {
	prefs, err := RuntimePreferences(context.Background())
	if err != nil {
		t.Fatalf("Preferences: %v", err)
	}
	if len(prefs) == 0 {
		t.Fatal("expected at least one preference module")
	}
	namedCount := 0
	for _, p := range prefs {
		if p.Name != "" {
			namedCount++
		}
	}
	if namedCount == 0 {
		t.Fatal("expected at least one named preference module")
	}
	t.Logf("found %d preference modules (%d named)", len(prefs), namedCount)
}
