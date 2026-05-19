package gowireshark

import (
	stderrors "errors"
	"testing"
)

func TestFieldMetadata(t *testing.T) {
	if err := ValidateField("tcp.stream"); err != nil {
		t.Fatalf("ValidateField(tcp.stream): %v", err)
	}
	if err := ValidateField("definitely.not.a.real.field"); !stderrors.Is(err, ErrFieldNotFound) {
		t.Fatalf("ValidateField(invalid) error=%v, want ErrFieldNotFound", err)
	}

	field, err := FieldInfo("frame.number")
	if err != nil {
		t.Fatalf("FieldInfo(frame.number): %v", err)
	}
	if field.Abbrev != "frame.number" || field.Type == "" {
		t.Fatalf("unexpected field info: %#v", field)
	}

	fields, err := Fields()
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
	protocols, err := Protocols()
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
