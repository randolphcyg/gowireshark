package gowireshark

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/randolphcyg/gowireshark/internal/testfixture"
)

func TestExportObjectsHTTP_DoesNotCrash(t *testing.T) {
	pcap := testfixture.Pcap(t)

	objs, err := ExportObjects(pcap, "http")
	if err != nil {
		t.Fatalf("ExportObjects http: %v", err)
	}
	if objs == nil {
		t.Fatal("expected non-nil objects")
	}
	t.Logf("found %d HTTP export objects", len(objs))

	for _, obj := range objs {
		if obj.PacketNum <= 0 {
			t.Fatalf("invalid packetNum: %#v", obj)
		}
		if obj.Protocol != "http" {
			t.Fatalf("expected protocol http, got %q", obj.Protocol)
		}
		if obj.Length > 0 {
			t.Logf("  packet=%d hostname=%q content-type=%q filename=%q length=%d sha256=%s",
				obj.PacketNum, obj.Hostname, obj.ContentType, obj.Filename, obj.Length, obj.SHA256)
		}
	}
}

func TestExportObjectsHTTP_WithFilter(t *testing.T) {
	pcap := testfixture.Pcap(t)

	all, err := ExportObjects(pcap, "http")
	if err != nil {
		t.Fatalf("ExportObjects all: %v", err)
	}

	filtered, err := ExportObjects(pcap, "http", WithDisplayFilter("frame.number == 1"))
	if err != nil {
		t.Fatalf("ExportObjects filtered: %v", err)
	}

	if len(filtered) > len(all) {
		t.Fatalf("filtered (%d) should not exceed unfiltered (%d)", len(filtered), len(all))
	}
}

func TestWriteExportObject(t *testing.T) {
	pcap := testfixture.Pcap(t)

	objs, err := ExportObjects(pcap, "http")
	if err != nil {
		t.Fatalf("ExportObjects: %v", err)
	}
	if len(objs) == 0 {
		t.Skip("no HTTP export objects in fixture, skipping WriteExportObject")
	}

	obj := objs[0]
	if obj.Length <= 0 {
		t.Skip("empty export object, skipping WriteExportObject")
	}

	s, err := openSession(pcap)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer s.Close()

	var buf bytes.Buffer
	if err := s.WriteExportObject("http", obj.PacketNum, &buf, Query{}); err != nil {
		t.Fatalf("WriteExportObject: %v", err)
	}
	written := buf.Bytes()

	if len(written) == 0 {
		t.Fatal("expected non-empty written data")
	}
	if int64(len(written)) != obj.Length {
		t.Fatalf("written length %d != object length %d", len(written), obj.Length)
	}

	sha256 := computeSHA256Bytes(written)
	if sha256 != obj.SHA256 {
		t.Fatalf("SHA256 mismatch: got %s, expected %s", sha256, obj.SHA256)
	}
}

func computeSHA256Bytes(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func TestExportObjectsHTTP_EmptyPcap(t *testing.T) {
	pcap := testfixture.Pcap(t)

	objs, err := ExportObjects(pcap, "http")
	if err != nil {
		t.Fatalf("ExportObjects: %v", err)
	}
	_ = objs
}

func TestExportObjectsUnsupportedProtocol(t *testing.T) {
	pcap := testfixture.Pcap(t)

	_, err := ExportObjects(pcap, "bogus_proto")
	if err == nil {
		t.Fatal("expected error for unsupported protocol")
	}
}

func TestExportObjectsInvalidFilter(t *testing.T) {
	pcap := testfixture.Pcap(t)

	_, err := ExportObjects(pcap, "http", WithDisplayFilter("bogus_field == 42"))
	if err == nil {
		t.Fatal("expected error for invalid filter")
	}
}

func TestSessionExportObjectsMatchesFreeFunction(t *testing.T) {
	pcap := testfixture.Pcap(t)

	freeObjs, err := ExportObjects(pcap, "http", WithDisplayFilter("frame.number <= 5"))
	if err != nil {
		t.Fatalf("ExportObjects: %v", err)
	}

	s, err := openSession(pcap)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer s.Close()

	sessionObjs, err := s.ExportObjects("http", Query{Filter: "frame.number <= 5"})
	if err != nil {
		t.Fatalf("Session.ExportObjects: %v", err)
	}
	if len(sessionObjs) != len(freeObjs) {
		t.Fatalf("export objects count mismatch: session=%d free=%d", len(sessionObjs), len(freeObjs))
	}
}

func TestWriteExportObjectToFile(t *testing.T) {
	pcap := testfixture.Pcap(t)

	objs, err := ExportObjects(pcap, "http")
	if err != nil {
		t.Fatalf("ExportObjects: %v", err)
	}
	if len(objs) == 0 {
		t.Skip("no HTTP export objects in fixture")
	}

	obj := objs[0]
	if obj.Length <= 0 {
		t.Skip("empty export object")
	}

	dir, err := os.MkdirTemp("", "gowireshark-export-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)

	var buf bytes.Buffer
	if err := WriteExportObject(pcap, "http", obj.PacketNum, &buf); err != nil {
		t.Fatalf("WriteExportObject: %v", err)
	}

	fname := strings.ReplaceAll(obj.Filename, "/", "_")
	if fname == "" {
		fname = "object.bin"
	}
	outPath := dir + "/" + fname
	if err := os.WriteFile(outPath, buf.Bytes(), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	readBack, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(readBack, buf.Bytes()) {
		t.Fatal("file read-back mismatch")
	}
}

func TestExportObjectsSessionClosed(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, err := openSession(pcap)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	s.Close()

	_, err = s.ExportObjects("http", Query{})
	if err == nil {
		t.Fatal("expected error for closed session")
	}
}

func TestExportObjectProtocols(t *testing.T) {
	protos := ExportObjectProtocols()
	if len(protos) != 6 {
		t.Fatalf("expected 6 protocols, got %d: %v", len(protos), protos)
	}
	expected := map[string]bool{
		"http": true, "smb": true, "tftp": true,
		"ftp-data": true, "imf": true, "dicom": true,
	}
	for _, p := range protos {
		if !expected[p] {
			t.Fatalf("unexpected protocol %q", p)
		}
	}
}

func TestSupportsExportObjects(t *testing.T) {
	for _, p := range ExportObjectProtocols() {
		if !SupportsExportObjects(p) {
			t.Fatalf("SupportsExportObjects(%q) should be true", p)
		}
	}
	if SupportsExportObjects("bogus_proto") {
		t.Fatal("SupportsExportObjects(bogus_proto) should be false")
	}
}

func TestExportObjectsExtProtocols_DoesNotCrash(t *testing.T) {
	pcap := testfixture.Pcap(t)

	protocols := []string{"smb", "tftp", "ftp-data", "imf", "dicom"}

	for _, proto := range protocols {
		t.Run(proto, func(t *testing.T) {
			if !SupportsExportObjects(proto) {
				t.Fatalf("%s should be supported", proto)
			}
			objs, err := ExportObjects(pcap, proto)
			if err != nil {
				t.Fatalf("ExportObjects %s: %v", proto, err)
			}
			for _, obj := range objs {
				if obj.Protocol != proto {
					t.Fatalf("expected protocol %q, got %q", proto, obj.Protocol)
				}
				if obj.PacketNum <= 0 {
					t.Fatalf("invalid packetNum: %#v", obj)
				}
			}
			t.Logf("%s: %d export objects", proto, len(objs))
		})
	}
}

func TestSessionExportObjectsExtProtocols(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer s.Close()

	protocols := []string{"smb", "tftp", "ftp-data", "imf", "dicom"}

	for _, proto := range protocols {
		t.Run(proto, func(t *testing.T) {
			objs, err := s.ExportObjects(proto, Query{})
			if err != nil {
				t.Fatalf("Session.ExportObjects %s: %v", proto, err)
			}
			t.Logf("%s: %d export objects", proto, len(objs))
		})
	}
}
