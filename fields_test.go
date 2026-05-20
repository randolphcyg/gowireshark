package gowireshark

import (
	"strconv"
	"testing"

	"github.com/randolphcyg/gowireshark/internal/testfixture"
)

func TestFieldsRows_WithDisplayFilter(t *testing.T) {
	pcap := testfixture.Pcap(t)

	fields := []string{"frame.number", "ip.src"}

	rows, err := FieldsRows(pcap, fields, WithDisplayFilter("frame.number == 1"))
	if err != nil {
		t.Fatalf("FieldsRows with filter: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row with filter frame.number==1, got %d", len(rows))
	}

	row := rows[0]
	if row["frame.number"] != "1" {
		t.Fatalf("expected frame.number=1, got %q", row["frame.number"])
	}
	if _, ok := row["ip.src"]; !ok {
		t.Log("ip.src not present in first frame (expected if no IP)")
	}
}

func TestFieldsRows_SessionMatchesFreeFunc(t *testing.T) {
	pcap := testfixture.Pcap(t)

	fields := []string{"frame.number", "frame.len", "frame.protocols"}

	filter := "frame.number <= 5"

	freeRows, err := FieldsRows(pcap, fields, WithDisplayFilter(filter))
	if err != nil {
		t.Fatalf("free FieldsRows: %v", err)
	}

	s, err := OpenSession(pcap)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	sRows, err := s.FieldsRows(Query{Filter: filter}, fields)
	if err != nil {
		s.Close()
		t.Fatalf("session FieldsRows: %v", err)
	}
	s.Close()

	if len(freeRows) != len(sRows) {
		t.Fatalf("row count mismatch: free=%d session=%d", len(freeRows), len(sRows))
	}

	for i := range freeRows {
		for _, f := range fields {
			if freeRows[i][f] != sRows[i][f] {
				t.Fatalf("row %d field %q mismatch: free=%q session=%q",
					i, f, freeRows[i][f], sRows[i][f])
			}
		}
	}
}

func TestFieldsRows_NoFilterReturnsAll(t *testing.T) {
	pcap := testfixture.Pcap(t)

	fields := []string{"frame.number"}

	rows, err := FieldsRows(pcap, fields)
	if err != nil {
		t.Fatalf("FieldsRows: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("expected at least 1 row")
	}

	count, err := FrameCount(pcap)
	if err != nil {
		t.Fatalf("FrameCount: %v", err)
	}
	if len(rows) != count {
		t.Fatalf("FieldsRows returned %d rows, FrameCount=%d", len(rows), count)
	}
}

func TestFieldsRows_ClosedSession(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, _ := OpenSession(pcap)
	s.Close()

	fields := []string{"frame.number"}

	_, err := s.FieldsRows(Query{}, fields)
	if err != ErrSessionClosed {
		t.Fatalf("expected ErrSessionClosed, got %v", err)
	}
}

func TestFieldsRows_PreservesOrder(t *testing.T) {
	pcap := testfixture.Pcap(t)

	fields := []string{"frame.number"}

	rows, err := FieldsRows(pcap, fields)
	if err != nil {
		t.Fatalf("FieldsRows: %v", err)
	}
	if len(rows) < 2 {
		t.Skip("need at least 2 frames for order test")
	}

	for i := 1; i < len(rows); i++ {
		prev, _ := strconv.Atoi(rows[i-1]["frame.number"])
		curr, _ := strconv.Atoi(rows[i]["frame.number"])
		if curr <= prev {
			t.Fatalf("order broken at row %d: %q <= %q",
				i, rows[i]["frame.number"], rows[i-1]["frame.number"])
		}
	}
}