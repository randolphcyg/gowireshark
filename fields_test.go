package gowireshark

import (
	stderrors "errors"
	"testing"

	"github.com/randolphcyg/gowireshark/internal/testfixture"
)

func TestSession_FieldsRows_FirstOccurrence_MatchesDefault(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	fields := []string{"frame.number", "ip.src", "ip.dst"}

	rows, err := s.FieldsRows(Query{}, fields)
	if err != nil {
		t.Fatal(err)
	}
	rowsFirst, err := s.FieldsRows(Query{}, fields, WithFieldOccurrence(OccurrenceFirst))
	if err != nil {
		t.Fatal(err)
	}

	if len(rows) != len(rowsFirst) {
		t.Fatalf("length mismatch: FieldsRows=%d FieldsRows(first)=%d", len(rows), len(rowsFirst))
	}
	for i := range rows {
		if rows[i]["frame.number"] != rowsFirst[i]["frame.number"] {
			t.Fatalf("row %d frame.number mismatch: %q != %q", i, rows[i]["frame.number"], rowsFirst[i]["frame.number"])
		}
	}
}

func TestSession_FieldsRows_LastOccurrence(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	fields := []string{"ip.src", "ip.dst", "frame.protocols"}
	rowsFirst, err := s.FieldsRows(Query{}, fields, WithFieldOccurrence(OccurrenceFirst))
	if err != nil {
		t.Fatal(err)
	}
	rowsLast, err := s.FieldsRows(Query{}, fields, WithFieldOccurrence(OccurrenceLast))
	if err != nil {
		t.Fatal(err)
	}

	if len(rowsFirst) != len(rowsLast) {
		t.Fatalf("length mismatch: first=%d last=%d", len(rowsFirst), len(rowsLast))
	}
	for i := range rowsFirst {
		if rowsFirst[i]["ip.src"] == "" && rowsLast[i]["ip.src"] == "" {
			continue
		}
		if rowsFirst[i]["ip.src"] == "" || rowsLast[i]["ip.src"] == "" {
			continue
		}
		if rowsFirst[i]["frame.protocols"] != rowsLast[i]["frame.protocols"] {
			t.Logf("row %d frame.protocols: first=%q last=%q", i,
				rowsFirst[i]["frame.protocols"], rowsLast[i]["frame.protocols"])
		}
	}
}

func TestSession_FieldsRows_WithFilterAndOccurrence(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	fields := []string{"frame.number", "ip.src"}
	rows, err := s.FieldsRows(Query{Filter: "tcp"}, fields, WithFieldOccurrence(OccurrenceFirst))
	if err != nil {
		t.Fatal(err)
	}

	if len(rows) == 0 {
		t.Skip("no TCP frames")
	}

	for _, r := range rows {
		if r["ip.src"] == "" {
			t.Fatalf("missing ip.src in row: %+v", r)
		}
	}
}

func TestSession_FieldsRows_RejectsAll(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	_, err = s.FieldsRows(Query{}, []string{"ip.src"}, WithFieldOccurrence(OccurrenceAll))
	if !stderrors.Is(err, ErrUnsupportedFieldOccurrence) {
		t.Fatalf("error=%v, want ErrUnsupportedFieldOccurrence", err)
	}
}

func TestSession_FieldsRows_OccurrenceClosedSession(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	if _, err := s.FieldsRows(Query{}, []string{"ip.src"}, WithFieldOccurrence(OccurrenceFirst)); err != ErrSessionClosed {
		t.Fatalf("expected ErrSessionClosed, got %v", err)
	}
}

func TestSession_FieldsRows_OccurrenceInvalidFilter(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if _, err := s.FieldsRows(Query{Filter: "!!invalid!!"}, []string{"ip.src"}, WithFieldOccurrence(OccurrenceFirst)); err == nil {
		t.Fatal("expected error for invalid filter")
	}
}

func TestSession_FieldsRowsValues_MultiValueFields(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	fields := []string{"ip.dst", "frame.protocols"}
	rows, err := s.FieldsRowsValues(Query{}, fields)
	if err != nil {
		t.Fatal(err)
	}

	if len(rows) == 0 {
		t.Fatal("expected at least one row")
	}

	for _, r := range rows {
		if r.FrameNumber <= 0 {
			t.Fatalf("invalid frame number: %d", r.FrameNumber)
		}
		for _, f := range fields {
			vals, ok := r.Values[f]
			if !ok {
				t.Fatalf("frame %d: missing field %q in Values", r.FrameNumber, f)
			}
			_ = vals
		}
	}
}

func TestFieldsRowsValues_FreeFunction(t *testing.T) {
	pcap := testfixture.Pcap(t)

	rows, err := FieldsRowsValues(pcap, []string{"frame.number", "ip.src"}, WithDisplayFilter("frame.number <= 2"))
	if err != nil {
		t.Fatalf("FieldsRowsValues free function: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows length: want 2 got %d", len(rows))
	}
	for i, row := range rows {
		if row.FrameNumber != i+1 {
			t.Fatalf("row %d frame number: want %d got %d", i, i+1, row.FrameNumber)
		}
	}
}

func TestFieldsRows_FreeFunctionOccurrenceLast(t *testing.T) {
	pcap := testfixture.Pcap(t)

	rows, err := FieldsRows(pcap, []string{"frame.number", "ip.src"},
		WithDisplayFilter("frame.number <= 2"),
		WithFieldOccurrence(OccurrenceLast))
	if err != nil {
		t.Fatalf("FieldsRows free function: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows length: want 2 got %d", len(rows))
	}
}

func TestSession_FieldsRowsValues_EmptyFields(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	rows, err := s.FieldsRowsValues(Query{}, nil)
	if err != nil {
		t.Fatalf("FieldsRowsValues empty fields: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("empty fields should return no rows, got %d", len(rows))
	}
}

func TestSession_FieldsRowsValues_FilterFrameNumbers(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	filter := "frame.number <= 3"
	rows, err := s.FieldsRowsValues(Query{Filter: filter}, []string{"frame.number", "ip.src"})
	if err != nil {
		t.Fatalf("FieldsRowsValues filtered: %v", err)
	}
	numbers, err := s.FrameNumbers(Query{Filter: filter})
	if err != nil {
		t.Fatalf("FrameNumbers filtered: %v", err)
	}
	if len(rows) != len(numbers) {
		t.Fatalf("rows/numbers length mismatch: %d != %d", len(rows), len(numbers))
	}
	for i := range rows {
		if rows[i].FrameNumber != numbers[i] {
			t.Fatalf("row %d frame number: want %d got %d", i, numbers[i], rows[i].FrameNumber)
		}
	}
}

func TestSession_FieldsRowsValues_FrameProtocolsHasMultiple(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	rows, err := s.FieldsRowsValues(Query{}, []string{"frame.protocols"})
	if err != nil {
		t.Fatal(err)
	}

	foundMulti := false
	for _, r := range rows {
		vals := r.Values["frame.protocols"]
		if len(vals) > 1 {
			foundMulti = true
			for _, v := range vals {
				if v == "" {
					t.Fatalf("empty value in multi-protocol row %d", r.FrameNumber)
				}
			}
		}
	}
	if !foundMulti {
		t.Log("no frames with multiple protocols in test pcap")
	}
}

func TestSession_FieldsRowsValues_MatchesFieldsRowsFirst(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	fields := []string{"frame.number", "ip.src", "ip.dst"}
	rowsFirst, err := s.FieldsRows(Query{}, fields, WithFieldOccurrence(OccurrenceFirst))
	if err != nil {
		t.Fatal(err)
	}
	rowsAll, err := s.FieldsRowsValues(Query{}, fields)
	if err != nil {
		t.Fatal(err)
	}

	if len(rowsFirst) != len(rowsAll) {
		t.Fatalf("length mismatch: first=%d all=%d", len(rowsFirst), len(rowsAll))
	}

	for i := range rowsFirst {
		for _, f := range fields {
			if rowsFirst[i][f] == "" {
				continue
			}
			allVals := rowsAll[i].Values[f]
			if len(allVals) == 0 {
				continue
			}
			if rowsFirst[i][f] != allVals[0] {
				t.Fatalf("row %d field %q: first=%q values_all[0]=%q",
					i, f, rowsFirst[i][f], allVals[0])
			}
		}
	}
}

func TestSession_FieldsRowsValues_ClosedSession(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	if _, err := s.FieldsRowsValues(Query{}, []string{"ip.src"}); err != ErrSessionClosed {
		t.Fatalf("expected ErrSessionClosed, got %v", err)
	}
}

func TestSession_FieldsRowsValues_InvalidFilter(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if _, err := s.FieldsRowsValues(Query{Filter: "!!invalid!!"}, []string{"ip.src"}); err == nil {
		t.Fatal("expected error for invalid filter")
	}
}

func TestSession_FieldsRows_BackwardCompat(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	fields := []string{"frame.number", "ip.src", "ip.dst", "tcp.stream"}
	rows, err := s.FieldsRows(Query{Filter: "tcp"}, fields)
	if err != nil {
		t.Fatal(err)
	}

	if len(rows) == 0 {
		t.Skip("no TCP frames")
	}

	for _, r := range rows {
		if r["frame.number"] == "" {
			t.Fatal("missing frame.number")
		}
		if r["ip.src"] == "" {
			t.Fatal("missing ip.src in TCP frame")
		}
	}
}

func TestSession_FieldsRows_UnchangedFrameCountAcrossOccurrence(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	fields := []string{"ip.src", "ip.dst", "frame.protocols"}
	rowsFirst, _ := s.FieldsRows(Query{}, fields, WithFieldOccurrence(OccurrenceFirst))
	rowsLast, _ := s.FieldsRows(Query{}, fields, WithFieldOccurrence(OccurrenceLast))
	rowsAll, _ := s.FieldsRowsValues(Query{}, fields)

	if len(rowsFirst) != len(rowsLast) {
		t.Fatalf("frame count differs between first and last: %d != %d", len(rowsFirst), len(rowsLast))
	}
	if len(rowsFirst) != len(rowsAll) {
		t.Fatalf("frame count differs between first and all: %d != %d", len(rowsFirst), len(rowsAll))
	}
}
