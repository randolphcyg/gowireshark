package gowireshark

import (
	"bytes"
	stderrors "errors"
	"testing"

	"github.com/randolphcyg/gowireshark/internal/testfixture"
)

func TestIterFrames_All(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	iter, err := s.IterFrames(Query{})
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for iter.Next() {
		f := iter.Frame()
		if f == nil {
			t.Fatal("unexpected nil frame")
		}
		count++
	}
	if err := iter.Close(); err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatal("expected at least one frame")
	}
	t.Logf("iterated %d frames", count)
}

func TestIterFrames_FullConsumeWithoutCloseReleasesSession(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	iter, err := s.IterFrames(Query{Filter: "frame.number <= 2"})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for iter.Next() {
		count++
	}
	if iter.Err() != nil {
		t.Fatalf("iterator error: %v", iter.Err())
	}
	if count != 2 {
		t.Fatalf("count: want 2 got %d", count)
	}

	total, err := s.FrameCount(Query{})
	if err != nil {
		t.Fatalf("session operation after full iterator consume: %v", err)
	}
	if total == 0 {
		t.Fatal("expected non-zero frame count")
	}
}

func TestIterFrames_MatchesWalkFrames(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	iter, err := s.IterFrames(Query{})
	if err != nil {
		t.Fatal(err)
	}

	var iterFrames []*FrameData
	for iter.Next() {
		iterFrames = append(iterFrames, iter.Frame())
	}
	if err := iter.Close(); err != nil {
		t.Fatal(err)
	}

	var walkFrames []*FrameData
	err = s.WalkFrames(Query{}, func(f *FrameData) error {
		walkFrames = append(walkFrames, f)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(iterFrames) != len(walkFrames) {
		t.Fatalf("count mismatch: iter=%d walk=%d", len(iterFrames), len(walkFrames))
	}
	for i := range iterFrames {
		if iterFrames[i].BaseLayers.Frame.Number != walkFrames[i].BaseLayers.Frame.Number {
			t.Fatalf("frame %d mismatch: iter=%d walk=%d", i,
				iterFrames[i].BaseLayers.Frame.Number, walkFrames[i].BaseLayers.Frame.Number)
		}
	}
}

func TestIterFrames_EarlyClose(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	iter, err := s.IterFrames(Query{})
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for iter.Next() {
		count++
		if count >= 3 {
			break
		}
	}
	if err := iter.Close(); err != nil {
		t.Fatal(err)
	}
	if count < 3 {
		t.Fatalf("expected at least 3 frames, got %d", count)
	}

	iter2, err := s.IterFrames(Query{})
	if err != nil {
		t.Fatal(err)
	}
	count2 := 0
	for iter2.Next() {
		count2++
	}
	if err := iter2.Close(); err != nil {
		t.Fatal(err)
	}
	t.Logf("first run: %d frames (early close), second run: %d frames", count, count2)
}

func TestIterFrames_ClosedSession(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	_, err = s.IterFrames(Query{})
	if !stderrors.Is(err, ErrSessionClosed) {
		t.Fatalf("expected ErrSessionClosed, got %v", err)
	}
}

func TestIterFrames_InvalidFilter(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	_, err = s.IterFrames(Query{Filter: "not.a.valid.filter!!!!"})
	if err == nil {
		t.Fatal("expected error for invalid filter")
	}
	var dfErr *DisplayFilterError
	if !stderrors.As(err, &dfErr) {
		t.Fatalf("expected DisplayFilterError, got %T: %v", err, err)
	}
}

func TestIterFieldsRows_All(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	fields := []string{"frame.number", "ip.src", "ip.dst"}
	iter, err := s.IterFieldsRows(Query{}, fields)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for iter.Next() {
		row := iter.Row()
		if row == nil {
			t.Fatal("unexpected nil row")
		}
		if row["frame.number"] == "" {
			t.Fatal("expected frame.number in row")
		}
		count++
	}
	if err := iter.Close(); err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatal("expected at least one field row")
	}
	t.Logf("iterated %d field rows", count)
}

func TestIterFieldsRows_FullConsumeWithoutCloseReleasesSession(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	iter, err := s.IterFieldsRows(Query{Filter: "frame.number <= 2"}, []string{"frame.number"})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for iter.Next() {
		count++
	}
	if iter.Err() != nil {
		t.Fatalf("iterator error: %v", iter.Err())
	}
	if count != 2 {
		t.Fatalf("count: want 2 got %d", count)
	}

	total, err := s.FrameCount(Query{})
	if err != nil {
		t.Fatalf("session operation after full field iterator consume: %v", err)
	}
	if total == 0 {
		t.Fatal("expected non-zero frame count")
	}
}

func TestIterFieldsRows_MatchesFieldsRows(t *testing.T) {
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

	iter, err := s.IterFieldsRows(Query{}, fields)
	if err != nil {
		t.Fatal(err)
	}

	var iterRows []FieldRow
	for iter.Next() {
		iterRows = append(iterRows, iter.Row())
	}
	if err := iter.Close(); err != nil {
		t.Fatal(err)
	}

	if len(iterRows) != len(rows) {
		t.Fatalf("count mismatch: iter=%d batch=%d", len(iterRows), len(rows))
	}
	for i := range rows {
		if rows[i]["frame.number"] != iterRows[i]["frame.number"] {
			t.Fatalf("row %d frame.number mismatch: %q != %q", i,
				rows[i]["frame.number"], iterRows[i]["frame.number"])
		}
	}
}

func TestIterFieldsRows_OccurrenceLast(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	fields := []string{"frame.number", "frame.protocols"}
	rowsFirst, err := s.FieldsRows(Query{}, fields, WithFieldOccurrence(OccurrenceFirst))
	if err != nil {
		t.Fatal(err)
	}
	iter, err := s.IterFieldsRows(Query{}, fields, WithFieldOccurrence(OccurrenceLast))
	if err != nil {
		t.Fatal(err)
	}

	var iterRows []FieldRow
	for iter.Next() {
		iterRows = append(iterRows, iter.Row())
	}
	if err := iter.Close(); err != nil {
		t.Fatal(err)
	}
	if len(iterRows) != len(rowsFirst) {
		t.Fatalf("count mismatch: iter=%d batch=%d", len(iterRows), len(rowsFirst))
	}
	for i := range iterRows {
		if iterRows[i]["frame.number"] != rowsFirst[i]["frame.number"] {
			t.Fatalf("row %d frame.number mismatch: %q != %q", i,
				iterRows[i]["frame.number"], rowsFirst[i]["frame.number"])
		}
	}
}

func TestIterFieldsRows_RejectsOccurrenceAll(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	_, err = s.IterFieldsRows(Query{}, []string{"frame.protocols"}, WithFieldOccurrence(OccurrenceAll))
	if !stderrors.Is(err, ErrUnsupportedFieldOccurrence) {
		t.Fatalf("error=%v, want ErrUnsupportedFieldOccurrence", err)
	}
}

func TestIterFieldsRows_EarlyClose(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	fields := []string{"frame.number"}
	iter, err := s.IterFieldsRows(Query{}, fields)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for iter.Next() {
		count++
		if count >= 5 {
			break
		}
	}
	if err := iter.Close(); err != nil {
		t.Fatal(err)
	}

	iter2, err := s.IterFieldsRows(Query{}, fields)
	if err != nil {
		t.Fatal(err)
	}
	count2 := 0
	for iter2.Next() {
		count2++
	}
	if err := iter2.Close(); err != nil {
		t.Fatal(err)
	}
	t.Logf("first run: %d rows (early close), second run: %d rows", count, count2)
}

func TestWriteFieldsRows(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	fields := []string{"frame.number", "ip.src"}
	var buf bytes.Buffer
	count, err := s.WriteFieldsRows(Query{}, fields, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatal("expected at least one row written")
	}
	lines := bytes.Count(buf.Bytes(), []byte("\n"))
	if lines != count {
		t.Fatalf("newline count mismatch: lines=%d count=%d", lines, count)
	}
	t.Logf("wrote %d field rows (%d bytes)", count, buf.Len())
}

func TestIterFieldsRows_EmptyFields(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	_, err = s.IterFieldsRows(Query{}, []string{})
	if !stderrors.Is(err, ErrInvalidField) {
		t.Fatalf("error=%v, want ErrInvalidField", err)
	}
}

func TestIterFrames_DoubleClose(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	iter, err := s.IterFrames(Query{})
	if err != nil {
		t.Fatal(err)
	}

	if iter.Next() {
		_ = iter.Frame()
	}
	if err := iter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := iter.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestIterFieldsRows_DoubleClose(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	iter, err := s.IterFieldsRows(Query{}, []string{"frame.number"})
	if err != nil {
		t.Fatal(err)
	}

	if iter.Next() {
		_ = iter.Row()
	}
	if err := iter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := iter.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestIterFrames_FilteredMatchesWalkFrames(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	filter := "ip"

	iter, err := s.IterFrames(Query{Filter: filter})
	if err != nil {
		t.Fatal(err)
	}

	var iterFrames []*FrameData
	for iter.Next() {
		iterFrames = append(iterFrames, iter.Frame())
	}
	if err := iter.Close(); err != nil {
		t.Fatal(err)
	}

	var walkFrames []*FrameData
	err = s.WalkFrames(Query{Filter: filter}, func(f *FrameData) error {
		walkFrames = append(walkFrames, f)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(iterFrames) != len(walkFrames) {
		t.Fatalf("count mismatch: iter=%d walk=%d", len(iterFrames), len(walkFrames))
	}
}
