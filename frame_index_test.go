package gowireshark

import (
	"testing"

	"github.com/randolphcyg/gowireshark/internal/testfixture"
)

func TestSession_FrameIndex_NoFilter(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	idx, err := s.FrameIndex(Query{})
	if err != nil {
		t.Fatal(err)
	}

	total := s.TotalFrames()
	if idx.TotalFrames != total {
		t.Fatalf("TotalFrames: want %d got %d", total, idx.TotalFrames)
	}
	if len(idx.FrameNumbers) != total {
		t.Fatalf("FrameNumbers length: want %d got %d", total, len(idx.FrameNumbers))
	}
	if idx.Filter != "" {
		t.Fatalf("Filter: want '' got %q", idx.Filter)
	}

	for i, n := range idx.FrameNumbers {
		if n != i+1 {
			t.Fatalf("FrameNumbers[%d]: want %d got %d", i, i+1, n)
		}
	}
}

func TestSession_FrameIndex_WithFilter(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	idx, err := s.FrameIndex(Query{Filter: "tcp"})
	if err != nil {
		t.Fatal(err)
	}

	if idx.Filter != "tcp" {
		t.Fatalf("Filter: want 'tcp' got %q", idx.Filter)
	}

	expectedCount, err := s.FrameCount(Query{Filter: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.FrameNumbers) != expectedCount {
		t.Fatalf("FrameNumbers length: want %d got %d", expectedCount, len(idx.FrameNumbers))
	}

	directNums, err := s.FrameNumbers(Query{Filter: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	if len(directNums) != len(idx.FrameNumbers) {
		t.Fatalf("length mismatch with FrameNumbers: %d != %d", len(directNums), len(idx.FrameNumbers))
	}
	for i, n := range directNums {
		if idx.FrameNumbers[i] != n {
			t.Fatalf("FrameNumbers[%d] mismatch: %d != %d", i, idx.FrameNumbers[i], n)
		}
	}

	allIdx, _ := s.FrameIndex(Query{})
	allSet := make(map[int]bool, len(allIdx.FrameNumbers))
	for _, n := range allIdx.FrameNumbers {
		allSet[n] = true
	}
	for _, n := range idx.FrameNumbers {
		if !allSet[n] {
			t.Fatalf("filtered FrameNumbers contained %d not in all numbers", n)
		}
	}
}

func TestSession_FrameIndex_Cache(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	idx1, err := s.FrameIndex(Query{Filter: "tcp"})
	if err != nil {
		t.Fatal(err)
	}

	idx2, err := s.FrameIndex(Query{Filter: "tcp"})
	if err != nil {
		t.Fatal(err)
	}

	if len(idx1.FrameNumbers) != len(idx2.FrameNumbers) {
		t.Fatalf("cached FrameNumbers length differs: %d != %d", len(idx1.FrameNumbers), len(idx2.FrameNumbers))
	}
	for i := range idx1.FrameNumbers {
		if idx1.FrameNumbers[i] != idx2.FrameNumbers[i] {
			t.Fatalf("cached FrameNumbers[%d] differs: %d != %d", i, idx1.FrameNumbers[i], idx2.FrameNumbers[i])
		}
	}
}

func TestSession_FrameIndex_NoMutationLeak(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	idx1, err := s.FrameIndex(Query{})
	if err != nil {
		t.Fatal(err)
	}

	origLen := len(idx1.FrameNumbers)
	if origLen > 0 {
		idx1.FrameNumbers[0] = -9999
	}

	idx2, err := s.FrameIndex(Query{})
	if err != nil {
		t.Fatal(err)
	}

	if len(idx2.FrameNumbers) != origLen {
		t.Fatalf("cache polluted: length changed from %d to %d", origLen, len(idx2.FrameNumbers))
	}
	if origLen > 0 && idx2.FrameNumbers[0] != 1 {
		t.Fatalf("cache polluted: FrameNumbers[0] expected 1 got %d", idx2.FrameNumbers[0])
	}
}

func TestSession_FrameIndex_ClosedSession(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	if _, err := s.FrameIndex(Query{}); err != ErrSessionClosed {
		t.Fatalf("expected ErrSessionClosed, got %v", err)
	}
}

func TestSession_FrameIndex_InvalidFilter(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if _, err := s.FrameIndex(Query{Filter: "!!invalid!!"}); err == nil {
		t.Fatal("expected error for invalid filter")
	}
}

func TestSession_FrameIndex_DifferentFiltersDontPollute(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	idxTCP, err := s.FrameIndex(Query{Filter: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	idxUDP, err := s.FrameIndex(Query{Filter: "udp"})
	if err != nil {
		t.Fatal(err)
	}

	if idxTCP.Filter != "tcp" {
		t.Fatalf("tcp filter lost: %q", idxTCP.Filter)
	}
	if idxUDP.Filter != "udp" {
		t.Fatalf("udp filter lost: %q", idxUDP.Filter)
	}

	if len(idxTCP.FrameNumbers) > s.TotalFrames() {
		t.Fatalf("tcp count exceeds total: %d > %d", len(idxTCP.FrameNumbers), s.TotalFrames())
	}
}

func TestSession_BuildFrameIndex_ReturnsIndex(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	idx, err := s.BuildFrameIndex(Query{Filter: "tcp"})
	if err != nil {
		t.Fatal(err)
	}

	if idx.Filter != "tcp" {
		t.Fatalf("Filter: want 'tcp' got %q", idx.Filter)
	}
	if idx.TotalFrames != s.TotalFrames() {
		t.Fatalf("TotalFrames: want %d got %d", s.TotalFrames(), idx.TotalFrames)
	}

	numbers, err := s.FrameNumbers(Query{Filter: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	for i, n := range numbers {
		if idx.FrameNumbers[i] != n {
			t.Fatalf("FrameNumbers[%d] mismatch: %d != %d", i, idx.FrameNumbers[i], n)
		}
	}
}

func TestSession_BuildFrameIndex_Rebuilds(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	first, err := s.BuildFrameIndex(Query{})
	if err != nil {
		t.Fatal(err)
	}

	second, err := s.BuildFrameIndex(Query{})
	if err != nil {
		t.Fatal(err)
	}

	if first == second {
		t.Log("BuildFrameIndex pointers are equal (cached returned) — acceptable")
	}

	if len(first.FrameNumbers) != len(second.FrameNumbers) {
		t.Fatalf("rebuild changed count: %d != %d", len(first.FrameNumbers), len(second.FrameNumbers))
	}
	for i := range first.FrameNumbers {
		if first.FrameNumbers[i] != second.FrameNumbers[i] {
			t.Fatalf("rebuild changed FrameNumbers[%d]: %d != %d", i, first.FrameNumbers[i], second.FrameNumbers[i])
		}
	}
}

func TestSession_Frame_First(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	fd, err := s.Frame(1)
	if err != nil {
		t.Fatal(err)
	}

	if fd.BaseLayers.Frame == nil {
		t.Fatal("expected Frame layer")
	}
	if fd.BaseLayers.Frame.Number != 1 {
		t.Fatalf("frame number: want 1 got %d", fd.BaseLayers.Frame.Number)
	}
}

func TestSession_Frame_Last(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	total := s.TotalFrames()
	fd, err := s.Frame(total)
	if err != nil {
		t.Fatal(err)
	}

	if fd.BaseLayers.Frame == nil {
		t.Fatal("expected Frame layer")
	}
	if fd.BaseLayers.Frame.Number != total {
		t.Fatalf("frame number: want %d got %d", total, fd.BaseLayers.Frame.Number)
	}
}

func TestSession_Frame_Mid(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	total := s.TotalFrames()
	if total < 3 {
		t.Skip("need at least 3 frames")
	}

	mid := total / 2
	fd, err := s.Frame(mid)
	if err != nil {
		t.Fatal(err)
	}

	if fd.BaseLayers.Frame == nil {
		t.Fatal("expected Frame layer")
	}
	if fd.BaseLayers.Frame.Number != mid {
		t.Fatalf("frame number: want %d got %d", mid, fd.BaseLayers.Frame.Number)
	}
}

func TestSession_Frame_InvalidZero(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if _, err := s.Frame(0); err != ErrInvalidFrameNumber {
		t.Fatalf("expected ErrInvalidFrameNumber for 0, got %v", err)
	}
}

func TestSession_Frame_InvalidTooLarge(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	total := s.TotalFrames()
	if _, err := s.Frame(total + 1); err != ErrInvalidFrameNumber {
		t.Fatalf("expected ErrInvalidFrameNumber for %d, got %v", total+1, err)
	}
}

func TestSession_Frame_ClosedSession(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	if _, err := s.Frame(1); err != ErrSessionClosed {
		t.Fatalf("expected ErrSessionClosed, got %v", err)
	}
}

func TestSession_Frame_MatchesSelf(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	total := s.TotalFrames()
	if total < 2 {
		t.Skip("need at least 2 frames")
	}

	fdNum, err := s.Frame(total)
	if err != nil {
		t.Fatal(err)
	}

	fdIdx, err := s.Frame(total)
	if err != nil {
		t.Fatal(err)
	}

	if fdNum.BaseLayers.Frame.Number != fdIdx.BaseLayers.Frame.Number {
		t.Fatalf("frame number mismatch: %d != %d", fdNum.BaseLayers.Frame.Number, fdIdx.BaseLayers.Frame.Number)
	}
}

func TestSession_Frame_Basic(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	fd, err := s.Frame(1)
	if err != nil {
		t.Fatal(err)
	}
	if fd.BaseLayers.Frame == nil || fd.BaseLayers.Frame.Number != 1 {
		t.Fatalf("Frame returned unexpected result: %#v", fd.BaseLayers.Frame)
	}
}

func TestSession_FrameIndex_TotalFramesConsistent(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	idxNoFilter, err := s.FrameIndex(Query{})
	if err != nil {
		t.Fatal(err)
	}
	idxWithFilter, err := s.FrameIndex(Query{Filter: "tcp"})
	if err != nil {
		t.Fatal(err)
	}

	if idxNoFilter.TotalFrames != idxWithFilter.TotalFrames {
		t.Fatalf("TotalFrames should be consistent: %d != %d", idxNoFilter.TotalFrames, idxWithFilter.TotalFrames)
	}
	if idxNoFilter.TotalFrames != s.TotalFrames() {
		t.Fatalf("FrameIndex.TotalFrames != Session.TotalFrames: %d != %d", idxNoFilter.TotalFrames, s.TotalFrames())
	}
}

func TestSession_FrameIndex_MaxIndexCountEvicts(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap, WithSessionCache(SessionCacheOptions{MaxIndexCount: 2}))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	_, err = s.FrameIndex(Query{Filter: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.FrameIndex(Query{Filter: "udp"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.FrameIndex(Query{Filter: "http"})
	if err != nil {
		t.Fatal(err)
	}

	s.cache.mu.RLock()
	idxLen := len(s.cache.frameIndexes)
	s.cache.mu.RUnlock()

	if idxLen > 2 {
		t.Fatalf("expected at most 2 cached indexes after MaxIndexCount=2, got %d", idxLen)
	}
}

func TestSession_FrameIndex_Disabled(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap, WithSessionCache(SessionCacheOptions{Disable: true}))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	idx1, err := s.FrameIndex(Query{Filter: "tcp"})
	if err != nil {
		t.Fatal(err)
	}

	// Cache disabled — raw map should stay empty.
	s.cache.mu.RLock()
	idxLen := len(s.cache.frameIndexes)
	s.cache.mu.RUnlock()

	if idxLen != 0 {
		t.Fatalf("expected frameIndexes map to be empty when cache disabled, got %d entries", idxLen)
	}

	idx2, err := s.FrameIndex(Query{Filter: "tcp"})
	if err != nil {
		t.Fatal(err)
	}

	if len(idx1.FrameNumbers) != len(idx2.FrameNumbers) {
		t.Fatalf("disabled cache returned inconsistent results: %d != %d", len(idx1.FrameNumbers), len(idx2.FrameNumbers))
	}
}
