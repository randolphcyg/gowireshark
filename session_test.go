package gowireshark

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/randolphcyg/gowireshark/internal/testfixture"
)

func TestSession_OpenClose(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, err := openSession(pcap)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestSession_DoubleClose(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, _ := openSession(pcap)
	s.Close()

	if err := s.Close(); err != nil {
		t.Fatalf("second Close should be safe: %v", err)
	}
}

func TestSession_SecondOpenCanBeCanceled(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, err := openSession(pcap)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer s.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := OpenSessionContext(ctx, pcap); err == nil {
		t.Fatal("expected context timeout while session is active")
	}
}

func TestSession_AllowsNewSessionAfterClose(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, err := openSession(pcap)
	if err != nil {
		t.Fatalf("first OpenSession: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}

	next, err := openSession(pcap)
	if err != nil {
		t.Fatalf("second OpenSession: %v", err)
	}
	defer next.Close()
}

func TestSession_ClosedPreventsUse(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, _ := openSession(pcap)
	s.Close()

	_, err := s.FrameCount(Query{})
	if err != ErrSessionClosed {
		t.Fatalf("expected ErrSessionClosed, got %v", err)
	}

	_, _, err = s.FramesPage(Query{}, 1, 10)
	if err != ErrSessionClosed {
		t.Fatalf("expected ErrSessionClosed for FramesPage, got %v", err)
	}

	err = s.WalkFrames(Query{}, func(_ *FrameData) error { return nil })
	if err != ErrSessionClosed {
		t.Fatalf("expected ErrSessionClosed for WalkFrames, got %v", err)
	}

	_, err = s.FollowStream(Query{}, "tcp")
	if err != ErrSessionClosed {
		t.Fatalf("expected ErrSessionClosed for FollowStream, got %v", err)
	}
}

func TestSession_TotalFrames_MatchesCount(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, _ := openSession(pcap)
	defer s.Close()

	total := s.TotalFrames()
	if total <= 0 {
		t.Fatal("expected positive total frame count")
	}

	count, err := s.FrameCount(Query{})
	if err != nil {
		t.Fatalf("FrameCount: %v", err)
	}

	if total != count {
		t.Fatalf("TotalFrames (%d) != FrameCount({}) (%d)", total, count)
	}
}

func TestSession_FrameCount_Consistent(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, _ := openSession(pcap)
	defer s.Close()

	count1, err := s.FrameCount(Query{})
	if err != nil {
		t.Fatalf("FrameCount: %v", err)
	}

	count2, err := s.FrameCount(Query{})
	if err != nil {
		t.Fatalf("second FrameCount: %v", err)
	}

	if count1 != count2 {
		t.Fatalf("inconsistent counts: %d != %d", count1, count2)
	}

	if count1 <= 0 {
		t.Fatal("expected positive frame count")
	}
}

func TestSession_FrameCount_MatchesFreeFunc(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, _ := openSession(pcap)
	sCount, err := s.FrameCount(Query{})
	if err != nil {
		t.Fatalf("session FrameCount: %v", err)
	}
	s.Close()

	fCount, err := FrameCount(pcap)
	if err != nil {
		t.Fatalf("free FrameCount: %v", err)
	}

	if sCount != fCount {
		t.Fatalf("mismatch: session=%d free=%d", sCount, fCount)
	}
}

func TestSession_FrameCount_WithFilter(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, _ := openSession(pcap)
	defer s.Close()

	allCount, _ := s.FrameCount(Query{})
	tcpCount, err := s.FrameCount(Query{Filter: "tcp"})
	if err != nil {
		t.Fatalf("FrameCount(tcp): %v", err)
	}

	if tcpCount > allCount {
		t.Fatalf("tcp count (%d) > all count (%d)", tcpCount, allCount)
	}
}

func TestSession_FrameCount_Cache(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, _ := openSession(pcap)
	defer s.Close()

	s.FrameCount(Query{Filter: "tcp"})

	if v, ok := s.cache.getCount("tcp"); !ok || v <= 0 {
		t.Fatalf("expected cached count for tcp, got ok=%v val=%d", ok, v)
	}
}

func TestSession_FrameCount_NoFilterUsesIndex(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, _ := openSession(pcap)
	defer s.Close()

	count := s.TotalFrames()

	count2, _ := s.FrameCount(Query{})
	if count != count2 {
		t.Fatalf("index count (%d) != FrameCount({}) (%d)", count, count2)
	}

	count3, _ := s.FrameCount(Query{})
	if count != count3 {
		t.Fatalf("repeated FrameCount should use index: %d != %d", count, count3)
	}
}

func TestSession_FramesPage_Consistent(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, _ := openSession(pcap)
	defer s.Close()

	frames1, hasMore1, err := s.FramesPage(Query{}, 1, 10)
	if err != nil {
		t.Fatalf("FramesPage: %v", err)
	}

	frames2, hasMore2, err := s.FramesPage(Query{}, 1, 10)
	if err != nil {
		t.Fatalf("second FramesPage: %v", err)
	}

	if hasMore1 != hasMore2 {
		t.Fatalf("hasMore inconsistent: %v != %v", hasMore1, hasMore2)
	}

	if len(frames1) != len(frames2) {
		t.Fatalf("frame count inconsistent: %d != %d", len(frames1), len(frames2))
	}

	if len(frames1) > 0 && len(frames2) > 0 {
		if frames1[0].BaseLayers.Frame.Number != frames2[0].BaseLayers.Frame.Number {
			t.Fatalf("first frame mismatch: %d != %d",
				frames1[0].BaseLayers.Frame.Number, frames2[0].BaseLayers.Frame.Number)
		}
	}
}

func TestSession_FramesPage_MatchesFreeFunc(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, _ := openSession(pcap)
	sFrames, sMore, err := s.FramesPage(Query{}, 1, 5)
	if err != nil {
		t.Fatalf("session FramesPage: %v", err)
	}
	s.Close()

	fFrames, fMore, err := FramesPage(pcap, 1, 5)
	if err != nil {
		t.Fatalf("free FramesPage: %v", err)
	}

	if sMore != fMore {
		t.Fatalf("hasMore mismatch: %v != %v", sMore, fMore)
	}
	if len(sFrames) != len(fFrames) {
		t.Fatalf("frame count mismatch: %d != %d", len(sFrames), len(fFrames))
	}
}

func TestSession_FramesPage_DifferentFiltersDontPollute(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, _ := openSession(pcap)
	defer s.Close()

	_, _, _ = s.FramesPage(Query{Filter: "tcp"}, 1, 5)
	tcpCached, ok := s.cache.getPage("tcp", 1, 5)
	if !ok || tcpCached == nil {
		t.Fatal("expected tcp page to be cached")
	}

	_, _, _ = s.FramesPage(Query{Filter: "udp"}, 1, 5)
	udpCached, ok := s.cache.getPage("udp", 1, 5)
	if !ok || udpCached == nil {
		t.Fatal("expected udp page to be cached")
	}

	if tcpCached == udpCached {
		t.Fatal("tcp and udp caches should be independent")
	}
}

func TestSession_FramesPage_Cache(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, _ := openSession(pcap)
	defer s.Close()

	s.FramesPage(Query{Filter: "tcp"}, 2, 10)

	if v, ok := s.cache.getPage("tcp", 2, 10); !ok || v == nil {
		t.Fatalf("expected cached page for tcp page=2 size=10, got ok=%v", ok)
	}

	if _, ok := s.cache.getPage("tcp", 3, 10); ok {
		t.Fatal("unexpected cache hit for different page")
	}
}

func TestSession_WalkFrames_MatchesFreeFunc(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, _ := openSession(pcap)

	var sFrames []*FrameData
	err := s.WalkFrames(Query{Filter: "tcp"}, func(f *FrameData) error {
		sFrames = append(sFrames, f)
		if len(sFrames) >= 5 {
			return errWalkStop
		}
		return nil
	})
	if err != errWalkStop {
		t.Fatalf("expected errWalkStop, got %v", err)
	}
	s.Close()

	var fFrames []*FrameData
	err = WalkFrames(pcap, func(f *FrameData) error {
		fFrames = append(fFrames, f)
		if len(fFrames) >= 5 {
			return errWalkStop
		}
		return nil
	}, WithDisplayFilter("tcp"))
	if err != errWalkStop {
		t.Fatalf("free WalkFrames: expected errWalkStop, got %v", err)
	}

	if len(sFrames) != len(fFrames) {
		t.Fatalf("frame count mismatch: %d != %d", len(sFrames), len(fFrames))
	}
}

var errWalkStop = &walkStopError{}

type walkStopError struct{}

func (e *walkStopError) Error() string { return "stop" }

func TestSession_FollowStream_Consistent(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, _ := openSession(pcap)
	defer s.Close()

	r1, err := s.FollowStream(Query{Filter: "tcp.stream eq 0"}, "tcp")
	if err != nil {
		t.Fatalf("FollowStream: %v", err)
	}

	r2, err := s.FollowStream(Query{Filter: "tcp.stream eq 0"}, "tcp")
	if err != nil {
		t.Fatalf("second FollowStream: %v", err)
	}

	if r1.PacketCount != r2.PacketCount {
		t.Fatalf("packet count inconsistent: %d != %d", r1.PacketCount, r2.PacketCount)
	}
}

func TestSession_FollowStream_MatchesFreeFunc(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, _ := openSession(pcap)
	sRes, err := s.FollowStream(Query{Filter: "tcp.stream eq 0"}, "tcp")
	if err != nil {
		t.Fatalf("session FollowStream: %v", err)
	}
	s.Close()

	fRes, err := FollowStream(pcap, "tcp.stream eq 0", "tcp")
	if err != nil {
		t.Fatalf("free FollowStream: %v", err)
	}

	if sRes.PacketCount != fRes.PacketCount {
		t.Fatalf("packet count mismatch: %d != %d", sRes.PacketCount, fRes.PacketCount)
	}
}

func TestSession_MixedOperationsRemainConsistent(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, err := openSession(pcap)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer s.Close()

	count, err := s.FrameCount(Query{Filter: "tcp"})
	if err != nil {
		t.Fatalf("FrameCount: %v", err)
	}
	frames, _, err := s.FramesPage(Query{Filter: "tcp"}, 1, 5)
	if err != nil {
		t.Fatalf("FramesPage: %v", err)
	}
	var walked int
	if err := s.WalkFrames(Query{Filter: "tcp"}, func(*FrameData) error {
		walked++
		return nil
	}); err != nil {
		t.Fatalf("WalkFrames: %v", err)
	}
	if _, err := s.FollowStream(Query{Filter: "tcp.stream eq 0"}, "tcp"); err != nil {
		t.Fatalf("FollowStream: %v", err)
	}
	countAgain, err := s.FrameCount(Query{Filter: "tcp"})
	if err != nil {
		t.Fatalf("second FrameCount: %v", err)
	}

	if count <= 0 || len(frames) == 0 || walked != count || countAgain != count {
		t.Fatalf("inconsistent mixed results: count=%d page=%d walked=%d countAgain=%d",
			count, len(frames), walked, countAgain)
	}
}

func TestSession_ResetReadPositionError(t *testing.T) {
	src := testfixture.Pcap(t)
	tmp := filepath.Join(t.TempDir(), "capture.pcap")

	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s, err := openSession(tmp)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer s.Close()

	if err := os.Remove(tmp); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	if _, err := s.FrameCount(Query{Filter: "tcp"}); err == nil {
		t.Fatal("expected reset error after capture file removal")
	}
}

func TestSession_FileNotFound(t *testing.T) {
	_, err := openSession("/nonexistent/pcap/file.pcap")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestSession_InvalidFilterInQuery(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, _ := openSession(pcap)
	defer s.Close()

	_, err := s.FrameCount(Query{Filter: "!!invalid!!"})
	if err == nil {
		t.Fatal("expected error for invalid filter in query")
	}
}

func TestSession_ReuseWithoutReinit(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, _ := openSession(pcap)
	defer s.Close()

	total := s.TotalFrames()

	for i := 0; i < 3; i++ {
		count, err := s.FrameCount(Query{})
		if err != nil {
			t.Fatalf("iteration %d FrameCount: %v", i, err)
		}
		if count != total {
			t.Fatalf("iteration %d: count %d != total %d", i, count, total)
		}
	}

	for i := 0; i < 3; i++ {
		frames, _, err := s.FramesPage(Query{}, 1, 5)
		if err != nil {
			t.Fatalf("iteration %d FramesPage: %v", i, err)
		}
		if len(frames) == 0 {
			t.Fatalf("iteration %d: expected non-empty frames", i)
		}
	}
}

func TestSession_DifferentFiltersDontPolluteCount(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, _ := openSession(pcap)
	defer s.Close()

	allCount, _ := s.FrameCount(Query{})
	tcpCount, _ := s.FrameCount(Query{Filter: "tcp"})
	udpCount, _ := s.FrameCount(Query{Filter: "udp"})

	if tcpCount == 0 && udpCount == 0 {
		t.Skip("no TCP or UDP frames in test pcap")
	}

	if tcpCount > allCount {
		t.Fatalf("tcp count (%d) > all (%d)", tcpCount, allCount)
	}
	if udpCount > allCount {
		t.Fatalf("udp count (%d) > all (%d)", udpCount, allCount)
	}
}

func TestSession_StreamsCache_NoMutationLeak(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, _ := openSession(pcap)
	defer s.Close()

	r1, err := s.Streams(Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r1) == 0 {
		t.Skip("no streams")
	}

	origProtocol := r1[0].Protocol
	r1[0].Protocol = "CORRUPTED"

	r2, err := s.Streams(Query{})
	if err != nil {
		t.Fatal(err)
	}
	if r2[0].Protocol != origProtocol {
		t.Fatalf("cache polluted: expected %q got %q", origProtocol, r2[0].Protocol)
	}
}

func TestSession_StreamsCache_CloseClears(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, _ := openSession(pcap)

	_, err := s.Streams(Query{})
	if err != nil {
		t.Fatal(err)
	}

	s.Close()

	_, err = s.Streams(Query{})
	if err != ErrSessionClosed {
		t.Fatalf("expected ErrSessionClosed after close, got %v", err)
	}
}

func TestSession_ExpertInfosCache_NoMutationLeak(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, _ := openSession(pcap)
	defer s.Close()

	r1, err := s.ExpertInfos(Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r1) == 0 {
		t.Skip("no expert infos")
	}

	origSummary := r1[0].Summary
	r1[0].Summary = "CORRUPTED"

	r2, err := s.ExpertInfos(Query{})
	if err != nil {
		t.Fatal(err)
	}
	if r2[0].Summary != origSummary {
		t.Fatalf("cache polluted: expected %q got %q", origSummary, r2[0].Summary)
	}
}

func TestSession_ExpertInfosCache_CloseClears(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, _ := openSession(pcap)

	_, err := s.ExpertInfos(Query{})
	if err != nil {
		t.Fatal(err)
	}

	s.Close()

	_, err = s.ExpertInfos(Query{})
	if err != ErrSessionClosed {
		t.Fatalf("expected ErrSessionClosed after close, got %v", err)
	}
}

func TestSession_FollowStreamCache_NoMutationLeak(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, _ := openSession(pcap)
	defer s.Close()

	r1, err := s.FollowStream(Query{Filter: "tcp.stream eq 0"}, "tcp")
	if err != nil {
		t.Fatal(err)
	}
	if len(r1.Payloads) == 0 {
		t.Skip("no follow stream payloads")
	}

	origPayloadLen := len(r1.Payloads[0].Bytes)
	if origPayloadLen > 0 {
		r1.Payloads[0].Bytes[0] = 0xFF
	}

	r2, err := s.FollowStream(Query{Filter: "tcp.stream eq 0"}, "tcp")
	if err != nil {
		t.Fatal(err)
	}
	if len(r2.Payloads) != len(r1.Payloads) {
		t.Fatalf("payload count mismatch: %d != %d", len(r2.Payloads), len(r1.Payloads))
	}
	if origPayloadLen > 0 && r2.Payloads[0].Bytes[0] == 0xFF {
		t.Fatal("cache polluted: payload Bytes mutated through returned FollowResult")
	}
}

func TestSession_FollowStreamCache_CloseClears(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, _ := openSession(pcap)

	_, err := s.FollowStream(Query{Filter: "tcp.stream eq 0"}, "tcp")
	if err != nil {
		t.Fatal(err)
	}

	s.Close()

	_, err = s.FollowStream(Query{Filter: "tcp.stream eq 0"}, "tcp")
	if err != ErrSessionClosed {
		t.Fatalf("expected ErrSessionClosed after close, got %v", err)
	}
}

func TestSession_FramesPageCache_NoMutationLeak(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, _ := openSession(pcap)
	defer s.Close()

	r1, _, err := s.FramesPage(Query{}, 1, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(r1) == 0 {
		t.Skip("no frames")
	}

	origNum := r1[0].BaseLayers.Frame.Number
	r1[0] = &FrameData{}

	r2, _, err := s.FramesPage(Query{}, 1, 5)
	if err != nil {
		t.Fatal(err)
	}
	if r2[0].BaseLayers.Frame.Number != origNum {
		t.Fatalf("cache polluted: expected frame %d got %d", origNum, r2[0].BaseLayers.Frame.Number)
	}
}

func TestSession_ConcurrentOpenWaitsForGate(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, err := openSession(pcap)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer s.Close()

	done := make(chan error, 1)
	go func() {
		s2, e := OpenSessionContext(context.Background(), pcap)
		if e == nil {
			s2.Close()
		}
		done <- e
	}()

	select {
	case <-done:
		t.Fatal("concurrent OpenSessionContext should block while session is active")
	case <-time.After(500 * time.Millisecond):
	}

	s.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("concurrent OpenSessionContext after release: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent OpenSessionContext did not acquire gate after release")
	}
}

func TestSession_OpenSessionContext_WaitsForGate(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, err := openSession(pcap)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		s2, e := OpenSessionContext(context.Background(), pcap)
		if e != nil {
			done <- e
			return
		}
		s2.Close()
		done <- nil
	}()

	select {
	case <-done:
		t.Fatal("OpenSessionContext should block while session is active")
	case <-time.After(500 * time.Millisecond):
	}

	s.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("OpenSessionContext after close: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("OpenSessionContext did not acquire gate after Close")
	}
}

func TestSession_OpenSessionContext_ContextCancel(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, err := openSession(pcap)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer s.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = OpenSessionContext(ctx, pcap)
	if err == nil {
		t.Fatal("expected context.Canceled error")
	}
}

func TestSession_OpenSessionContext_ContextTimeout(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, err := openSession(pcap)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer s.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = OpenSessionContext(ctx, pcap)
	if err == nil {
		t.Fatal("expected context.DeadlineExceeded error")
	}
}

func TestSession_FreeFuncWaitsWhenSessionActive(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, err := openSession(pcap)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		e := WalkFrames(pcap, func(_ *FrameData) error { return nil })
		done <- e
	}()

	select {
	case <-done:
		t.Fatal("WalkFrames should block while session is active")
	case <-time.After(500 * time.Millisecond):
	}

	s.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("WalkFrames after release: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("WalkFrames did not complete after gate release")
	}
}

func TestSession_AllowsReopenAfterPantryCallback(t *testing.T) {
	pcap := testfixture.Pcap(t)

	panicWalkFn := func(_ *FrameData) error {
		panic("intentional test panic")
	}

	func() {
		defer func() { recover() }()
		s, err := openSession(pcap)
		if err != nil {
			t.Fatalf("OpenSession: %v", err)
		}
		defer s.Close()

		_ = s.WalkFrames(Query{Filter: "frame.number <= 1"}, panicWalkFn)
	}()

	s2, err := openSession(pcap)
	if err != nil {
		t.Fatalf("OpenSession after panic: %v", err)
	}
	defer s2.Close()

	total := s2.TotalFrames()
	if total <= 0 {
		t.Fatal("expected positive frame count after panic recovery")
	}
}

func TestSession_SessionGateAcquireRelease(t *testing.T) {
	if err := acquireSessionGate(context.Background()); err != nil {
		t.Fatalf("acquire gate: %v", err)
	}
	releaseSessionGate()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := acquireSessionGate(ctx); err == nil {
		t.Fatal("expected canceled context error")
	}
}

func TestSession_PanicCallbackRecovery_GlobalStateCleanup(t *testing.T) {
	pcap := testfixture.Pcap(t)

	func() {
		defer func() { recover() }()
		s, err := openSession(pcap)
		if err != nil {
			t.Fatalf("OpenSession: %v", err)
		}
		defer s.Close()

		panicWalkFn := func(_ *FrameData) error {
			panic("intentional test panic for cleanup")
		}
		_ = s.WalkFrames(Query{Filter: "frame.number <= 2"}, panicWalkFn)
	}()

	if globalFrameSink != nil {
		t.Fatal("globalFrameSink should be nil after panic recovery")
	}
	if globalFrameChan != nil {
		t.Fatal("globalFrameChan should be nil after panic recovery")
	}

	s2, err := openSession(pcap)
	if err != nil {
		t.Fatalf("OpenSession after panic cleanup: %v", err)
	}
	defer s2.Close()

	frames, _, err := s2.FramesPage(Query{}, 1, 1)
	if err != nil {
		t.Fatalf("FramesPage after panic cleanup: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame, got %d", len(frames))
	}
}

func TestSession_FrameNumbers_NoFilter(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	numbers, err := s.FrameNumbers(Query{})
	if err != nil {
		t.Fatal(err)
	}

	total, err := s.FrameCount(Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(numbers) != total {
		t.Fatalf("FrameNumbers length: want %d got %d", total, len(numbers))
	}
	for i, n := range numbers {
		if n != i+1 {
			t.Fatalf("FrameNumbers[%d]: want %d got %d", i, i+1, n)
		}
	}
}

func TestSession_FrameNumbers_WithFilter(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	allNumbers, err := s.FrameNumbers(Query{})
	if err != nil {
		t.Fatal(err)
	}

	tcpNumbers, err := s.FrameNumbers(Query{Filter: "tcp"})
	if err != nil {
		t.Fatal(err)
	}

	expectedCount, err := s.FrameCount(Query{Filter: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	if len(tcpNumbers) != expectedCount {
		t.Fatalf("FrameNumbers(tcp) length: want %d got %d", expectedCount, len(tcpNumbers))
	}

	allSet := make(map[int]bool, len(allNumbers))
	for _, n := range allNumbers {
		allSet[n] = true
	}
	for _, n := range tcpNumbers {
		if !allSet[n] {
			t.Fatalf("FrameNumbers(tcp) returned %d not in all numbers", n)
		}
	}
}

func TestSession_FrameNumbers_Cache(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if _, err := s.FrameNumbers(Query{Filter: "tcp"}); err != nil {
		t.Fatal(err)
	}

	nums2, err := s.FrameNumbers(Query{Filter: "tcp"})
	if err != nil {
		t.Fatal(err)
	}

	expectedCount, err := s.FrameCount(Query{Filter: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	if len(nums2) != expectedCount {
		t.Fatalf("cache FrameNumbers(tcp): want %d got %d", expectedCount, len(nums2))
	}
}

func TestSession_FrameNumbers_ClosedSession(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	if _, err := s.FrameNumbers(Query{}); err != ErrSessionClosed {
		t.Fatalf("expected ErrSessionClosed, got %v", err)
	}
}

func TestSession_FrameNumbers_InvalidFilter(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if _, err := s.FrameNumbers(Query{Filter: "!!invalid!!"}); err == nil {
		t.Fatal("expected error for invalid filter")
	}
}

func TestSession_TimelineBy(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	buckets, err := s.TimelineBy(Query{}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	totalFrames := 0
	totalBytes := int64(0)
	for _, b := range buckets {
		totalFrames += b.FrameCount
		totalBytes += b.ByteCount
	}

	expectedCount, err := s.FrameCount(Query{})
	if err != nil {
		t.Fatal(err)
	}
	if totalFrames != expectedCount {
		t.Fatalf("total frames across buckets: want %d got %d", expectedCount, totalFrames)
	}
	if totalBytes <= 0 {
		t.Fatal("expected non-zero bytes")
	}
}

func TestSession_TimelineBy_MatchesFreeFunc(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	sBuckets, err := s.TimelineBy(Query{}, time.Minute)
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	s.Close()

	fBuckets, err := TimelineBy(pcap, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	if len(sBuckets) != len(fBuckets) {
		t.Fatalf("buckets length mismatch: session=%d free=%d", len(sBuckets), len(fBuckets))
	}

	for i := range sBuckets {
		if sBuckets[i].StartEpoch != fBuckets[i].StartEpoch {
			t.Fatalf("bucket[%d] start: session=%d free=%d", i, sBuckets[i].StartEpoch, fBuckets[i].StartEpoch)
		}
		if sBuckets[i].FrameCount != fBuckets[i].FrameCount {
			t.Fatalf("bucket[%d] FrameCount: session=%d free=%d", i, sBuckets[i].FrameCount, fBuckets[i].FrameCount)
		}
		if sBuckets[i].ByteCount != fBuckets[i].ByteCount {
			t.Fatalf("bucket[%d] ByteCount: session=%d free=%d", i, sBuckets[i].ByteCount, fBuckets[i].ByteCount)
		}
	}
}

func TestSession_TimelineBy_ClosedSession(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	if _, err := s.TimelineBy(Query{}, time.Minute); err != ErrSessionClosed {
		t.Fatalf("expected ErrSessionClosed, got %v", err)
	}
}

func TestSession_TimelineBy_SecondBuckets(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	buckets, err := s.TimelineBy(Query{}, time.Second)
	if err != nil {
		t.Fatal(err)
	}

	for _, b := range buckets {
		if b.EndEpoch-b.StartEpoch != 1 {
			t.Fatalf("expected 1-second buckets, got %d..%d", b.StartEpoch, b.EndEpoch)
		}
	}
}

func TestRace_CloseConcurrentFrame(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			_, _ = s.Frame(1)
		}
	}()

	go func() {
		defer wg.Done()
		time.Sleep(10 * time.Millisecond)
		_ = s.Close()
	}()

	wg.Wait()
}

func TestRace_CloseConcurrentFrameCount(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			_, _ = s.FrameCount(Query{Filter: "tcp"})
		}
	}()

	go func() {
		defer wg.Done()
		time.Sleep(10 * time.Millisecond)
		_ = s.Close()
	}()

	wg.Wait()
}

func TestRace_CloseConcurrentFieldsRows(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			_, _ = s.FieldsRows(Query{Filter: "frame.number <= 3"}, []string{"frame.number", "ip.src"})
		}
	}()

	go func() {
		defer wg.Done()
		time.Sleep(10 * time.Millisecond)
		_ = s.Close()
	}()

	wg.Wait()
}

func TestRace_CloseConcurrentIterFrames(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			iter, err := s.IterFrames(Query{Filter: "frame.number <= 3"})
			if err != nil {
				continue
			}
			for iter.Next() {
				_ = iter.Frame()
			}
			_ = iter.Close()
		}
	}()

	go func() {
		defer wg.Done()
		time.Sleep(10 * time.Millisecond)
		_ = s.Close()
	}()

	wg.Wait()
}

func TestRace_DoubleClose(t *testing.T) {
	pcap := testfixture.Pcap(t)
	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_ = s.Close()
	}()

	go func() {
		defer wg.Done()
		_ = s.Close()
	}()

	wg.Wait()
}
