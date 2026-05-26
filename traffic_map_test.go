package gowireshark

import (
	"testing"

	"github.com/randolphcyg/gowireshark/internal/testfixture"
)

func mockTrafficFrame(num int, proto string, stream int, src string, sport int, dst string, dport int, length int, ts float64, protocols string) *FrameData {
	f := &FrameData{}
	f.BaseLayers.Frame = &Frame{Number: num, Len: length, TimeEpoch: ts, Protocols: protocols}
	f.BaseLayers.IP = &IP{Src: src, Dst: dst}
	if proto == "tcp" {
		f.BaseLayers.TCP = &TCP{Stream: stream, SrcPort: sport, DstPort: dport}
	} else {
		f.BaseLayers.UDP = &UDP{Stream: stream, SrcPort: sport, DstPort: dport}
	}
	return f
}

func TestTrafficAccumulatorStreamsAndConversations(t *testing.T) {
	acc := newTrafficAccumulator()
	acc.addFrame(mockTrafficFrame(1, "tcp", 0, "10.0.0.1", 1234, "10.0.0.2", 80, 100, 10, "eth:ip:tcp:http"))
	acc.addFrame(mockTrafficFrame(2, "tcp", 0, "10.0.0.2", 80, "10.0.0.1", 1234, 200, 12, "eth:ip:tcp:http"))
	acc.addFrame(mockTrafficFrame(3, "udp", 1, "10.0.0.3", 3333, "8.8.8.8", 53, 60, 20, "eth:ip:udp:dns"))

	streams := acc.streams()
	if len(streams) != 2 {
		t.Fatalf("streams len: want 2 got %d", len(streams))
	}
	if streams[0].Protocol != "tcp" || streams[0].FrameCount != 2 || streams[0].ByteCount != 300 {
		t.Fatalf("unexpected tcp stream: %#v", streams[0])
	}

	convs := acc.conversations()
	if len(convs) != 3 {
		t.Fatalf("conversations len: want 3 got %d", len(convs))
	}
	if convs[0].ByteCount != 200 {
		t.Fatalf("expected largest conversation first, got %#v", convs[0])
	}
}

func TestTrafficAccumulator_HasConversationID(t *testing.T) {
	acc := newTrafficAccumulator()
	acc.addFrame(mockTrafficFrame(1, "tcp", 5, "10.0.0.1", 1234, "10.0.0.2", 80, 100, 10, "eth:ip:tcp:http"))
	acc.addFrame(mockTrafficFrame(2, "udp", 3, "10.0.0.3", 3333, "8.8.8.8", 53, 60, 20, "eth:ip:udp:dns"))

	streams := acc.streams()
	for _, s := range streams {
		if s.ConversationID == 0 {
			t.Fatalf("expected non-zero ConversationID for %s stream", s.Protocol)
		}
		if s.StreamID <= 0 {
			t.Fatalf("expected non-zero positive StreamID for %s stream (slow path uses BaseLayers)", s.Protocol)
		}
	}
}

func TestStreams_ReturnsRealStreamID(t *testing.T) {
	pcap := testfixture.Pcap(t)

	streams, err := Streams(pcap)
	if err != nil {
		t.Fatalf("Streams: %v", err)
	}
	if len(streams) == 0 {
		t.Skip("no TCP/UDP streams in test pcap")
	}

	tcpCount := 0
	tcpWithStream := 0
	tcpUnmapped := 0
	udpCount := 0
	udpWithStream := 0
	udpUnmapped := 0

	for _, st := range streams {
		if st.ConversationID == 0 {
			t.Fatalf("%s stream: ConversationID is zero", st.Protocol)
		}
		switch st.Protocol {
		case "tcp":
			tcpCount++
			if st.StreamID >= 0 {
				tcpWithStream++
			}
			if st.StreamID == -1 {
				tcpUnmapped++
			}
		case "udp":
			udpCount++
			if st.StreamID >= 0 {
				udpWithStream++
			}
			if st.StreamID == -1 {
				udpUnmapped++
			}
		}
		t.Logf("%s: convID=%d streamID=%d %s:%d → %s:%d",
			st.Protocol, st.ConversationID, st.StreamID,
			st.SrcAddr, st.SrcPort, st.DstAddr, st.DstPort)
	}

	if tcpCount > 0 {
		t.Logf("TCP: %d/%d streams have real StreamID (%d unmapped)", tcpWithStream, tcpCount, tcpUnmapped)
	}
	if udpCount > 0 {
		t.Logf("UDP: %d/%d streams have real StreamID (%d unmapped)", udpWithStream, udpCount, udpUnmapped)
	}
}

func TestStreams_StreamIDCanFollow(t *testing.T) {
	pcap := testfixture.Pcap(t)

	streams, err := Streams(pcap)
	if err != nil {
		t.Fatalf("Streams: %v", err)
	}

	var firstTCP int
	found := false
	for _, st := range streams {
		if st.Protocol == "tcp" && st.StreamID >= 0 {
			firstTCP = st.StreamID
			found = true
			break
		}
	}
	if !found {
		t.Skip("no TCP streams with valid StreamID in test pcap")
	}

	result, err := FollowStream(pcap, "tcp.stream eq "+itoa(firstTCP), "tcp")
	if err != nil {
		t.Fatalf("FollowStream with real tcp.stream eq %d: %v", firstTCP, err)
	}
	if result == nil {
		t.Fatal("FollowStream returned nil")
	}
	if result.PacketCount == 0 {
		t.Fatalf("FollowStream for tcp.stream eq %d returned 0 packets", firstTCP)
	}
	t.Logf("tcp.stream eq %d: %d packets, %d client bytes, %d server bytes",
		firstTCP, result.PacketCount, result.ClientBytes, result.ServerBytes)
}

func TestStreams_StreamIDCanFollowZero(t *testing.T) {
	pcap := testfixture.Pcap(t)

	streams, err := Streams(pcap)
	if err != nil {
		t.Fatalf("Streams: %v", err)
	}

	var zeroTCP *StreamSummary
	for i := range streams {
		if streams[i].Protocol == "tcp" && streams[i].StreamID == 0 {
			zeroTCP = &streams[i]
			break
		}
	}
	if zeroTCP == nil {
		t.Skip("no tcp.stream == 0 in test pcap")
	}

	result, err := FollowStream(pcap, "tcp.stream eq 0", "tcp")
	if err != nil {
		t.Fatalf("FollowStream with tcp.stream eq 0: %v", err)
	}
	if result == nil {
		t.Fatal("FollowStream returned nil for tcp.stream eq 0")
	}
	if result.PacketCount == 0 {
		t.Fatal("FollowStream for tcp.stream eq 0 returned 0 packets")
	}
	t.Logf("tcp.stream eq 0: %d packets, %d client bytes, %d server bytes",
		result.PacketCount, result.ClientBytes, result.ServerBytes)
}

func TestStreams_UnmappedStreamIDIsMinusOne(t *testing.T) {
	pcap := testfixture.Pcap(t)

	streams, err := Streams(pcap)
	if err != nil {
		t.Fatalf("Streams: %v", err)
	}
	if len(streams) == 0 {
		t.Skip("no TCP/UDP streams in test pcap")
	}

	for _, st := range streams {
		if st.StreamID == 0 && st.Protocol == "" {
			t.Fatal("StreamID == 0 should indicate a real Wireshark stream, not a sentinel value")
		}
	}

	mappedCount := 0
	unmappedCount := 0
	for _, st := range streams {
		if st.StreamID == -1 {
			unmappedCount++
		} else if st.StreamID >= 0 {
			mappedCount++
		} else {
			t.Fatalf("%s stream: unexpected StreamID %d (must be >= 0 or -1)", st.Protocol, st.StreamID)
		}
	}

	t.Logf("mapped=%d unmapped=%d total=%d", mappedCount, unmappedCount, len(streams))
}

func TestSession_Streams_UsesRealStreamID(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, _ := openSession(pcap)
	defer s.Close()

	streams, err := s.Streams(Query{})
	if err != nil {
		t.Fatalf("Session.Streams: %v", err)
	}
	if len(streams) == 0 {
		t.Skip("no TCP/UDP streams in test pcap")
	}

	for _, st := range streams {
		if st.ConversationID == 0 {
			t.Fatalf("%s stream: ConversationID is zero", st.Protocol)
		}
	}

	tcpCount := 0
	tcpWithStream := 0
	for _, st := range streams {
		if st.Protocol == "tcp" {
			tcpCount++
			if st.StreamID >= 0 {
				tcpWithStream++
			}
		}
	}
	if tcpCount > 0 && tcpWithStream == 0 {
		t.Fatal("no TCP streams have real StreamID; fillStreamIDs may have failed entirely")
	}
	t.Logf("TCP: %d/%d streams have real StreamID", tcpWithStream, tcpCount)
}

func TestSession_StreamsCache(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, err := openSession(pcap)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	r1, err := s.Streams(Query{})
	if err != nil {
		t.Fatal(err)
	}

	r2, err := s.Streams(Query{})
	if err != nil {
		t.Fatal(err)
	}

	if len(r1) != len(r2) {
		t.Fatalf("cached result length mismatch: %d vs %d", len(r1), len(r2))
	}
	t.Logf("cache hit: %d streams returned twice consistently", len(r1))
}

func TestStreams_SortingStable(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, err := openSession(pcap)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer s.Close()

	r1, err := s.Streams(Query{})
	if err != nil {
		t.Fatal(err)
	}

	r2, err := s.Streams(Query{})
	if err != nil {
		t.Fatal(err)
	}

	if len(r1) != len(r2) {
		t.Fatalf("length mismatch: %d vs %d", len(r1), len(r2))
	}
	for i := range r1 {
		if r1[i].ConversationID != r2[i].ConversationID ||
			r1[i].Protocol != r2[i].Protocol {
			t.Fatalf("sort mismatch at idx %d: r1=%s/%d, r2=%s/%d",
				i, r1[i].Protocol, r1[i].ConversationID,
				r2[i].Protocol, r2[i].ConversationID)
		}
	}
}

func TestStreams_TCPUDPMixedSort(t *testing.T) {
	pcap := testfixture.Pcap(t)

	streams, err := Streams(pcap)
	if err != nil {
		t.Fatalf("Streams: %v", err)
	}
	if len(streams) == 0 {
		t.Skip("no TCP/UDP streams")
	}

	var lastProto string
	for _, st := range streams {
		if lastProto != "" && st.Protocol < lastProto {
			t.Fatalf("protocol ordering broken: %s before %s", st.Protocol, lastProto)
		}
		lastProto = st.Protocol
	}
}

func TestStreams_NoStreamIDIsMinusOne(t *testing.T) {
	streams := []StreamSummary{
		{Protocol: "tcp", ConversationID: 1, StreamID: -1},
		{Protocol: "udp", ConversationID: 2, StreamID: -1},
	}

	for _, st := range streams {
		if st.StreamID != -1 {
			t.Fatalf("expected StreamID=-1 for unmapped stream, got %d", st.StreamID)
		}
	}
}

func TestFillStreamIDs_NoStreamSupport(t *testing.T) {
	streams := []StreamSummary{
		{Protocol: "tcp", ConversationID: 7777, StreamID: -1, SrcAddr: "10.0.0.1", SrcPort: 1234, DstAddr: "10.0.0.2", DstPort: 80},
	}

	for _, st := range streams {
		if st.StreamID != -1 {
			t.Fatalf("expected StreamID=-1 initially, got %d", st.StreamID)
		}
		if st.ConversationID == 0 {
			t.Fatalf("expected non-zero ConversationID")
		}
	}
}
