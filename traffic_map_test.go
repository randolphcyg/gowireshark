package gowireshark

import "testing"

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
