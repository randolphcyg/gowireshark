package analysis

import (
	"strings"
	"testing"

	"github.com/randolphcyg/gowireshark"
	"github.com/randolphcyg/gowireshark/internal/testfixture"
)

func makeMockFrame(num int, protocolStack string, src, dst string, frameLen int, timeEpoch float64) *gowireshark.FrameData {
	fd := &gowireshark.FrameData{}
	fd.BaseLayers.Frame = &gowireshark.Frame{
		Number:    num,
		Len:       frameLen,
		Protocols: protocolStack,
		TimeEpoch: timeEpoch,
	}
	if src != "" || dst != "" {
		fd.BaseLayers.IP = &gowireshark.IP{
			Src: src,
			Dst: dst,
		}
	}
	return fd
}

func TestAnalyze_EmptyFrames(t *testing.T) {
	s := Analyze(nil)
	if s.FrameCount != 0 || s.ByteCount != 0 || len(s.Protocols) != 0 || len(s.Endpoints) != 0 {
		t.Fatal("expected empty Summary for nil input")
	}

	s = Analyze([]*gowireshark.FrameData{})
	if s.FrameCount != 0 || s.ByteCount != 0 {
		t.Fatal("expected empty Summary for empty slice")
	}
}

func TestAnalyze_BasicStats(t *testing.T) {
	frames := []*gowireshark.FrameData{
		makeMockFrame(1, "eth:ethertype:ip:tcp:http", "10.0.0.1", "10.0.0.2", 100, 1000.0),
		makeMockFrame(2, "eth:ethertype:ip:tcp:http", "10.0.0.1", "10.0.0.2", 200, 1001.0),
		makeMockFrame(3, "eth:ethertype:ip:udp:dns", "10.0.0.1", "10.0.0.3", 80, 1002.0),
	}

	s := Analyze(frames)

	if s.FrameCount != 3 {
		t.Fatalf("FrameCount: want 3, got %d", s.FrameCount)
	}
	if s.ByteCount != 380 {
		t.Fatalf("ByteCount: want 380, got %d", s.ByteCount)
	}
	if s.Duration != 2*1e9 {
		t.Fatalf("Duration: want 2s, got %v", s.Duration)
	}

	protoMap := make(map[string]int)
	for _, p := range s.Protocols {
		protoMap[p.Protocol] = p.FrameCount
	}
	if protoMap["http"] != 2 {
		t.Errorf("http FrameCount: want 2, got %d", protoMap["http"])
	}
	if protoMap["dns"] != 1 {
		t.Errorf("dns FrameCount: want 1, got %d", protoMap["dns"])
	}
	if protoMap["tcp"] != 2 {
		t.Errorf("tcp FrameCount: want 2, got %d", protoMap["tcp"])
	}
	if protoMap["udp"] != 1 {
		t.Errorf("udp FrameCount: want 1, got %d", protoMap["udp"])
	}

	endpointMap := make(map[string]EndpointStat)
	for _, ep := range s.Endpoints {
		endpointMap[ep.Address] = ep
	}
	if ep, ok := endpointMap["10.0.0.1"]; !ok || ep.FrameCount != 3 {
		t.Errorf("10.0.0.1 FrameCount: want 3, got %v", ep)
	}
	if ep, ok := endpointMap["10.0.0.2"]; !ok || ep.FrameCount != 2 {
		t.Errorf("10.0.0.2 FrameCount: want 2, got %v", ep)
	}
	if ep, ok := endpointMap["10.0.0.3"]; !ok || ep.FrameCount != 1 {
		t.Errorf("10.0.0.3 FrameCount: want 1, got %v", ep)
	}
}

func TestAnalyze_Percentage(t *testing.T) {
	frames := []*gowireshark.FrameData{
		makeMockFrame(1, "eth:ip:tcp:http", "10.0.0.1", "10.0.0.2", 100, 1000.0),
		makeMockFrame(2, "eth:ip:tcp", "10.0.0.1", "10.0.0.2", 200, 1001.0),
	}

	s := Analyze(frames)

	for _, p := range s.Protocols {
		if p.Protocol == "http" && p.Percentage != 50.0 {
			t.Errorf("http Percentage: want 50.0, got %f", p.Percentage)
		}
		if p.Protocol == "tcp" && p.Percentage != 100.0 {
			t.Errorf("tcp Percentage: want 100.0, got %f", p.Percentage)
		}
	}

	for _, ep := range s.Endpoints {
		if ep.Address == "10.0.0.1" {
			if ep.ByteCount != 300 {
				t.Errorf("10.0.0.1 ByteCount: want 300, got %d", ep.ByteCount)
			}
			if ep.Percentage != 50.0 {
				t.Errorf("10.0.0.1 Percentage: want 50.0, got %f", ep.Percentage)
			}
		}
	}
}

func TestAnalyze_NoIP(t *testing.T) {
	frames := []*gowireshark.FrameData{
		makeMockFrame(1, "eth:arp", "", "", 60, 1000.0),
	}

	s := Analyze(frames)

	if s.FrameCount != 1 {
		t.Fatalf("FrameCount: want 1, got %d", s.FrameCount)
	}
	if len(s.Endpoints) != 0 {
		t.Fatalf("Endpoints: want 0, got %d", len(s.Endpoints))
	}
	if arpCount, ok := protoCount(s.Protocols)["arp"]; !ok || arpCount != 1 {
		t.Errorf("arp not found in protocol stats")
	}
}

func TestAnalyze_NilFrameSafety(t *testing.T) {
	frames := []*gowireshark.FrameData{
		nil,
		makeMockFrame(1, "eth:ip:tcp", "10.0.0.1", "10.0.0.2", 100, 1000.0),
		nil,
	}

	s := Analyze(frames)
	if s.FrameCount != 1 {
		t.Fatalf("FrameCount: want 1, got %d", s.FrameCount)
	}
}

func TestWalkAnalyze_MatchesFramesAnalyze(t *testing.T) {
	pcapFile := testfixture.Pcap(t)

	frames, err := gowireshark.Frames(pcapFile)
	if err != nil {
		t.Fatal(err)
	}
	expected := Analyze(frames)

	actual, err := WalkAnalyze(pcapFile)
	if err != nil {
		t.Fatal(err)
	}

	if expected.FrameCount != actual.FrameCount {
		t.Errorf("FrameCount: Frames+Analyze=%d WalkAnalyze=%d", expected.FrameCount, actual.FrameCount)
	}
	if expected.ByteCount != actual.ByteCount {
		t.Errorf("ByteCount: Frames+Analyze=%d WalkAnalyze=%d", expected.ByteCount, actual.ByteCount)
	}

	expProto := protoCount(expected.Protocols)
	actProto := protoCount(actual.Protocols)
	for proto, expCount := range expProto {
		actCount, ok := actProto[proto]
		if !ok {
			t.Errorf("protocol %q missing from WalkAnalyze result", proto)
		} else if actCount != expCount {
			t.Errorf("protocol %q: Frames=%d Walk=%d", proto, expCount, actCount)
		}
	}

	if len(expected.Endpoints) != len(actual.Endpoints) {
		t.Errorf("Endpoint count: Frames=%d Walk=%d", len(expected.Endpoints), len(actual.Endpoints))
	}
}

func TestWalkAnalyze_WithDisplayFilter(t *testing.T) {
	pcapFile := testfixture.Pcap(t)

	summary, err := WalkAnalyze(pcapFile, gowireshark.WithDisplayFilter("frame.number <= 2"))
	if err != nil {
		t.Fatal(err)
	}

	if summary.FrameCount > 2 {
		t.Fatalf("expected at most 2 frames with filter, got %d", summary.FrameCount)
	}
}

func TestWalkAnalyze_FileNotFound(t *testing.T) {
	_, err := WalkAnalyze("/nonexistent/file.pcap")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected 'not found' error, got %v", err)
	}
}

func TestProtocolStatsSortedByCount(t *testing.T) {
	frames := []*gowireshark.FrameData{
		makeMockFrame(1, "eth:ip:tcp:http", "10.0.0.1", "10.0.0.2", 100, 1000.0),
		makeMockFrame(2, "eth:ip:tcp:http", "10.0.0.1", "10.0.0.2", 100, 1001.0),
		makeMockFrame(3, "eth:ip:tcp:http", "10.0.0.1", "10.0.0.2", 100, 1002.0),
		makeMockFrame(4, "eth:ip:udp:dns", "10.0.0.1", "10.0.0.3", 80, 1003.0),
		makeMockFrame(5, "eth:ip:udp:dns", "10.0.0.1", "10.0.0.3", 80, 1004.0),
		makeMockFrame(6, "eth:arp", "", "", 60, 1005.0),
	}

	s := Analyze(frames)

	for i := 1; i < len(s.Protocols); i++ {
		if s.Protocols[i-1].FrameCount < s.Protocols[i].FrameCount {
			t.Errorf("protocols not sorted by FrameCount descending: %s(%d) before %s(%d)",
				s.Protocols[i-1].Protocol, s.Protocols[i-1].FrameCount,
				s.Protocols[i].Protocol, s.Protocols[i].FrameCount)
		}
	}
}

func protoCount(stats []ProtocolStat) map[string]int {
	m := make(map[string]int, len(stats))
	for _, s := range stats {
		m[s.Protocol] = s.FrameCount
	}
	return m
}