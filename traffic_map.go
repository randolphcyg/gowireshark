package gowireshark

import (
	"slices"
	"strings"
	"time"
)

// StreamSummary describes one TCP or UDP stream observed in a capture.
type StreamSummary struct {
	Protocol   string   `json:"protocol"`
	StreamID   int      `json:"streamId"`
	SrcAddr    string   `json:"srcAddr"`
	SrcPort    int      `json:"srcPort"`
	DstAddr    string   `json:"dstAddr"`
	DstPort    int      `json:"dstPort"`
	FrameCount int      `json:"frameCount"`
	ByteCount  int64    `json:"byteCount"`
	StartEpoch float64  `json:"startEpoch"`
	EndEpoch   float64  `json:"endEpoch"`
	Duration   string   `json:"duration"`
	Protocols  []string `json:"protocols"`
}

// ConversationSummary describes one directional 5-tuple aggregate.
type ConversationSummary struct {
	Protocol   string   `json:"protocol"`
	SrcAddr    string   `json:"srcAddr"`
	SrcPort    int      `json:"srcPort"`
	DstAddr    string   `json:"dstAddr"`
	DstPort    int      `json:"dstPort"`
	FrameCount int      `json:"frameCount"`
	ByteCount  int64    `json:"byteCount"`
	StartEpoch float64  `json:"startEpoch"`
	EndEpoch   float64  `json:"endEpoch"`
	Duration   string   `json:"duration"`
	Protocols  []string `json:"protocols"`
}

// TimelineBucket summarizes traffic in one wall-clock interval.
type TimelineBucket struct {
	StartEpoch int64          `json:"startEpoch"`
	EndEpoch   int64          `json:"endEpoch"`
	FrameCount int            `json:"frameCount"`
	ByteCount  int64          `json:"byteCount"`
	Protocols  map[string]int `json:"protocols"`
}

// FileObject describes file-like data observed in protocol dissections without
// writing the object to disk.
type FileObject struct {
	FrameNumber int    `json:"frameNumber"`
	Protocol    string `json:"protocol"`
	Filename    string `json:"filename,omitempty"`
	ContentType string `json:"contentType,omitempty"`
	Size        int64  `json:"size"`
	SrcAddr     string `json:"srcAddr,omitempty"`
	DstAddr     string `json:"dstAddr,omitempty"`
}

// Streams walks a capture and returns TCP/UDP stream aggregates.
func Streams(path string, opts ...Option) ([]StreamSummary, error) {
	acc := newTrafficAccumulator()
	err := WalkFrames(path, func(f *FrameData) error {
		acc.addFrame(f)
		return nil
	}, opts...)
	if err != nil {
		return nil, err
	}
	return acc.streams(), nil
}

// Conversations walks a capture and returns directional 5-tuple aggregates.
func Conversations(path string, opts ...Option) ([]ConversationSummary, error) {
	acc := newTrafficAccumulator()
	err := WalkFrames(path, func(f *FrameData) error {
		acc.addFrame(f)
		return nil
	}, opts...)
	if err != nil {
		return nil, err
	}
	return acc.conversations(), nil
}

// Timeline walks a capture and groups traffic into one-minute buckets.
func Timeline(path string, opts ...Option) ([]TimelineBucket, error) {
	return TimelineBy(path, time.Minute, opts...)
}

// TimelineBy walks a capture and groups traffic into caller-selected buckets.
func TimelineBy(path string, bucket time.Duration, opts ...Option) ([]TimelineBucket, error) {
	if bucket <= 0 {
		bucket = time.Minute
	}
	buckets := map[int64]*TimelineBucket{}
	err := WalkFrames(path, func(f *FrameData) error {
		if f == nil || f.BaseLayers.Frame == nil || f.BaseLayers.Frame.TimeEpoch <= 0 {
			return nil
		}
		sec := int64(f.BaseLayers.Frame.TimeEpoch)
		bucketSec := int64(bucket / time.Second)
		if bucketSec <= 0 {
			bucketSec = 1
		}
		start := sec - (sec % bucketSec)
		b := buckets[start]
		if b == nil {
			b = &TimelineBucket{StartEpoch: start, EndEpoch: start + bucketSec, Protocols: map[string]int{}}
			buckets[start] = b
		}
		b.FrameCount++
		b.ByteCount += int64(f.BaseLayers.Frame.Len)
		for _, proto := range protocolList(f.BaseLayers.Frame.Protocols) {
			b.Protocols[proto]++
		}
		return nil
	}, opts...)
	if err != nil {
		return nil, err
	}
	out := make([]TimelineBucket, 0, len(buckets))
	for _, b := range buckets {
		out = append(out, *b)
	}
	slices.SortFunc(out, func(a, b TimelineBucket) int { return int(a.StartEpoch - b.StartEpoch) })
	return out, nil
}

// Files walks a capture and returns file-like metadata surfaced by dissectors.
func Files(path string, opts ...Option) ([]FileObject, error) {
	var out []FileObject
	err := WalkFrames(path, func(f *FrameData) error {
		out = append(out, filesFromFrame(f)...)
		return nil
	}, opts...)
	return out, err
}

type trafficAccumulator struct {
	streamMap map[string]*StreamSummary
	convMap   map[string]*ConversationSummary
}

func newTrafficAccumulator() *trafficAccumulator {
	return &trafficAccumulator{streamMap: map[string]*StreamSummary{}, convMap: map[string]*ConversationSummary{}}
}

func (a *trafficAccumulator) addFrame(f *FrameData) {
	if f == nil || f.BaseLayers.Frame == nil || f.BaseLayers.IP == nil {
		return
	}
	fr := f.BaseLayers.Frame
	ip := f.BaseLayers.IP
	proto, streamID, srcPort, dstPort, ok := transportTuple(f)
	if !ok {
		return
	}
	byteCount := int64(fr.Len)
	protos := protocolList(fr.Protocols)

	sk := proto + ":" + itoa(streamID)
	s := a.streamMap[sk]
	if s == nil {
		s = &StreamSummary{Protocol: proto, StreamID: streamID, SrcAddr: ip.Src, SrcPort: srcPort, DstAddr: ip.Dst, DstPort: dstPort, Protocols: protos}
		a.streamMap[sk] = s
	}
	updateStreamSummary(s, fr.TimeEpoch, byteCount, protos)

	ck := proto + ":" + ip.Src + ":" + itoa(srcPort) + ">" + ip.Dst + ":" + itoa(dstPort)
	c := a.convMap[ck]
	if c == nil {
		c = &ConversationSummary{Protocol: proto, SrcAddr: ip.Src, SrcPort: srcPort, DstAddr: ip.Dst, DstPort: dstPort, Protocols: protos}
		a.convMap[ck] = c
	}
	updateConversationSummary(c, fr.TimeEpoch, byteCount, protos)
}

func (a *trafficAccumulator) streams() []StreamSummary {
	out := make([]StreamSummary, 0, len(a.streamMap))
	for _, s := range a.streamMap {
		finalizeStream(s)
		out = append(out, *s)
	}
	slices.SortFunc(out, func(a, b StreamSummary) int {
		if a.Protocol != b.Protocol {
			return strings.Compare(a.Protocol, b.Protocol)
		}
		return a.StreamID - b.StreamID
	})
	return out
}

func (a *trafficAccumulator) conversations() []ConversationSummary {
	out := make([]ConversationSummary, 0, len(a.convMap))
	for _, c := range a.convMap {
		finalizeConversation(c)
		out = append(out, *c)
	}
	slices.SortFunc(out, func(a, b ConversationSummary) int {
		if a.ByteCount != b.ByteCount {
			return int(b.ByteCount - a.ByteCount)
		}
		return b.FrameCount - a.FrameCount
	})
	return out
}

func transportTuple(f *FrameData) (proto string, streamID, srcPort, dstPort int, ok bool) {
	if f.BaseLayers.TCP != nil {
		return "tcp", f.BaseLayers.TCP.Stream, f.BaseLayers.TCP.SrcPort, f.BaseLayers.TCP.DstPort, true
	}
	if f.BaseLayers.UDP != nil {
		return "udp", f.BaseLayers.UDP.Stream, f.BaseLayers.UDP.SrcPort, f.BaseLayers.UDP.DstPort, true
	}
	return "", 0, 0, 0, false
}

func updateStreamSummary(s *StreamSummary, ts float64, bytes int64, protos []string) {
	s.FrameCount++
	s.ByteCount += bytes
	if ts > 0 && (s.StartEpoch == 0 || ts < s.StartEpoch) {
		s.StartEpoch = ts
	}
	if ts > s.EndEpoch {
		s.EndEpoch = ts
	}
	s.Protocols = mergeProtocols(s.Protocols, protos)
}

func updateConversationSummary(c *ConversationSummary, ts float64, bytes int64, protos []string) {
	c.FrameCount++
	c.ByteCount += bytes
	if ts > 0 && (c.StartEpoch == 0 || ts < c.StartEpoch) {
		c.StartEpoch = ts
	}
	if ts > c.EndEpoch {
		c.EndEpoch = ts
	}
	c.Protocols = mergeProtocols(c.Protocols, protos)
}

func finalizeStream(s *StreamSummary) {
	if s.EndEpoch > s.StartEpoch {
		s.Duration = time.Duration((s.EndEpoch - s.StartEpoch) * float64(time.Second)).String()
	}
}

func finalizeConversation(c *ConversationSummary) {
	if c.EndEpoch > c.StartEpoch {
		c.Duration = time.Duration((c.EndEpoch - c.StartEpoch) * float64(time.Second)).String()
	}
}

func protocolList(protocols string) []string {
	parts := strings.Split(protocols, ":")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func mergeProtocols(existing, added []string) []string {
	seen := make(map[string]bool, len(existing)+len(added))
	out := make([]string, 0, len(existing)+len(added))
	for _, p := range append(existing, added...) {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

func filesFromFrame(f *FrameData) []FileObject {
	if f == nil || f.BaseLayers.Frame == nil {
		return nil
	}
	var out []FileObject
	if f.BaseLayers.HTTP != nil {
		for _, h := range f.BaseLayers.HTTP {
			if h == nil || h.FileData == "" {
				continue
			}
			fo := FileObject{FrameNumber: f.BaseLayers.Frame.Number, Protocol: "http", ContentType: h.ContentType, Size: int64(len(h.FileData) / 2)}
			if f.BaseLayers.IP != nil {
				fo.SrcAddr, fo.DstAddr = f.BaseLayers.IP.Src, f.BaseLayers.IP.Dst
			}
			out = append(out, fo)
		}
	}
	return out
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
