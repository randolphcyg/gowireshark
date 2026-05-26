package analysis

import (
	"slices"
	"strings"
	"time"

	"github.com/randolphcyg/gowireshark"
)

// Summary is the top-level aggregation result.
type Summary struct {
	FrameCount int            `json:"frameCount"`
	ByteCount  int64          `json:"byteCount"`
	Duration   time.Duration  `json:"duration"`
	Protocols  []ProtocolStat `json:"protocols"`
	Endpoints  []EndpointStat `json:"endpoints"`
}

// ProtocolStat describes the presence of one protocol layer.
type ProtocolStat struct {
	Protocol   string  `json:"protocol"`
	FrameCount int     `json:"frameCount"`
	Percentage float64 `json:"percentage"`
}

// EndpointStat describes traffic for one IP endpoint.
type EndpointStat struct {
	Address    string  `json:"address"`
	FrameCount int     `json:"frameCount"`
	ByteCount  int64   `json:"byteCount"`
	Percentage float64 `json:"percentage"`
}

// Analyze computes summary statistics from already-collected frames.
func Analyze(frames []*gowireshark.FrameData) *Summary {
	s := &Summary{}

	if len(frames) == 0 {
		return s
	}

	protoCount := make(map[string]int)
	endpointFrames := make(map[string]int)
	endpointBytes := make(map[string]int64)
	var firstTS, lastTS float64

	for i, frame := range frames {
		if frame == nil {
			continue
		}

		f := frame.BaseLayers.Frame
		ip := frame.BaseLayers.IP

		if f != nil {
			s.FrameCount++
			s.ByteCount += int64(f.Len)

			if f.TimeEpoch > 0 {
				if i == 0 || f.TimeEpoch < firstTS {
					firstTS = f.TimeEpoch
				}
				if f.TimeEpoch > lastTS {
					lastTS = f.TimeEpoch
				}
			}

			for _, proto := range strings.Split(f.Protocols, ":") {
				if proto != "" {
					protoCount[proto]++
				}
			}
		}

		if ip != nil {
			frameLen := 0
			if f != nil {
				frameLen = f.Len
			}

			endpointFrames[ip.Src]++
			endpointBytes[ip.Src] += int64(frameLen)
			endpointFrames[ip.Dst]++
			endpointBytes[ip.Dst] += int64(frameLen)
		}
	}

	if lastTS > firstTS {
		s.Duration = time.Duration((lastTS - firstTS) * float64(time.Second))
	}

	s.Protocols = buildProtocolStats(protoCount, s.FrameCount)
	s.Endpoints = buildEndpointStats(endpointFrames, endpointBytes)

	return s
}

// WalkAnalyze walks a pcap file and computes summary statistics without
// keeping all frames in memory.
func WalkAnalyze(path string, opts ...gowireshark.Option) (*Summary, error) {
	s := &Summary{}
	protoCount := make(map[string]int)
	endpointFrames := make(map[string]int)
	endpointBytes := make(map[string]int64)
	var firstTS, lastTS float64
	var frameIdx int

	err := gowireshark.WalkFrames(path, func(frame *gowireshark.FrameData) error {
		if frame == nil {
			return nil
		}

		f := frame.BaseLayers.Frame
		ip := frame.BaseLayers.IP

		if f != nil {
			s.FrameCount++
			s.ByteCount += int64(f.Len)

			if f.TimeEpoch > 0 {
				if frameIdx == 0 || f.TimeEpoch < firstTS {
					firstTS = f.TimeEpoch
				}
				if f.TimeEpoch > lastTS {
					lastTS = f.TimeEpoch
				}
			}

			for _, proto := range strings.Split(f.Protocols, ":") {
				if proto != "" {
					protoCount[proto]++
				}
			}
		}

		if ip != nil {
			frameLen := 0
			if f != nil {
				frameLen = f.Len
			}

			endpointFrames[ip.Src]++
			endpointBytes[ip.Src] += int64(frameLen)
			endpointFrames[ip.Dst]++
			endpointBytes[ip.Dst] += int64(frameLen)
		}

		frameIdx++
		return nil
	}, opts...)

	if err != nil {
		return nil, err
	}

	if lastTS > firstTS {
		s.Duration = time.Duration((lastTS - firstTS) * float64(time.Second))
	}

	s.Protocols = buildProtocolStats(protoCount, s.FrameCount)
	s.Endpoints = buildEndpointStats(endpointFrames, endpointBytes)

	return s, nil
}

func buildProtocolStats(protoCount map[string]int, totalFrames int) []ProtocolStat {
	stats := make([]ProtocolStat, 0, len(protoCount))
	for proto, count := range protoCount {
		pct := float64(0)
		if totalFrames > 0 {
			pct = float64(count) / float64(totalFrames) * 100
		}
		stats = append(stats, ProtocolStat{
			Protocol:   proto,
			FrameCount: count,
			Percentage: pct,
		})
	}
	slices.SortFunc(stats, func(a, b ProtocolStat) int {
		return b.FrameCount - a.FrameCount
	})
	return stats
}

func buildEndpointStats(endpointFrames map[string]int, endpointBytes map[string]int64) []EndpointStat {
	var totalBytes int64
	for _, bytes := range endpointBytes {
		totalBytes += bytes
	}

	stats := make([]EndpointStat, 0, len(endpointFrames))
	for addr, frames := range endpointFrames {
		bytes := endpointBytes[addr]
		pct := float64(0)
		if totalBytes > 0 {
			pct = float64(bytes) / float64(totalBytes) * 100
		}
		stats = append(stats, EndpointStat{
			Address:    addr,
			FrameCount: frames,
			ByteCount:  bytes,
			Percentage: pct,
		})
	}
	slices.SortFunc(stats, func(a, b EndpointStat) int {
		if a.ByteCount != b.ByteCount {
			return int(b.ByteCount - a.ByteCount)
		}
		return b.FrameCount - a.FrameCount
	})
	return stats
}
