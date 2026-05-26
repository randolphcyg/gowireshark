package bench

import (
	"fmt"
	"os"
	"testing"

	"github.com/randolphcyg/gowireshark"
)

func benchPcapOrSkip(tb testing.TB) string {
	tb.Helper()
	pcap := BenchPcap()
	if pcap == "" {
		tb.Skip("no benchmark pcap; set GOWIRESHARK_BENCH_PCAP or place .pcap in ./pcaps")
	}
	return pcap
}

func benchTsharkOrSkip(tb testing.TB) string {
	tb.Helper()
	tshark := TsharkPath()
	if tshark == "" {
		tb.Skip("tshark not found; set GOWIRESHARK_TSHARK or add to PATH")
	}
	return tshark
}

func warmSessionForBenchmark(b *testing.B, pcap string) *WarmSession {
	b.Helper()
	warm := NewWarmSession(pcap)
	if err := warm.Setup(); err != nil {
		b.Fatalf("warm setup: %v", err)
	}
	b.Cleanup(func() {
		b.StopTimer()
		warm.Teardown()
	})
	b.ResetTimer()
	return warm
}

func BenchmarkFrameLookup(b *testing.B) {
	pcap := benchPcapOrSkip(b)

	gr := NewGowiresharkRunner(pcap)
	mid := gr.frameCountFromSession() / 2
	last := gr.frameCountFromSession()
	if last < 1 {
		b.Fatal("pcap has no frames")
	}

	b.Run("gowireshark_cold_first", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := gr.FrameLookupCold(1)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_warm_first", func(b *testing.B) {
		warm := warmSessionForBenchmark(b, pcap)
		for i := 0; i < b.N; i++ {
			_, _, err := warm.FrameLookup(1)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_cold_mid", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := gr.FrameLookupCold(mid)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_warm_mid", func(b *testing.B) {
		warm := warmSessionForBenchmark(b, pcap)
		for i := 0; i < b.N; i++ {
			_, _, err := warm.FrameLookup(mid)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_cold_last", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := gr.FrameLookupCold(last)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_warm_last", func(b *testing.B) {
		warm := warmSessionForBenchmark(b, pcap)
		for i := 0; i < b.N; i++ {
			_, _, err := warm.FrameLookup(last)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	tshark := TsharkPath()
	if tshark != "" {
		tr := NewTsharkRunner(pcap, tshark)
		b.Run("tshark_subprocess_first", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, err := tr.FrameLookup(1)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("tshark_subprocess_mid", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, err := tr.FrameLookup(mid)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("tshark_subprocess_last", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, err := tr.FrameLookup(last)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkFields(b *testing.B) {
	pcap := benchPcapOrSkip(b)

	gr := NewGowiresharkRunner(pcap)

	fields := []string{"frame.number", "frame.len", "ip.src", "ip.dst", "_ws.col.info"}

	b.Run("gowireshark_cold", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := gr.FieldsCold(fields)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_warm", func(b *testing.B) {
		warm := warmSessionForBenchmark(b, pcap)
		for i := 0; i < b.N; i++ {
			_, _, err := warm.Fields(fields)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	tshark := TsharkPath()
	if tshark != "" {
		tr := NewTsharkRunner(pcap, tshark)
		b.Run("tshark_subprocess", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, err := tr.Fields(fields)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkExpertInfo(b *testing.B) {
	pcap := benchPcapOrSkip(b)

	gr := NewGowiresharkRunner(pcap)

	b.Run("gowireshark_cold", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := gr.ExpertInfoCold()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_warm", func(b *testing.B) {
		warm := warmSessionForBenchmark(b, pcap)
		for i := 0; i < b.N; i++ {
			_, _, err := warm.ExpertInfo()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	tshark := TsharkPath()
	if tshark != "" {
		tr := NewTsharkRunner(pcap, tshark)
		b.Run("tshark_subprocess", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, err := tr.ExpertInfo()
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkFollowStream(b *testing.B) {
	pcap := benchPcapOrSkip(b)

	gr := NewGowiresharkRunner(pcap)
	if !gr.hasTCPFromSession() {
		b.Skip("pcap has no TCP streams")
	}

	streamID := gr.firstTCPStreamFromSession()
	if streamID < 0 {
		b.Skip("no TCP stream with valid StreamID found")
	}
	streamFilter := fmt.Sprintf("tcp.stream eq %d", streamID)

	b.Run("gowireshark_cold", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := gr.FollowStreamCold(streamFilter)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_warm", func(b *testing.B) {
		warm := warmSessionForBenchmark(b, pcap)
		for i := 0; i < b.N; i++ {
			_, _, err := warm.FollowStream(streamFilter)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	tshark := TsharkPath()
	if tshark != "" {
		tr := NewTsharkRunner(pcap, tshark)
		b.Run("tshark_subprocess", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, err := tr.FollowStream(streamID)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkStreamList(b *testing.B) {
	pcap := benchPcapOrSkip(b)

	gr := NewGowiresharkRunner(pcap)

	b.Run("gowireshark_cold_tcp", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := gr.StreamListTCPCold()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_warm_tcp", func(b *testing.B) {
		warm := warmSessionForBenchmark(b, pcap)
		for i := 0; i < b.N; i++ {
			_, _, err := warm.StreamListTCP()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_cold_udp", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := gr.StreamListUDPCold()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_warm_udp", func(b *testing.B) {
		warm := warmSessionForBenchmark(b, pcap)
		for i := 0; i < b.N; i++ {
			_, _, err := warm.StreamListUDP()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_cold_all", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := gr.StreamListCold()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_warm_all", func(b *testing.B) {
		warm := warmSessionForBenchmark(b, pcap)
		for i := 0; i < b.N; i++ {
			_, _, err := warm.StreamList()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	tshark := TsharkPath()
	if tshark != "" {
		tr := NewTsharkRunner(pcap, tshark)
		b.Run("tshark_subprocess_tcp", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, err := tr.StreamListTCP()
				if err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("tshark_subprocess_udp", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, err := tr.StreamListUDP()
				if err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("tshark_subprocess_all", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, err := tr.StreamListAll()
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkPcapSlice(b *testing.B) {
	pcap := benchPcapOrSkip(b)

	gr := NewGowiresharkRunner(pcap)

	b.Run("gowireshark_cold", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := gr.PcapSliceCold(100)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_warm", func(b *testing.B) {
		warm := warmSessionForBenchmark(b, pcap)
		for i := 0; i < b.N; i++ {
			_, _, err := warm.PcapSlice(100)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	tshark := TsharkPath()
	if tshark != "" {
		tmpDir, err := os.MkdirTemp("", "gowireshark-bench")
		if err != nil {
			b.Fatalf("temp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		tr := NewTsharkRunner(pcap, tshark)
		b.Run("tshark_subprocess", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, err := tr.PcapSlice(tmpDir, 100)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkFieldsOccurrence(b *testing.B) {
	pcap := benchPcapOrSkip(b)

	gr := NewGowiresharkRunner(pcap)
	fields := []string{"ip.src", "ip.dst", "frame.protocols"}

	b.Run("gowireshark_cold_first", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := gr.FieldsRowsOccurrenceCold(fields, gowireshark.OccurrenceFirst)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_warm_first", func(b *testing.B) {
		warm := warmSessionForBenchmark(b, pcap)
		for i := 0; i < b.N; i++ {
			_, _, err := warm.FieldsRowsOccurrence(fields, gowireshark.OccurrenceFirst)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_cold_last", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := gr.FieldsRowsOccurrenceCold(fields, gowireshark.OccurrenceLast)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_warm_last", func(b *testing.B) {
		warm := warmSessionForBenchmark(b, pcap)
		for i := 0; i < b.N; i++ {
			_, _, err := warm.FieldsRowsOccurrence(fields, gowireshark.OccurrenceLast)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_cold_all", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := gr.FieldsRowsValuesCold(fields)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_warm_all", func(b *testing.B) {
		warm := warmSessionForBenchmark(b, pcap)
		for i := 0; i < b.N; i++ {
			_, _, err := warm.FieldsRowsValues(fields)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_cold_baseline", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := gr.FieldsCold(fields)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_warm_baseline", func(b *testing.B) {
		warm := warmSessionForBenchmark(b, pcap)
		for i := 0; i < b.N; i++ {
			_, _, err := warm.Fields(fields)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkFrameCount(b *testing.B) {
	pcap := benchPcapOrSkip(b)

	gr := NewGowiresharkRunner(pcap)

	b.Run("gowireshark_cold", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = gr.FrameCount()
		}
	})

	b.Run("gowireshark_warm", func(b *testing.B) {
		warm := warmSessionForBenchmark(b, pcap)
		for i := 0; i < b.N; i++ {
			_ = warm.sess.TotalFrames()
		}
	})

	tshark := TsharkPath()
	if tshark != "" {
		tr := NewTsharkRunner(pcap, tshark)
		b.Run("tshark_subprocess", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = tr.FrameCount()
			}
		})
	}
}

func BenchmarkFrameNumbers(b *testing.B) {
	pcap := benchPcapOrSkip(b)

	gr := NewGowiresharkRunner(pcap)

	b.Run("gowireshark_cold_nofilter", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := gr.FrameNumbersCold("")
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_cold_filter", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := gr.FrameNumbersCold("ip")
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_warm_nofilter", func(b *testing.B) {
		warm := warmSessionForBenchmark(b, pcap)
		for i := 0; i < b.N; i++ {
			_, _, err := warm.FrameNumbers("")
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_warm_filter", func(b *testing.B) {
		warm := warmSessionForBenchmark(b, pcap)
		for i := 0; i < b.N; i++ {
			_, _, err := warm.FrameNumbers("ip")
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	tshark := TsharkPath()
	if tshark != "" {
		tr := NewTsharkRunner(pcap, tshark)
		b.Run("tshark_subprocess_nofilter", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, err := tr.FrameNumbers("")
				if err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("tshark_subprocess_filter", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, err := tr.FrameNumbers("ip")
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkIOStats(b *testing.B) {
	pcap := benchPcapOrSkip(b)

	gr := NewGowiresharkRunner(pcap)

	b.Run("gowireshark_cold", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := gr.IOStatsCold(1.0)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_warm", func(b *testing.B) {
		warm := warmSessionForBenchmark(b, pcap)
		for i := 0; i < b.N; i++ {
			_, _, err := warm.IOStats(1.0)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	tshark := TsharkPath()
	if tshark != "" {
		tr := NewTsharkRunner(pcap, tshark)
		b.Run("tshark_subprocess", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, err := tr.IOStats(1.0)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkProtocolHierarchy(b *testing.B) {
	pcap := benchPcapOrSkip(b)

	gr := NewGowiresharkRunner(pcap)

	b.Run("gowireshark_cold", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := gr.ProtocolHierarchyCold()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_warm", func(b *testing.B) {
		warm := warmSessionForBenchmark(b, pcap)
		for i := 0; i < b.N; i++ {
			_, _, err := warm.ProtocolHierarchy()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	tshark := TsharkPath()
	if tshark != "" {
		tr := NewTsharkRunner(pcap, tshark)
		b.Run("tshark_subprocess", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, err := tr.ProtocolHierarchy()
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkServiceResponseTimes(b *testing.B) {
	pcap := benchPcapOrSkip(b)

	gr := NewGowiresharkRunner(pcap)

	b.Run("gowireshark_cold_smb", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			records, _, err := gr.ServiceResponseTimesCold("smb")
			if err != nil {
				if records == 0 && b.N == 1 {
					b.Skip("no SMB traffic in pcap")
				}
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_warm_smb", func(b *testing.B) {
		warm := warmSessionForBenchmark(b, pcap)
		for i := 0; i < b.N; i++ {
			records, _, err := warm.ServiceResponseTimes("smb")
			if err != nil {
				if records == 0 && b.N == 1 {
					b.Skip("no SMB traffic in pcap")
				}
				b.Fatal(err)
			}
		}
	})

	tshark := TsharkPath()
	if tshark != "" {
		tr := NewTsharkRunner(pcap, tshark)
		b.Run("tshark_subprocess_smb", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, err := tr.ServiceResponseTimes("smb")
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkTapConversations(b *testing.B) {
	pcap := benchPcapOrSkip(b)

	gr := NewGowiresharkRunner(pcap)

	b.Run("gowireshark_cold_ip", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := gr.TapConversationsCold("ip")
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_warm_ip", func(b *testing.B) {
		warm := warmSessionForBenchmark(b, pcap)
		for i := 0; i < b.N; i++ {
			_, _, err := warm.TapConversations("ip")
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_cold_tcp", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := gr.TapConversationsCold("tcp")
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_warm_tcp", func(b *testing.B) {
		warm := warmSessionForBenchmark(b, pcap)
		for i := 0; i < b.N; i++ {
			_, _, err := warm.TapConversations("tcp")
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	tshark := TsharkPath()
	if tshark != "" {
		tr := NewTsharkRunner(pcap, tshark)
		b.Run("tshark_subprocess_ip", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, err := tr.TapConversations("ip")
				if err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("tshark_subprocess_tcp", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, err := tr.TapConversations("tcp")
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkTapEndpoints(b *testing.B) {
	pcap := benchPcapOrSkip(b)

	gr := NewGowiresharkRunner(pcap)

	b.Run("gowireshark_cold_ip", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := gr.TapEndpointsCold("ip")
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_warm_ip", func(b *testing.B) {
		warm := warmSessionForBenchmark(b, pcap)
		for i := 0; i < b.N; i++ {
			_, _, err := warm.TapEndpoints("ip")
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	tshark := TsharkPath()
	if tshark != "" {
		tr := NewTsharkRunner(pcap, tshark)
		b.Run("tshark_subprocess_ip", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, err := tr.TapEndpoints("ip")
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkTimeline(b *testing.B) {
	pcap := benchPcapOrSkip(b)

	gr := NewGowiresharkRunner(pcap)

	b.Run("gowireshark_cold", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := gr.TimelineCold()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_warm", func(b *testing.B) {
		warm := warmSessionForBenchmark(b, pcap)
		for i := 0; i < b.N; i++ {
			_, _, err := warm.Timeline()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	tshark := TsharkPath()
	if tshark != "" {
		tr := NewTsharkRunner(pcap, tshark)
		b.Run("tshark_subprocess", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, err := tr.Timeline()
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkWriteDissection(b *testing.B) {
	pcap := benchPcapOrSkip(b)

	gr := NewGowiresharkRunner(pcap)

	b.Run("gowireshark_cold_text", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := gr.WriteDissectionTextCold()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_warm_text", func(b *testing.B) {
		warm := warmSessionForBenchmark(b, pcap)
		for i := 0; i < b.N; i++ {
			_, _, err := warm.WriteDissectionText()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_cold_pdml", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := gr.WriteDissectionPDMLCold()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_warm_pdml", func(b *testing.B) {
		warm := warmSessionForBenchmark(b, pcap)
		for i := 0; i < b.N; i++ {
			_, _, err := warm.WriteDissectionPDML()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	tshark := TsharkPath()
	if tshark != "" {
		tr := NewTsharkRunner(pcap, tshark)
		b.Run("tshark_subprocess_text", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, err := tr.WriteDissectionText()
				if err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("tshark_subprocess_pdml", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, err := tr.WriteDissectionPDML()
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkIterFrames(b *testing.B) {
	pcap := benchPcapOrSkip(b)

	gr := NewGowiresharkRunner(pcap)

	b.Run("gowireshark_iter_cold", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := gr.IterFramesCold()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_iter_warm", func(b *testing.B) {
		warm := warmSessionForBenchmark(b, pcap)
		for i := 0; i < b.N; i++ {
			_, _, err := warm.IterFrames()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_walk_warm", func(b *testing.B) {
		warm := warmSessionForBenchmark(b, pcap)
		for i := 0; i < b.N; i++ {
			count := 0
			err := warm.sess.WalkFrames(gowireshark.Query{}, func(f *gowireshark.FrameData) error {
				count++
				return nil
			})
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkWriteFieldsRows(b *testing.B) {
	pcap := benchPcapOrSkip(b)

	gr := NewGowiresharkRunner(pcap)
	fields := []string{"frame.number", "frame.len", "ip.src", "ip.dst"}

	b.Run("gowireshark_cold", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := gr.WriteFieldsRowsCold(fields)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_warm", func(b *testing.B) {
		warm := warmSessionForBenchmark(b, pcap)
		for i := 0; i < b.N; i++ {
			_, _, err := warm.WriteFieldsRows(fields)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkFrameJSONIterator(b *testing.B) {
	pcap := benchPcapOrSkip(b)

	gr := NewGowiresharkRunner(pcap)

	b.Run("gowireshark_iter_json_cold", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := gr.IterFrameJSONCold()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_iter_json_warm", func(b *testing.B) {
		warm := warmSessionForBenchmark(b, pcap)
		for i := 0; i < b.N; i++ {
			_, _, err := warm.IterFrameJSON()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_iter_warm", func(b *testing.B) {
		warm := warmSessionForBenchmark(b, pcap)
		for i := 0; i < b.N; i++ {
			_, _, err := warm.IterFrames()
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkConversations(b *testing.B) {
	pcap := benchPcapOrSkip(b)

	gr := NewGowiresharkRunner(pcap)

	b.Run("gowireshark_cold", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := gr.ConversationsCold()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_warm", func(b *testing.B) {
		warm := warmSessionForBenchmark(b, pcap)
		for i := 0; i < b.N; i++ {
			_, _, err := warm.Conversations()
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
