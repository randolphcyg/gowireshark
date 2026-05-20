package bench

import (
	"fmt"
	"os"
	"testing"
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

func BenchmarkFrameLookup(b *testing.B) {
	pcap := benchPcapOrSkip(b)

	gr := NewGowiresharkRunner(pcap)
	mid := gr.frameCountFromSession() / 2
	last := gr.frameCountFromSession()
	if last < 1 {
		b.Fatal("pcap has no frames")
	}

	warm := NewWarmSession(pcap)
	if err := warm.Setup(); err != nil {
		b.Fatalf("warm setup: %v", err)
	}
	defer warm.Teardown()

	b.Run("gowireshark_cold_first", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := gr.FrameLookupCold(1)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_warm_first", func(b *testing.B) {
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

func BenchmarkExpertInfo(b *testing.B) {
	pcap := benchPcapOrSkip(b)

	gr := NewGowiresharkRunner(pcap)

	warm := NewWarmSession(pcap)
	if err := warm.Setup(); err != nil {
		b.Fatalf("warm setup: %v", err)
	}
	defer warm.Teardown()

	b.Run("gowireshark_cold", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := gr.ExpertInfoCold()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_warm", func(b *testing.B) {
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

	warm := NewWarmSession(pcap)
	if err := warm.Setup(); err != nil {
		b.Fatalf("warm setup: %v", err)
	}
	defer warm.Teardown()

	b.Run("gowireshark_cold", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := gr.FollowStreamCold(streamFilter)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_warm", func(b *testing.B) {
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

	warm := NewWarmSession(pcap)
	if err := warm.Setup(); err != nil {
		b.Fatalf("warm setup: %v", err)
	}
	defer warm.Teardown()

	b.Run("gowireshark_cold_tcp", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := gr.StreamListTCPCold()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_warm_tcp", func(b *testing.B) {
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

	warm := NewWarmSession(pcap)
	if err := warm.Setup(); err != nil {
		b.Fatalf("warm setup: %v", err)
	}
	defer warm.Teardown()

	b.Run("gowireshark_cold", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := gr.PcapSliceCold(100)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("gowireshark_warm", func(b *testing.B) {
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