package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/randolphcyg/gowireshark/bench"
)

func main() {
	pcapFlag := flag.String("pcap", "", "path to pcap file (default: $GOWIRESHARK_BENCH_PCAP or ./pcaps/*.pcap)")
	tsharkFlag := flag.String("tshark", "", "path to tshark (default: $GOWIRESHARK_TSHARK or PATH or Wireshark.app)")
	iterFlag := flag.Int("iter", 0, "iterations per case (default: $GOWIRESHARK_BENCH_ITER or 30)")
	formatFlag := flag.String("format", "json", "output format: json or markdown")
	outputFlag := flag.String("output", "", "output file path (default: stdout)")
	flag.Parse()

	pcap := *pcapFlag
	if pcap == "" {
		pcap = bench.BenchPcap()
	}
	if pcap == "" {
		fmt.Fprintln(os.Stderr, "no pcap file; set GOWIRESHARK_BENCH_PCAP or use -pcap flag")
		os.Exit(1)
	}

	tshark := *tsharkFlag
	if tshark == "" {
		tshark = bench.TsharkPath()
	}

	iterations := *iterFlag
	if iterations <= 0 {
		iterations = bench.BenchIterations()
	}

	tsharkVer := "unavailable"
	if tshark != "" {
		tsharkVer = tsharkVersion(tshark)
	}

	results := runAllCases(pcap, tshark, iterations)

	var output string
	switch *formatFlag {
	case "markdown":
		output = bench.ToMarkdown(results)
	default:
		out := bench.ToJSON(results, pcap, tsharkVer)
		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "json marshal:", err)
			os.Exit(1)
		}
		output = string(data)
	}

	if *outputFlag != "" {
		if err := os.WriteFile(*outputFlag, []byte(output), 0644); err != nil {
			fmt.Fprintln(os.Stderr, "write output:", err)
			os.Exit(1)
		}
		fmt.Printf("results written to %s\n", *outputFlag)
	} else {
		fmt.Println(output)
	}
}

func runAllCases(pcap, tshark string, iterations int) []bench.BenchResult {
	var results []bench.BenchResult

	frameCnt, hasTCP, tcpStream := discoverMetadata(pcap)
	fmt.Fprintf(os.Stderr, "discovered: %d frames, hasTCP=%v, firstTCPStream=%d\n", frameCnt, hasTCP, tcpStream)

	mid := frameCnt / 2
	last := frameCnt

	results = append(results, runColdFrameLookup(pcap, 1, mid, last, iterations)...)
	results = append(results, runColdExpertInfo(pcap, iterations)...)
	if hasTCP {
		if tcpStream < 0 {
			fmt.Fprintf(os.Stderr, "skipping follow_stream: no TCP stream with valid StreamID\n")
		} else {
			streamFilter := fmt.Sprintf("tcp.stream eq %d", tcpStream)
			results = append(results, runColdFollowStream(pcap, streamFilter, iterations)...)
		}
	}
	results = append(results, runColdStreamList(pcap, iterations)...)
	results = append(results, runColdStreamListTCP(pcap, iterations)...)
	results = append(results, runColdStreamListUDP(pcap, iterations)...)
	results = append(results, runColdPcapSlice(pcap, iterations)...)

	results = append(results, runWarmAll(pcap, 1, mid, last, hasTCP, tcpStream, iterations)...)

	if tshark != "" {
		results = append(results, runTsharkAll(pcap, tshark, 1, mid, last, hasTCP, tcpStream, iterations)...)
	} else {
		results = append(results, bench.SkippedResult("frame_lookup_first", "tshark_subprocess", "tshark not found"))
		results = append(results, bench.SkippedResult("frame_lookup_mid", "tshark_subprocess", "tshark not found"))
		results = append(results, bench.SkippedResult("frame_lookup_last", "tshark_subprocess", "tshark not found"))
		results = append(results, bench.SkippedResult("expert_info", "tshark_subprocess", "tshark not found"))
		results = append(results, bench.SkippedResult("follow_stream", "tshark_subprocess", "tshark not found"))
		results = append(results, bench.SkippedResult("stream_list_all", "tshark_subprocess", "tshark not found"))
		results = append(results, bench.SkippedResult("stream_list_tcp", "tshark_subprocess", "tshark not found"))
		results = append(results, bench.SkippedResult("stream_list_udp", "tshark_subprocess", "tshark not found"))
		results = append(results, bench.SkippedResult("pcap_slice", "tshark_subprocess", "tshark not found"))
	}

	return results
}

func discoverMetadata(pcap string) (frameCnt int, hasTCP bool, firstStream int) {
	gr := bench.NewGowiresharkRunner(pcap)
	frameCnt = gr.FrameCount()
	if frameCnt < 1 {
		return
	}
	hasTCP = gr.HasTCP()
	if hasTCP {
		firstStream = gr.FirstTCPStream()
	}
	return
}

func runColdFrameLookup(pcap string, first, mid, last, iterations int) []bench.BenchResult {
	gr := bench.NewGowiresharkRunner(pcap)
	return []bench.BenchResult{
		bench.RunTimedCase("frame_lookup_first", "gowireshark_cold", iterations, func() (int, int64, error) { return gr.FrameLookupCold(first) }),
		bench.RunTimedCase("frame_lookup_mid", "gowireshark_cold", iterations, func() (int, int64, error) { return gr.FrameLookupCold(mid) }),
		bench.RunTimedCase("frame_lookup_last", "gowireshark_cold", iterations, func() (int, int64, error) { return gr.FrameLookupCold(last) }),
	}
}

func runColdExpertInfo(pcap string, iterations int) []bench.BenchResult {
	gr := bench.NewGowiresharkRunner(pcap)
	return []bench.BenchResult{
		bench.RunTimedCase("expert_info", "gowireshark_cold", iterations, func() (int, int64, error) { return gr.ExpertInfoCold() }),
	}
}

func runColdFollowStream(pcap, streamFilter string, iterations int) []bench.BenchResult {
	gr := bench.NewGowiresharkRunner(pcap)
	return []bench.BenchResult{
		bench.RunTimedCase("follow_stream", "gowireshark_cold", iterations, func() (int, int64, error) { return gr.FollowStreamCold(streamFilter) }),
	}
}

func runColdStreamList(pcap string, iterations int) []bench.BenchResult {
	gr := bench.NewGowiresharkRunner(pcap)
	return []bench.BenchResult{
		bench.RunTimedCase("stream_list_all", "gowireshark_cold", iterations, func() (int, int64, error) { return gr.StreamListCold() }),
	}
}

func runColdStreamListTCP(pcap string, iterations int) []bench.BenchResult {
	gr := bench.NewGowiresharkRunner(pcap)
	return []bench.BenchResult{
		bench.RunTimedCase("stream_list_tcp", "gowireshark_cold", iterations, func() (int, int64, error) { return gr.StreamListTCPCold() }),
	}
}

func runColdStreamListUDP(pcap string, iterations int) []bench.BenchResult {
	gr := bench.NewGowiresharkRunner(pcap)
	return []bench.BenchResult{
		bench.RunTimedCase("stream_list_udp", "gowireshark_cold", iterations, func() (int, int64, error) { return gr.StreamListUDPCold() }),
	}
}

func runColdPcapSlice(pcap string, iterations int) []bench.BenchResult {
	gr := bench.NewGowiresharkRunner(pcap)
	return []bench.BenchResult{
		bench.RunTimedCase("pcap_slice", "gowireshark_cold", iterations, func() (int, int64, error) { return gr.PcapSliceCold(100) }),
	}
}

func runWarmAll(pcap string, first, mid, last int, hasTCP bool, tcpStream, iterations int) []bench.BenchResult {
	var results []bench.BenchResult

	warm := bench.NewWarmSession(pcap)
	if err := warm.Setup(); err != nil {
		results = append(results, bench.BenchResult{Name: "frame_lookup_first", Runner: "gowireshark_warm", Error: err.Error()})
		return results
	}
	defer warm.Teardown()

	results = append(results, bench.RunTimedCase("frame_lookup_first", "gowireshark_warm", iterations, func() (int, int64, error) { return warm.FrameLookup(first) }))
	results = append(results, bench.RunTimedCase("frame_lookup_mid", "gowireshark_warm", iterations, func() (int, int64, error) { return warm.FrameLookup(mid) }))
	results = append(results, bench.RunTimedCase("frame_lookup_last", "gowireshark_warm", iterations, func() (int, int64, error) { return warm.FrameLookup(last) }))
	results = append(results, bench.RunTimedCase("expert_info", "gowireshark_warm", iterations, func() (int, int64, error) { return warm.ExpertInfo() }))

	if hasTCP && tcpStream >= 0 {
		streamFilter := fmt.Sprintf("tcp.stream eq %d", tcpStream)
		results = append(results, bench.RunTimedCase("follow_stream", "gowireshark_warm", iterations, func() (int, int64, error) { return warm.FollowStream(streamFilter) }))
	}
	results = append(results, bench.RunTimedCase("stream_list_all", "gowireshark_warm", iterations, func() (int, int64, error) { return warm.StreamList() }))
	results = append(results, bench.RunTimedCase("stream_list_tcp", "gowireshark_warm", iterations, func() (int, int64, error) { return warm.StreamListTCP() }))
	results = append(results, bench.RunTimedCase("stream_list_udp", "gowireshark_warm", iterations, func() (int, int64, error) { return warm.StreamListUDP() }))
	results = append(results, bench.RunTimedCase("pcap_slice", "gowireshark_warm", iterations, func() (int, int64, error) { return warm.PcapSlice(100) }))

	return results
}

func runTsharkAll(pcap, tshark string, first, mid, last int, hasTCP bool, tcpStream, iterations int) []bench.BenchResult {
	var results []bench.BenchResult

	tr := bench.NewTsharkRunner(pcap, tshark)

	results = append(results, bench.RunTimedCase("frame_lookup_first", "tshark_subprocess", iterations, func() (int, int64, error) { return tr.FrameLookup(first) }))
	results = append(results, bench.RunTimedCase("frame_lookup_mid", "tshark_subprocess", iterations, func() (int, int64, error) { return tr.FrameLookup(mid) }))
	results = append(results, bench.RunTimedCase("frame_lookup_last", "tshark_subprocess", iterations, func() (int, int64, error) { return tr.FrameLookup(last) }))
	results = append(results, bench.RunTimedCase("expert_info", "tshark_subprocess", iterations, func() (int, int64, error) { return tr.ExpertInfo() }))

	if hasTCP && tcpStream >= 0 {
		results = append(results, bench.RunTimedCase("follow_stream", "tshark_subprocess", iterations, func() (int, int64, error) { return tr.FollowStream(tcpStream) }))
	}
	results = append(results, bench.RunTimedCase("stream_list_all", "tshark_subprocess", iterations, func() (int, int64, error) { return tr.StreamListAll() }))
	results = append(results, bench.RunTimedCase("stream_list_tcp", "tshark_subprocess", iterations, func() (int, int64, error) { return tr.StreamListTCP() }))
	results = append(results, bench.RunTimedCase("stream_list_udp", "tshark_subprocess", iterations, func() (int, int64, error) { return tr.StreamListUDP() }))

	tmpDir, err := os.MkdirTemp("", "gowireshark-bench-slice")
	if err == nil {
		defer os.RemoveAll(tmpDir)
		results = append(results, bench.RunTimedCase("pcap_slice", "tshark_subprocess", iterations, func() (int, int64, error) { return tr.PcapSlice(tmpDir, 100) }))
	} else {
		results = append(results, bench.BenchResult{Name: "pcap_slice", Runner: "tshark_subprocess", Error: err.Error()})
	}

	return results
}

func tsharkVersion(tshark string) string {
	out, err := bench.TsharkVersion(tshark)
	if err != nil {
		return "unknown"
	}
	return out
}