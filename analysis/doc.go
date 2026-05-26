// Package analysis provides reusable statistical summaries over gowireshark frame data.
//
// Use Analyze when frames are already in memory:
//
//	summary := analysis.Analyze(frames)
//
// Use WalkAnalyze for memory-efficient streaming analysis:
//
//	summary, err := analysis.WalkAnalyze("capture.pcap", gowireshark.WithDisplayFilter("http"))
package analysis
