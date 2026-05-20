package bench

import (
	"fmt"
	"sort"
	"time"
)

type BenchResult struct {
	Name       string  `json:"name"`
	Runner     string  `json:"runner"`
	Iterations int     `json:"iterations"`
	P50Ms      float64 `json:"p50_ms"`
	P95Ms      float64 `json:"p95_ms"`
	MeanMs     float64 `json:"mean_ms"`
	MinMs      float64 `json:"min_ms"`
	MaxMs      float64 `json:"max_ms"`
	BytesOut   int64   `json:"bytes_out"`
	Records    int     `json:"records"`
	Error      string  `json:"error,omitempty"`
	Skipped    bool    `json:"skipped,omitempty"`
	SkipReason string  `json:"skip_reason,omitempty"`
}

type BenchCase struct {
	Name string
	Fn   func() (records int, bytesOut int64, err error)
}

type BenchOutput struct {
	Pcap    string        `json:"pcap"`
	Tshark  string        `json:"tshark"`
	Results []BenchResult `json:"cases"`
}

func RunTimedCase(name, runner string, iterations int, fn func() (records int, bytesOut int64, err error)) BenchResult {
	result := BenchResult{
		Name:       name,
		Runner:     runner,
		Iterations: iterations,
	}

	times := make([]float64, 0, iterations)
	var records int
	var bytesOut int64

	for i := 0; i < iterations; i++ {
		start := time.Now()
		recs, out, err := fn()
		elapsed := float64(time.Since(start).Microseconds()) / 1000.0

		if err != nil {
			if i == 0 {
				result.Error = err.Error()
				return result
			}
			continue
		}

		times = append(times, elapsed)
		if i == 0 {
			records = recs
			bytesOut = out
		}
	}

	if len(times) == 0 {
		result.Error = "no successful iterations"
		return result
	}

	sort.Float64s(times)

	result.MinMs = times[0]
	result.MaxMs = times[len(times)-1]
	result.Records = records
	result.BytesOut = bytesOut

	n := len(times)
	result.P50Ms = percentile(times, 50)
	result.P95Ms = percentile(times, 95)

	sum := 0.0
	for _, t := range times {
		sum += t
	}
	result.MeanMs = sum / float64(n)

	return result
}

func SkippedResult(name, runner, reason string) BenchResult {
	return BenchResult{
		Name:       name,
		Runner:     runner,
		Skipped:    true,
		SkipReason: reason,
	}
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[len(sorted)-1]
	}
	idx := p / 100.0 * float64(len(sorted)-1)
	lo := int(idx)
	hi := lo + 1
	if hi >= len(sorted) {
		return sorted[lo]
	}
	frac := idx - float64(lo)
	return sorted[lo]*(1-frac) + sorted[hi]*frac
}

func ToJSON(results []BenchResult, pcap, tsharkVersion string) BenchOutput {
	return BenchOutput{
		Pcap:    pcap,
		Tshark:  tsharkVersion,
		Results: results,
	}
}

func ToMarkdown(results []BenchResult) string {
	var out string
	out += "| case | tshark subprocess | gowireshark cold | gowireshark warm | speedup warm/tshark |\n"
	out += "|------|-------------------|------------------|------------------|--------------------|\n"

	groups := groupByCase(results)
	for _, caseName := range caseOrder(results) {
		group := groups[caseName]
		tsharkMean := groupMean(group, "tshark_subprocess")
		coldMean := groupMean(group, "gowireshark_cold")
		warmMean := groupMean(group, "gowireshark_warm")

		tsharkStr := formatMean(tsharkMean, group, "tshark_subprocess")
		coldStr := formatMean(coldMean, group, "gowireshark_cold")
		warmStr := formatMean(warmMean, group, "gowireshark_warm")

		speedup := ""
		if tsharkMean > 0 && warmMean > 0 {
			speedup = fmt.Sprintf("%.2fx", tsharkMean/warmMean)
		}

		out += fmt.Sprintf("| %s | %s | %s | %s | %s |\n", caseName, tsharkStr, coldStr, warmStr, speedup)
	}
	return out
}

func groupByCase(results []BenchResult) map[string][]BenchResult {
	groups := make(map[string][]BenchResult)
	for _, r := range results {
		groups[r.Name] = append(groups[r.Name], r)
	}
	return groups
}

func caseOrder(results []BenchResult) []string {
	seen := make(map[string]bool)
	var order []string
	for _, r := range results {
		if !seen[r.Name] {
			seen[r.Name] = true
			order = append(order, r.Name)
		}
	}
	return order
}

func groupMean(group []BenchResult, runner string) float64 {
	for _, r := range group {
		if r.Runner == runner && !r.Skipped && r.Error == "" {
			return r.MeanMs
		}
	}
	return 0
}

func formatMean(mean float64, group []BenchResult, runner string) string {
	for _, r := range group {
		if r.Runner == runner {
			if r.Skipped {
				return fmt.Sprintf("skipped (%s)", r.SkipReason)
			}
			if r.Error != "" {
				return fmt.Sprintf("error: %s", r.Error)
			}
		}
	}
	if mean > 0 {
		return fmt.Sprintf("%.2f ms", mean)
	}
	return "N/A"
}