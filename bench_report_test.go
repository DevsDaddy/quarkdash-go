/*
    QuarkDash Benchmark

    @git             https://github.com/devsdaddy/quarkdash-go
    @version         1.2.1
    @author          Elijah Rastorguev
    @build           1023
    @website         https://dev.to/devsdaddy
    @updated         28.08.2026
*/
package quarkdash

import (
	"flag"
	"fmt"
	"testing"
)

// runBenchReport enable table generation for benchmark with ms/op column.
// Usage: go test -bench-report -v -run TestBenchmarkReport
var runBenchReport = flag.Bool("bench-report", false, "print benchmark report table with ms/op column")

// TestBenchmarkReport run all benchmarks (testing.Benchmark)
// and print markdown-table with operations time in ms (ms/op),
// speed (ops/sec) and encryption speed (MB/s) if available.
//
// By default is skipping, to speed up basic `go test`.
// Enable by flag: go test -bench-report -v -run TestBenchmarkReport
func TestBenchmarkReport(t *testing.T) {
	if !*runBenchReport {
		t.Skip("skipping benchmark report; enable with -bench-report flag")
	}

	type benchRow struct {
		name    string
		msPerOp float64
		opsSec  float64
		mbps    float64 // 0 if bytes not set (SetBytes)
	}

	run := func(name string, fn func(b *testing.B)) benchRow {
		res := testing.Benchmark(fn)
		if res.N == 0 || res.T == 0 {
			return benchRow{name: name}
		}
		row := benchRow{
			name:    name,
			msPerOp: float64(res.T.Nanoseconds()) / float64(res.N) / 1e6,
			opsSec:  float64(res.N) / res.T.Seconds(),
		}
		if mb, ok := res.Extra["MB/s"]; ok {
			row.mbps = mb
		} else if res.Bytes > 0 {
			row.mbps = float64(res.Bytes) * float64(res.N) / res.T.Seconds() / (1024 * 1024)
		}
		return row
	}

	rows := []benchRow{
		run("Key Generation", BenchmarkKeyGeneration),
		run("Encapsulate", BenchmarkEncapsulate),
		run("Encrypt 1KB", BenchmarkEncrypt1KB),
		run("Decrypt 1KB", BenchmarkDecrypt1KB),
		run("Encrypt 1MB", BenchmarkEncrypt1MB),
		run("Decrypt 1MB", BenchmarkDecrypt1MB),
		run("ChaCha20 raw 1MB", BenchmarkChaCha),
		run("Gimli raw 1MB", BenchmarkGimli),
	}

	out := "\n| Benchmark | Time/op (ms) | Ops/sec | Speed (MB/s) |\n"
	out += "|----------|---------------|---------|------------------------|\n"
	for _, r := range rows {
		tp := "-"
		if r.mbps > 0 {
			tp = fmt.Sprintf("%.2f MB/s", r.mbps)
		}
		out += fmt.Sprintf("| %s | %.3f ms | %.0f | %s |\n", r.name, r.msPerOp, r.opsSec, tp)
	}
	t.Log(out)
	fmt.Print(out)
}
