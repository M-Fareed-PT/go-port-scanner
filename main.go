// port-scanner/main.go
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type ScanResult struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Open     bool   `json:"open"`
	Banner   string `json:"banner,omitempty"`
	Duration string `json:"duration_ms"`
}

func worker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan int, results chan<- ScanResult, host string, timeout time.Duration, bannerReadBytes int) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case port, ok := <-jobs:
			if !ok {
				return
			}
			start := time.Now()
			addr := fmt.Sprintf("%s:%d", host, port)
			conn, err := net.DialTimeout("tcp", addr, timeout)
			res := ScanResult{Host: host, Port: port}
			if err != nil {
				res.Open = false
				res.Duration = fmt.Sprintf("%d", time.Since(start).Milliseconds())
				results <- res
				continue
			}
			res.Open = true
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			if bannerReadBytes > 0 {
				buf := make([]byte, bannerReadBytes)
				n, _ := conn.Read(buf)
				if n > 0 {
					res.Banner = strings.TrimSpace(string(buf[:n]))
				}
			}
			conn.Close()
			res.Duration = fmt.Sprintf("%d", time.Since(start).Milliseconds())
			results <- res
		}
	}
}

func main() {
	host := flag.String("host", "", "Target host (IP or hostname) — REQUIRED")
	ports := flag.String("ports", "1-1024", "Ports (e.g., 22,80,443 or 1-65535 or 22,80,8000-8100)")
	concurrency := flag.Int("c", 200, "Concurrency (workers)")
	timeoutMS := flag.Int("t", 300, "Dial timeout in ms")
	bannerBytes := flag.Int("b", 128, "Banner read bytes (0 to skip)")
	outFile := flag.String("o", "scan_results.json", "Output JSON file (array)")
	flag.Parse()

	if *host == "" {
		fmt.Println("host required")
		flag.Usage()
		return
	}

	portList, err := parsePorts(*ports)
	if err != nil {
		fmt.Println("invalid ports:", err)
		return
	}

	jobs := make(chan int, len(portList))
	results := make(chan ScanResult, len(portList))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go worker(ctx, &wg, jobs, results, *host, time.Duration(*timeoutMS)*time.Millisecond, *bannerBytes)
	}

	for _, p := range portList {
		jobs <- p
	}
	close(jobs)

	// collect results asynchronously
	go func() {
		wg.Wait()
		close(results)
	}()

	out := make([]ScanResult, 0, len(portList))
	for r := range results {
		out = append(out, r)
		// live console output for feedback
		if r.Open {
			fmt.Printf("[OPEN] %s:%d banner=%s\n", r.Host, r.Port, r.Banner)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Port == out[j].Port {
			return out[i].Host < out[j].Host
		}
		return out[i].Port < out[j].Port
	})

	f, err := os.Create(*outFile)
	if err != nil {
		fmt.Println("error creating output:", err)
		return
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Println("error writing json:", err)
		return
	}
	f.Close()
	fmt.Printf("Scan complete. Results saved to %s\n", *outFile)
}

func parsePorts(s string) ([]int, error) {
	set := make(map[int]struct{})
	parts := strings.Split(s, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "-") {
			var lo, hi int
			_, err := fmt.Sscanf(p, "%d-%d", &lo, &hi)
			if err != nil {
				return nil, fmt.Errorf("bad range: %s", p)
			}
			if lo < 1 {
				lo = 1
			}
			if hi > 65535 {
				hi = 65535
			}
			for i := lo; i <= hi; i++ {
				set[i] = struct{}{}
			}
		} else {
			var v int
			_, err := fmt.Sscanf(p, "%d", &v)
			if err != nil {
				return nil, fmt.Errorf("bad port: %s", p)
			}
			if v >= 1 && v <= 65535 {
				set[v] = struct{}{}
			}
		}
	}
	out := make([]int, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Ints(out)
	return out, nil
}
