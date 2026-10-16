package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
)

func readJSON(path string, value any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, value)
}

func effectiveAddress(path string, stdout io.Writer) error {
	var profile struct {
		Peers []struct {
			EffectiveAddresses []string `json:"effectiveAddresses"`
		} `json:"peers"`
	}
	if err := readJSON(path, &profile); err != nil {
		return err
	}
	if len(profile.Peers) == 0 || len(profile.Peers[0].EffectiveAddresses) == 0 || profile.Peers[0].EffectiveAddresses[0] == "" {
		return errors.New("missing effective peer address")
	}
	_, err := fmt.Fprintln(stdout, profile.Peers[0].EffectiveAddresses[0])
	return err
}

func benchmarkReport(dir string, stdout io.Writer) error {
	for _, concurrency := range []int{1, 4, 8} {
		for _, direction := range []string{"normal", "reverse"} {
			throughputs := make([]float64, 0, 3)
			fmt.Fprintf(stdout, "P%d %s runs:\n", concurrency, direction)
			for run := 1; run <= 3; run++ {
				var result struct {
					Error string `json:"error"`
					End   struct {
						Received *struct {
							BitsPerSecond *float64 `json:"bits_per_second"`
						} `json:"sum_received"`
						Sent struct {
							Retransmits int64 `json:"retransmits"`
						} `json:"sum_sent"`
					} `json:"end"`
				}
				path := filepath.Join(dir, fmt.Sprintf("p%d-%s-%d.json", concurrency, direction, run))
				if err := readJSON(path, &result); err != nil {
					return err
				}
				if result.Error != "" {
					return fmt.Errorf("iperf3 P%d %s run %d failed", concurrency, direction, run)
				}
				if result.End.Received == nil || result.End.Received.BitsPerSecond == nil {
					return errors.New("missing received throughput")
				}
				bps := *result.End.Received.BitsPerSecond
				if bps < 0 || math.IsNaN(bps) || math.IsInf(bps, 0) {
					return errors.New("invalid received throughput")
				}
				throughputs = append(throughputs, bps)
				fmt.Fprintf(stdout, "  run %d: %.3f Gbit/s, retransmits=%d\n", run, bps/1e9, result.End.Sent.Retransmits)
			}
			slices.Sort(throughputs)
			minimum, median, maximum := throughputs[0], throughputs[1], throughputs[2]
			unstable := "no"
			if maximum-minimum > 0.10*median {
				unstable = "yes"
			}
			fmt.Fprintf(stdout, "  summary: median=%.3f Gbit/s min=%.3f Gbit/s max=%.3f Gbit/s unstable=%s\n", median/1e9, minimum/1e9, maximum/1e9, unstable)
		}
	}
	return nil
}
