package report

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/Courtcircuits/sterak/stun"
)

// PrintResults prints success/failure counts and a percentile table.
func PrintResults(results []stun.Result) {
	var successfulTimes []int64
	var errorCount int

	for i, r := range results {
		if r.Err != nil {
			errorCount++
			continue
		}

		successfulTimes = append(successfulTimes, r.Time)

		if i == 0 {
			fmt.Printf("First request time: %d μs\n", r.Time)
		}
	}

	if len(successfulTimes) == 0 {
		fmt.Println("No successful requests")
		fmt.Printf("Failed requests: %d\n", errorCount)
		return
	}

	sort.Slice(successfulTimes, func(i, j int) bool { return successfulTimes[i] < successfulTimes[j] })

	fmt.Println("\nResults:")
	fmt.Printf("Successful requests: %d\n", len(successfulTimes))
	fmt.Printf("Failed requests: %d\n\n", errorCount)

	fmt.Println("┌───────┬───────────┐")
	fmt.Printf("│ %%tile │ Time (μs) │" + "\n")
	fmt.Println("├───────┼───────────┤")
	fmt.Printf("│  p0   │ %9d │\n", successfulTimes[0])
	fmt.Printf("│  p25  │ %9d │\n", percentile(successfulTimes, 25))
	fmt.Printf("│  p50  │ %9d │\n", percentile(successfulTimes, 50))
	fmt.Printf("│  p75  │ %9d │\n", percentile(successfulTimes, 75))
	fmt.Printf("│ p100  │ %9d │\n", successfulTimes[len(successfulTimes)-1])
	fmt.Println("└───────┴───────────┘")
}

func percentile(sorted []int64, p int) int64 {
	index := int(math.Round(float64(len(sorted)-1) * float64(p) / 100))
	return sorted[index]
}

// PrintASCIIHistogram prints a 20-bucket latency histogram of successful requests.
func PrintASCIIHistogram(results []stun.Result) {
	var successfulTimes []int64
	for _, r := range results {
		if r.Err == nil {
			successfulTimes = append(successfulTimes, r.Time)
		}
	}

	if len(successfulTimes) == 0 {
		return
	}

	// Determine min and max times
	minTime, maxTime := successfulTimes[0], successfulTimes[0]
	for _, t := range successfulTimes {
		if t < minTime {
			minTime = t
		}
		if t > maxTime {
			maxTime = t
		}
	}

	// Create buckets
	numBuckets := 20
	bucketSize := float64(maxTime-minTime) / float64(numBuckets)
	buckets := make([]int, numBuckets)

	for _, t := range successfulTimes {
		bucket := int(float64(t-minTime) / bucketSize)
		if bucket == numBuckets {
			bucket--
		}
		buckets[bucket]++
	}

	// Find max bucket count for scaling
	maxCount := 0
	for _, count := range buckets {
		if count > maxCount {
			maxCount = count
		}
	}

	// Print histogram
	fmt.Println("\nLatency Distribution (μs):")
	for i, count := range buckets {
		start := int64(float64(i)*bucketSize) + minTime
		end := int64(float64(i+1)*bucketSize) + minTime
		bar := strings.Repeat("█", count*40/maxCount)
		fmt.Printf("%6d - %6d | %-40s | %d\n", start, end, bar, count)
	}
}
