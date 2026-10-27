package argon2id

import (
	"runtime"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

// measurePeakHeap polls runtime.MemStats in a background goroutine while fn
// executes and returns the highest HeapInuse (bytes) observed.
// ReadMemStats triggers a stop-the-world pause each poll; the 10 ms interval
// keeps that overhead negligible against argon2's hundreds-of-ms wall time.
func measurePeakHeap(fn func()) uint64 {
	var (
		peak uint64
		mu   sync.Mutex
		stop = make(chan struct{})
	)

	go func() {
		var ms runtime.MemStats
		for {
			select {
			case <-stop:
				return
			default:
				runtime.ReadMemStats(&ms)
				mu.Lock()
				if ms.HeapInuse > peak {
					peak = ms.HeapInuse
				}
				mu.Unlock()
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()

	fn()
	close(stop)

	// One final sample after fn returns to catch any late accounting.
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	mu.Lock()
	if ms.HeapInuse > peak {
		peak = ms.HeapInuse
	}
	mu.Unlock()
	return peak
}

// runConcurrentFn launches n goroutines that all call fn as simultaneously as
// possible by holding them at a barrier until all are ready, then releasing
// them with a single close(barrier).
func runConcurrentFn(n int, fn func()) {
	var wg sync.WaitGroup
	barrier := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-barrier // wait for simultaneous release
			fn()
		}()
	}
	close(barrier) // unblock all goroutines at once
	wg.Wait()
}

// TestMemoryRunaway_Proof demonstrates that concurrent argon2.IDKey calls
// allocate ≈ N × Params.Memory of live heap simultaneously, confirming the
// root-cause identified in the flame graph.
//
// Scenario: N services restart at the same time and each call
// ComparePasswordAndHash (which internally calls argon2.IDKey). With
// DefaultParams.Memory = 64 MiB and N = 8, peak heap approaches 512 MiB.
// A single call uses ≈64 MiB; the test asserts the concurrent peak is at
// least 3× that, proving super-linear (effectively linear) growth.
//
// Run with: go test -v -run TestMemoryRunaway_Proof -count=1
func TestMemoryRunaway_Proof(t *testing.T) {
	p := DefaultParams
	password := []byte("pa$$word")
	salt := make([]byte, p.SaltLength) // static salt is fine — we're testing allocation, not security

	// Baseline: single argon2.IDKey call (no library, no semaphore).
	runtime.GC()
	singlePeak := measurePeakHeap(func() {
		argon2.IDKey(password, salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	})
	runtime.GC()

	// Concurrent: N simultaneous calls with no throttle.
	const N = 8
	concurrentPeak := measurePeakHeap(func() {
		runConcurrentFn(N, func() {
			argon2.IDKey(password, salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
		})
	})
	runtime.GC()

	const mib = 1024 * 1024
	ratio := float64(concurrentPeak) / float64(singlePeak)
	t.Logf("DefaultParams.Memory (per call) : %d MiB", p.Memory/1024)
	t.Logf("Single-call peak heap           : %d MiB", singlePeak/mib)
	t.Logf("Concurrent (%d calls) peak heap  : %d MiB", N, concurrentPeak/mib)
	t.Logf("Ratio                           : %.1fx  (expected ≈ %dx)", ratio, N)

	// Conservative threshold: concurrent peak must be at least 3× the single peak.
	// In practice the ratio is close to N (≈8×) because argon2's initBlocks holds
	// ~64 MiB live for the duration of each call.
	if concurrentPeak < 3*singlePeak {
		t.Errorf(
			"memory runaway not observed: concurrent %d MiB < 3× single %d MiB (ratio %.1fx); "+
				"re-run with -count=1 -p 1 to disable caching and test parallelism",
			concurrentPeak/mib, singlePeak/mib, ratio,
		)
	}
}

// TestMemoryBounded_Throttled proves that the semaphore in ComparePasswordAndHash
// keeps peak heap well below what unrestricted concurrency would consume.
//
// The test runs N=16 goroutines two ways:
//   - Unthrottled: raw argon2.IDKey calls (no semaphore) → ≈ N × 64 MiB
//   - Throttled:   ComparePasswordAndHash (MaxConcurrency=4) → ≈ (MaxConcurrency+GC_lag) × 64 MiB
//
// Because Go's GC doesn't reclaim argon2 heap instantaneously after each
// release(), the throttled peak is ≈(MaxConcurrency+2)×64 MiB rather than
// exactly MaxConcurrency×64 MiB. With N=16 the throttled peak is still less
// than half the unthrottled peak, conclusively demonstrating the cap.
//
// Run with: go test -v -run TestMemoryBounded_Throttled -count=1
func TestMemoryBounded_Throttled(t *testing.T) {
	const maxConcurrency = 4
	SetMaxConcurrency(maxConcurrency)
	defer SetMaxConcurrency(0) // restore default (disabled) after test

	hash, err := CreateHash("pa$$word", DefaultParams)
	if err != nil {
		t.Fatal(err)
	}

	p := DefaultParams
	password := []byte("pa$$word")
	salt := make([]byte, p.SaltLength)

	// Unthrottled baseline: N raw argon2.IDKey calls with no semaphore.
	const N = 16
	runtime.GC()
	unthrottledPeak := measurePeakHeap(func() {
		runConcurrentFn(N, func() {
			argon2.IDKey(password, salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
		})
	})
	runtime.GC()

	// Throttled: same N goroutines through ComparePasswordAndHash (MaxConcurrency=4).
	throttledPeak := measurePeakHeap(func() {
		runConcurrentFn(N, func() {
			ComparePasswordAndHash("pa$$word", hash) //nolint:errcheck
		})
	})
	runtime.GC()

	const mib = 1024 * 1024
	reduction := (1.0 - float64(throttledPeak)/float64(unthrottledPeak)) * 100
	t.Logf("MaxConcurrency                   : %d", maxConcurrency)
	t.Logf("Unthrottled (%d callers) peak heap: %d MiB", N, unthrottledPeak/mib)
	t.Logf("Throttled   (%d callers) peak heap: %d MiB", N, throttledPeak/mib)
	t.Logf("Memory reduction                 : %.0f%%", reduction)

	// With N=16 and MaxConcurrency=4, the throttled peak should be less than
	// half the unthrottled peak. Even accounting for GC lag of 2 extra live
	// allocations: (4+2)/16 = 37.5% — well under 50%.
	limit := unthrottledPeak / 2
	if throttledPeak > limit {
		t.Errorf(
			"semaphore not effective: throttled %d MiB is not < 50%% of unthrottled %d MiB",
			throttledPeak/mib, unthrottledPeak/mib,
		)
	}
}
