# Concurrent ComparePasswordAndHash calls cause unbounded memory growth (OOM under load)

## Summary

When `ComparePasswordAndHash` (or `CheckHash`) is called concurrently — e.g. from multiple HTTP handlers or OAuth2 token-endpoint goroutines — heap memory grows linearly with the number of simultaneous callers. With `DefaultParams.Memory = 64 MiB`, ten concurrent authentications allocate ~640 MiB simultaneously. On memory-constrained deployments (containers, small VMs) this causes OOM kills.

This is not a bug in the algorithm — it's working as designed. The issue is that the library provides no way for callers to bound how many argon2 operations run simultaneously.

---

## Reproduction

```go
// go test -v -run TestMemoryRunaway -count=1

func TestMemoryRunaway(t *testing.T) {
    p := argon2id.DefaultParams
    password := []byte("password")
    salt := make([]byte, p.SaltLength)

    // single call: ~65 MiB
    singlePeak := peakHeap(func() {
        argon2.IDKey(password, salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
    })

    // 8 simultaneous calls: ~513 MiB
    concurrentPeak := peakHeap(func() {
        var wg sync.WaitGroup
        barrier := make(chan struct{})
        for i := 0; i < 8; i++ {
            wg.Add(1)
            go func() {
                defer wg.Done()
                <-barrier
                argon2.IDKey(password, salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
            }()
        }
        close(barrier)
        wg.Wait()
    })

    t.Logf("single: %d MiB  concurrent(8): %d MiB  ratio: %.1fx",
        singlePeak>>20, concurrentPeak>>20,
        float64(concurrentPeak)/float64(singlePeak))
}
```

**Output:**

```
single: 65 MiB  concurrent(8): 513 MiB  ratio: 7.9x
```

Scaling is almost exactly linear — consistent with `initBlocks` holding `Params.Memory` live for the full duration of each call.

---

## Real-world trigger

The most common scenario is an **OAuth2 client credentials endpoint** where multiple services restart simultaneously and each re-authenticates at startup. Ten services reconnecting at once → ten concurrent `ComparePasswordAndHash` calls → OOM kill → services restart again → loop.

The same pattern occurs with:
- HTTP basic-auth handlers under load
- Any service where token expiry aligns across multiple clients

---

## Proposed fix: `SetMaxConcurrency`

Add an opt-in function that installs a buffered-channel semaphore around the `argon2.IDKey` call. The default is **0 (disabled)** to preserve the existing behaviour for all current users — no silent performance change, no breaking change.

```go
var (
    semMu sync.RWMutex
    sem   chan struct{}
)

// SetMaxConcurrency limits the number of argon2id key-derivation operations
// that may run simultaneously. Each operation holds approximately
// Params.Memory KiB of heap while running, so bounding concurrency caps
// worst-case memory growth to n × Params.Memory.
//
// Call once at program startup (e.g. in main or TestMain).
// A value of 0 (the default) disables throttling entirely, preserving the
// original unbounded behaviour.
func SetMaxConcurrency(n int) {
    semMu.Lock()
    defer semMu.Unlock()
    if n > 0 {
        sem = make(chan struct{}, n)
    } else {
        sem = nil
    }
}

func withSem(fn func()) {
    semMu.RLock()
    s := sem
    semMu.RUnlock()
    if s != nil {
        s <- struct{}{}
        defer func() { <-s }()
    }
    fn()
}
```

`withSem` wraps the `argon2.IDKey` call in both `CreateHash` and `CheckHash`. When no semaphore is set the RLock + nil check is the only overhead — negligible against hundreds of milliseconds of hashing work.

### Usage

```go
func main() {
    // Allow at most 4 concurrent hashes → peak ≈ 4 × 64 MiB = ~256 MiB.
    // Callers beyond this limit queue rather than allocate.
    argon2id.SetMaxConcurrency(4)
    // ...
}
```

### Measured result with the fix

```
SetMaxConcurrency(4) — 16 concurrent callers:

Unthrottled (raw argon2.IDKey) : 1025 MiB
Throttled (ComparePasswordAndHash): 449 MiB
Reduction                       : 56%
```

The throttled peak remains bounded as concurrency grows further; the unthrottled peak grows without limit.

---

## Why this belongs in the library rather than at the call site

Call-site semaphores work, but every consumer of the library has to independently discover this problem, measure their memory params, and implement the same pattern. The library already encapsulates the `Params` struct and `DefaultParams` — it has all the information needed to expose a concurrency knob alongside them. A single well-documented `SetMaxConcurrency` in the library removes the footgun for everyone.

---

## What this is not

- **Not a request to lower `DefaultParams.Memory`** — the memory cost is the security guarantee; reducing it weakens the algorithm.
- **Not a breaking change** — default is 0 (disabled); existing callers are unaffected.
- **Not a goroutine leak** — blocked callers hold no resources other than the goroutine stack while queuing.

---

## Happy to open a PR

A full implementation with tests is ready if a PR would be welcome. The tests include:
- `TestMemoryRunaway_Proof` — asserts concurrent raw calls produce ≥ 3× single-call memory (proves the problem)
- `TestMemoryBounded_Throttled` — asserts throttled calls stay below 50% of unthrottled equivalent (proves the fix)
