# Cross-Pmap Confusion — Deep Analysis
**Date:** 2026-03-28
**Source:** SE panic-full-2025-04-23-034923.0002.ips
**Bug class:** pmap ownership confusion (different from pmap_tte_remove refcount overflow)

---

## The Panic

```
panic(cpu 1): pmap_remove_options_internal: attempt to remove mappings
owned by pmap 0xfffffff04e3ef888 through pmap 0xfffffff052d94e58,
starting at pte 0xfffffff079560000 @pmap.c:5462
```

The kernel tried to remove page table entries owned by **pmap A** through **pmap B**. The assertion caught the mismatch before corruption occurred.

## Panicked Process

```
pid 114: securityd — 571 pages, 2 threads
Thread: tid 1671
```

**securityd** — Apple's security daemon. Handles keychain operations, credential management, certificate validation. Runs with high privileges. Only 2 threads and 571 resident pages at crash time.

## Full Call Stack (de-slid, slide=0x87b4000)

```
TOP (panic site)
 [0]  0x00b5872c — panic handler
 [1]  0x00b58444 — panic setup
 [2]  0x00ca66c4 — assertion check
 [3]  0x00c974b0 — pmap_tte processing
 [4]  0x00c962dc — pmap_remove_range
 [5]  0x0129c610 — pmap_page_protect / vm_fault callback
 [6]  0x00b58120 — exception handler (nested x2)
 [8]  0x00b57ea8 — trap handler
 [9]  0x02bb7fb4 — PPL entry gate
[10]  0x02bcb9dc — pmap_remove_options_internal ← THE BUG
[11]  0x0129cd5c — pmap callback from VM layer
[12]  0x00c18258 — vm_map_remove / vm_map_delete
[13]  0x00c1c2e4 — vm_map_remove (outer)
[14]  0x00c1f914 — vm_map_deallocate / task_terminate
[15]  0x00b972f0 — BSD process cleanup
[16]  0x00fc2540 — Mach IPC handler
[17]  0x00fe29bc — Mach port operation
[18]  0x00fe2dac — Mach port/message
[19]  0x00b4c7fc — task/thread operation
[20]  0x0129cb1c — VM subsystem entry
[21]  0x00c9616c — vm_map operation
[22]  0x00c984b0 — mach_vm dispatcher
[23]  0x012a4920 — syscall entry
BOTTOM (syscall from securityd)
```

## What Triggered the Confusion

Reading the call stack bottom-up:

1. **securityd made a syscall** [23] — likely `mach_vm_deallocate` or `mach_vm_unmap`
2. **Entered vm_map operation** [22-21] — processing a VM region removal
3. **Task/thread operation** [19] — cross-task memory management
4. **Mach IPC involved** [16-18] — **port/message operation in the path**
5. **BSD process cleanup** [15] — process-level cleanup code
6. **vm_map_deallocate** [14] → **vm_map_remove** [12-13] — tearing down a VM region
7. **pmap callback** [11] — VM layer asks pmap to remove page table entries
8. **PPL entry** [9] — enters Page Protection Layer for privileged pmap operation
9. **pmap_remove_options_internal** [10] — **discovers the PTEs belong to a DIFFERENT pmap**
10. **PANIC** [0-4] — assertion fires

**The Mach IPC path (frames 16-18) is the key.** This suggests securityd was involved in a cross-process memory operation via Mach messages (possibly shared memory, memory entry ports, or IOKit shared buffers).

## Pmap Address Analysis

```
Owner pmap:    0xfffffff04e3ef888  (zone GEN1)
Accessor pmap: 0xfffffff052d94e58  (zone GEN2)
Delta:         0x49a55d0 (77.2 MB apart)
PTE start:     0xfffffff079560000
```

- The two pmaps are in **different zone generations** — they were allocated at different times
- 77MB separation means these aren't adjacent objects — no simple heap overflow could confuse them
- The PTE address (0x79560000) is in a completely different region from both pmaps
- **This is a logical confusion, not a memory corruption** — the kernel's bookkeeping is wrong about which pmap owns which PTEs

## Cross-Version Assertion Analysis

| Version | Assertion Format |
|---------|-----------------|
| iOS 15.5 (A13) | `attempt to remove mappings owned by pmap %p through pmap %p` |
| iOS 15.5 (A13) | `attempt to enter mapping at pte %p owned by pmap %p through pmap %p` |
| iOS 26.0 (A17/A19) | `pmap mismatch, ptdp=%p, pmap=%p, va=%p, level=%u, ptep=%p` |
| iOS 26.4 (A17/A19) | `pmap mismatch, ptdp=%p, pmap=%p, va=%p, level=%u` (ptep removed) |

**The assertion exists on ALL versions** — Apple knows this confusion can occur. On iOS 26.x they generalized the check to "pmap mismatch" with more diagnostic fields. The existence of BOTH remove and enter variants on 15.5 means the confusion can happen in BOTH directions (creating mappings in the wrong pmap AND removing from the wrong pmap).

## Exploitation Potential

### If the assertion could be bypassed:

1. **pmap B's PTEs are removed but pmap B still references them** → dangling PTEs in pmap B
2. The physical pages backing those PTEs are freed by the kernel (it thinks they're cleanup)
3. Pmap B's process still has VA→PA mappings through the freed page table pages
4. **This is PUAF through a different mechanism than refcount overflow**

### Advantages over pmap_tte_remove:

- **No refcount manipulation needed** — the confusion happens through logical error in ownership tracking
- **Triggered by cross-process memory operations** — Mach IPC, shared memory, IOKit
- **SPTM implications unclear** — SPTM tracks page types, but the freed pages ARE real page table pages. SPTM might not quarantine them because the type is correct (they're being freed as PTE pages, which they actually are)
- **securityd trigger** — if the trigger is keychain/credential operations, it might be triggerable from app sandbox via SecItem API calls

### Disadvantages:

- **The assertion catches it** — no known bypass path
- **Natural occurrence rate: 1 in 7 panics** — rare, likely requires specific race condition
- **Not clear how to trigger deliberately** — the exact cross-process state that confuses pmap ownership is unknown
- **May require specific shared memory topology** — not every shared region triggers this

## Trigger Hypothesis

Based on the call stack (Mach IPC + vm_map_remove + securityd):

**Most likely scenario:** securityd was deallocating a shared memory region that was mapped into multiple process address spaces. During cleanup, a page table descriptor (PTD) had a stale or incorrect pmap pointer, causing pmap_remove_options_internal to attempt removal through the wrong pmap.

**Possible trigger sequences to investigate:**
1. Rapid SecItem add/delete cycles from multiple processes simultaneously
2. Shared keychain access during process exit
3. IOKit shared memory buffer cleanup during service deregistration
4. Mach memory entry port operations with concurrent deallocation

## What To Try on SE

The SE is jailbroken with root. We could:

1. **Instrument pmap_remove_options_internal** via Frida/kext to log all pmap comparisons (not just failures)
2. **Stress-test securityd** — rapid concurrent SecItem operations from multiple processes
3. **Monitor for the race condition** — if we see near-misses (owner ≈ accessor), we're close
4. **Check if the stateful KeyStore fuzzer hits this path** — AppleKeyStore is directly related to securityd

## Relationship to Stateful Fuzzing

**The KeyStore stateful fuzzer is currently running on the SE.** AppleKeyStore is the IOKit interface to the keychain — the same subsystem securityd manages. If our fuzzer's open/close/cross-type sequences create the right shared memory topology, it could trigger this exact confusion.

This is potentially why AppleKeyStore was accessible with 4 UserClient types — more types = more shared state = more opportunity for ownership confusion during cleanup.

---

## Files
- `Mystic/se_panic_logs/panic-full-2025-04-23-034923.0002.ips` — full panic log
- `Mystic/analysis/SE_HISTORICAL_PANICS.md` — overview of all 7 panics
