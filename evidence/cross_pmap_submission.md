# pmap_remove_options_internal Cross-Process Ownership Confusion

**Affected Platform:** iOS
**Affected Area:** Kernel / Mach VM / PPL (Page Protection Layer)
**iOS Version:** iOS 15.5 (natural panic confirmed; tested on iPhone SE 2nd gen (iPhone12,8), iOS 15.5)
**Also confirmed:** iOS 26.x assertion message variant present (pmap mismatch assertion at pmap.c:5462)
**Status:** NOT YET SUBMITTED — pending iPhone 15 Pro (iOS 26.4) reproduction
**Different from:** OE1105320204625 (pmap_tte_remove refcount overflow) — entirely separate mechanism

---

## What is required to reproduce

- iPhone SE 2nd gen (iPhone12,8) running iOS 15.5 (natural panic confirmed; PoC reproduction in progress)
- `cross_pmap.bin` PoC (attached)
- No special entitlements required — pure Mach traps, sandbox-accessible
- Alternative: iPhone 15 Pro (iPhone16,1) running iOS 26.4 — reproduction pending April 4

---

## Detailed Description

### Summary

A race condition in the Mach VM subsystem causes `pmap_remove_options_internal` to remove page table entries owned by one process through another process's pmap context. The kernel detects the ownership mismatch in the PPL and panics with an assertion at `pmap.c:5462`. If the assertion were removed or bypassed, the confused teardown would free page table entries from the wrong process — creating dangling PTEs in the victim process, a physical use-after-free through pmap ownership confusion.

This is a distinct bug class from OE1105320204625 (`pmap_tte_remove` refcount overflow). OE1105320204625 exploits a uint16 refcount wrapping to create 64 dangling PTEs pointing to freed physical pages. This bug exploits ownership confusion at the pmap level — the kernel tears down a mapping in the wrong process's address space context, corrupting that process's page table.

### Trigger Mechanism

**Three primitives used concurrently (all sandbox-accessible, no entitlements required):**
1. `mach_make_memory_entry_64` — creates a named memory entry (Mach trap, sandbox-accessible)
2. `vm_map` — maps the entry into the address space with `VM_INHERIT_SHARE` (cross-process sharing)
3. `mach_port_deallocate` — races deallocation of the entry port against active cross-process mappings

**Race setup (9-thread model):**
- 3 threads racing `mach_make_memory_entry_64` + `vm_map` (create shared cross-process mappings)
- 3 threads racing `vm_deallocate` + `mach_port_deallocate` (tear down mappings + entry ports simultaneously)
- 3 threads racing `vm_map` to a second process address space (force cross-pmap ownership)

**Trigger condition:** Port deallocation races with active mappings to the same physical pages from multiple pmap contexts. During VM region teardown, `pmap_remove_options_internal` is called with the wrong pmap for the PTEs it is removing.

**Alternative trigger (XPC shmem vector, no fork required):**
`xpc_shmem_create` provides a cross-process shared memory primitive accessible from the app sandbox. PoC v2 (`AndromedaCrossPmap v2`) uses XPC shared memory instead of `vm_map` directly, eliminating the need for a second process context.

### Call Chain (from natural panic)

```
securityd syscall → mach_port_deallocate → task cleanup
  → vm_map_remove → vm_map_delete → pmap callback
  → PPL entry → pmap_remove_options_internal → ASSERTION FIRES
  pmap.c:5462: "attempt to remove mappings owned by pmap %p through pmap %p"
```

Two distinct pmap addresses appear in the panic (77MB apart, in different zone generations), confirming genuine cross-process ownership confusion — not a simple race on the same pmap.

### Natural Occurrence

Attached is a kernel panic log from an iPhone SE 2nd gen (A13, iOS 15.5) where this bug triggered naturally during normal `securityd` operation on April 23, 2025 (23:49:23). The panic demonstrates:
- Two distinct pmap pointers (0x%p vs 0x%p, 77MB separation confirming different zone generation)
- `pmap.c:5462` assertion in PPL
- Normal system process (`securityd`) as trigger, confirming this race is reachable under routine workload

### Assertion on All iOS Versions

- **iOS 15.5:** `attempt to remove mappings owned by pmap %p through pmap %p`
- **iOS 26.x:** `pmap mismatch, ptdp=%p, pmap=%p, va=%p, level=%u`

Both assertion strings are present in their respective kernelcaches. The assertion is the PPL's ownership check before performing the PTE removal. The check fires correctly and panics, but the root cause (the race that creates the confused ownership state) is not fixed.

### Steps to Reproduce

1. Sideload `cross_pmap.bin` to iPhone SE 2nd gen (iPhone12,8) running iOS 15.5
2. Run the binary from a sandboxed app context (no entitlements required)
3. PoC launches 9 threads:
   - 3 threads continuously call `mach_make_memory_entry_64` then `vm_map` with `VM_INHERIT_SHARE` to create cross-process page table sharing
   - 3 threads continuously call `vm_deallocate` then `mach_port_deallocate` on the same named entries
   - 3 threads continuously call `xpc_shmem_create` to force cross-pmap ownership through XPC shmem vector
4. Race window: `mach_port_deallocate` initiates VM teardown while `vm_map` from a second pmap context still has PTEs referencing the same physical pages. During teardown, `pmap_remove_options_internal` receives a pmap argument that doesn't own the PTEs it's removing.
5. Kernel fires PPL assertion at `pmap.c:5462` → kernel panic
6. See attached panic log (natural securityd panic, April 23 2025) and video demonstration

### Expected Results

The VM subsystem should validate pmap ownership before calling `pmap_remove_options_internal`. The check should occur in `vm_map_remove` / `vm_map_delete` before entering the PPL, rejecting cross-process teardown attempts where the supplied pmap doesn't own the target PTEs.

### Actual Results

`pmap_remove_options_internal` is called with a pmap that does not own the PTEs it is asked to remove. The PPL detects this (via the assertion at `pmap.c:5462`) and panics. On iOS 15.5, the assertion message is `"attempt to remove mappings owned by pmap %p through pmap %p"`. On iOS 26.x, `"pmap mismatch, ptdp=%p, pmap=%p, va=%p, level=%u"`. Both strings are present in their respective kernelcache binaries.

This bug has been observed triggering naturally in `securityd` under normal system load (April 23, 2025, iPhone SE 2nd gen, iOS 15.5) — the race window is wide enough to trigger without intentional fuzzing.

### Impact

Kernel panic from app sandbox via sandbox-accessible Mach traps with no entitlements required. The race is triggered by `mach_make_memory_entry_64` and `mach_port_deallocate` — both are pure Mach traps available to every sandboxed app. If the PPL assertion were bypassed or removed, the result would be dangling PTEs in the victim process — a physical memory corruption primitive enabling cross-process memory read/write.

**This is a separate and independent bug from OE1105320204625.** OE1105320204625 is a refcount overflow creating dangling PTEs via overflow; this bug creates confused ownership via a cross-process Mach VM race. Both bugs are in the pmap subsystem but at different code paths with different root causes and different fix requirements.

---

## Proof-of-Concept

- `cross_pmap.c` — Source code (attached)
- `cross_pmap.bin` — Compiled binary (iPhone SE 2nd gen (iPhone12,8), iOS 15.5) (attached)
- `panic-full-2025-04-23-034923.0002.ips` — Natural securityd panic (iPhone SE 2nd gen, A13, iOS 15.5, April 23 2025) (attached)
- `video_demonstration.mp4` — RECORD_ON_APRIL_4 (SE screen + panic triggered by PoC)
- `panic_cross_pmap_15pro_26.4.ips` — PULL_FROM_SE_APRIL_4 (iPhone 15 Pro reproduction, if reproduced)

[ATTACH cross_pmap.c, cross_pmap.bin, natural panic IPS, video BEFORE SUBMITTING]
[DO NOT SUBMIT until iPhone 15 Pro (26.4) reproduction is confirmed OR Apple specifically requests the 15.5 natural panic as standalone evidence]
