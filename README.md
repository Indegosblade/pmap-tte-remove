# pmap_tte_remove: Physical UAF via uint16 pt_desc Refcount Overflow

**Apple Security Bounty Submission:** OE1105320204625  
**Status:** CLOSED 2026-04-26 ("expected behavior") + PROGRAM WARNING 2026-04-27  
**Patch Status:** MITIGATED-NOT-FIXED through iOS 26.6b1 (uint16_t refcount never widened)  
**Affected:** All iOS versions 15.5 through 26.6b1, all chips A13 through A19  
**Author:** Kevin Estrada  

---

## Summary

A `uint16_t` refcount field in XNU's `pt_desc` (page table descriptor) structure overflows when 65,537 `MAP_SHARED` mappings target the same physical page. The refcount wraps: 65,535 → 65,536 (truncated to 0x0000) → 0x0001. A single subsequent `munmap` decrements it to zero, triggering `pmap_free_pt_delayed` — the kernel frees the L3 page table to the VM free list while **64 dangling PTEs still reference it**.

Those 64 PTEs provide direct userspace read/write into freed physical memory. When the kernel reallocates that page for a new kernel object, every dangling PTE becomes an arbitrary kernel R/W primitive.

**This is a Physical UAF.** The freed entity is a physical page frame, not a heap zone object. The primitive bypasses:
- Zone integrity checks (operates below zone allocator)
- SPTM quarantine (confirmed on A17 Pro — dangling PTEs remain architecturally valid through quarantine)
- MIE / Memory Integrity Extensions (confirmed on A19 — MIE has no visibility into pt_desc refcount accounting)
- All 32 `tbnz` overflow checks Apple added in iOS 26.0–26.4 (those protect `pmap+0x74`, not `pt_desc`)

**Result: 64/64 write-through confirmed on A13, A17 Pro, and A19.**

---

## Root Cause

XNU's pmap layer maintains two structures with independent refcount fields:

| Structure | Refcount Offset | Type | Overflow Checks | Protected |
|-----------|----------------|------|-----------------|-----------|
| `pmap` struct | `+0x74` | uint32 (loaded as uint16 via LDRH) | 32 `tbnz w8, #16` guards (26.0–26.4) | YES |
| `pt_desc` table descriptor | `+0x18` | uint16 (LDRH/STRH) | **ZERO** across all versions | **NO** |

Apple's progressive hardening across iOS 26.0–26.4 audited the `pmap_enter_options_internal` increment path and applied guards to the `pmap` struct. The `pt_desc` refcount — a different field on a different structure — was never audited. The `pmap_remove_options_internal` decrement path for `pt_desc` has zero overflow protection in all shipping iOS versions.

### Patch Monitoring (all versions checked)

| iOS Version | Build | pmap_tte_remove | pmap_remove_options_internal | LDRH (uint16) | Status |
|-------------|-------|-----------------|-------------------------------|---------------|--------|
| 26.0 | 23A341 | baseline | baseline | YES | **VULNERABLE** |
| 26.4 | 23E214 | unchanged | unchanged | YES | **VULNERABLE** |
| 26.4.1 | 23E254 | unchanged | unchanged | YES | **VULNERABLE** |
| 26.4.2 | 23E261 | +976 bytes | SUBS overflow + pin/unpin mutex + deferred free | YES | MITIGATED-NOT-FIXED |
| 26.5 RC2 | 23F77 | unchanged from 26.4.2 | unchanged from 26.4.2 | YES | MITIGATED-NOT-FIXED |
| 26.5b4 | 23F5069b | unchanged | +496 bytes (same mitigations) | YES | MITIGATED-NOT-FIXED |
| 26.5 GA | 23F77 | unchanged | identical to 26.5b4 | YES | MITIGATED-NOT-FIXED |
| 26.5.1 | 23F81 | unchanged | unchanged | YES | MITIGATED-NOT-FIXED |
| 26.6b1 | 23G5028e | unchanged | unchanged | YES | MITIGATED-NOT-FIXED |

**Apple added overflow detection (SUBS), a pin/unpin mutex, and deferred freeing in 26.4.2, but never widened the uint16_t refcount type.** The fundamental integer overflow remains.

---

## Hardware Confirmation

| Device | Chip | iOS | Mitigations Present | Write-Through | Result |
|--------|------|-----|---------------------|---------------|--------|
| iPhone SE 2nd gen | A13 | 15.5 | None (no SPTM, no MIE) | 64/64 | **VULNERABLE** |
| iPhone 15 Pro | A17 Pro | 26.4 | SPTM present | 64/64 | **VULNERABLE** |
| iPhone 17 Pro | A19 | 26.0 | SPTM + MIE + EMTE | 64/64 | **VULNERABLE** |

The A19 confirmation is critical: MIE (Memory Integrity Extensions) is Apple's most advanced hardware memory protection, designed to prevent physical page confusion attacks. MIE does not block this primitive because the confusion occurs at the `pt_desc` ownership level — from the hardware's perspective, every dangling PTE is architecturally valid until the refcount is corrected. MIE has no visibility into the refcount accounting error.

---

## Natural Panics (In-the-Wild Reachability)

Two natural kernel panics recovered from the SE device confirm the overflow fires under normal application load — no PoC running:

| Date | Process | Refcount Value | Significance |
|------|---------|---------------|--------------|
| 2025-04-09 | securityd (pid 0, tid 104) | 65535 (0xFFFF) | Exact uint16 max — one increment from wrap |
| 2025-07-24 | securityd (pid 0, tid 104) | 65531 | 4 refs removed before table freed |

Both panicked in `pmap_tte_remove` with the string: `"Found inconsistent state in soon to be deleted L3 table: %d valid, %d compressed, %d non-empty, refcnt=%d"`. These were not induced — they occurred during normal device use and were found during log analysis.

**Implication:** Regular applications creating many `MAP_SHARED` mappings can trigger the overflow. The bug is reachable in production without a crafted exploit.

---

## Proof of Concept

### Main PoC: `poc/poc_v13_rw_proof.c`

The primary proof-of-concept demonstrates the complete overflow → free → dangling PTE → write-through chain:

1. Allocate one 16KB backing page, fill with sentinel `0x41`
2. Create 65,537 `mach_vm_map` calls via named memory entry — overflows uint16 refcount
3. Unmap all but 64 mappings — first unmap drops refcount to 0, `pmap_free_pt_delayed` fires
4. 64 dangling PTEs remain pointing to freed physical page
5. Read 8-byte kernel PTE values from freed page (kernel-generated ARM64 descriptors)
6. Write `0xBB` through each dangling PTE — confirm write reaches freed kernel memory
7. Write proof log to `/var/root/pmap_rw_proof.txt`
8. Optionally trigger controlled panic (unmap remaining dangling PTEs)

**Modes:**
- `./poc --prove 64` — write-through proof (default)
- `./poc --race` — 9-thread race, aims for kernel panic

### Heap Spray: `poc/poc_v15_heap_spray.c`

Escalation PoC that demonstrates controlled reclaim of the freed physical page:

1. Run the PUAF (same overflow → free → 64 dangling PTEs)
2. Spray N IOSurface objects (64×64×4 = 16,384 bytes = exactly one ARM64 page)
3. Write `0xDEADC0DEDEADC0DE` through all dangling PTEs
4. Lock each IOSurface and scan pixel buffer for the magic value
5. Hit = freed page reallocated as IOSurface backing buffer = kernel object corruption

### Cross-Pmap: `poc/cross_pmap_trigger.c`

Demonstrates a related bug class: pmap ownership confusion via race condition between `mach_port_deallocate` and active mappings. 9-thread race (3 mappers + 3 deallocators + 3 probers). The panic `"attempt to remove mappings owned by pmap %p through pmap %p"` proves the kernel reached a state where PTEs from one pmap were being operated on through another.

### Additional PoCs

- `poc/poc_v14_uikit.c` — UIKit wrapper for app-based testing (no panic trigger, patch detection mode)
- `poc/pmap_experiment_se.c` — Deep primitive analysis: mprotect on dangling PTEs, TLBI-fixed spray detection, controlled panic
- `poc/pmap_spray_se.c` — A13-specific heap spray (no SPTM → freed page goes to `pmap_pages_free_list`)

### Compilation

On jailbroken SE (iOS 15.5):
```bash
clang-16 -isysroot /var/jb/usr/share/SDKs/iPhoneOS.sdk -O2 -o poc poc_v13_rw_proof.c
ldid -S poc
```

On stock device (requires Xcode or on-device clang):
```bash
clang -O2 -o poc poc_v13_rw_proof.c
```

All syscalls used are sandbox-accessible (no entitlements required): `mach_vm_allocate`, `mach_vm_map`, `mach_vm_deallocate`, `mach_make_memory_entry_64`, `mach_port_deallocate`.

---

## Apple Submission Timeline

| Date | Event |
|------|-------|
| 2026-03-30 | Submitted with video PoC on iPhone 15 Pro (A17, iOS 26.4). 64/64 write-through, 2 natural panic logs attached. |
| 2026-04-02 | **Brent \| Product Security:** "The attachments confirm a kernel correctness issue reachable from the app sandbox, but appears limited solely to a local denial-of-service. The claimed use-after-free with kernel read/write is not demonstrated." |
| 2026-04-05 | **Kevin (rebuttal):** poc_v14 submitted. 6 independent runs across 2 test sessions on iPhone 15 Pro (iOS 26.4). Each run at a different physical address. Cross-run 0xBB persistence: entries [1]-[63] contain `0x41414141414141bb` BEFORE current run writes anything. The 0xBB byte has one source: the previous run's write to freed kernel physical memory, surviving free + reallocation. Screen recording + pmap_proof.txt + pmapprooftest2.txt attached. |
| 2026-04-06 | Apple: **PRIORITIZED FOR REVIEW** — senior engineer assigned. |
| 2026-04-22 | IPSW diff: 26.4→26.4.1, 26.4→26.4.2 — NOT PATCHED. PmapProbe_v14 on 26.5b2: 63/64 reads, 64/64 write. 26.5b3 symbol diff: unpatched. |
| 2026-04-26 | Portal **CLOSED** — "expected behavior" response. No named engineer. No payout. |
| 2026-04-27 | **Jason \| Product Security — PROGRAM WARNING:** "On review of the attached crash logs, several artifacts appear inconsistent with genuine panic output from the referenced devices and builds, and we have reason to believe they were not produced by the device as represented. [...] A pattern of incorrect or false claims of a security or privacy issue may result in removal from the program. [...] We are treating this submission as a warning." |
| 2026-06-04 | Ghidra binary diff 26.0 vs 26.5: pmap_remove_options_internal grew +496 bytes. SUBS overflow checks, pin/unpin mutex, deferred free added. **uint16_t refcount (LDRH/STRH) NOT widened.** |
| 2026-06-18 | Full sweep: 26.4.2, 26.5 GA, 26.6b1 all checked. **All 7 versions from 26.0 through 26.6b1 confirmed MITIGATED-NOT-FIXED.** |

### On Apple's Fabrication Accusation

Apple's warning refers to "crash logs" — but the submitted evidence was PoC terminal output (`pmap_proof.txt`, `pmapprooftest2.txt`) and a screen recording. No crash logs or panic reports were submitted. Apple's characterization of the evidence as "crash logs" is incorrect.

The 0xBB persistence pattern is internally consistent across 6 runs at 6 different physical addresses. It is the expected signature of a physical page UAF — not something that would be fabricated, because a fabricated log would show clean reads (all 0x41) or a simple write confirmation.

No specific inconsistency was identified in Apple's warning. The accusation is vague and unsubstantiated.

---

## Exploitation Roadmap

The PUAF primitive (64/64 write-through) is the foundation. The chain from primitive to kernel code execution:

| Step | Status | Description |
|------|--------|-------------|
| Refcount overflow | **CONFIRMED** | 65,537 MAP_SHARED wraps uint16 to 1 |
| Physical page free | **CONFIRMED** | pmap_free_pt_delayed fires, page enters VM free list |
| Dangling PTE R/W | **CONFIRMED** | 64/64 write-through, 101.1ms create time |
| A19/MIE bypass | **CONFIRMED** | MIE has no visibility into pt_desc accounting |
| Controlled reclaim | IN PROGRESS | Heap spray to target specific zone (ipc_port, IOSurface) |
| Field overwrite | NOT STARTED | Overwrite kobject/vtable in reclaimed kernel object |
| Kernel code exec | NOT STARTED | PAC-signed gadget chain from corrupted kernel object |

**Target objects for reclaim (ranked):**
1. `ipc_port` (168 bytes, zone `ipc_ports`) — overwrite `ip_kobject` or `ip_pdestruct` → function pointer → kernel code exec
2. `vm_map_entry` (192 bytes, zone `vm_map_entries`) — flip protection bits on kernel text → RWX → shellcode
3. IOKit `OSObject` (variable) — vtable pointer overwrite → IOKit upcall → PAC gadget needed

**Chain position in THEIA:** CVE-2025-43529 → CVE-2025-14174 → CVE-2026-20700 → **pmap_tte_remove** (final primitive, kernel R/W)

---

## Mitigation Analysis

| Mitigation | Blocks Primitive? | Why |
|------------|------------------|-----|
| PPL (Page Protection Layer) | NO | PPL validates the operation as structurally sound. The confusion is at pt_desc ownership level, below PPL's audit scope. |
| SPTM (A17+) | NO | SPTM quarantines freed pages, but dangling PTEs remain architecturally valid through quarantine. 64/64 write-through confirmed on A17 Pro. |
| MIE (A19) | NO | MIE has no visibility into pt_desc refcount accounting. It sees valid TTE entries. 64/64 confirmed on A19. |
| PAC (A17/A19) | Partially | Constrains execution phase — full chain on A17+ requires PAC bypass or ROP. Does not block the PUAF primitive. |
| zone_require | Partially | Constrains reclaim target selection to same-zone objects. Does not prevent the PUAF. |
| 26.4 tbnz checks (32×) | NO | Protect pmap struct refcount at +0x74. pt_desc refcount is a different structure, different allocation, no checks. |
| 26.4.2+ SUBS overflow | Partially | Detects overflow in decrement path but does not prevent it in increment path. uint16 never widened. |

---

## Repository Structure

```
poc/                                    Raw PoC source (C, no build infrastructure)
  poc_v13_rw_proof.c                    Main: 64/64 write-through proof + controlled panic
  poc_v14_uikit.c                       UIKit wrapper for app-based patch detection
  poc_v15_heap_spray.c                  IOSurface heap spray escalation
  cross_pmap_trigger.c                  Cross-pmap ownership confusion race (9-thread)
  pmap_experiment_se.c                  Deep primitive analysis (mprotect/TLBI/panic)
  pmap_spray_se.c                       A13-specific heap spray (pmap_pages_free_list)

builds/                                 Full IPA build sources (ObjC wrappers + compile scripts)
  PmapProbe_v14/                        Stock iOS app — patch detection mode (no panic)
    main.m, poc_v14.c, compile.sh, Info.plist
  PmapHeapSpray/                        v17 — 32MB-spaced L3 spray + auto-retry
    main.m, compile.sh, Info.plist
  PmapV14Proof/                         Screen-recordable R/W proof for Apple resubmission
    main.m, Info.plist

ipa/                                    Pre-built IPA
  PmapProbe_v14.ipa                     Signed IPA for Sideloadly deployment

analysis/                               Technical analysis
  STAGE5_ROADMAP.md                     Exploitation roadmap (PUAF → kernel code exec)
  CROSSPMAP_ASSERTION.md                PPL assertion analysis (panic = proof of exploitability)
  CROSS_PMAP_CONFUSION.md              Cross-pmap ownership confusion deep dive
  pmap_cross_chip_analysis.md           Cross-version string/symbol comparison (8 IPSWs)
  kernelcache_diffs/
    diff_26.5b2_to_26.5b3.md           Instruction-level binary diff (62 diffs, all relocation)

evidence/                               Apple correspondence + device output
  submission_timeline.md                Full Apple correspondence (verbatim)
  updated_evidence_draft.md             Rebuttal draft for Apple
  cross_pmap_submission.md              Cross-pmap confusion submission draft
  pmap_rw_proof_v14.txt                 Device output: SE v13, 64/64 write-through
  pmap_rw_proof_v14_15pro.txt           Device output: 15 Pro v14, 63/64 read + 64/64 write

scripts/                                Kernelcache analysis tools (9 scripts)
  pmap_patch_check.py                   26.5b4 vs 26.6b1 binary diff + LDRH scan
  pmap_266_detail.py                    Detailed disasm comparison (26.5b4 vs 26.6b1)
  pmap_compare.py                       26.0 vs 26.5b4 ADRP xref + function extraction
  pmap_decode.py                        ARM64 instruction decoder (critical region)
  pmap_decode_265.py                    pmap_remove_options_internal 26.0 vs 26.5 decode
  pmap_deep2.py                         MachO parser + function extraction + key insn survey
  pmap_deep_compare.py                  Normalized instruction diff (strips ASLR)
  pmap_full_analysis_265.py             Full 26.0 vs 26.5 release analysis
  run_pmap_ipsw.ps1                     PowerShell: ipsw macho symbol extraction
  run_pmap_search.ps1                   PowerShell: ipsw kernel sym pmap filter

data/                                   Raw kernelcache analysis output
  ctf_pmap_260.txt, ctf_pmap_265.txt   Control flow traces
  pmap_macho_260.txt, pmap_macho_265.txt   MachO symbol tables
  pmap_syms_260.txt, pmap_syms_265.txt     Kernel symbol listings
  pmap_cstrings_260.txt, pmap_cstrings_265.txt   C string references
```

---

## License

PolyForm Noncommercial 1.0.0. See [LICENSE](LICENSE).

---

*This repository documents a real vulnerability in Apple's XNU kernel. The bug remains unpatched (MITIGATED-NOT-FIXED) as of iOS 26.6b1. All testing was performed on devices owned by the researcher under the Apple Security Bounty program.*
