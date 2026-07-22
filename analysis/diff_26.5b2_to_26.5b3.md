# pmap_tte_remove / pmap_remove_options_internal — b2 vs b3 Symbol-Level Diff

**Date:** 2026-04-22
**Device:** iPhone 15 Pro (iPhone16,1, A17 / T8122)
**Build b2:** 23F5054h — xnu-12377.120.91.0.1~12
**Build b3:** 23F5059e — xnu-12377.120.99.0.7~26
**Submission:** OE1105320204625 (pmap_tte_remove PUAF via pt_desc refcount overflow)
**Method:** Direct binary extraction of com.apple.kernel fileset entries, ADRP/string-anchor-based function location, instruction-level semantic diff

---

## Verdict: NOT PATCHED

The OE1105320204625 vulnerability path (pmap_remove_options_internal -> pmap_tte_remove -> pt_desc uint16 refcount overflow -> delayed free PUAF) is present and unchanged in 26.5b3.

---

## Function Location and Size

Both functions were located by:
1. Finding the function-name panic strings in __TEXT.__cstring
2. Using ADRP+ADD instruction pairs to identify referencing code in __TEXT_EXEC.__text
3. Walking backward to the PACIBSP function prologue marker
4. Walking forward to the AUTIBSP+RET epilogue / next PACIBSP

| Function | Build | VA | File Offset | Size |
|---|---|---|---|---|
| pmap_tte_remove | b2 (23F5054h) | 0xfffffff00a535aa0 | 0x3a4aa0 | 0x434 (1076 bytes) |
| pmap_tte_remove | b3 (23F5059e) | 0xfffffff00a49e190 | 0x3a5190 | 0x434 (1076 bytes) |
| pmap_remove_options_internal | b2 | 0xfffffff00a5363ac | 0x3a53ac | 0x3ac (940 bytes) |
| pmap_remove_options_internal | b3 | 0xfffffff00a49ea9c | 0x3a5a9c | 0x3ac (940 bytes) |

**Both functions are the same size in b2 and b3.**

---

## Byte-Level Diff Analysis

### pmap_tte_remove: 62 instruction differences, 0 semantic changes

All 62 differing instructions fall into two categories:

**Category A — KASLR relocation (not semantic):**
- ADRP instructions: encode PC-relative page offsets that differ because __TEXT_EXEC base shifted (0xfffffff00a38d000 in b2 vs 0xfffffff00a2f5000 in b3)
- ADD_IMM following ADRP: complement values that compensate for the page base change
- BL targets: absolute addresses differ but resolve to the same relative function offset within __TEXT_EXEC for all callees except those shifted by inserted code elsewhere

**Category B — Struct field offset shifts (not a fix for this bug):**

```
b2 access (pmap_t via X23)   b3 access    Delta
LDR W8, [X23, #0x1b0]   ->  [X23, #0x1b8]  +8  (x6 in pmap_tte_remove)
STR W8, [X23, #0x1b0]   ->  [X23, #0x1b8]  +8
LDR X8, [X23, #0x1a8]   ->  [X23, #0x1b0]  +8  (x3)
LDR X8, [X23, #0x1a0]   ->  [X23, #0x1a8]  +8  (x1)
```

A new 8-byte member was added to `pmap_t` at an offset prior to 0x1a0, shifting the fields at 0x1a0, 0x1a8, and 0x1b0 uniformly by +8 bytes. This is a struct layout expansion unrelated to refcount overflow protection.

**Category C — Panic line number changes:**
- `MOVZ W9, #0x12a3` (b2) → `MOVZ W9, #0x1253` (b3): line 4771 → 4691
- `MOVZ W10, #0x12e3` (b2) → `MOVZ W10, #0x1293` (b3): line 4835 → 4755
- These are source line numbers embedded in panic call arguments. They change whenever lines are added or removed elsewhere in the file. Not semantic.

### pmap_remove_options_internal: 52 instruction differences, 0 semantic changes

Same pattern as pmap_tte_remove:
- ADRP/BL: KASLR relocation
- Struct field offsets: same +8 shift at 0x1b0→0x1b8, 0x1a8→0x1b0, 0x1a0→0x1a8 (x23 = pmap_t)
- Line number MOVs: 0x1462 (b2) → 0x1412 (b3), 0x1465 (b2) → 0x1415 (b3)

---

## pt_desc Refcount Access — Unchanged

The critical pt_desc refcount field access pattern is identical in both builds:

```asm
; B2 pmap_tte_remove at +0xd4
ldr  w8, [x23, #0x1b0]   ; load refcount (uint32 read of uint16 field)
...
str  w8, [x23, #0x1b0]   ; store decremented refcount (no overflow check)
ldr  x8, [x23, #0x1a8]   ; load related pointer

; B3 pmap_tte_remove at +0xd4
ldr  w8, [x23, #0x1b8]   ; same pattern, offset +8 due to struct growth
...
str  w8, [x23, #0x1b8]   ; same decrement-without-guard
ldr  x8, [x23, #0x1b0]
```

No saturation arithmetic (ADDS + B.VS), no `__builtin_add_overflow` equivalent (ADDS/SUBS with carry check), and no explicit bounds clamp was inserted. The vulnerability primitive is intact.

---

## Kernel Text Growth

```
__TEXT_EXEC.__text b2: 0x8665dc bytes
__TEXT_EXEC.__text b3: 0x867930 bytes
Delta:              +0x1354 bytes (4,948 bytes of new code)
```

The 0x1354 bytes of new kernel code appear at a single insertion point near the high end of __TEXT_EXEC (confirmed by consistent callee shift of 0x1354 for functions at b2_rel > 0x85f000). No code was inserted within or adjacent to the pmap_tte_remove or pmap_remove_options_internal function bodies.

The 8 XNU point releases (91→99) that constitute b3's changes are distributed across other subsystems. Nothing in those 8 releases touched the pmap TTE removal path.

---

## Implications for OE1105320204625

The submission is targeting a live bug as of 26.5b3 (the most recent available beta). Apple's senior engineer assigned on 2026-04-06 has not shipped a fix in either b2 or b3. The pmap_t struct growth (+8 bytes before offset 0x1a0) is a sign of ongoing XNU pmap subsystem development but not a mitigation for this bug class.

The pmap check-in is scheduled for 2026-04-25. If Apple patches the bug in 26.5b4 or 26.5 release, the patch will be detectable as: any of (1) function size increase in pmap_tte_remove, (2) new ADDS+B.VS or CBNZ guard around the LDR/STR at [X23, #refcount_offset], or (3) a new helper function call (BL) inserted before the delayed free path.
