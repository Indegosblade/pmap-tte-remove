#!/usr/bin/env python3
"""
Deep comparison of pmap_remove_options_internal between 26.0 and 26.5b4.
Focus: refcount handling (uint16 overflow vulnerability).
Normalizes ASLR-dependent instructions before comparing.
"""
import struct
import sys

KC26 = r"kernelcaches/26.0/com.apple.kernel"
KC265B4 = r"kernelcaches/26.5b4/com.apple.kernel"

KC26_TEXT_EXEC_ADDR   = 0xfffffe0008240000
KC26_TEXT_EXEC_OFF    = 0x00262000
KC26_TEXT_EXEC_SZ     = 0x0089c614

KC265B4_TEXT_EXEC_ADDR = 0xfffffe000a641000
KC265B4_TEXT_EXEC_OFF  = 0x00277000
KC265B4_TEXT_EXEC_SZ   = 0x008b6be8


def is_adrp(word):
    return (word & 0x9F000000) == 0x90000000

def is_bl(word):
    return (word & 0xFC000000) == 0x94000000

def is_b_cond(word):
    return (word & 0xFF000010) == 0x54000000

def is_ldr_adr_relative(word):
    # LDR (literal): bits[31:30,27:24] = xx_0110_00
    return (word & 0x3F000000) == 0x18000000 or (word & 0x3F000000) == 0x10000000

def normalize_insn(word):
    """Normalize ASLR-dependent fields to 0 for comparison."""
    if is_adrp(word):
        # Zero out immhi and immlo
        return word & 0x1F000000  # keep only opcode + Rd
    if is_bl(word):
        return 0x94000000  # BL with offset zeroed
    if is_b_cond(word):
        return word & 0xFF00001F  # keep condition, zero offset
    # LDR literal
    if (word & 0x3B000000) == 0x18000000:
        return word & 0xFF00001F
    return word


def extract_func_bytes(kc_path, text_exec_off, text_exec_addr, func_va, max_bytes=0x1000):
    with open(kc_path, 'rb') as f:
        f.seek(text_exec_off)
        text = f.read(max_bytes * 4)
    off = func_va - text_exec_addr
    result = []
    for i in range(off, min(off + max_bytes, len(text)), 4):
        word = struct.unpack_from('<I', text, i)[0]
        result.append(word)
        if word == 0xD65F03C0:  # RET
            break
    return result


# Function addresses from previous run
PMAP_REMOVE_OPT_26    = 0xfffffe0008405eb4
PMAP_REMOVE_OPT_265B4 = 0xfffffe000a825408
PMAP_TTE_REMOVE_26    = 0xfffffe0008405350
PMAP_TTE_REMOVE_265B4 = 0xfffffe000a824af0


def analyze_func(name, va26, va265b4):
    print(f"\n{'='*70}")
    print(f"DEEP ANALYSIS: {name}")
    print(f"  26.0    VA: 0x{va26:016x}")
    print(f"  26.5b4  VA: 0x{va265b4:016x}")
    print(f"{'='*70}")

    insns26    = extract_func_bytes(KC26, KC26_TEXT_EXEC_OFF, KC26_TEXT_EXEC_ADDR, va26)
    insns265b4 = extract_func_bytes(KC265B4, KC265B4_TEXT_EXEC_OFF, KC265B4_TEXT_EXEC_ADDR, va265b4)

    print(f"  26.0    instruction count: {len(insns26)}")
    print(f"  26.5b4  instruction count: {len(insns265b4)}")
    print(f"  Size delta: {(len(insns265b4) - len(insns26)) * 4:+d} bytes")

    # ARM64 opcodes relevant to uint16 refcount handling:
    # LDRH  (load halfword):  bits[31:22] = 0111100101 = 0x79400000
    # STRH  (store halfword): bits[31:22] = 0111100000 = 0x78000000
    # UXTH  (zero extend hw): it's AND x,x,#0xFFFF or LSL+LSR pattern
    # ADD (immediate for refcount increment)
    # CBNZ/CBZ for zero check
    # CMP for overflow check (refcount == 0 or refcount == 0xFFFF)

    def classify(word):
        if (word & 0xFFC00000) == 0x79400000:
            return 'LDRH'
        if (word & 0xFFC00000) == 0x79000000:
            return 'STRH'
        if word == 0xD65F03C0:
            return 'RET'
        if (word & 0xFF000000) == 0x36000000 or (word & 0xFF000000) == 0x37000000:
            return 'TBZ/TBNZ'
        if (word & 0xFF000000) == 0xB4000000 or (word & 0xFF000000) == 0xB5000000:
            return 'CBZ/CBNZ'
        if (word & 0x7F800000) == 0x71000000:
            return 'SUBS/CMP-imm'
        if (word & 0x7F800000) == 0x6B000000:
            return 'SUBS/CMP-reg'
        if is_adrp(word):
            return 'ADRP'
        if is_bl(word):
            return 'BL'
        if (word & 0xFF800000) == 0x11000000:
            return 'ADD-imm'
        if (word & 0xFF800000) == 0x51000000:
            return 'SUB-imm'
        if (word & 0xFFC00000) == 0x53000000 or (word & 0xFFC00000) == 0xD3400000:
            return 'UBFM/LSR'  # used for UXTH normalization
        if (word & 0xFFC00000) == 0x12000000:
            return 'AND-imm'   # can mask to 0xFFFF
        return None

    print(f"\n  --- Key instructions (LDRH/STRH/CMP/CBZ/TBZ) ---")

    def show_key(insns, label, base_va):
        hits = []
        for i, w in enumerate(insns):
            c = classify(w)
            if c and c not in ('ADRP', 'BL', 'ADD-imm', 'SUB-imm', 'RET'):
                hits.append((i, w, c))
        print(f"  {label}:")
        for i, w, c in hits:
            va = base_va + i * 4
            print(f"    +{i*4:04x}  0x{w:08x}  {c}")
        return hits

    h26    = show_key(insns26, "26.0",    va26)
    h265b4 = show_key(insns265b4, "26.5b4", va265b4)

    # Specific check: LDRH (refcount load) pattern
    ldrh_26    = [(i, w) for i, w, c in h26    if c == 'LDRH']
    ldrh_265b4 = [(i, w) for i, w, c in h265b4 if c == 'LDRH']
    strh_26    = [(i, w) for i, w, c in h26    if c == 'STRH']
    strh_265b4 = [(i, w) for i, w, c in h265b4 if c == 'STRH']

    print(f"\n  LDRH count:  26.0={len(ldrh_26)}  26.5b4={len(ldrh_265b4)}")
    print(f"  STRH count:  26.0={len(strh_26)}  26.5b4={len(strh_265b4)}")

    # Look for uint16 overflow check: would be CMP against 0xFFFF or similar
    # In ARM64: SUBS wzr, wN, #0xffff  or  MOVZ + CMP
    print(f"\n  SUBS/CMP instructions:")
    for i, w, c in h26:
        if 'CMP' in c or 'SUBS' in c:
            if (w & 0x7F800000) == 0x71000000:
                imm = (w >> 10) & 0xFFF
                print(f"    26.0    +{i*4:04x}  CMP/SUBS imm=0x{imm:x} ({imm})")
            else:
                print(f"    26.0    +{i*4:04x}  0x{w:08x}")
    for i, w, c in h265b4:
        if 'CMP' in c or 'SUBS' in c:
            if (w & 0x7F800000) == 0x71000000:
                imm = (w >> 10) & 0xFFF
                print(f"    26.5b4  +{i*4:04x}  CMP/SUBS imm=0x{imm:x} ({imm})")
            else:
                print(f"    26.5b4  +{i*4:04x}  0x{w:08x}")

    # Normalize and compare
    norm26    = [normalize_insn(w) for w in insns26]
    norm265b4 = [normalize_insn(w) for w in insns265b4]

    min_len = min(len(norm26), len(norm265b4))
    norm_diff = sum(1 for a, b in zip(norm26, norm265b4) if a != b)
    print(f"\n  Normalized diff: {norm_diff} of {min_len} instructions differ")
    if norm_diff == 0 and len(insns26) == len(insns265b4):
        print(f"  VERDICT: IDENTICAL LOGIC (only ASLR relocations differ)")
    elif norm_diff <= 5:
        print(f"  VERDICT: MINOR CHANGE (likely just relocation differences)")
    else:
        print(f"  VERDICT: SUBSTANTIVE CODE CHANGE ({norm_diff} instructions differ after normalization)")

    # Print normalized diffs
    print(f"\n  Normalized instruction diffs:")
    shown = 0
    for i in range(min_len):
        if shown >= 20:
            print(f"    ... ({norm_diff - shown} more)")
            break
        if norm26[i] != norm265b4[i]:
            print(f"    +{i*4:04x}  norm26=0x{norm26[i]:08x}  norm265b4=0x{norm265b4[i]:08x}  raw26=0x{insns26[i]:08x}  raw265b4=0x{insns265b4[i]:08x}")
            shown += 1


if __name__ == '__main__':
    analyze_func("pmap_remove_options_internal", PMAP_REMOVE_OPT_26, PMAP_REMOVE_OPT_265B4)
    analyze_func("pmap_tte_remove", PMAP_TTE_REMOVE_26, PMAP_TTE_REMOVE_265B4)
