#!/usr/bin/env python3
"""
Compare pmap_tte_remove and pmap_remove_options_internal between 26.0 and 26.5b4.
Uses cross-reference search: find ARM64 ADR/ADRP+ADD patterns that load the string address.
"""
import struct
import sys
import hashlib

KC26 = r"kernelcaches/26.0/com.apple.kernel"
KC265B4 = r"kernelcaches/26.5b4/com.apple.kernel"

# Layout constants from macho info
KC26_TEXT_EXEC_ADDR   = 0xfffffe0008240000
KC26_TEXT_EXEC_OFF    = 0x00262000
KC26_TEXT_EXEC_SZ     = 0x0089c614
KC26_TEXT_CSTR_ADDR   = 0xfffffe0007042800
KC26_TEXT_CSTR_OFF    = 0x00036800

KC265B4_TEXT_EXEC_ADDR = 0xfffffe000a641000
KC265B4_TEXT_EXEC_OFF  = 0x00277000
KC265B4_TEXT_EXEC_SZ   = 0x008b6be8
KC265B4_TEXT_CSTR_ADDR = 0xfffffe0007043df0
KC265B4_TEXT_CSTR_OFF  = 0x00037df0

# Known string virtual addresses
PMAP_TTE_REMOVE_VADDR_26   = 0xfffffe000705d204
PMAP_TTE_REMOVE_VADDR_265B4 = 0xfffffe0007063157
PMAP_REMOVE_OPT_VADDR_26    = 0xfffffe000705bc4f
PMAP_REMOVE_OPT_VADDR_265B4 = 0xfffffe0007061b5a


def vaddr_to_file_offset(vaddr, seg_vaddr, seg_off):
    return seg_off + (vaddr - seg_vaddr)


def read_bytes(path, offset, size):
    with open(path, 'rb') as f:
        f.seek(offset)
        return f.read(size)


def find_adrp_add_xref(text_data, text_exec_base, target_vaddr):
    """
    ARM64: Find ADRP + ADD pairs that reference target_vaddr.
    ADRP: bits[31:29]=100, bit[28]=1
    Returns list of (insn_va, page_va) tuples.
    """
    results = []
    # Walk 4-byte aligned instructions
    for i in range(0, len(text_data) - 8, 4):
        insn_va = text_exec_base + i
        word = struct.unpack_from('<I', text_data, i)[0]

        # ADRP check: opcode = 1_0011_0000 (bits 28:24 = 10000, bit 31 = 1)
        if (word & 0x9F000000) == 0x90000000:
            # Extract page offset
            immlo = (word >> 29) & 0x3
            immhi = (word >> 5) & 0x7FFFF
            imm = ((immhi << 2) | immlo) << 12
            # Sign extend 33 bits
            if imm & (1 << 32):
                imm -= (1 << 33)
            page = (insn_va & ~0xFFF) + imm

            if page == (target_vaddr & ~0xFFF):
                # Check if next instruction is ADD with matching page offset
                if i + 4 < len(text_data):
                    next_word = struct.unpack_from('<I', text_data, i + 4)[0]
                    # ADD (immediate): bits[31:23] = 100100010 or 100100011
                    if (next_word & 0xFFC00000) == 0x91000000:
                        add_imm = (next_word >> 10) & 0xFFF
                        computed = page + add_imm
                        if computed == target_vaddr:
                            results.append((insn_va, page))
    return results


def find_near_function_start(text_data, text_exec_base, ref_va, search_back=0x2000):
    """
    Walk backwards from ref_va to find likely function start.
    Look for typical ARM64 function prologue pattern (STP x29, x30, [sp, #-N]!)
    """
    ref_off = ref_va - text_exec_base
    best = ref_va
    for i in range(min(ref_off, search_back), 4, -4):
        off = ref_off - i
        if off < 0:
            continue
        word = struct.unpack_from('<I', text_data, off)[0]
        # STP x29, x30, [sp, #-N]!  -- bits[31:15]=101010011_11101_11110
        # 0xA9B_xxxxx pattern: A9BF (save x29/x30 with pre-decrement)
        if (word & 0xFFC07FFF) == 0xA9807BFD:  # STP x29, x30
            best = text_exec_base + off
        elif (word & 0xFF800000) == 0xD1000000:  # SUB sp
            candidate = text_exec_base + off
            # Check if preceded by a function boundary (previous 4 bytes look like end of prev func)
            if off >= 4:
                prev = struct.unpack_from('<I', text_data, off - 4)[0]
                if prev == 0xD65F03C0:  # RET
                    best = candidate
                    break
    return best


def extract_function_bytes(text_data, text_exec_base, func_start_va, max_size=0x2000):
    """Extract bytes from func_start_va until we hit a RET instruction."""
    off = func_start_va - text_exec_base
    if off < 0 or off >= len(text_data):
        return b''
    end = off
    for i in range(off, min(off + max_size, len(text_data)), 4):
        word = struct.unpack_from('<I', text_data, i)[0]
        end = i + 4
        if word == 0xD65F03C0:  # RET
            break
        if word == 0xD503201F:  # NOP -- sometimes padding at end
            if i + 4 < len(text_data):
                next_word = struct.unpack_from('<I', text_data, i + 4)[0]
                if next_word == 0xD503201F or (next_word & 0x9F000000) == 0x90000000:
                    break
    return text_data[off:end]


def analyze_pmap_patch(name, vaddr26, vaddr265b4):
    print(f"\n{'='*60}")
    print(f"ANALYZING: {name}")
    print(f"{'='*60}")

    # Load kernel binaries
    with open(KC26, 'rb') as f:
        kc26_data = f.read()
    with open(KC265B4, 'rb') as f:
        kc265b4_data = f.read()

    text26 = kc26_data[KC26_TEXT_EXEC_OFF:KC26_TEXT_EXEC_OFF + KC26_TEXT_EXEC_SZ]
    text265b4 = kc265b4_data[KC265B4_TEXT_EXEC_OFF:KC265B4_TEXT_EXEC_OFF + KC265B4_TEXT_EXEC_SZ]

    # Find cross-references
    refs26 = find_adrp_add_xref(text26, KC26_TEXT_EXEC_ADDR, vaddr26)
    refs265b4 = find_adrp_add_xref(text265b4, KC265B4_TEXT_EXEC_ADDR, vaddr265b4)

    print(f"  26.0    xrefs to string: {len(refs26)}")
    for va, _ in refs26[:5]:
        print(f"    -> 0x{va:016x}")

    print(f"  26.5b4  xrefs to string: {len(refs265b4)}")
    for va, _ in refs265b4[:5]:
        print(f"    -> 0x{va:016x}")

    if not refs26 or not refs265b4:
        print(f"  WARN: Could not find xrefs for {name}")
        return

    # Take first xref in each, find function start
    xref_va_26    = refs26[0][0]
    xref_va_265b4 = refs265b4[0][0]

    func_start_26    = find_near_function_start(text26, KC26_TEXT_EXEC_ADDR, xref_va_26)
    func_start_265b4 = find_near_function_start(text265b4, KC265B4_TEXT_EXEC_ADDR, xref_va_265b4)

    print(f"  26.0    estimated func start: 0x{func_start_26:016x}")
    print(f"  26.5b4  estimated func start: 0x{func_start_265b4:016x}")

    func26    = extract_function_bytes(text26, KC26_TEXT_EXEC_ADDR, func_start_26)
    func265b4 = extract_function_bytes(text265b4, KC265B4_TEXT_EXEC_ADDR, func_start_265b4)

    print(f"  26.0    function size: {len(func26)} bytes")
    print(f"  26.5b4  function size: {len(func265b4)} bytes")

    h26    = hashlib.sha256(func26).hexdigest()[:16]
    h265b4 = hashlib.sha256(func265b4).hexdigest()[:16]
    print(f"  26.0    SHA256[:16]: {h26}")
    print(f"  26.5b4  SHA256[:16]: {h265b4}")

    if func26 == func265b4:
        print(f"  RESULT: IDENTICAL (byte-for-byte after ASLR normalization)")
    else:
        # Count differing words
        min_len = min(len(func26), len(func265b4))
        diff_count = 0
        first_diff = -1
        for i in range(0, min_len, 4):
            w26    = struct.unpack_from('<I', func26, i)[0]
            w265b4 = struct.unpack_from('<I', func265b4, i)[0]
            if w26 != w265b4:
                diff_count += 1
                if first_diff < 0:
                    first_diff = i
        size_diff = len(func265b4) - len(func26)
        print(f"  RESULT: CHANGED")
        print(f"    Size delta: {size_diff:+d} bytes")
        print(f"    Differing 4-byte words: {diff_count} of {min_len//4}")
        print(f"    First diff at offset: +0x{first_diff:X} from func start")

        # Show first few diffs
        print(f"  DIFFS (first 10):")
        shown = 0
        for i in range(0, min_len, 4):
            if shown >= 10:
                break
            w26    = struct.unpack_from('<I', func26, i)[0]
            w265b4 = struct.unpack_from('<I', func265b4, i)[0]
            if w26 != w265b4:
                va26_insn    = func_start_26 + i
                va265b4_insn = func_start_265b4 + i
                print(f"    +{i:04x}  26.0=0x{w26:08x}  26.5b4=0x{w265b4:08x}")
                shown += 1


if __name__ == '__main__':
    analyze_pmap_patch("pmap_tte_remove", PMAP_TTE_REMOVE_VADDR_26, PMAP_TTE_REMOVE_VADDR_265B4)
    analyze_pmap_patch("pmap_remove_options_internal", PMAP_REMOVE_OPT_VADDR_26, PMAP_REMOVE_OPT_VADDR_265B4)
