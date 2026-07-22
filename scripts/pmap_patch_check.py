#!/usr/bin/env python3
"""
pmap_tte_remove / pmap_remove_options_internal patch check: 26.5b4 vs 26.6b1
"""
import struct
import hashlib

KC265B4 = r'kernelcaches/26.5b4/com.apple.kernel'
KC266   = r'kernelcaches/26.6b1/kernelcache.release.iPhone18,1'

# 26.5b4 layout (from pmap_compare.py)
KC265B4_TEXT_EXEC_ADDR = 0xfffffe000a641000
KC265B4_TEXT_EXEC_OFF  = 0x00277000
KC265B4_TEXT_EXEC_SZ   = 0x008b6be8

# 26.6b1 layout (from macho info)
KC266_TEXT_EXEC_ADDR = 0xfffffe00082f0000
KC266_TEXT_EXEC_OFF  = 0x012ec000
KC266_TEXT_EXEC_SZ   = 0x02cac000
KC266_TEXT_ADDR      = 0xfffffe0007004000
KC266_TEXT_OFF       = 0x00000000

# String virtual addresses (derived from binary search + segment layout)
PMAP_TTE_REMOVE_VADDR_265B4 = 0xfffffe0007063157
PMAP_TTE_REMOVE_VADDR_266   = 0xfffffe0007063177

PMAP_REMOVE_OPT_VADDR_265B4 = 0xfffffe0007061b5a
PMAP_REMOVE_OPT_VADDR_266   = 0xfffffe0007061b7a


def find_adrp_add_xref(text_data, text_exec_base, target_vaddr):
    results = []
    target_page = target_vaddr & ~0xFFF
    target_off  = target_vaddr & 0xFFF
    for i in range(0, len(text_data) - 8, 4):
        insn_va = text_exec_base + i
        word = struct.unpack_from('<I', text_data, i)[0]
        if (word & 0x9F000000) == 0x90000000:
            immlo = (word >> 29) & 0x3
            immhi = (word >> 5) & 0x7FFFF
            imm   = ((immhi << 2) | immlo) << 12
            if imm & (1 << 32):
                imm -= (1 << 33)
            page = (insn_va & ~0xFFF) + imm
            if page == target_page:
                if i + 4 < len(text_data):
                    next_word = struct.unpack_from('<I', text_data, i + 4)[0]
                    if (next_word & 0xFFC00000) == 0x91000000:
                        add_imm = (next_word >> 10) & 0xFFF
                        if add_imm == target_off:
                            results.append((insn_va, page))
    return results


def find_near_function_start(text_data, text_exec_base, ref_va, search_back=0x2000):
    ref_off = ref_va - text_exec_base
    best = ref_va
    for i in range(min(ref_off, search_back), 4, -4):
        off = ref_off - i
        if off < 0:
            continue
        word = struct.unpack_from('<I', text_data, off)[0]
        if (word & 0xFFC07FFF) == 0xA9807BFD:
            best = text_exec_base + off
        elif (word & 0xFF800000) == 0xD1000000:
            candidate = text_exec_base + off
            if off >= 4:
                prev = struct.unpack_from('<I', text_data, off - 4)[0]
                if prev == 0xD65F03C0:
                    best = candidate
                    break
    return best


def extract_function_bytes(text_data, text_exec_base, func_start_va, max_size=0x2000):
    off = func_start_va - text_exec_base
    if off < 0 or off >= len(text_data):
        return b''
    end = off
    for i in range(off, min(off + max_size, len(text_data)), 4):
        word = struct.unpack_from('<I', text_data, i)[0]
        end = i + 4
        if word == 0xD65F03C0:
            break
    return text_data[off:end]


def norm_insn(w):
    """Strip PC-relative fields so structural comparison ignores KASLR."""
    if (w & 0x9F000000) == 0x90000000: return w & 0x9F00001F  # ADRP
    if (w & 0xFC000000) == 0x94000000: return w & 0xFC000000  # BL
    if (w & 0xFC000000) == 0x14000000: return w & 0xFC000000  # B
    if (w & 0x9F000000) == 0x10000000: return w & 0x9F00001F  # ADR
    return w


def scan_refcount_loads(func_bytes, func_start_va, label):
    print(f'  --- {label} refcount load scan ---')
    ldrh_count = 0
    ldrw_count = 0
    for i in range(0, len(func_bytes), 4):
        word = struct.unpack_from('<I', func_bytes, i)[0]
        va = func_start_va + i
        # LDRH immediate (unsigned offset): 0x79400000 / mask 0xFFC00000
        if (word & 0xFFC00000) == 0x79400000:
            ldrh_count += 1
            rn = (word >> 5) & 0x1F
            rt = word & 0x1F
            imm = ((word >> 10) & 0xFFF) * 2
            print(f'    +{i:04x} (0x{va:016x}): LDRH  w{rt}, [x{rn}, #{imm}]  (uint16_t load)')
        # LDR 32-bit immediate offset: 0xB9400000 / mask 0xFFC00000
        elif (word & 0xFFC00000) == 0xB9400000:
            ldrw_count += 1
    if ldrh_count == 0:
        print(f'    NO LDRH instructions — uint16_t NOT used for refcount load (widened or different pattern)')
    print(f'    Total LDRH: {ldrh_count}  LDR(32-bit): {ldrw_count}')


def analyze(name, vaddr265b4, vaddr266):
    print()
    print('=' * 65)
    print(f'ANALYZING: {name}')
    print('=' * 65)

    with open(KC265B4, 'rb') as f:
        data265 = f.read()
    with open(KC266, 'rb') as f:
        data266 = f.read()

    text265 = data265[KC265B4_TEXT_EXEC_OFF:KC265B4_TEXT_EXEC_OFF + KC265B4_TEXT_EXEC_SZ]
    text266 = data266[KC266_TEXT_EXEC_OFF:KC266_TEXT_EXEC_OFF + KC266_TEXT_EXEC_SZ]

    refs265 = find_adrp_add_xref(text265, KC265B4_TEXT_EXEC_ADDR, vaddr265b4)
    refs266 = find_adrp_add_xref(text266, KC266_TEXT_EXEC_ADDR,   vaddr266)

    print(f'  26.5b4  xrefs to string: {len(refs265)}')
    for va, _ in refs265[:3]:
        print(f'    -> 0x{va:016x}')
    print(f'  26.6b1  xrefs to string: {len(refs266)}')
    for va, _ in refs266[:3]:
        print(f'    -> 0x{va:016x}')

    if not refs265 or not refs266:
        print('  WARN: Could not find xrefs — cannot compare')
        return

    xref_va_265 = refs265[0][0]
    xref_va_266 = refs266[0][0]

    func_start_265 = find_near_function_start(text265, KC265B4_TEXT_EXEC_ADDR, xref_va_265)
    func_start_266 = find_near_function_start(text266, KC266_TEXT_EXEC_ADDR,   xref_va_266)

    print(f'  26.5b4  func start: 0x{func_start_265:016x}')
    print(f'  26.6b1  func start: 0x{func_start_266:016x}')

    func265 = extract_function_bytes(text265, KC265B4_TEXT_EXEC_ADDR, func_start_265)
    func266 = extract_function_bytes(text266, KC266_TEXT_EXEC_ADDR,   func_start_266)

    print(f'  26.5b4  size: {len(func265)} bytes')
    print(f'  26.6b1  size: {len(func266)} bytes')
    size_delta = len(func266) - len(func265)
    print(f'  Size delta: {size_delta:+d} bytes')

    h265 = hashlib.sha256(func265).hexdigest()[:16]
    h266 = hashlib.sha256(func266).hexdigest()[:16]
    print(f'  26.5b4  SHA256[:16]: {h265}')
    print(f'  26.6b1  SHA256[:16]: {h266}')

    if func265 == func266:
        print('  RESULT: IDENTICAL (byte-for-byte)')
    else:
        min_len = min(len(func265), len(func266))
        diff_words = []
        for i in range(0, min_len, 4):
            w265 = struct.unpack_from('<I', func265, i)[0]
            w266 = struct.unpack_from('<I', func266, i)[0]
            if norm_insn(w265) != norm_insn(w266):
                diff_words.append((i, w265, w266))

        if not diff_words and size_delta == 0:
            print('  RESULT: FUNCTIONALLY IDENTICAL (only PC-relative operands differ)')
        else:
            print(f'  RESULT: STRUCTURALLY CHANGED ({len(diff_words)} words differ, size delta {size_delta:+d})')
            print(f'  First 20 structural diffs:')
            for (off, w265, w266) in diff_words[:20]:
                print(f'    +{off:04x}  265b4=0x{w265:08x}  266=0x{w266:08x}')

    scan_refcount_loads(func265, func_start_265, '26.5b4')
    scan_refcount_loads(func266, func_start_266, '26.6b1')


if __name__ == '__main__':
    analyze('pmap_tte_remove',              PMAP_TTE_REMOVE_VADDR_265B4, PMAP_TTE_REMOVE_VADDR_266)
    analyze('pmap_remove_options_internal', PMAP_REMOVE_OPT_VADDR_265B4, PMAP_REMOVE_OPT_VADDR_266)
