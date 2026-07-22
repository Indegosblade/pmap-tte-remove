#!/usr/bin/env python3
"""
Full pmap patch analysis: 26.0 vs 26.5 final release.
Finds pmap_tte_remove + pmap_remove_options_internal via ADRP xref,
then deep-compares for uint16 refcount overflow fix.
"""
import struct, hashlib, sys

KC26  = r"kernelcaches/26.0/com.apple.kernel"
KC265 = r"kernelcaches/26.5/com.apple.kernel"

STRS_26 = {
    "pmap_tte_remove":              0xfffffe000705d204,
    "pmap_remove_options_internal": 0xfffffe000705bc4f,
}
STRS_265 = {
    "pmap_tte_remove":              0xfffffe000706009c,
    "pmap_remove_options_internal": 0xfffffe000705ea9f,
}


def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]


def parse_text_exec(data):
    magic = read_u32(data, 0)
    if magic != 0xFEEDFACF:
        return None, None, None
    ncmds = read_u32(data, 16)
    off = 32
    for _ in range(ncmds):
        if off + 8 > len(data): break
        cmd = read_u32(data, off)
        cmdsize = read_u32(data, off + 4)
        if cmd == 0x19:
            segname = data[off+8:off+24].rstrip(b'\x00').decode('ascii', errors='replace')
            vmaddr  = struct.unpack_from('<Q', data, off+24)[0]
            fileoff = struct.unpack_from('<Q', data, off+40)[0]
            filesize = struct.unpack_from('<Q', data, off+48)[0]
            if segname == '__TEXT_EXEC':
                return vmaddr, fileoff, filesize
        off += cmdsize
    return None, None, None


def find_adrp_add_xref(text_data, text_base, target_va):
    target_page = target_va & ~0xFFF
    target_off  = target_va & 0xFFF
    results = []
    for i in range(0, len(text_data) - 8, 4):
        word = read_u32(text_data, i)
        if (word & 0x9F000000) != 0x90000000: continue
        insn_va = text_base + i
        immlo = (word >> 29) & 3
        immhi = (word >> 5) & 0x7FFFF
        imm   = ((immhi << 2) | immlo) << 12
        if imm & (1 << 32): imm -= (1 << 33)
        page = (insn_va & ~0xFFF) + imm
        if page != target_page: continue
        rd = word & 0x1F
        nw = read_u32(text_data, i + 4)
        if (nw & 0xFF800000) == 0x91000000:
            add_imm = (nw >> 10) & 0xFFF
            rn = (nw >> 5) & 0x1F
            if rn == rd and add_imm == target_off:
                results.append(insn_va)
    return results


def find_func_start(text_data, text_base, ref_va, max_back=0x3000):
    ref_off = ref_va - text_base
    best = ref_va
    for delta in range(8, min(ref_off, max_back), 4):
        off = ref_off - delta
        if off < 0: break
        word = read_u32(text_data, off)
        if (word & 0xFFC07FE0) == 0xA9007BE0 or (word & 0xFFC07FFF) == 0xA9807BFD:
            best = text_base + off
        elif word == 0xD65F03C0 and delta > 4:
            best = text_base + off + 4
            break
    return best


def extract_func(text_data, text_base, func_va, max_insns=2000):
    off = func_va - text_base
    if off < 0 or off >= len(text_data): return []
    insns = []
    for i in range(off, min(off + max_insns*4, len(text_data)), 4):
        w = read_u32(text_data, i)
        insns.append(w)
        if w == 0xD65F03C0: break
    return insns


def classify(w):
    if (w & 0xFFC00000) == 0x79400000: return 'LDRH'
    if (w & 0xFFC00000) == 0x79000000: return 'STRH'
    if w == 0xD65F03C0: return 'RET'
    if (w & 0xFF000000) in (0x36000000, 0x37000000): return 'TBZ/TBNZ'
    if (w & 0xFF000000) in (0xB4000000, 0xB5000000): return 'CBZ/CBNZ'
    if (w & 0x7F800000) == 0x71000000: return 'SUBS/CMP-imm'
    if (w & 0x7F800000) == 0x6B000000: return 'SUBS/CMP-reg'
    if (w & 0x9F000000) == 0x90000000: return 'ADRP'
    if (w & 0xFC000000) == 0x94000000: return 'BL'
    if (w & 0xFF800000) == 0x11000000: return 'ADD32'
    if (w & 0xFF800000) == 0x91000000: return 'ADD64'
    if (w & 0xFFC00000) == 0x53000000:
        immr = (w >> 16) & 0x3F
        imms = (w >> 10) & 0x3F
        if immr == 0 and imms == 15: return 'UXTH'
        return 'UBFM32'
    if (w & 0xFFC00000) == 0xD3400000:
        imms = (w >> 10) & 0x3F
        if imms == 31: return 'UXTW'
        return 'UBFM64'
    if (w & 0xFFC00000) == 0xB9400000: return 'LDR-w'
    if (w & 0xFFC00000) == 0xF9400000: return 'LDR-x'
    if (w & 0xFFC00000) == 0xB9000000: return 'STR-w'
    if (w & 0xFFC00000) == 0xF9000000: return 'STR-x'
    return None


def decode(w):
    c = classify(w)
    if c == 'LDRH':
        imm = ((w>>10)&0xFFF)*2; rn=(w>>5)&0x1F; rt=w&0x1F
        return f"LDRH w{rt},[x{rn},#0x{imm:x}]"
    if c == 'STRH':
        imm = ((w>>10)&0xFFF)*2; rn=(w>>5)&0x1F; rt=w&0x1F
        return f"STRH w{rt},[x{rn},#0x{imm:x}]"
    if c == 'UXTH':
        rn=(w>>5)&0x1F; rd=w&0x1F
        return f"UXTH w{rd},w{rn}"
    if c == 'UXTW':
        rn=(w>>5)&0x1F; rd=w&0x1F
        return f"UXTW x{rd},w{rn}"
    if c == 'SUBS/CMP-imm':
        imm=(w>>10)&0xFFF; rn=(w>>5)&0x1F; rd=w&0x1F
        op='CMP' if rd==31 else 'SUBS'
        sz='w' if (w>>31)==0 else 'x'
        return f"{op} {sz}{rn if rd==31 else rd}, #0x{imm:x}({imm})"
    if c == 'CBZ/CBNZ':
        rt=w&0x1F; off=((w>>5)&0x7FFFF)<<2
        if off&0x100000: off-=0x200000
        return f"CB{'NZ' if (w>>24)&1 else 'Z'} x{rt},{off:+d}"
    if c == 'TBZ/TBNZ':
        rt=w&0x1F; bit=((w>>19)&0x1F)|(((w>>31)&1)<<5)
        off=((w>>5)&0x3FFF)<<2
        if off&0x8000: off-=0x10000
        return f"TB{'NZ' if (w>>24)&1 else 'Z'} x{rt},#{bit},{off:+d}"
    if c == 'LDR-w':
        imm=((w>>10)&0xFFF)*4; rn=(w>>5)&0x1F; rt=w&0x1F
        return f"LDR w{rt},[x{rn},#0x{imm:x}]"
    if c == 'LDR-x':
        imm=((w>>10)&0xFFF)*8; rn=(w>>5)&0x1F; rt=w&0x1F
        return f"LDR x{rt},[x{rn},#0x{imm:x}]"
    if c == 'STR-w':
        imm=((w>>10)&0xFFF)*4; rn=(w>>5)&0x1F; rt=w&0x1F
        return f"STR w{rt},[x{rn},#0x{imm:x}]"
    if c == 'STR-x':
        imm=((w>>10)&0xFFF)*8; rn=(w>>5)&0x1F; rt=w&0x1F
        return f"STR x{rt},[x{rn},#0x{imm:x}]"
    return f"0x{w:08x}"


def normalize(w):
    if (w & 0x9F000000) == 0x90000000: return w & 0x1F000000
    if (w & 0xFC000000) == 0x94000000: return 0x94000000
    if (w & 0xFF000010) == 0x54000000: return w & 0xFF00001F
    if (w & 0x3B000000) == 0x18000000: return w & 0xFF00001F
    return w


print("=" * 70)
print("LOADING KERNELS")
print("=" * 70)
with open(KC26,  'rb') as f: data26  = f.read()
with open(KC265, 'rb') as f: data265 = f.read()
print(f"26.0 size: {len(data26):,}")
print(f"26.5 size: {len(data265):,}")

va26,  off26,  sz26  = parse_text_exec(data26)
va265, off265, sz265 = parse_text_exec(data265)
print(f"26.0 __TEXT_EXEC: va=0x{va26:x} off=0x{off26:x} sz=0x{sz26:x}")
print(f"26.5 __TEXT_EXEC: va=0x{va265:x} off=0x{off265:x} sz=0x{sz265:x}")

text26  = data26[off26:off26+sz26]
text265 = data265[off265:off265+sz265]

for fname in ["pmap_tte_remove", "pmap_remove_options_internal"]:
    print()
    print("=" * 70)
    print(f"ANALYZING: {fname}")
    print("=" * 70)

    str_va26  = STRS_26[fname]
    str_va265 = STRS_265[fname]

    refs26  = find_adrp_add_xref(text26,  va26,  str_va26)
    refs265 = find_adrp_add_xref(text265, va265, str_va265)
    print(f"Xrefs 26.0: {len(refs26)}")
    for r in refs26[:3]: print(f"  0x{r:016x}")
    print(f"Xrefs 26.5: {len(refs265)}")
    for r in refs265[:3]: print(f"  0x{r:016x}")

    if not refs26 or not refs265:
        print("SKIP: no xrefs")
        continue

    func26  = find_func_start(text26,  va26,  refs26[0])
    func265 = find_func_start(text265, va265, refs265[0])
    print(f"Func 26.0:  0x{func26:016x}")
    print(f"Func 26.5:  0x{func265:016x}")

    insns26  = extract_func(text26,  va26,  func26)
    insns265 = extract_func(text265, va265, func265)
    size26  = len(insns26)*4
    size265 = len(insns265)*4
    print(f"Size 26.0:  {size26} bytes ({len(insns26)} insns)")
    print(f"Size 26.5:  {size265} bytes ({len(insns265)} insns)")
    print(f"Size delta: {size265-size26:+d} bytes")

    # --- Classify all instructions ---
    def survey(insns, label):
        ldrh=[]; strh=[]; uxth=[]; uxtw=[]; cbz=[]; tbz=[]; cmp_insns=[]
        for i, w in enumerate(insns):
            c = classify(w)
            if c == 'LDRH': ldrh.append((i,w))
            elif c == 'STRH': strh.append((i,w))
            elif c == 'UXTH': uxth.append((i,w))
            elif c == 'UXTW': uxtw.append((i,w))
            elif c == 'CBZ/CBNZ': cbz.append((i,w))
            elif c == 'TBZ/TBNZ': tbz.append((i,w))
            elif c and ('CMP' in c or 'SUBS' in c): cmp_insns.append((i,w,c))
        print(f"\n{label}:")
        print(f"  LDRH: {len(ldrh)}")
        for i,w in ldrh: print(f"    +{i*4:04x}  {decode(w)}")
        print(f"  STRH: {len(strh)}")
        for i,w in strh: print(f"    +{i*4:04x}  {decode(w)}")
        print(f"  UXTH: {len(uxth)}")
        for i,w in uxth: print(f"    +{i*4:04x}  {decode(w)}")
        print(f"  UXTW: {len(uxtw)}")
        for i,w in uxtw: print(f"    +{i*4:04x}  {decode(w)}")
        print(f"  CBZ/CBNZ: {len(cbz)}")
        for i,w in cbz: print(f"    +{i*4:04x}  {decode(w)}")
        print(f"  TBZ/TBNZ: {len(tbz)}")
        for i,w in tbz: print(f"    +{i*4:04x}  {decode(w)}")
        print(f"  CMP/SUBS: {len(cmp_insns)}")
        for i,w,c in cmp_insns: print(f"    +{i*4:04x}  {decode(w)}")
        return ldrh, strh, uxth, uxtw, cbz, tbz, cmp_insns

    ldrh26, strh26, uxth26, uxtw26, cbz26, tbz26, cmps26 = survey(insns26, "26.0")
    ldrh265, strh265, uxth265, uxtw265, cbz265, tbz265, cmps265 = survey(insns265, "26.5")

    # Normalized diff
    norm26  = [normalize(w) for w in insns26]
    norm265 = [normalize(w) for w in insns265]
    ndiff = sum(1 for a,b in zip(norm26,norm265) if a!=b)
    print(f"\nNormalized diff: {ndiff} of {min(len(norm26),len(norm265))} instructions")

    if ndiff == 0 and len(insns26) == len(insns265):
        print("VERDICT: IDENTICAL LOGIC (only ASLR relocations)")
    elif ndiff <= 3 and len(insns26) == len(insns265):
        print("VERDICT: TRIVIAL CHANGE")
    else:
        extra = len(insns265) - len(insns26)
        print(f"VERDICT: CODE CHANGED (ndiff={ndiff}, size_delta={extra*4:+d}B)")

    print(f"\nNormalized diffs (first 30):")
    shown = 0
    for i in range(min(len(norm26),len(norm265))):
        if shown >= 30: break
        if norm26[i] != norm265[i]:
            print(f"  +{i*4:04x}  26.0: {decode(insns26[i])}  26.5: {decode(insns265[i])}")
            shown += 1

    if len(insns265) > len(insns26):
        extra_start = len(insns26)
        print(f"\nExtra instructions in 26.5 (+{len(insns265)-len(insns26)} insns after idx {extra_start}):")
        for i in range(extra_start, min(len(insns265), extra_start+50)):
            c = classify(insns265[i]) or ""
            print(f"  +{i*4:04x}  0x{insns265[i]:08x}  {decode(insns265[i])}  [{c}]")
