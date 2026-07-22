#!/usr/bin/env python3
"""
Deep comparison using the extracted com.apple.kernel files.
Parse MachO header to get correct segment layouts.
"""
import struct
import sys
import hashlib

KC26    = r"kernelcaches/26.0/com.apple.kernel"
KC265B4 = r"kernelcaches/26.5b4/com.apple.kernel"


def parse_macho_segments(path):
    """Parse MachO segments, return dict: name -> (vmaddr, vmsize, fileoff, filesize)"""
    segs = {}
    with open(path, 'rb') as f:
        data = f.read()

    magic = struct.unpack_from('<I', data, 0)[0]
    assert magic in (0xFEEDFACF, 0xCFFAEDFE), f"Bad magic: 0x{magic:X}"

    # MachO 64-bit header: magic(4) cputype(4) cpusubtype(4) filetype(4) ncmds(4) sizeofcmds(4) flags(4) reserved(4)
    ncmds = struct.unpack_from('<I', data, 16)[0]
    off = 32  # header size for 64-bit
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', data, off)
        if cmd == 0x19:  # LC_SEGMENT_64
            # segname(16) vmaddr(8) vmsize(8) fileoff(8) filesize(8) ...
            segname = data[off+8:off+24].rstrip(b'\x00').decode('ascii', errors='replace')
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', data, off+24)
            segs[segname] = (vmaddr, vmsize, fileoff, filesize)
        off += cmdsize
    return segs, data


def vaddr_to_data(data, segs, vaddr, size=4):
    """Convert virtual address to bytes using segment map."""
    for sname, (vmaddr, vmsize, fileoff, filesize) in segs.items():
        if vmaddr <= vaddr < vmaddr + vmsize:
            off = fileoff + (vaddr - vmaddr)
            if off + size <= len(data):
                return data[off:off+size]
    return None


def extract_func_from_va(data, segs, func_va, max_bytes=0x2000):
    """Extract function bytes starting at func_va, stop at RET."""
    insns = []
    va = func_va
    for _ in range(max_bytes // 4):
        b = vaddr_to_data(data, segs, va, 4)
        if b is None or len(b) < 4:
            break
        word = struct.unpack_from('<I', b)[0]
        insns.append(word)
        va += 4
        if word == 0xD65F03C0:  # RET
            break
    return insns


def is_adrp(w): return (w & 0x9F000000) == 0x90000000
def is_bl(w):   return (w & 0xFC000000) == 0x94000000
def is_bcond(w): return (w & 0xFF000010) == 0x54000000

def normalize(w):
    if is_adrp(w): return w & 0x1F000000
    if is_bl(w):   return 0x94000000
    if is_bcond(w): return w & 0xFF00001F
    # LDR literal
    if (w & 0x3B000000) in (0x18000000, 0x10000000): return w & 0xFF00001F
    return w


def classify(w):
    if (w & 0xFFC00000) == 0x79400000: return 'LDRH'
    if (w & 0xFFC00000) == 0x79000000: return 'STRH'
    if (w & 0xFF000010) == 0x54000000: return 'B.cond'
    if (w & 0xFF000000) in (0xB4000000, 0xB5000000): return 'CBZ/CBNZ'
    if (w & 0xFF000000) in (0x36000000, 0x37000000): return 'TBZ/TBNZ'
    if (w & 0x7F800000) == 0x71000000:
        imm = (w >> 10) & 0xFFF
        return f'SUBS/CMP imm={imm}(0x{imm:x})'
    if (w & 0x7F800000) == 0x6B000000: return 'SUBS/CMP-reg'
    if w == 0xD65F03C0: return 'RET'
    if (w & 0xFF800000) == 0x11000000:
        imm = (w >> 10) & 0xFFF
        return f'ADD imm={imm}'
    if (w & 0xFF800000) == 0x51000000:
        imm = (w >> 10) & 0xFFF
        return f'SUB imm={imm}'
    if is_adrp(w): return 'ADRP'
    if is_bl(w):   return 'BL'
    return None


# Known function addresses from first run
FUNCS = {
    'pmap_remove_options_internal': (0xfffffe0008405eb4, 0xfffffe000a825408),
    'pmap_tte_remove':               (0xfffffe0008405350, 0xfffffe000a824af0),
}

segs26,    data26    = parse_macho_segments(KC26)
segs265b4, data265b4 = parse_macho_segments(KC265B4)

print("=== 26.0 segments ===")
for k, v in segs26.items():
    print(f"  {k}: vmaddr=0x{v[0]:016x} fileoff=0x{v[2]:08x} filesz=0x{v[3]:08x}")

print("\n=== 26.5b4 segments ===")
for k, v in segs265b4.items():
    print(f"  {k}: vmaddr=0x{v[0]:016x} fileoff=0x{v[2]:08x} filesz=0x{v[3]:08x}")


for fname, (va26, va265b4) in FUNCS.items():
    print(f"\n{'='*70}")
    print(f"FUNCTION: {fname}")
    print(f"  26.0    VA: 0x{va26:016x}")
    print(f"  26.5b4  VA: 0x{va265b4:016x}")

    # Verify address is in a segment
    b26_test = vaddr_to_data(data26, segs26, va26)
    b265b4_test = vaddr_to_data(data265b4, segs265b4, va265b4)
    print(f"  26.0    first 4 bytes at VA: {b26_test.hex() if b26_test else 'NOT FOUND'}")
    print(f"  26.5b4  first 4 bytes at VA: {b265b4_test.hex() if b265b4_test else 'NOT FOUND'}")

    insns26    = extract_func_from_va(data26, segs26, va26)
    insns265b4 = extract_func_from_va(data265b4, segs265b4, va265b4)

    if not insns26 or not insns265b4:
        print(f"  ERROR: Could not extract function bytes")
        continue

    print(f"  26.0    instruction count: {len(insns26)}")
    print(f"  26.5b4  instruction count: {len(insns265b4)}")
    print(f"  Size delta: {(len(insns265b4) - len(insns26)) * 4:+d} bytes")

    # Show key instructions
    for label, insns, base in [("26.0", insns26, va26), ("26.5b4", insns265b4, va265b4)]:
        hits = [(i, w) for i, w in enumerate(insns) if classify(w) and classify(w) not in ('ADRP', 'BL')]
        if hits:
            print(f"\n  {label} key instructions:")
            for i, w in hits:
                c = classify(w)
                print(f"    +{i*4:04x}  0x{w:08x}  {c}")

    # Normalize and compare
    norm26    = [normalize(w) for w in insns26]
    norm265b4 = [normalize(w) for w in insns265b4]
    min_len = min(len(norm26), len(norm265b4))
    n_diff = sum(1 for a, b in zip(norm26, norm265b4) if a != b)
    print(f"\n  Normalized diff: {n_diff}/{min_len} instructions")

    if n_diff == 0 and len(insns26) == len(insns265b4):
        print(f"  VERDICT: IDENTICAL (ASLR relocs only)")
    elif n_diff <= 3:
        print(f"  VERDICT: NEAR-IDENTICAL (minor reloc diffs)")
    else:
        print(f"  VERDICT: SUBSTANTIVE CHANGE")
        print(f"\n  Normalized instruction diffs (first 20):")
        shown = 0
        for i in range(min_len):
            if shown >= 20: break
            if norm26[i] != norm265b4[i]:
                c26    = classify(insns26[i]) or ''
                c265b4 = classify(insns265b4[i]) or ''
                print(f"    +{i*4:04x}  26.0=0x{insns26[i]:08x}({c26})  265b4=0x{insns265b4[i]:08x}({c265b4})")
                shown += 1
        if len(insns26) != len(insns265b4):
            print(f"\n  EXTRA INSTRUCTIONS in {'26.5b4' if len(insns265b4) > len(insns26) else '26.0'}:")
            # Print trailing instructions
            if len(insns265b4) > len(insns26):
                extra = insns265b4[len(insns26):]
                for i, w in enumerate(extra[:20]):
                    c = classify(w) or ''
                    print(f"    265b4+{(len(insns26)+i)*4:04x}  0x{w:08x}  {c}")
