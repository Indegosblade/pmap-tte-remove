#!/usr/bin/env python3
"""Decode pmap_remove_options_internal critical region in 26.5"""
import struct

KC260 = r"kernelcaches/26.0/com.apple.kernel"
KC265 = r"kernelcaches/26.5/com.apple.kernel"

def decode(w):
    if (w & 0xFFC00000) == 0x79400000:
        imm=((w>>10)&0xFFF)*2; rn=(w>>5)&0x1F; rt=w&0x1F
        return f"LDRH w{rt},[x{rn},#0x{imm:x}]"
    if (w & 0xFFC00000) == 0x79000000:
        imm=((w>>10)&0xFFF)*2; rn=(w>>5)&0x1F; rt=w&0x1F
        return f"STRH w{rt},[x{rn},#0x{imm:x}]"
    if (w & 0xFFC00000) == 0x53000000:
        immr=(w>>16)&0x3F; imms=(w>>10)&0x3F; rn=(w>>5)&0x1F; rd=w&0x1F
        if immr==0 and imms==15: return f"UXTH w{rd},w{rn}"
        if imms==31: return f"LSR w{rd},w{rn},#{immr}"
        return f"UBFM w{rd},w{rn},#{immr},#{imms}"
    if (w & 0xFFC00000) == 0xD3400000:
        immr=(w>>16)&0x3F; imms=(w>>10)&0x3F; rn=(w>>5)&0x1F; rd=w&0x1F
        if imms==31: return f"UXTW x{rd},w{rn}"
        return f"LSR x{rd},x{rn},#{immr}"
    if (w & 0xFF800000) == 0x11000000:
        imm=(w>>10)&0xFFF; rn=(w>>5)&0x1F; rd=w&0x1F
        return f"ADD w{rd},w{rn},#0x{imm:x}({imm})"
    if (w & 0xFF800000) == 0x91000000:
        imm=(w>>10)&0xFFF; rn=(w>>5)&0x1F; rd=w&0x1F
        return f"ADD x{rd},x{rn},#0x{imm:x}({imm})"
    if (w & 0xFF800000) == 0xD1000000:
        imm=(w>>10)&0xFFF; rn=(w>>5)&0x1F; rd=w&0x1F
        return f"SUB x{rd},x{rn},#0x{imm:x}({imm})"
    if (w & 0x7F800000) == 0x71000000:
        imm=(w>>10)&0xFFF; rn=(w>>5)&0x1F; rd=w&0x1F
        op='CMP' if rd==31 else 'SUBS'
        return f"{op} w{rn},#{imm}"
    if (w & 0xFF200000) == 0x71000000:
        imm=(w>>10)&0xFFF; rn=(w>>5)&0x1F; rd=w&0x1F
        op='CMP' if rd==31 else 'SUBS'
        return f"{op} w{rn},#{imm}"
    if (w & 0x7F800000) == 0x6B000000:
        rm=(w>>16)&0x1F; rn=(w>>5)&0x1F; rd=w&0x1F
        op='CMP' if rd==31 else 'SUBS'
        return f"{op} w{rn},w{rm}"
    if (w & 0xFF200000) == 0xEB000000:
        rm=(w>>16)&0x1F; rn=(w>>5)&0x1F; rd=w&0x1F
        op='CMP' if rd==31 else 'SUBS'
        return f"{op} x{rn},x{rm}"
    if (w & 0xFF000000) in (0xB4000000, 0xB5000000):
        rt=w&0x1F; off=((w>>5)&0x7FFFF)<<2
        if off&0x100000: off-=0x200000
        return f"CB{'NZ' if (w>>24)&1 else 'Z'} x{rt},{off:+d}"
    if (w & 0xFF000000) in (0x36000000, 0x37000000):
        rt=w&0x1F; bit=((w>>19)&0x1F)|(((w>>31)&1)<<5)
        off=((w>>5)&0x3FFF)<<2
        if off&0x8000: off-=0x10000
        return f"TB{'NZ' if (w>>24)&1 else 'Z'} w{rt},#{bit},{off:+d}"
    if (w & 0xFFC00000) == 0xB9400000:
        imm=((w>>10)&0xFFF)*4; rn=(w>>5)&0x1F; rt=w&0x1F
        return f"LDR w{rt},[x{rn},#0x{imm:x}]"
    if (w & 0xFFC00000) == 0xF9400000:
        imm=((w>>10)&0xFFF)*8; rn=(w>>5)&0x1F; rt=w&0x1F
        return f"LDR x{rt},[x{rn},#0x{imm:x}]"
    if (w & 0xFFC00000) == 0xB9000000:
        imm=((w>>10)&0xFFF)*4; rn=(w>>5)&0x1F; rt=w&0x1F
        return f"STR w{rt},[x{rn},#0x{imm:x}]"
    if (w & 0xFFC00000) == 0xF9000000:
        imm=((w>>10)&0xFFF)*8; rn=(w>>5)&0x1F; rt=w&0x1F
        return f"STR x{rt},[x{rn},#0x{imm:x}]"
    if (w & 0xFC000000) == 0x94000000:
        off=((w&0x3FFFFFF)<<2)
        if off&0x8000000: off-=0x10000000
        return f"BL {off:+d}"
    if (w & 0xFF000010) == 0x54000000:
        off=((w>>5)&0x7FFFF)<<2
        if off&0x100000: off-=0x200000
        conds=['eq','ne','cs','cc','mi','pl','vs','vc','hi','ls','ge','lt','gt','le','al','nv']
        return f"B.{conds[w&0xF]} {off:+d}"
    if (w & 0x9F000000) == 0x90000000:
        rd=w&0x1F; return f"ADRP x{rd},..."
    if (w & 0xFF800000) == 0x52800000:
        imm=(w>>5)&0xFFFF; rd=w&0x1F
        return f"MOVZ w{rd},#0x{imm:x}({imm})"
    if (w & 0xFF800000) == 0xD2800000:
        imm=(w>>5)&0xFFFF; rd=w&0x1F
        return f"MOVZ x{rd},#0x{imm:x}({imm})"
    if w == 0xD65F03C0: return "RET"
    if w == 0xD503201F: return "NOP"
    if (w & 0xFFF00000) == 0xD5300000: return f"MRS x{w&0x1F},sysreg(0x{(w>>5)&0x7FFF:04x})"
    if (w & 0xFFF00000) == 0xD5100000: return f"MSR sysreg(0x{(w>>5)&0x7FFF:04x}),x{w&0x1F}"
    if (w & 0xFFC00000) == 0x39400000:
        imm=(w>>10)&0xFFF; rn=(w>>5)&0x1F; rt=w&0x1F
        return f"LDRB w{rt},[x{rn},#0x{imm:x}]"
    if (w & 0xFFC00000) == 0x39000000:
        imm=(w>>10)&0xFFF; rn=(w>>5)&0x1F; rt=w&0x1F
        return f"STRB w{rt},[x{rn},#0x{imm:x}]"
    if (w & 0xFFE0FFE0) == 0xAA0003E0:
        rm=(w>>16)&0x1F; rd=w&0x1F
        return f"MOV x{rd},x{rm}"
    if (w & 0xFFC00000) == 0xA9800000:
        rt2=(w>>10)&0x1F; rn=(w>>5)&0x1F; rt1=w&0x1F
        imm=((w>>15)&0x7F)<<3
        if imm&0x200: imm-=0x400
        pre='!' if (w>>23)&1 else ''
        return f"STP x{rt1},x{rt2},[x{rn},{imm:+d}]{pre}"
    if (w & 0xFFC00000) == 0xA9400000:
        rt2=(w>>10)&0x1F; rn=(w>>5)&0x1F; rt1=w&0x1F
        imm=((w>>15)&0x7F)<<3
        if imm&0x200: imm-=0x400
        return f"LDP x{rt1},x{rt2},[x{rn},{imm:+d}]"
    if (w & 0xFF000000) == 0x2A000000:
        rm=(w>>16)&0x1F; rn=(w>>5)&0x1F; rd=w&0x1F
        return f"ORR w{rd},w{rn},w{rm}"
    if (w & 0xFF000000) == 0x4A000000:
        rm=(w>>16)&0x1F; rn=(w>>5)&0x1F; rd=w&0x1F
        return f"EOR w{rd},w{rn},w{rm}"
    if (w & 0xFF000000) == 0x0A000000:
        rm=(w>>16)&0x1F; rn=(w>>5)&0x1F; rd=w&0x1F
        return f"AND w{rd},w{rn},w{rm}"
    if (w & 0xFF200000) == 0x8B000000:
        rm=(w>>16)&0x1F; rn=(w>>5)&0x1F; rd=w&0x1F
        return f"ADD x{rd},x{rn},x{rm}"
    if (w & 0xFF200000) == 0x0B000000:
        rm=(w>>16)&0x1F; rn=(w>>5)&0x1F; rd=w&0x1F
        return f"ADD w{rd},w{rn},w{rm}"
    if (w & 0xFF200000) == 0xCB000000:
        rm=(w>>16)&0x1F; rn=(w>>5)&0x1F; rd=w&0x1F
        return f"SUB x{rd},x{rn},x{rm}"
    if (w & 0xFF200000) == 0x4B000000:
        rm=(w>>16)&0x1F; rn=(w>>5)&0x1F; rd=w&0x1F
        return f"SUB w{rd},w{rn},w{rm}"
    if (w & 0xFFC00000) == 0x92000000:
        rn=(w>>5)&0x1F; rd=w&0x1F
        return f"AND x{rd},x{rn},#imm"
    if (w & 0xFFC00000) == 0x12000000:
        rn=(w>>5)&0x1F; rd=w&0x1F
        return f"AND w{rd},w{rn},#imm"
    return f"??? 0x{w:08x}"


def load_func_at(kc_path, func_va, text_base, file_off_base, max_insns=600):
    with open(kc_path, 'rb') as f:
        foff = file_off_base + (func_va - text_base)
        f.seek(foff)
        data = f.read(max_insns * 4)
    insns = []
    for i in range(0, len(data), 4):
        w = struct.unpack_from('<I', data, i)[0]
        insns.append(w)
        if w == 0xD65F03C0 and i >= 16:
            break
    return insns


# Known function addresses from analysis
FUNC_260  = 0xfffffe00084068e0   # pmap_remove_options_internal 26.0
FUNC_265  = 0xfffffe000a8144e4   # pmap_remove_options_internal 26.5

TEXT26_BASE  = 0xfffffe0008240000
TEXT26_FOFF  = 0x262000
TEXT265_BASE = 0xfffffe000a63c000
TEXT265_FOFF = 0x273000

insns26  = load_func_at(KC260, FUNC_260,  TEXT26_BASE,  TEXT26_FOFF)
insns265 = load_func_at(KC265, FUNC_265,  TEXT265_BASE, TEXT265_FOFF)

print("=" * 70)
print("pmap_remove_options_internal: 26.0 vs 26.5 DEEP DECODE")
print("=" * 70)
print(f"26.0  function size: {len(insns26)*4} bytes ({len(insns26)} insns)")
print(f"26.5  function size: {len(insns265)*4} bytes ({len(insns265)} insns)")

print("\n=== 26.0: Full function (key region, first 350 insns) ===")
for i, w in enumerate(insns26[:350]):
    d = decode(w)
    marker = ""
    c = ""
    if 'LDRH' in d: marker = " <<< LDRH"
    elif 'STRH' in d: marker = " <<< STRH"
    elif 'SUBS w' in d and '#1' in d: marker = " <<< SUBS -1"
    elif 'SUBS w' in d: marker = " <<< SUBS"
    elif 'CMP' in d: marker = " <<< CMP"
    if marker:
        print(f"  +{i*4:04x}  0x{w:08x}  {d}{marker}")

print("\n=== 26.5: Full function (key region, first 450 insns) ===")
for i, w in enumerate(insns265[:450]):
    d = decode(w)
    marker = ""
    if 'LDRH' in d: marker = " <<< LDRH"
    elif 'STRH' in d: marker = " <<< STRH"
    elif 'SUBS w' in d and '#1)' in d: marker = " <<< SUBS -1 (decrement)"
    elif 'SUBS w' in d: marker = " <<< SUBS"
    elif 'CMP' in d: marker = " <<< CMP"
    if marker:
        print(f"  +{i*4:04x}  0x{w:08x}  {d}{marker}")

# Show full function 26.5 around the new LDRH instructions
print("\n=== 26.5: Context around NEW LDRH at +04b4 (+0x490..+0x560) ===")
for i in range(0x490//4, min(0x560//4, len(insns265))):
    d = decode(insns265[i])
    print(f"  +{i*4:04x}  0x{insns265[i]:08x}  {d}")

print("\n=== 26.5: Context around NEW LDRH at +0578 (+0x560..+0x6b0) ===")
for i in range(0x560//4, min(0x6b0//4, len(insns265))):
    d = decode(insns265[i])
    print(f"  +{i*4:04x}  0x{insns265[i]:08x}  {d}")

print("\n=== SPTM section size comparison ===")
# We already know from the macho info:
# 26.0 __DATA_SPTM: 0x0003c000 bytes at 0xfffffe000b240000
# Let's parse this from the kernel files
def get_sptm_size(kc_path):
    with open(kc_path, 'rb') as f:
        data = f.read(0x10000)
    magic = struct.unpack_from('<I', data, 0)[0]
    if magic != 0xFEEDFACF: return None
    ncmds = struct.unpack_from('<I', data, 16)[0]
    off = 32
    for _ in range(ncmds):
        if off+8 > len(data): break
        cmd = struct.unpack_from('<I', data, off)[0]
        cmdsize = struct.unpack_from('<I', data, off+4)[0]
        if cmd == 0x19:
            segname = data[off+8:off+24].rstrip(b'\x00').decode('ascii', errors='replace')
            filesize = struct.unpack_from('<Q', data, off+48)[0]
            vmsize = struct.unpack_from('<Q', data, off+32)[0]
            if segname == '__DATA_SPTM':
                return vmsize, filesize
        off += cmdsize
    return None

r26  = get_sptm_size(KC260)
r265 = get_sptm_size(KC265)
print(f"  26.0 __DATA_SPTM: vmsize=0x{r26[0]:x} filesize=0x{r26[1]:x}")
print(f"  26.5 __DATA_SPTM: vmsize=0x{r265[0]:x} filesize=0x{r265[1]:x}")
if r26 and r265:
    print(f"  Delta: vmsize={r265[0]-r26[0]:+d} filesize={r265[1]-r26[1]:+d}")
