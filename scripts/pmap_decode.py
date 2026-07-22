#!/usr/bin/env python3
"""
Decode specific ARM64 instructions from the diff to understand the vulnerability patch.
Focus on offset +0x005c region in pmap_remove_options_internal.
"""
import struct

def decode_arm64(w, va=0):
    """Basic ARM64 decoder for relevant instructions."""
    if w == 0xD65F03C0: return "RET"
    if w == 0xD503201F: return "NOP"

    # BL
    if (w & 0xFC000000) == 0x94000000:
        offset = (w & 0x03FFFFFF) << 2
        if offset & 0x8000000: offset -= 0x10000000
        return f"BL 0x{va+offset:x}"

    # B.cond
    if (w & 0xFF000010) == 0x54000000:
        cond = w & 0xF
        offset = ((w >> 5) & 0x7FFFF) << 2
        if offset & 0x100000: offset -= 0x200000
        conds = ['eq','ne','cs','cc','mi','pl','vs','vc','hi','ls','ge','lt','gt','le','al','nv']
        return f"B.{conds[cond]} +{offset:+d}"

    # ADRP
    if (w & 0x9F000000) == 0x90000000:
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm = ((immhi << 2) | immlo) << 12
        if imm & (1<<32): imm -= (1<<33)
        rd = w & 0x1F
        page = (va & ~0xFFF) + imm
        return f"ADRP x{rd}, 0x{page:x}"

    # ADD imm (64-bit)
    if (w & 0xFF800000) == 0x91000000:
        imm = (w >> 10) & 0xFFF
        shift = (w >> 22) & 1
        if shift: imm <<= 12
        rn = (w >> 5) & 0x1F
        rd = w & 0x1F
        return f"ADD x{rd}, x{rn}, #0x{imm:x}"

    # ADD imm (32-bit)
    if (w & 0xFF800000) == 0x11000000:
        imm = (w >> 10) & 0xFFF
        rn = (w >> 5) & 0x1F
        rd = w & 0x1F
        return f"ADD w{rd}, w{rn}, #0x{imm:x}"

    # SUB imm (64-bit)
    if (w & 0xFF800000) == 0xD1000000:
        imm = (w >> 10) & 0xFFF
        rn = (w >> 5) & 0x1F
        rd = w & 0x1F
        return f"SUB x{rd}, x{rn}, #0x{imm:x}"

    # SUBS imm (32-bit) / CMP
    if (w & 0xFF800000) == 0x71000000:
        imm = (w >> 10) & 0xFFF
        rn = (w >> 5) & 0x1F
        rd = w & 0x1F
        if rd == 31:
            return f"CMP w{rn}, #0x{imm:x}"
        return f"SUBS w{rd}, w{rn}, #0x{imm:x}"

    # SUBS reg (64-bit)
    if (w & 0xFF200000) == 0xEB000000:
        rm = (w >> 16) & 0x1F
        shift = (w >> 22) & 3
        imm6 = (w >> 10) & 0x3F
        rn = (w >> 5) & 0x1F
        rd = w & 0x1F
        snames = ['LSL','LSR','ASR','ROR']
        if imm6 and shift < 3:
            if rd == 31:
                return f"CMP x{rn}, x{rm}, {snames[shift]} #{imm6}"
            return f"SUBS x{rd}, x{rn}, x{rm}, {snames[shift]} #{imm6}"
        if rd == 31:
            return f"CMP x{rn}, x{rm}"
        return f"SUBS x{rd}, x{rn}, x{rm}"

    # SUBS reg (32-bit)
    if (w & 0xFF200000) == 0x6B000000:
        rm = (w >> 16) & 0x1F
        rn = (w >> 5) & 0x1F
        rd = w & 0x1F
        if rd == 31:
            return f"CMP w{rn}, w{rm}"
        return f"SUBS w{rd}, w{rn}, w{rm}"

    # LDRH
    if (w & 0xFFC00000) == 0x79400000:
        imm = ((w >> 10) & 0xFFF) * 2
        rn = (w >> 5) & 0x1F
        rt = w & 0x1F
        return f"LDRH w{rt}, [x{rn}, #0x{imm:x}]"

    # STRH
    if (w & 0xFFC00000) == 0x79000000:
        imm = ((w >> 10) & 0xFFF) * 2
        rn = (w >> 5) & 0x1F
        rt = w & 0x1F
        return f"STRH w{rt}, [x{rn}, #0x{imm:x}]"

    # LDR x (64-bit, unsigned offset)
    if (w & 0xFFC00000) == 0xF9400000:
        imm = ((w >> 10) & 0xFFF) * 8
        rn = (w >> 5) & 0x1F
        rt = w & 0x1F
        return f"LDR x{rt}, [x{rn}, #0x{imm:x}]"

    # LDR w (32-bit, unsigned offset)
    if (w & 0xFFC00000) == 0xB9400000:
        imm = ((w >> 10) & 0xFFF) * 4
        rn = (w >> 5) & 0x1F
        rt = w & 0x1F
        return f"LDR w{rt}, [x{rn}, #0x{imm:x}]"

    # STR x (64-bit, unsigned offset)
    if (w & 0xFFC00000) == 0xF9000000:
        imm = ((w >> 10) & 0xFFF) * 8
        rn = (w >> 5) & 0x1F
        rt = w & 0x1F
        return f"STR x{rt}, [x{rn}, #0x{imm:x}]"

    # AND imm (64-bit)
    if (w & 0xFF800000) == 0x92000000:
        # Immediate encoding is complex but let's extract it
        n = (w >> 22) & 1
        immr = (w >> 16) & 0x3F
        imms = (w >> 10) & 0x3F
        rn = (w >> 5) & 0x1F
        rd = w & 0x1F
        return f"AND x{rd}, x{rn}, #<immr={immr},imms={imms},N={n}>"

    # MOVZ w
    if (w & 0xFF800000) == 0x52800000:
        imm = (w >> 5) & 0xFFFF
        shift = (w >> 21) & 3
        rd = w & 0x1F
        return f"MOVZ w{rd}, #0x{imm:x}" + (f", LSL #{shift*16}" if shift else "")

    # MOVZ x
    if (w & 0xFF800000) == 0xD2800000:
        imm = (w >> 5) & 0xFFFF
        shift = (w >> 21) & 3
        rd = w & 0x1F
        return f"MOVZ x{rd}, #0x{imm:x}" + (f", LSL #{shift*16}" if shift else "")

    # UBFM / LSR / UXTH
    if (w & 0xFFC00000) == 0xD3400000:
        immr = (w >> 16) & 0x3F
        imms = (w >> 10) & 0x3F
        rn = (w >> 5) & 0x1F
        rd = w & 0x1F
        if imms == 63:
            return f"LSR x{rd}, x{rn}, #{immr}"
        return f"UBFM x{rd}, x{rn}, #{immr}, #{imms}"

    if (w & 0xFFC00000) == 0x53000000:
        immr = (w >> 16) & 0x3F
        imms = (w >> 10) & 0x3F
        rn = (w >> 5) & 0x1F
        rd = w & 0x1F
        if imms == 31:
            return f"LSR w{rd}, w{rn}, #{immr}"
        if immr == 0 and imms == 15:
            return f"UXTH w{rd}, w{rn}"
        return f"UBFM w{rd}, w{rn}, #{immr}, #{imms}"

    # CBZ/CBNZ x
    if (w & 0xFF000000) in (0xB4000000, 0xB5000000):
        rt = w & 0x1F
        off = ((w >> 5) & 0x7FFFF) << 2
        if off & 0x100000: off -= 0x200000
        nz = 'NZ' if (w >> 24) & 1 else 'Z'
        return f"CB{nz} x{rt}, {off:+d}"

    # STP/LDP
    if (w & 0xFFC00000) == 0xA9800000:
        imm = ((w >> 15) & 0x7F) << 3
        if imm & 0x200: imm -= 0x400
        rt2 = (w >> 10) & 0x1F
        rn = (w >> 5) & 0x1F
        rt1 = w & 0x1F
        pre = '!' if (w >> 23) & 1 else ''
        return f"STP x{rt1}, x{rt2}, [x{rn}, #0x{imm:x}]{pre}"

    if (w & 0xFFC00000) == 0xA9400000:
        imm = ((w >> 15) & 0x7F) << 3
        if imm & 0x200: imm -= 0x400
        rt2 = (w >> 10) & 0x1F
        rn = (w >> 5) & 0x1F
        rt1 = w & 0x1F
        return f"LDP x{rt1}, x{rt2}, [x{rn}, #0x{imm:x}]"

    # MOV reg
    if (w & 0xFFE0FFE0) == 0xAA0003E0:
        rm = (w >> 16) & 0x1F
        rd = w & 0x1F
        return f"MOV x{rd}, x{rm}"

    return f"0x{w:08x}"


print("=== pmap_remove_options_internal: CRITICAL REGION +0x050..+0x070 ===")
print("\n26.0 instructions:")
insns_26 = [
    (0x050, 0xf9437529),
    (0x054, 0xf9437529),  # actually next instruction
    (0x058, 0xd34eb508),
    (0x05c, 0xd37ff908),
    (0x060, 0xf940000a),
    (0x064, 0xf9400288),
    (0x068, 0xd37ae52b),
    (0x06c, 0xcb090d75),
    (0x070, 0x910062ab),
    (0x074, 0xeb2bc17f),  # CMP/SUBS
    (0x078, 0x8b2bc10c),
    (0x07c, 0x8b0b0110),
    (0x080, 0xf2e575b0),
    (0x084, 0x9a90016b),
]

for off, w in insns_26:
    print(f"  +{off:04x}  {decode_arm64(w, 0xfffffe0008405eb4+off)}")

print("\n26.5b4 instructions (same region):")
insns_265b4 = [
    (0x050, 0xf9437529),
    (0x054, 0xf9406929),
    (0x058, 0xd34dfd08),
    (0x05c, 0x927f7d08),
    (0x060, 0xf9400288),
    (0x064, 0xd37ae52a),
    (0x068, 0xcb090d55),
    (0x06c, 0x910062aa),
    (0x070, 0xeb2ac15f),  # CMP/SUBS
    (0x074, 0x8b2ac10b),
    (0x078, 0x8b090150),
    (0x07c, 0xf2e575b0),
    (0x080, 0x9a90016b),
]

for off, w in insns_265b4:
    print(f"  +{off:04x}  {decode_arm64(w, 0xfffffe000a825408+off)}")

print("\n=== pmap_tte_remove: EXTRA INSTRUCTIONS IN 26.5b4 ===")
extra_265b4 = [
    (0x0d8, 0xd503245f),
    (0x0dc, 0x92748c08),
    (0x0e0, 0x90fea7e9),
    (0x0e4, 0xf9462929),
    (0x0e8, 0xcb090109),
    (0x0ec, 0xf0fea38a),
    (0x0f0, 0xf9406d4a),
    (0x0f4, 0xd34bfd29),
    (0x0f8, 0x927d7d29),
    (0x0fc, 0xeb29c13f),
    (0x100, 0x8b29c14b),
    (0x104, 0x8b090150),
    (0x108, 0xf2e575b0),
    (0x10c, 0x9a90016b),
    (0x110, 0xf9400169),
    (0x114, 0x2a2903ea),
    (0x118, 0xf240055f),
    (0x11c, 0x540000a1),
    (0x120, 0x927ef528),
    (0x124, 0xd2ee9809),
    (0x128, 0x9a892908),
    (0x12c, 0xd65f03c0),
]
print("\n26.5b4 pmap_tte_remove extra instructions:")
for off, w in extra_265b4:
    print(f"  +{off:04x}  0x{w:08x}  {decode_arm64(w, 0xfffffe000a824af0+off)}")

# Decode the critical diff at +0x05c
print("\n=== CRITICAL: +0x005c decode ===")
print(f"  26.0    0xd37ff908 = {decode_arm64(0xd37ff908)}")
print(f"  26.5b4  0x927f7d08 = {decode_arm64(0x927f7d08)}")

# Also decode the LDRH at +0x074
print(f"\n  26.0    LDRH at +0x074: 0x79400148 = {decode_arm64(0x79400148)}")

# Decode pmap_tte_remove key branch at end
print(f"\n  pmap_tte_remove 26.5b4 +0x0fc:  0xeb29c13f = {decode_arm64(0xeb29c13f)}")
print(f"  pmap_tte_remove 26.5b4 +0x114:  0x2a2903ea = {decode_arm64(0x2a2903ea)}")
print(f"  pmap_tte_remove 26.5b4 +0x118:  0xf240055f = {decode_arm64(0xf240055f)}")
