#!/usr/bin/env python3
"""
Detailed disassembly comparison of pmap_tte_remove between 26.5b4 and 26.6b1.
"""
import struct

KC265B4 = r'kernelcaches/26.5b4/com.apple.kernel'
KC266   = r'kernelcaches/26.6b1/kernelcache.release.iPhone18,1'

KC265B4_TEXT_EXEC_ADDR = 0xfffffe000a641000
KC265B4_TEXT_EXEC_OFF  = 0x00277000
KC265B4_TEXT_EXEC_SZ   = 0x008b6be8

KC266_TEXT_EXEC_ADDR = 0xfffffe00082f0000
KC266_TEXT_EXEC_OFF  = 0x012ec000
KC266_TEXT_EXEC_SZ   = 0x02cac000

# Function starts from prior run
PMAP_TTE_REMOVE_265B4 = 0xfffffe000a824af0
PMAP_TTE_REMOVE_266   = 0xfffffe000a8c0bc8

PMAP_REM_OPT_265B4    = 0xfffffe000a825408
PMAP_REM_OPT_266      = 0xfffffe000a8c14e0

FUNC_SIZE = 304
FUNC_SIZE_OPT = 500


def read_func(path, text_exec_off, text_exec_addr, func_va, size):
    with open(path, 'rb') as f:
        f.seek(text_exec_off + (func_va - text_exec_addr))
        return f.read(size)


def classify_insn(word):
    """Return a human-readable ARM64 instruction class."""
    if (word & 0x9F000000) == 0x90000000: return 'ADRP'
    if (word & 0xFFC00000) == 0x91000000: return 'ADD(imm)'
    if (word & 0xFFC00000) == 0xD1000000: return 'SUB(imm)'
    if (word & 0xFFC00000) == 0x79400000: return 'LDRH'
    if (word & 0xFFC00000) == 0x79000000: return 'STRH'
    if (word & 0xFFC00000) == 0xB9400000: return 'LDR(32)'
    if (word & 0xFFC00000) == 0xB9000000: return 'STR(32)'
    if (word & 0xFFC00000) == 0xF9400000: return 'LDR(64)'
    if (word & 0xFFC00000) == 0xF9000000: return 'STR(64)'
    if (word & 0xFC000000) == 0x94000000: return 'BL'
    if (word & 0xFC000000) == 0x14000000: return 'B'
    if (word & 0xFF000010) == 0x54000000: return 'B.cond'
    if word == 0xD65F03C0: return 'RET'
    if word == 0xD503201F: return 'NOP'
    if (word & 0xFFC07FFF) == 0xA9807BFD: return 'STP(x29,x30)'
    if (word & 0xFFC07C00) == 0xA9400000: return 'LDP'
    if (word & 0xFFC07C00) == 0xA9800000: return 'STP'
    if (word & 0xFF200C00) == 0xEB000000: return 'SUBS'
    if (word & 0xFF200C00) == 0xAB000000: return 'ADDS'
    if (word & 0xFF200C00) == 0x6B000000: return 'SUBS(32)'
    if (word & 0x7FC00000) == 0x0B000000: return 'ADD(reg)'
    if (word & 0xFF800000) == 0xD3000000: return 'LSL/LSR/UBFX'
    if (word & 0xFF000000) == 0x52000000: return 'MOVZ'
    if (word & 0xFF000000) == 0x72000000: return 'MOVK'
    if (word & 0xFFFFFC1F) == 0xD503309F: return 'CSDB'
    return f'0x{word:08x}'


def norm_insn(w):
    if (w & 0x9F000000) == 0x90000000: return w & 0x9F00001F   # ADRP
    if (w & 0xFC000000) == 0x94000000: return w & 0xFC000000   # BL
    if (w & 0xFC000000) == 0x14000000: return w & 0xFC000000   # B
    if (w & 0x9F000000) == 0x10000000: return w & 0x9F00001F   # ADR
    # ADD(imm) with large offset — these are data-section ADDs, strip imm
    if (w & 0xFFC00000) == 0x91000000:
        imm = (w >> 10) & 0xFFF
        if imm > 0x100:  # large immediate = likely a data ref
            return w & 0xFFC003FF
    return w


def compare_funcs(name, func265, func266, va265, va266):
    print()
    print('=' * 65)
    print(f'DETAIL: {name}')
    print(f'  26.5b4 func @ 0x{va265:016x}  size={len(func265)}')
    print(f'  26.6b1 func @ 0x{va266:016x}  size={len(func266)}')
    print('=' * 65)

    size = min(len(func265), len(func266))
    structural_diffs = 0
    add_imm_diffs = 0

    for i in range(0, size, 4):
        w265 = struct.unpack_from('<I', func265, i)[0]
        w266 = struct.unpack_from('<I', func266, i)[0]
        va265_insn = va265 + i
        va266_insn = va266 + i
        cls265 = classify_insn(w265)
        cls266 = classify_insn(w266)

        if w265 != w266:
            # Check if it's only an ADD(imm) immediate value changing (data section offset)
            is_add_imm_only = (
                cls265 == 'ADD(imm)' and cls266 == 'ADD(imm)' and
                (w265 & 0xFFC003FF) == (w266 & 0xFFC003FF)  # same dst/src registers
            )
            if norm_insn(w265) == norm_insn(w266):
                # PC-relative diff only
                tag = '[PC-REL]'
            elif is_add_imm_only:
                add_imm_diffs += 1
                tag = '[ADD-IMM-OFFSET]'
            else:
                structural_diffs += 1
                tag = '[STRUCTURAL]'
            print(f'  +{i:04x}  {tag}')
            print(f'    265b4: 0x{w265:08x}  {cls265}')
            print(f'    266:   0x{w266:08x}  {cls266}')

    print()
    print(f'  Summary: {structural_diffs} structural diffs, {add_imm_diffs} ADD-imm-only diffs')
    if structural_diffs == 0 and add_imm_diffs == 0:
        print(f'  VERDICT: FUNCTIONALLY IDENTICAL')
    elif structural_diffs == 0:
        print(f'  VERDICT: FUNCTIONALLY IDENTICAL (only data section offset immediates differ)')
    else:
        print(f'  VERDICT: STRUCTURALLY CHANGED ({structural_diffs} real diffs)')

    # LDRH / STRH scan
    print()
    print(f'  LDRH/STRH scan (uint16_t refcount operations):')
    ldrh_265 = [(i, struct.unpack_from('<I', func265, i)[0]) for i in range(0, len(func265), 4)
                if (struct.unpack_from('<I', func265, i)[0] & 0xFFC00000) == 0x79400000]
    ldrh_266 = [(i, struct.unpack_from('<I', func266, i)[0]) for i in range(0, len(func266), 4)
                if (struct.unpack_from('<I', func266, i)[0] & 0xFFC00000) == 0x79400000]
    strh_265 = [(i, struct.unpack_from('<I', func265, i)[0]) for i in range(0, len(func265), 4)
                if (struct.unpack_from('<I', func265, i)[0] & 0xFFC00000) == 0x79000000]
    strh_266 = [(i, struct.unpack_from('<I', func266, i)[0]) for i in range(0, len(func266), 4)
                if (struct.unpack_from('<I', func266, i)[0] & 0xFFC00000) == 0x79000000]
    subs_265 = [(i, struct.unpack_from('<I', func265, i)[0]) for i in range(0, len(func265), 4)
                if (struct.unpack_from('<I', func265, i)[0] & 0x7F200C00) == 0x6B000000]
    subs_266 = [(i, struct.unpack_from('<I', func266, i)[0]) for i in range(0, len(func266), 4)
                if (struct.unpack_from('<I', func266, i)[0] & 0x7F200C00) == 0x6B000000]

    print(f'    265b4: {len(ldrh_265)} LDRH, {len(strh_265)} STRH, {len(subs_265)} SUBS')
    for off, w in ldrh_265:
        rn = (w >> 5) & 0x1F
        rt = w & 0x1F
        imm = ((w >> 10) & 0xFFF) * 2
        print(f'      +{off:04x} LDRH w{rt}, [x{rn}, #{imm}]')
    print(f'    266:   {len(ldrh_266)} LDRH, {len(strh_266)} STRH, {len(subs_266)} SUBS')
    for off, w in ldrh_266:
        rn = (w >> 5) & 0x1F
        rt = w & 0x1F
        imm = ((w >> 10) & 0xFFF) * 2
        print(f'      +{off:04x} LDRH w{rt}, [x{rn}, #{imm}]')

    # Check for CSDB (speculation barrier — indicates overflow check)
    csdb_265 = [i for i in range(0, len(func265), 4)
                if struct.unpack_from('<I', func265, i)[0] == 0xD503309F]
    csdb_266 = [i for i in range(0, len(func266), 4)
                if struct.unpack_from('<I', func266, i)[0] == 0xD503309F]
    print(f'    CSDB barriers: 265b4={len(csdb_265)}  266={len(csdb_266)}')


with open(KC265B4, 'rb') as f:
    data265 = f.read()
with open(KC266, 'rb') as f:
    data266 = f.read()

text265 = data265[KC265B4_TEXT_EXEC_OFF:KC265B4_TEXT_EXEC_OFF + KC265B4_TEXT_EXEC_SZ]
text266 = data266[KC266_TEXT_EXEC_OFF:KC266_TEXT_EXEC_OFF + KC266_TEXT_EXEC_SZ]

func_tte_265 = read_func(KC265B4, KC265B4_TEXT_EXEC_OFF, KC265B4_TEXT_EXEC_ADDR, PMAP_TTE_REMOVE_265B4, FUNC_SIZE)
func_tte_266 = read_func(KC266,   KC266_TEXT_EXEC_OFF,   KC266_TEXT_EXEC_ADDR,   PMAP_TTE_REMOVE_266,   FUNC_SIZE)

func_opt_265 = read_func(KC265B4, KC265B4_TEXT_EXEC_OFF, KC265B4_TEXT_EXEC_ADDR, PMAP_REM_OPT_265B4, FUNC_SIZE_OPT)
func_opt_266 = read_func(KC266,   KC266_TEXT_EXEC_OFF,   KC266_TEXT_EXEC_ADDR,   PMAP_REM_OPT_266,   FUNC_SIZE_OPT)

compare_funcs('pmap_tte_remove',              func_tte_265, func_tte_266, PMAP_TTE_REMOVE_265B4, PMAP_TTE_REMOVE_266)
compare_funcs('pmap_remove_options_internal', func_opt_265, func_opt_266, PMAP_REM_OPT_265B4,    PMAP_REM_OPT_266)
