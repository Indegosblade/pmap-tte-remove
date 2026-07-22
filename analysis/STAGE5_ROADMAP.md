# DarkSword Stage 5 — pmap_tte_remove Kernel R/W → Privesc
# 2026-04-26 — post Apple "expected behavior" close

## Primitive recap (confirmed)

uint16_t refcount on L3 page table in pmap_remove_options_internal.
65537 mach_vm_map calls on same region → wraps to 1 → one unmap → refcount 0 → pmap_free_pt_delayed.
64 PTEs remain dangling. Physical frame backing those PTEs is freed but still mapped writable in userspace.
Result: **userspace R/W window into a freed physical page frame**. Confirmed 64/64 (v14).

## Why mach_vm_map is reachable from GPU/WebContent

mach_vm_map is a fundamental Mach trap (no sandbox gate — every process uses it for its own mappings).
GPU/WebContent process can call it freely. Stage 4 gives arb native code exec in that process.
No sandbox escape needed to trigger the overflow.

## Stage 5 entry point

Stage 4 output: arb native code via dyld interpose (dlopen/dlsym post IIOLoadCMPhotoSymbols redirect).
From there: call mach_vm_map 65537× on a controlled VA region → trigger overflow → one munmap → dangling PTE.
~65537 syscalls at ~5μs each ≈ 300-350ms. Acceptable for PoC timing.

## Physical page reclaim — the hard part

After pmap_free_pt_delayed the frame enters the VM page freelist.
Need to win the race: spray a useful kernel object before anything else claims the frame.

**Target objects (ranked by usefulness):**
1. **ipc_port** — 168 bytes, allocated from zone `ipc_ports`. Contains function pointers (port destruct).
   Win: overwrite kobject or ip_pdestruct → call → kernel code exec. High value, zone spray feasible.
2. **vm_map_entry** — 192 bytes, zone `vm_map_entries`. Contains vmaddr ranges and prot flags.
   Win: flip prot bits on kernel text → mark it RWX → write shellcode. Indirect but reliable.
3. **IOKit OSObject** — variable. Contains vtable pointer.
   Win: overwrite vtable ptr → IOKit upcall → PAC-signed gadget needed.
4. **task_t** — large (2KB+), harder to win spray.

**Spray strategy:**
Immediately after munmap, do a tight loop of `mach_port_allocate` calls (allocates ipc_port objects).
Zone allocator pulls from page freelist to back ipc_ports zone → high probability of reclaiming our freed frame.
Read back through dangling PTE to detect which spray allocation landed in the frame (scan for ipc_port magic).

## From R/W to code exec

Once a valid kernel object is in the freed frame:
- Read it through dangling PTE to identify the object type and existing field values.
- Write a controlled value to a function pointer / kobject field.
- Trigger a normal kernel path that calls through that pointer.
- PAC context: existing DarkSword chain has dsc_slide — PACIZA gadgets for dlopen/dlsym are already resolved.
  Use same PAC oracle to sign the target pointer before writing.

## What Apple meant by "expected behavior"

They almost certainly meant: "a process can call mach_vm_map on its own address space, and refcount overflow is a programmer error, not a security boundary."

What they missed: the freed frame is a shared physical resource. The *ownership of physical memory* is a security boundary even if the virtual mapping was yours to control. Once the frame re-enters the freelist, it is no longer yours — but you still have a writable window to it. That window persists across process contexts. That is not "expected behavior" for any security model.

The silent patch argument: if 26.5 ships with a uint16→uint32 change on that refcount field (2 instruction diff), that's admission. It takes 2 seconds to check. Document every IPSW diff.

## Chain position

CVE-2025-43529 → CVE-2025-14174 → CVE-2026-20700 → **pmap_tte_remove (Stage 5)**
WebContent RCE → kernel R/W via dangling PTE → ipc_port spray → overwrite kobject → kernel code exec

## Next concrete step

Read `poc_v13_rw_proof.c` and `pmap_spray_se.c` — confirm they use mach_vm_map or vm_allocate as the trigger.
If vm_allocate: that's also sandbox-accessible. Same path.
Build: call trigger from post-Stage-4 native code context, immediately spray mach_port_allocate in tight loop,
scan freed frame for ipc_port magic, overwrite ip_pdestruct, trigger port destruction.
