// PmapProbe v14 — pmap_tte_remove patch detection
// OE1105320204625 — runs on stock iOS via Sideloadly
// Captures stdout via pipe, displays in UITextView, logs to Documents/
// ANDROMEDA — 2026-04-22

#import <UIKit/UIKit.h>
#include <unistd.h>
#include <pthread.h>

int pmap_run_prove(int nprove, const char *log_path);

@interface PmapViewController : UIViewController
@property (nonatomic, strong) UITextView *logView;
@property (nonatomic, strong) UILabel *verdictLabel;
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, strong) NSMutableString *buffer;
@property (nonatomic, copy) NSString *logPath;
@property (nonatomic) int pipeReadFD;
@property (nonatomic) int pipeWriteFD;
@property (nonatomic) BOOL exploitRunning;
@end

@implementation PmapViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor blackColor];
    self.buffer = [NSMutableString string];

    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
    [fmt setDateFormat:@"yyyyMMdd_HHmmss"];
    NSString *ts = [fmt stringFromDate:[NSDate date]];
    self.logPath = [docs stringByAppendingPathComponent:[NSString stringWithFormat:@"pmap_v14_%@.log", ts]];

    CGFloat w = self.view.bounds.size.width, h = self.view.bounds.size.height;

    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(20, 50, w-40, 30)];
    title.text = @"PmapProbe v14";
    title.font = [UIFont boldSystemFontOfSize:22];
    title.textColor = [UIColor colorWithRed:0.75 green:1.0 blue:0.0 alpha:1.0];
    title.textAlignment = NSTextAlignmentCenter;
    [self.view addSubview:title];

    UILabel *sub = [[UILabel alloc] initWithFrame:CGRectMake(20, 80, w-40, 18)];
    sub.text = @"OE1105320204625 — patch detection (no panic)";
    sub.font = [UIFont systemFontOfSize:11];
    sub.textColor = [UIColor grayColor];
    sub.textAlignment = NSTextAlignmentCenter;
    [self.view addSubview:sub];

    self.statusLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, 105, w-40, 22)];
    self.statusLabel.text = @"Initializing...";
    self.statusLabel.font = [UIFont systemFontOfSize:13];
    self.statusLabel.textColor = [UIColor cyanColor];
    self.statusLabel.textAlignment = NSTextAlignmentCenter;
    [self.view addSubview:self.statusLabel];

    self.verdictLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, 132, w-40, 36)];
    self.verdictLabel.text = @"RUNNING";
    self.verdictLabel.font = [UIFont boldSystemFontOfSize:24];
    self.verdictLabel.textColor = [UIColor yellowColor];
    self.verdictLabel.textAlignment = NSTextAlignmentCenter;
    self.verdictLabel.numberOfLines = 0;
    [self.view addSubview:self.verdictLabel];

    self.logView = [[UITextView alloc] initWithFrame:CGRectMake(8, 180, w-16, h-196)];
    self.logView.backgroundColor = [UIColor colorWithWhite:0.08 alpha:1.0];
    self.logView.textColor = [UIColor lightGrayColor];
    self.logView.font = [UIFont fontWithName:@"Courier" size:9] ?: [UIFont systemFontOfSize:9];
    self.logView.editable = NO;
    self.logView.layer.cornerRadius = 8;
    [self.view addSubview:self.logView];

    [self appendLine:@"=== PmapProbe v14 — pmap_tte_remove patch detection ==="];
    [self appendLine:[NSString stringWithFormat:@"iOS %@  %@",
        [[UIDevice currentDevice] systemVersion], [[UIDevice currentDevice] model]]];
    [self appendLine:[NSString stringWithFormat:@"Log: %@", self.logPath]];
    [self appendLine:@"Starting in 1s..."];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ [self runExploit]; });
}

- (void)runExploit {
    self.statusLabel.text = @"Running --prove 64...";
    self.exploitRunning = YES;

    // Pipe: redirect stdout → read in background thread → update UI
    int fds[2]; pipe(fds);
    self.pipeReadFD = fds[0]; self.pipeWriteFD = fds[1];
    int savedStdout = dup(STDOUT_FILENO);
    dup2(self.pipeWriteFD, STDOUT_FILENO);
    close(self.pipeWriteFD);

    // Reader thread: drains the pipe and updates UI
    int readFD = self.pipeReadFD;
    __weak PmapViewController *wself = self;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        char buf[512];
        ssize_t n;
        while ((n = read(readFD, buf, sizeof(buf)-1)) > 0) {
            buf[n] = '\0';
            NSString *chunk = [NSString stringWithUTF8String:buf] ?: @"";
            dispatch_async(dispatch_get_main_queue(), ^{
                [wself appendLine:chunk];
            });
        }
        close(readFD);
    });

    // Exploit thread
    NSString *logPath = self.logPath;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        int confirmed = pmap_run_prove(64, [logPath fileSystemRepresentation]);

        // Restore stdout
        dup2(savedStdout, STDOUT_FILENO);
        close(savedStdout);

        dispatch_async(dispatch_get_main_queue(), ^{
            [wself showVerdict:confirmed];
        });
    });
}

- (void)showVerdict:(int)confirmed {
    self.exploitRunning = NO;
    NSString *verdict;
    UIColor *color;

    if (confirmed > 0) {
        verdict = [NSString stringWithFormat:@"NOT PATCHED\n%d/64 write-through confirmed", confirmed];
        color = [UIColor colorWithRed:0.75 green:1.0 blue:0.0 alpha:1.0];
        self.statusLabel.text = @"Bug present — pmap_tte_remove VULNERABLE";
        self.statusLabel.textColor = [UIColor colorWithRed:0.75 green:1.0 blue:0.0 alpha:1.0];
    } else if (confirmed == 0) {
        verdict = @"PATCHED? — 0/64\nRun again or check log";
        color = [UIColor orangeColor];
        self.statusLabel.text = @"0 confirmed — possibly patched or race lost";
        self.statusLabel.textColor = [UIColor orangeColor];
    } else {
        verdict = @"ERROR\nCheck log";
        color = [UIColor redColor];
        self.statusLabel.text = @"Setup error — check log";
        self.statusLabel.textColor = [UIColor redColor];
    }

    self.verdictLabel.text = verdict;
    self.verdictLabel.textColor = color;
    [self appendLine:@"\n=== COMPLETE — pull log via 3uTools Documents ==="];
}

- (void)appendLine:(NSString *)text {
    [self.buffer appendFormat:@"%@\n", text];
    self.logView.text = self.buffer;
    if (self.buffer.length > 0)
        [self.logView scrollRangeToVisible:NSMakeRange(self.buffer.length-1, 1)];
}

@end

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)app didFinishLaunchingWithOptions:(NSDictionary *)opts {
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    self.window.rootViewController = [[PmapViewController alloc] init];
    [self.window makeKeyAndVisible];
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool { return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class])); }
}
