// MCHook2.dylib — runtime tracer for MCNearbyDiscoveryPeerConnection.
//
// At +load: enumerate every method of the private class (and its super-
// classes' protocol-facing surface) and log it; then swizzle the data-plane
// and attach methods with the R9-verified signatures so a single run under
// `DYLD_INSERT_LIBRARIES` shows:
//   - every inbound segment (syncReceivedData:error:)
//   - every dispatch decision (syncProcessMessage:data:sequenceNumber:)
//   - every outbound send (syncSendData:*)
//   - the attach/accept lifecycle calls
// for BOTH peers in the same session (real iPhone + foreign PYSRV).
//
// Build:
//   clang -dynamiclib -framework Foundation -o MCHook2.dylib MCHook2.m
// Run:
//   DYLD_INSERT_LIBRARIES=./MCHook2.dylib .build/debug/mcoracle secondsee-mpc

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>

static void MLog(NSString *fmt, ...) NS_FORMAT_FUNCTION(1,2);
static void MLog(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    fprintf(stderr, "[MCHOOK] %s\n", s.UTF8String);
    fflush(stderr);
}

static void dumpClassMethods(const char *className) {
    Class c = objc_getClass(className);
    if (!c) { MLog(@"class %@ not found", [NSString stringWithUTF8String:className]); return; }
    MLog(@"=== %@ method list ===", [NSString stringWithUTF8String:className]);
    unsigned int n = 0;
    Method *methods = class_copyMethodList(c, &n);
    for (unsigned int i = 0; i < n; i++) {
        SEL sel = method_getName(methods[i]);
        MLog(@"  %@", NSStringFromSelector(sel));
    }
    free(methods);
}

// ---- swizzled implementations -------------------------------------------

// data received: - (void)syncReceivedData:(NSData *)data error:(NSError *)err
static void (*orig_syncReceivedData)(id, SEL, NSData *, NSError *);
static void hook_syncReceivedData(id self, SEL _cmd, NSData *data, NSError *err) {
    NSData *head = [data subdataWithRange:NSMakeRange(0, MIN((NSUInteger)48, (NSUInteger)data.length))];
    MLog(@"IN-SEG len=%lu hex=%@", (unsigned long)data.length, head);
    orig_syncReceivedData(self, _cmd, data, err);
}

// dispatch: - (void)syncProcessMessage:(int)type data:(NSData *)d sequenceNumber:(unsigned)seq
static void (*orig_syncProcessMessage)(id, SEL, int, NSData *, unsigned);
static void hook_syncProcessMessage(id self, SEL _cmd, int type, NSData *d, unsigned seq) {
    MLog(@"PROC msg=%d seq=%u len=%lu", type, seq, (unsigned long)d.length);
    orig_syncProcessMessage(self, _cmd, type, d, seq);
}

// generic outbound data: - (void)syncSendData:(NSData *)d ...
static void (*orig_syncSendData)(id, SEL, NSData *, id);
static void hook_syncSendData(id self, SEL _cmd, NSData *d, id a) {
    MLog(@"OUT-DATA len=%lu", (unsigned long)d.length);
    orig_syncSendData(self, _cmd, d, a);
}

// outbound queue: - syncAppendDataToSend:(NSData *)d
static void (*orig_syncAppend)(id, SEL, NSData *);
static void hook_syncAppend(id self, SEL _cmd, NSData *d) {
    NSData *head = [d subdataWithRange:NSMakeRange(0, MIN((NSUInteger)24, (NSUInteger)d.length))];
    MLog(@"APPEND len=%lu head=%@", (unsigned long)d.length, head);
    orig_syncAppend(self, _cmd, d);
}

// outbound send with completion: - syncSendMessage:data:withCompletionHandler:(id,NSData*,id)
static void (*orig_syncSendMessage)(id, SEL, id, NSData *, id);
static void hook_syncSendMessage(id self, SEL _cmd, id peer, NSData *d, id h) {
    MLog(@"SENDMSG len=%lu", (unsigned long)d.length);
    orig_syncSendMessage(self, _cmd, peer, d, h);
}

// receipt: - syncSendMessageReceipt:sequenceNumber:(id, unsigned)
static void (*orig_syncReceipt)(id, SEL, id, unsigned);
static void hook_syncReceipt(id self, SEL _cmd, id r, unsigned seq) {
    MLog(@"RECEIPT seq=%u", seq);
    orig_syncReceipt(self, _cmd, r, seq);
}

// attach decision: - shouldDecideAboutConnection
// THE GATE: the framework asks this before attaching the peer's session.
// For real peers it returns YES; for our foreign peer it returned NO (R53).
// MC_DECIDE_OVERRIDE=1 forces YES (experiment: does forcing the attach
// decision deliver foreign frames app-level?).
static BOOL (*orig_shouldDecide)(id, SEL);
static BOOL hook_shouldDecide(id self, SEL _cmd) {
    BOOL v = orig_shouldDecide(self, _cmd);
    NSString *force = [[NSProcessInfo processInfo] environment][@"MC_DECIDE_OVERRIDE"];
    BOOL out = (force && force.length > 0 && ![force isEqualToString:@"0"]) ? YES : v;
    MLog(@"shouldDecideAboutConnection native=%@ forced=%@ -> %@",
         v ? @"YES" : @"NO", force ?: @"(unset)", out ? @"YES" : @"NO");
    return out;
}

// stream attach: - attachInputStream:outputStream:
static void (*orig_attach)(id, SEL, NSInputStream *, NSOutputStream *);
static void hook_attach(id self, SEL _cmd, NSInputStream *in, NSOutputStream *out) {
    MLog(@"ATTACH streams in=%@ out=%@", in, out);
    orig_attach(self, _cmd, in, out);
}

// connect: - connectToNetService:
static void (*orig_connect)(id, SEL, id);
static void hook_connect(id self, SEL _cmd, id svc) {
    MLog(@"CONNECT to %@", svc);
    orig_connect(self, _cmd, svc);
}

// stream read pump: - syncReadFromInputStream
static int (*orig_syncRead)(id, SEL);
static int hook_syncRead(id self, SEL _cmd) {
    int r = orig_syncRead(self, _cmd);
    MLog(@"READ-FROM-STREAM -> %d", r);
    return r;
}

// inbound stream event: - syncHandleInputStreamEvent:(NSStreamEvent)
static void (*orig_syncHandleIn)(id, SEL, unsigned long);
static void hook_syncHandleIn(id self, SEL _cmd, unsigned long ev) {
    MLog(@"STREAM-IN event=%lu", ev);
    orig_syncHandleIn(self, _cmd, ev);
}

static void (*orig_syncOpen)(id, SEL, unsigned long);
static void hook_syncOpen(id self, SEL _cmd, unsigned long ev) {
    MLog(@"STREAM-OPEN-COMPLETE event=%lu", ev);
    orig_syncOpen(self, _cmd, ev);
}

// install: swap IMPs for selectors that exist on the class
static void swizzleIfExists(Class c, const char *selName, IMP newImp, IMP *origOut) {
    SEL sel = sel_registerName(selName);
    Method m = class_getInstanceMethod(c, sel);
    if (!m) { MLog(@"  (absent) %@", [NSString stringWithUTF8String:selName]); return; }
    *origOut = method_getImplementation(m);
    method_setImplementation(m, newImp);
    MLog(@"  hooked %@", [NSString stringWithUTF8String:selName]);
}

__attribute__((constructor))
static void MCHookInit(void) {
    @autoreleasepool {
        MLog(@"MCHook2 loaded (pid %d)", getpid());
        dumpClassMethods("MCNearbyDiscoveryPeerConnection");
        dumpClassMethods("MCNearbyServicePeerConnection");   // if it exists
        dumpClassMethods("GCKSession");                       // if exposed

        Class pc = objc_getClass("MCNearbyDiscoveryPeerConnection");
        if (!pc) { MLog(@"no MCNearbyDiscoveryPeerConnection"); return; }

        swizzleIfExists(pc, "syncReceivedData:error:",
                        (IMP)hook_syncReceivedData, (IMP *)&orig_syncReceivedData);
        swizzleIfExists(pc, "syncProcessMessage:data:sequenceNumber:",
                        (IMP)hook_syncProcessMessage, (IMP *)&orig_syncProcessMessage);
        // try a few plausible outbound signatures (harmless if absent)
        swizzleIfExists(pc, "syncSendData:", (IMP)hook_syncSendData, (IMP *)&orig_syncSendData);
        swizzleIfExists(pc, "syncSendData:error:", (IMP)hook_syncSendData, (IMP *)&orig_syncSendData);
        swizzleIfExists(pc, "syncAppendDataToSend:", (IMP)hook_syncAppend, (IMP *)&orig_syncAppend);
        swizzleIfExists(pc, "syncSendMessage:data:withCompletionHandler:",
                        (IMP)hook_syncSendMessage, (IMP *)&orig_syncSendMessage);
        swizzleIfExists(pc, "syncSendMessageReceipt:sequenceNumber:",
                        (IMP)hook_syncReceipt, (IMP *)&orig_syncReceipt);
        swizzleIfExists(pc, "shouldDecideAboutConnection:",
                        (IMP)hook_shouldDecide, (IMP *)&orig_shouldDecide);
        swizzleIfExists(pc, "shouldDecideAboutConnection",
                        (IMP)hook_shouldDecide, (IMP *)&orig_shouldDecide);
        swizzleIfExists(pc, "attachInputStream:outputStream:",
                        (IMP)hook_attach, (IMP *)&orig_attach);
        swizzleIfExists(pc, "connectToNetService:",
                        (IMP)hook_connect, (IMP *)&orig_connect);
        swizzleIfExists(pc, "syncReadFromInputStream",
                        (IMP)hook_syncRead, (IMP *)&orig_syncRead);
        swizzleIfExists(pc, "syncHandleInputStreamEvent:",
                        (IMP)hook_syncHandleIn, (IMP *)&orig_syncHandleIn);
        swizzleIfExists(pc, "syncHandleStreamEventOpenCompleted:",
                        (IMP)hook_syncOpen, (IMP *)&orig_syncOpen);
        MLog(@"hooking complete");
    }
}