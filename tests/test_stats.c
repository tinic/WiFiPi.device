/*
 * wifipi.device special statistics, run under an emulator: no Pi hardware
 * is touched.  The driver's own WiFi_Open/WiFi_BeginIO/WiFi_Close are linked
 * in and called against a fake WiFiBase/WiFiUnit/SDIO.
 *
 * S2_GETSPECIALSTATS never reads the firmware (#89): its wait has no
 * deadline and runs under wu_Lock.  AmiNetXDuo's RX reader asks
 * for 24 records and NetDevStats for 64, repeatedly and on an online unit:
 * those must never queue a firmware command.  A firmware command here goes
 * to s_ReceiverPort and waits for a reply nobody sends, so a gate that let
 * one through hangs the run instead of passing it (331410c, ungated, never
 * reaches step 2).
 */
#include <exec/exec.h>
#include <exec/io.h>
#include <devices/sana2.h>
#include <devices/sana2wireless.h>
#include <devices/newstyle.h>
#include <devices/timer.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <string.h>

#include "../src/wifipi.h"

void  WiFi_Open(REGARG(struct IOSana2Req *io, "a1"), REGARG(LONG unitNumber, "d0"), REGARG(ULONG flags, "d1"));
ULONG WiFi_Close(REGARG(struct IOSana2Req *io, "a1"));
void  WiFi_BeginIO(REGARG(struct IOSana2Req *io, "a1"));

static int checks, failures;

/* Every line also goes out the serial port, through RawPutChar: a run that
   hangs the machine never closes its stdout file, and the serial log is then
   the only record of how far it got. */
static void rawput(char c)
{
    register struct ExecBase *a6 __asm("a6") = SysBase;
    register char d0 __asm("d0") = c;
    __asm volatile ("jsr -516(%%a6)" : "+r"(d0) : "r"(a6) : "d1", "a0", "a1", "cc", "memory");
}
static void out(const char *s)
{
    const char *p;
    for (p = s; *p; p++) { if (*p == '\n') rawput('\r'); rawput(*p); }
    PutStr((CONST_STRPTR)s);
}
#undef PutStr
#define PutStr(s) out(s)
static void num(LONG v) { char b[12]; int i = 11; ULONG u = v < 0 ? -v : v; b[i] = 0; do { b[--i] = '0' + u % 10; u /= 10; } while (u); if (v < 0) b[--i] = '-'; PutStr(b + i); }
static void expect(int ok, const char *what)
{
    checks++;
    if (ok) return;
    failures++;
    PutStr("FAIL "); PutStr(what); PutStr("\n");
}
static void expect_eq(LONG got, LONG want, const char *what)
{
    checks++;
    if (got == want) return;
    failures++;
    PutStr("FAIL "); PutStr(what); PutStr(": got "); num(got); PutStr(", want "); num(want); PutStr("\n");
}

static ULONG lowsum(void)
{
    const volatile UBYTE *p = (const volatile UBYTE *)0;
    ULONG s = 0, i;
    for (i = 0; i < 0x400; i++) s = s * 31 + p[i];
    return s;
}

#define TAIL 64
typedef struct { UBYTE req[sizeof(struct IOSana2Req)]; UBYTE tail[TAIL]; } Frame;

static struct WiFiBase fbase;
static struct WiFiUnit funit;
static struct SDIO fsdio;

static struct IOSana2Req *frame(Frame *f, UWORD mn_length)
{
    struct IOSana2Req *io = (struct IOSana2Req *)f;
    memset(f, 0, sizeof(*f));
    memset(f->req + mn_length, 0xA5, sizeof(f->req) - mn_length);   /* past the request */
    memset(f->tail, 0xA5, TAIL);
    io->ios2_Req.io_Message.mn_Length = mn_length;
    io->ios2_Req.io_Device = (struct Device *)&fbase;
    return io;
}

static struct Sana2SpecialStatRecord *stats(struct IOSana2Req *io, ULONG max, ULONG *supplied)
{
    static struct { struct Sana2SpecialStatHeader h; struct Sana2SpecialStatRecord r[256]; } st;
    memset(&st, 0, sizeof(st));
    st.h.RecordCountMax = max;
    io->ios2_Req.io_Command = S2_GETSPECIALSTATS;
    io->ios2_Req.io_Flags = IOF_QUICK;
    io->ios2_StatData = &st;
    WiFi_BeginIO(io);
    *supplied = st.h.RecordCountSupplied;
    return st.r;
}

static int named(const struct Sana2SpecialStatRecord *r, const char *want)
{
    return r->String != NULL && strcmp((const char *)r->String, want) == 0;
}

int main(void)
{
    static Frame f;
    struct IOSana2Req *io;
    struct Sana2SpecialStatRecord *r;
    ULONG low0, lib0, unit0, supplied, k;
    const UWORD FULL = sizeof(struct IOSana2Req);

    fbase.w_SysBase = SysBase;
    fbase.w_Unit = &funit;
    fbase.w_SDIO = &fsdio;
    fbase.w_UtilityBase = OpenLibrary((CONST_STRPTR)"utility.library", 37);
    funit.wu_Base = &fbase;
    funit.wu_Flags = IFF_STARTED;
    InitSemaphore(&funit.wu_Lock);
    funit.wu_CmdQueue = CreateMsgPort();
    /* A real pool: with none the firmware read's buffer allocation fails
       and the read is skipped, which would hide an ungated read. */
    fbase.w_MemPool = CreatePool(MEMF_PUBLIC | MEMF_CLEAR, 16384, 8192);
    fsdio.s_SysBase = SysBase;
    fsdio.s_WiFiBase = &fbase;
    fsdio.s_ReceiverPort = CreateMsgPort();
    funit.wu_Openers.mlh_Head = (struct MinNode *)&funit.wu_Openers.mlh_Tail;
    funit.wu_Openers.mlh_Tail = NULL;
    funit.wu_Openers.mlh_TailPred = (struct MinNode *)&funit.wu_Openers.mlh_Head;

    PutStr("wifipi.device special statistics\n");
    if (funit.wu_CmdQueue == NULL || fsdio.s_ReceiverPort == NULL || fbase.w_MemPool == NULL)
    {
        PutStr("RESULT FAIL no ports\n");
        return 20;
    }
    low0 = lowsum();
    lib0 = fbase.w_Device.dd_Library.lib_OpenCnt;
    unit0 = funit.wu_Unit.unit_OpenCnt;

    io = frame(&f, FULL);
    WiFi_Open(io, 0, 0);
    expect_eq(io->ios2_Req.io_Error, 0, "full Open succeeds");

    PutStr("step 1 stack and NetDevStats queries, online, repeated\n");
    funit.wu_Flags |= IFF_UP | IFF_ONLINE;
    fsdio.s_StatFwRoute = 0;
    for (k = 0; k < 5; k++)
    {
        r = stats(io, 24, &supplied);
        expect_eq(io->ios2_Req.io_Error, 0, "24-record query answered");
        expect_eq(supplied, 24, "24 records supplied");
        r = stats(io, 64, &supplied);
        expect_eq(io->ios2_Req.io_Error, 0, "64-record query answered");
        expect_eq(supplied, 64, "64 records supplied");
        expect(named(&r[35], "tx CMD53s failed"), "record 35 is the first TX counter");
        expect(named(&r[63], "orphans multicast"), "record 63 is the last before the firmware block");
    }
    expect((struct Message *)GetMsg(fsdio.s_ReceiverPort) == NULL, "no firmware command queued");
    expect_eq(fsdio.s_StatFwRoute, 0, "firmware counters not read (route 0)");

    PutStr("step 2 full reader, unit online\n");
    r = stats(io, 256, &supplied);
    expect_eq(io->ios2_Req.io_Error, 0, "256-record query answered online");
    expect_eq(supplied, 203, "all 203 records supplied online");
    expect_eq(r[64].Count, 0, "online: route 0, firmware not read");
    for (k = 65; k < 203; k++)
        if (r[k].Count != 0xffffffff)
            break;
    expect_eq(k, 203, "online: every firmware value reads unavailable (0xffffffff), not zero");
    expect(named(&r[65], "fw counters error") && named(&r[72], "fw txfail"), "firmware record names in place");
    expect(named(&r[35], "tx CMD53s failed") && named(&r[63], "orphans multicast"), "driver TX/orphan records preserved");
    expect((struct Message *)GetMsg(fsdio.s_ReceiverPort) == NULL, "online 256: no firmware command queued");

    PutStr("step 3 full reader, unit offline\n");
    fsdio.s_StatFwRoute = 0;
    funit.wu_Flags &= ~IFF_ONLINE;
    r = stats(io, 256, &supplied);
    expect_eq(io->ios2_Req.io_Error, 0, "256-record query answered");
    expect_eq(supplied, 203, "all 203 records supplied");
    expect(named(&r[64], "fw counters route"), "record 64 is the firmware route");
    expect_eq(r[64].Count, 0, "offline: route 0");
    expect(named(&r[202], "fw raw +1fc"), "record 202 is the last raw word");
    expect((struct Message *)GetMsg(fsdio.s_ReceiverPort) == NULL, "still no firmware command queued");

    WiFi_Close(io);
    expect_eq(fbase.w_Device.dd_Library.lib_OpenCnt, lib0, "Close balances the device count");
    expect_eq(funit.wu_Unit.unit_OpenCnt, unit0, "Close balances the unit count");
    expect(lowsum() == low0, "low memory [0, 0x400) unchanged across the run");

    PutStr(failures ? "RESULT FAIL " : "RESULT PASS "); num(checks); PutStr(" checks, "); num(failures); PutStr(" failures\n");
    return failures ? 20 : 0;
}
