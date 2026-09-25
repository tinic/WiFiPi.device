/*
 * wifipi.device request lifecycle, run under an emulator: no Pi hardware is
 * touched on these paths.  The driver's own WiFi_Open/WiFi_BeginIO/WiFi_Close
 * are linked in and called against a fake WiFiBase/WiFiUnit.
 *
 * THE DEFECT.  A limited-mode Open (a request shorter than an IOSana2Req, as
 * NSCMD_DEVICEQUERY callers send) bumped the open counts and returned success
 * without setting io_Unit.  BeginIO then locked &NULL->wu_Lock and Close did
 * NULL->unit_OpenCnt--: writes into low memory.  Close also read
 * ios2_BufferManagement at offset 84 of a 48-byte request, a failed short
 * Open read and cleared it, and the query wrote its answer to io_Data with no
 * check -- address 0 in the form mcastfilter sends.
 *
 * Every request sits at the head of a block whose tail is a canary, and low
 * memory [0, 0x400) is checksummed around the whole run.
 */
#include <exec/exec.h>
#include <exec/io.h>
#include <devices/sana2.h>
#include <devices/newstyle.h>
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
static int beyond_intact(const Frame *f, UWORD mn_length)
{
    ULONG i;
    for (i = mn_length; i < sizeof(f->req); i++) if (f->req[i] != 0xA5) return 0;
    for (i = 0; i < TAIL; i++) if (f->tail[i] != 0xA5) return 0;
    return 1;
}

int main(void)
{
    static struct NSDeviceQueryResult ans;
    static Frame f, g;
    struct IOSana2Req *io;
    struct IOStdReq *std;
    ULONG low0, lib0, unit0;
    const UWORD SHORT = sizeof(struct IOStdReq), FULL = sizeof(struct IOSana2Req);

    fbase.w_SysBase = SysBase;
    fbase.w_Unit = &funit;
    fbase.w_UtilityBase = OpenLibrary((CONST_STRPTR)"utility.library", 37);
    funit.wu_Base = &fbase;
    funit.wu_Flags = IFF_STARTED;               /* no StartUnit(): no hardware */
    InitSemaphore(&funit.wu_Lock);
    funit.wu_CmdQueue = CreateMsgPort();
    funit.wu_Openers.mlh_Head = (struct MinNode *)&funit.wu_Openers.mlh_Tail;
    funit.wu_Openers.mlh_Tail = NULL;
    funit.wu_Openers.mlh_TailPred = (struct MinNode *)&funit.wu_Openers.mlh_Head;

    PutStr("wifipi.device request lifecycle\n");
    low0 = lowsum();
    lib0 = fbase.w_Device.dd_Library.lib_OpenCnt;
    unit0 = funit.wu_Unit.unit_OpenCnt;

    PutStr("step 1 short Open\n");
    /* 1. A 48-byte IOStdReq opens in limited mode, and gets a unit. */
    io = frame(&f, SHORT);
    WiFi_Open(io, 0, 0);
    expect_eq(io->ios2_Req.io_Error, 0, "short Open succeeds");
    expect(io->ios2_Req.io_Unit == &funit.wu_Unit, "short Open sets io_Unit");
    expect_eq(fbase.w_Device.dd_Library.lib_OpenCnt, lib0 + 1, "short Open counts the device");
    expect_eq(funit.wu_Unit.unit_OpenCnt, unit0 + 1, "short Open counts the unit");
    expect(beyond_intact(&f, SHORT), "short Open writes nothing past the request");

    PutStr("step 2 query\n");
    /* 2. NSCMD_DEVICEQUERY through it, IOStdReq form. */
    std = (struct IOStdReq *)io;
    memset(&ans, 0x5A, sizeof(ans));
    std->io_Command = NSCMD_DEVICEQUERY; std->io_Data = &ans; std->io_Length = sizeof(ans); std->io_Flags = IOF_QUICK;
    WiFi_BeginIO(io);
    expect_eq(std->io_Error, 0, "query answered");
    expect_eq(ans.nsdqr_SizeAvailable, 16, "SizeAvailable is what was filled");
    expect_eq(ans.nsdqr_DeviceType, NSDEVTYPE_SANA2, "DeviceType SANA-II");
    expect_eq(ans.nsdqr_DevQueryFormat, 0, "DevQueryFormat 0");
    expect(ans.nsdqr_SupportedCommands != NULL, "command list present");
    expect_eq(std->io_Actual, 16, "io_Actual is the byte count");
    expect(beyond_intact(&f, SHORT), "query writes nothing past the request");

    PutStr("step 3 no-buffer query\n");
    /* 3. No buffer: refused, nothing written anywhere. */
    std->io_Command = NSCMD_DEVICEQUERY; std->io_Data = NULL; std->io_Length = 16; std->io_Flags = IOF_QUICK;
    WiFi_BeginIO(io);
    expect_eq(std->io_Error, IOERR_BADLENGTH, "query with no buffer refused");

    PutStr("step 4 short non-query\n");
    /* 4. A non-query command in the short request: refused within it. */
    std->io_Command = CMD_READ; std->io_Flags = IOF_QUICK;
    WiFi_BeginIO(io);
    expect_eq(std->io_Error, IOERR_BADLENGTH, "short CMD_READ refused");
    std->io_Command = S2_ONEVENT; std->io_Flags = IOF_QUICK;
    WiFi_BeginIO(io);
    expect_eq(std->io_Error, IOERR_BADLENGTH, "short S2_ONEVENT refused");
    expect(beyond_intact(&f, SHORT), "refusals write nothing past the request");

    PutStr("step 5 short Close\n");
    /* 5. Close gives back exactly what Open took. */
    WiFi_Close(io);
    expect_eq(fbase.w_Device.dd_Library.lib_OpenCnt, lib0, "short Close balances the device count");
    expect_eq(funit.wu_Unit.unit_OpenCnt, unit0, "short Close balances the unit count");
    expect(beyond_intact(&f, SHORT), "short Close reads/writes nothing past the request");

    PutStr("step 6 undersized Open\n");
    /* 6. A request smaller than an IOStdReq is refused and left alone. */
    io = frame(&g, 32);
    WiFi_Open(io, 0, 0);
    expect_eq(io->ios2_Req.io_Error, IOERR_OPENFAIL, "a 32-byte request is refused");
    expect_eq(fbase.w_Device.dd_Library.lib_OpenCnt, lib0, "and counts nothing");
    expect(beyond_intact(&g, 32), "and nothing past it is touched");

    PutStr("step 7 full Open + SANA-II query\n");
    /* 7. A full IOSana2Req, and the SANA-II query form mcastfilter sends. */
    io = frame(&g, FULL);
    WiFi_Open(io, 0, 0);
    expect_eq(io->ios2_Req.io_Error, 0, "full Open succeeds");
    expect(io->ios2_Req.io_Unit == &funit.wu_Unit, "full Open sets io_Unit");
    memset(&ans, 0x5A, sizeof(ans));
    io->ios2_Req.io_Command = NSCMD_DEVICEQUERY; io->ios2_Req.io_Flags = IOF_QUICK;
    io->ios2_Data = &ans; io->ios2_DataLength = 16;
    WiFi_BeginIO(io);
    expect_eq(io->ios2_Req.io_Error, 0, "SANA-II form answered");
    expect_eq(ans.nsdqr_SizeAvailable, 16, "SANA-II form SizeAvailable");
    expect_eq(io->ios2_DataLength, 16, "SANA-II form byte count in ios2_DataLength");
    expect(beyond_intact(&g, FULL), "full request tail intact");

    PutStr("step 8 reused full request, stale MAC\n");
    /* 8. A full request's io_Data is a stale MAC, never a buffer: with a
          valid ios2_Data the answer goes there; without one the query is
          refused -- here with PacketType 64 and an even decoy, which a
          length/alignment heuristic would have believed. */
    {
        static struct NSDeviceQueryResult decoy;
        std = (struct IOStdReq *)io;
        memset(&ans, 0x5A, sizeof(ans));
        memset(&decoy, 0x5A, sizeof(decoy));
        io->ios2_Req.io_Command = NSCMD_DEVICEQUERY; io->ios2_Req.io_Flags = IOF_QUICK;
        std->io_Data = &decoy; std->io_Length = 0x0800;
        io->ios2_Data = &ans; io->ios2_DataLength = 1514;
        WiFi_BeginIO(io);
        expect_eq(ans.nsdqr_SizeAvailable, 16, "reused request answers into ios2_Data");
        expect_eq(decoy.nsdqr_SizeAvailable, 0x5A5A5A5A, "and never the MAC-derived address");
        memset(&decoy, 0x5A, sizeof(decoy));
        std->io_Data = &decoy; std->io_Length = 64; io->ios2_Data = NULL; io->ios2_DataLength = 0;
        io->ios2_Req.io_Command = NSCMD_DEVICEQUERY; io->ios2_Req.io_Flags = IOF_QUICK;
        WiFi_BeginIO(io);
        expect_eq(io->ios2_Req.io_Error, IOERR_BADLENGTH, "PacketType 64 + even decoy, no ios2_Data: refused");
        expect_eq(decoy.nsdqr_SizeAvailable, 0x5A5A5A5A, "and the MAC-derived address is not written");
    }
    WiFi_Close(io);
    expect_eq(fbase.w_Device.dd_Library.lib_OpenCnt, lib0, "full Close balances the device count");
    expect_eq(funit.wu_Unit.unit_OpenCnt, unit0, "full Close balances the unit count");

    expect(lowsum() == low0, "low memory [0, 0x400) unchanged across the run");

    PutStr(failures ? "RESULT FAIL " : "RESULT PASS "); num(checks); PutStr(" checks, "); num(failures); PutStr(" failures\n");
    return failures ? 10 : 0;
}
