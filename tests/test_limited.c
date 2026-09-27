/*
 * wifipi.device limited-mode opens (AmiNetXDuo #100), run under an emulator:
 * the driver's own WiFi_Open/WiFi_BeginIO/WiFi_Close against a fake
 * WiFiBase/WiFiUnit, no Pi hardware.
 *
 * A limited open is a request shorter than an IOSana2Req (88) but at least
 * an IOStdReq (48), as NSD query tools send from CreateIORequest.  Offset 84,
 * ios2_BufferManagement, is past its end.
 *
 * Reads past the request are invisible to canaries, so device.c is built
 * with every io->ios2_BufferManagement routed through wifipi_bm_seam(),
 * which counts accesses made on a request shorter than 88.  The rewrite is
 * mechanical and applies to any revision of device.c alike.  With $CF the
 * flags from tests/README:
 *
 *   awk 'BEGIN{skip=0} /^asm\("    \.text/{skip=1} skip&&/\);$/{skip=0; next} !skip' \
 *       src/device.c | sed 's/io->ios2_BufferManagement/WIFIPI_BM(io)/g' > device_lim.c
 *   $gcc $CF -include tests/test_limited.c -DWIFIPI_BM_SEAM_ONLY \
 *       '-DWIFIPI_BM(r)=(*wifipi_bm_seam(r))' -c device_lim.c
 *   $gcc $CF -o test_limited tests/test_limited.c device_lim.o src/unit.c \
 *       src/init.c src/mbox.c src/sdio.c src/wifipi.c src/packet.c src/d11.c \
 *       src/findtoken.c src/end.c
 *
 * Low memory [0, 0x400) is checksummed: with io_Unit NULL the unit's
 * wu_Lock and unit_OpenCnt fall there.
 */
#ifdef WIFIPI_BM_SEAM_ONLY
struct IOSana2Req;
void **wifipi_bm_seam(struct IOSana2Req *io);
#else
#include <exec/exec.h>
#include <exec/io.h>
#include <devices/sana2.h>
#include <devices/newstyle.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <stddef.h>
#include <string.h>

#include "../src/wifipi.h"

void  WiFi_Open(REGARG(struct IOSana2Req *io, "a1"), REGARG(LONG unitNumber, "d0"), REGARG(ULONG flags, "d1"));
ULONG WiFi_Close(REGARG(struct IOSana2Req *io, "a1"));
void  WiFi_BeginIO(REGARG(struct IOSana2Req *io, "a1"));

typedef char bm_at_84[offsetof(struct IOSana2Req, ios2_BufferManagement) == 84 ? 1 : -1];

static int checks, failures;
static ULONG short_bm;          /* ios2_BufferManagement accesses on a short request */

void **wifipi_bm_seam(struct IOSana2Req *io)
{
    if (io->ios2_Req.io_Message.mn_Length < sizeof(struct IOSana2Req))
        short_bm++;
    return &io->ios2_BufferManagement;
}

/* Every line also goes out the serial port: a run that hangs the machine
   leaves the serial log as the only record. */
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
#define SENTINEL ((APTR)0xB0B5E184)    /* at offset 84 past a short request */
typedef struct { UBYTE req[sizeof(struct IOSana2Req)]; UBYTE tail[TAIL]; } Frame;
typedef struct { Frame f, ref; UWORD len; } Box;

static struct WiFiBase fbase;
static struct WiFiUnit funit;

/* Request at the head, 0xA5 canaries after mn_Length, the sentinel pointer at
   offset 84 when that is past the end, and a copy to compare against. */
/* Each step starts from the same counts, so one failure does not cascade. */
static ULONG lib0, unit0;
static void reset(void)
{
    fbase.w_Device.dd_Library.lib_OpenCnt = lib0;
    funit.wu_Unit.unit_OpenCnt = unit0;
    funit.wu_Flags = IFF_STARTED;
}

static struct IOSana2Req *frame(Box *b, UWORD mn_length)
{
    struct IOSana2Req *io = (struct IOSana2Req *)&b->f;
    memset(&b->f, 0, sizeof(b->f));
    memset(b->f.req + mn_length, 0xA5, sizeof(b->f.req) - mn_length);
    memset(b->f.tail, 0xA5, TAIL);
    if (mn_length <= 84)
        io->ios2_BufferManagement = SENTINEL;
    io->ios2_Req.io_Message.mn_Length = mn_length;
    io->ios2_Req.io_Device = (struct Device *)&fbase;
    b->ref = b->f;
    b->len = mn_length;
    return io;
}
static int beyond_intact(const Box *b)
{
    return memcmp(b->f.req + b->len, b->ref.req + b->len, sizeof(b->f.req) - b->len) == 0 &&
           memcmp(b->f.tail, b->ref.tail, TAIL) == 0;
}

int main(void)
{
    static struct NSDeviceQueryResult ans;
    static Box a, x;
    struct IOSana2Req *io, *ex;
    struct IOStdReq *std;
    struct MsgPort *reply;
    ULONG low0, low;
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
    reply = CreateMsgPort();

    PutStr("wifipi.device limited open\n");
    if (funit.wu_CmdQueue == NULL || reply == NULL || fbase.w_UtilityBase == NULL)
    {
        PutStr("RESULT FAIL no ports\n");
        return 20;
    }
    lib0 = fbase.w_Device.dd_Library.lib_OpenCnt;
    unit0 = funit.wu_Unit.unit_OpenCnt;
    low0 = lowsum();

    PutStr("step 1 limited open, query, close\n");
    short_bm = 0;
    io = frame(&a, SHORT);
    WiFi_Open(io, 0, 0);
    expect_eq(io->ios2_Req.io_Error, 0, "1 limited Open succeeds");
    expect(io->ios2_Req.io_Unit == &funit.wu_Unit, "1 limited Open sets io_Unit");
    expect_eq(fbase.w_Device.dd_Library.lib_OpenCnt, lib0 + 1, "1 Open counts the device");
    expect_eq(funit.wu_Unit.unit_OpenCnt, unit0 + 1, "1 Open counts the unit");
    expect(beyond_intact(&a), "1 Open writes nothing past the request");
    if (io->ios2_Req.io_Unit == &funit.wu_Unit)
    {
        std = (struct IOStdReq *)io;
        memset(&ans, 0x5A, sizeof(ans));
        std->io_Command = NSCMD_DEVICEQUERY; std->io_Data = &ans;
        std->io_Length = sizeof(ans); std->io_Flags = IOF_QUICK;
        WiFi_BeginIO(io);
        expect_eq(std->io_Error, 0, "1 query answered");
        expect_eq(ans.nsdqr_DeviceType, NSDEVTYPE_SANA2, "1 DeviceType SANA-II");
        expect(ans.nsdqr_SupportedCommands != NULL, "1 command list present");
        /* beta4 short form, unchanged: 16 + sizeof(APTR) */
        expect_eq(std->io_Actual, sizeof(struct NSDeviceQueryResult) + sizeof(APTR), "1 io_Actual beta4 form");
        expect_eq(ans.nsdqr_SizeAvailable, std->io_Actual, "1 SizeAvailable beta4 form");
        expect(beyond_intact(&a), "1 query writes nothing past the request");
    }
    else
        expect(0, "1 query skipped: io_Unit NULL would lock low memory");
    WiFi_Close(io);
    expect_eq(fbase.w_Device.dd_Library.lib_OpenCnt, lib0, "1 Close balances the device");
    expect_eq(funit.wu_Unit.unit_OpenCnt, unit0, "1 Close balances the unit");
    expect(beyond_intact(&a), "1 Close writes nothing past the request");
    expect(io->ios2_BufferManagement == SENTINEL, "1 sentinel at 84 still there");
    expect_eq(short_bm, 0, "1 offset-84 accesses on the short request (Open/Close)");
    expect(funit.wu_Openers.mlh_Head == (struct MinNode *)&funit.wu_Openers.mlh_Tail, "1 no opener listed");
    expect(lowsum() == low0, "1 low memory unchanged");

    PutStr("step 2 failed short opens\n");
    reset();
    low = lowsum();
    short_bm = 0;
    io = frame(&a, 40);
    WiFi_Open(io, 0, 0);
    expect_eq(io->ios2_Req.io_Error, IOERR_OPENFAIL, "2 40-byte Open refused");
    expect(beyond_intact(&a), "2 40-byte Open: nothing past the request touched");
    expect_eq(short_bm, 0, "2 40-byte Open: offset-84 accesses");

    short_bm = 0;
    io = frame(&a, SHORT);
    WiFi_Open(io, 1, 0);
    expect_eq(io->ios2_Req.io_Error, IOERR_OPENFAIL, "2 limited Open of unit 1 refused");
    expect(beyond_intact(&a), "2 unit 1: nothing past the request touched");
    expect_eq(short_bm, 0, "2 unit 1: offset-84 accesses");
    expect_eq(fbase.w_Device.dd_Library.lib_OpenCnt, lib0, "2 unit 1 counts nothing");
    if (io->ios2_Req.io_Error == 0)
        WiFi_Close(io);                         /* parent: give the count back */

    /* An exclusive full opener holds the unit; a limited open conflicts. */
    reset();
    ex = frame(&x, FULL);
    WiFi_Open(ex, 0, SANA2OPF_MINE);
    expect_eq(ex->ios2_Req.io_Error, 0, "2 exclusive full Open succeeds");
    short_bm = 0;
    io = frame(&a, SHORT);
    WiFi_Open(io, 0, 0);
    expect_eq(io->ios2_Req.io_Error, IOERR_UNITBUSY, "2 limited Open vs exclusive refused");
    expect(beyond_intact(&a), "2 sharing conflict: nothing past the request touched");
    expect(io->ios2_BufferManagement == SENTINEL, "2 sharing conflict: sentinel at 84 still there");
    expect_eq(short_bm, 0, "2 sharing conflict: offset-84 accesses");
    expect_eq(funit.wu_Unit.unit_OpenCnt, unit0 + 1, "2 conflict counts nothing");
    WiFi_Close(ex);
    expect_eq(fbase.w_Device.dd_Library.lib_OpenCnt, lib0, "2 exclusive Close balances the device");
    expect_eq(funit.wu_Unit.unit_OpenCnt, unit0, "2 exclusive Close balances the unit");
    expect(lowsum() == low, "2 low memory unchanged");

    PutStr("step 3 full open/close\n");
    reset();
    low = lowsum();
    short_bm = 0;
    io = frame(&x, FULL);
    WiFi_Open(io, 0, 0);
    expect_eq(io->ios2_Req.io_Error, 0, "3 full Open succeeds");
    expect(io->ios2_Req.io_Unit == &funit.wu_Unit, "3 full Open sets io_Unit");
    expect(io->ios2_BufferManagement != NULL, "3 full Open makes an opener");
    expect(funit.wu_Openers.mlh_Head == (struct MinNode *)io->ios2_BufferManagement, "3 opener listed");
    expect((funit.wu_Flags & IFF_SHARED) != 0, "3 shared open marks the unit shared");
    expect_eq(fbase.w_Device.dd_Library.lib_OpenCnt, lib0 + 1, "3 full Open counts the device");
    expect_eq(funit.wu_Unit.unit_OpenCnt, unit0 + 1, "3 full Open counts the unit");
    WiFi_Close(io);
    expect(funit.wu_Openers.mlh_Head == (struct MinNode *)&funit.wu_Openers.mlh_Tail, "3 Close unlists the opener");
    expect_eq(fbase.w_Device.dd_Library.lib_OpenCnt, lib0, "3 full Close balances the device");
    expect_eq(funit.wu_Unit.unit_OpenCnt, unit0, "3 full Close balances the unit");
    expect(beyond_intact(&x), "3 full request tail intact");
    expect_eq(short_bm, 0, "3 no short accesses");
    expect(lowsum() == low, "3 low memory unchanged");

    PutStr("step 4 Close with io_Unit NULL\n");
    reset();
    low = lowsum();
    io = frame(&a, SHORT);
    fbase.w_Device.dd_Library.lib_OpenCnt++;    /* the count Close gives back */
    WiFi_Close(io);
    expect_eq(fbase.w_Device.dd_Library.lib_OpenCnt, lib0, "4 Close gives back the device count");
    expect_eq(funit.wu_Unit.unit_OpenCnt, unit0, "4 unit count untouched");
    expect(lowsum() == low, "4 low memory unchanged");

    /* On a driver without the guard this locks and queues through low
       memory, and may not come back: last, after a summary. */
    PutStr("so far "); num(checks); PutStr(" checks, "); num(failures); PutStr(" failures\n");
    PutStr("step 5 BeginIO with io_Unit NULL\n");
    reset();
    low = lowsum();
    io = frame(&a, SHORT);
    io->ios2_Req.io_Command = NSCMD_DEVICEQUERY;
    io->ios2_Req.io_Flags = IOF_QUICK;
    WiFi_BeginIO(io);
    expect_eq(io->ios2_Req.io_Error, IOERR_OPENFAIL, "5 quick: IOERR_OPENFAIL");
    expect(GetMsg(reply) == NULL, "5 quick: not replied");
    io = frame(&a, SHORT);
    io->ios2_Req.io_Message.mn_ReplyPort = reply;
    io->ios2_Req.io_Unit = (struct Unit *)-1;
    io->ios2_Req.io_Command = NSCMD_DEVICEQUERY;
    io->ios2_Req.io_Flags = 0;
    WiFi_BeginIO(io);
    expect_eq(io->ios2_Req.io_Error, IOERR_OPENFAIL, "5 io_Unit -1: IOERR_OPENFAIL");
    expect(GetMsg(reply) == (struct Message *)io, "5 io_Unit -1: replied");
    expect(beyond_intact(&a), "5 nothing past the request touched");
    expect(lowsum() == low, "5 low memory unchanged");

    expect(lowsum() == low0, "low memory [0, 0x400) unchanged across the run");

    PutStr(failures ? "RESULT FAIL " : "RESULT PASS "); num(checks); PutStr(" checks, "); num(failures); PutStr(" failures\n");
    return failures ? 10 : 0;
}
#endif
