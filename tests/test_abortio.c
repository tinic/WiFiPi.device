/*
 * WiFi_AbortIO on a limited (48-byte) request, run under an emulator: no Pi
 * hardware.  In an IOStdReq offset 32 is io_Actual; ios2_WireError is the
 * same longword only in a full IOSana2Req.  A write there stays inside the
 * request, where no outer canary sees it, so io_Actual is checked by value.
 *
 * The request is made pending by hand (queued on a private port, IOF_QUICK
 * clear), as AbortIO sees any request still in a queue.  Built like
 * test_devquery (tests/README); it uses nothing newer than device.c's AbortIO,
 * so the same file builds against the parent revision.
 */
#include <exec/exec.h>
#include <exec/io.h>
#include <devices/sana2.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <string.h>

#include "../src/wifipi.h"

void  WiFi_Open(REGARG(struct IOSana2Req *io, "a1"), REGARG(LONG unitNumber, "d0"), REGARG(ULONG flags, "d1"));
ULONG WiFi_Close(REGARG(struct IOSana2Req *io, "a1"));
LONG  WiFi_AbortIO(REGARG(struct IOSana2Req *io, "a1"));

static int checks, failures;

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

#define CANARY 0xC3
#define ACTUAL 0x1234ABCD
typedef struct { UBYTE before[16]; UBYTE req[sizeof(struct IOSana2Req)]; UBYTE after[16]; } Req;

static struct WiFiBase fbase;
static struct WiFiUnit funit;

static int guards(const Req *r, UWORD mn_length)
{
    ULONG i;
    for (i = 0; i < 16; i++)
        if (r->before[i] != CANARY || r->after[i] != CANARY) return 0;
    for (i = mn_length; i < sizeof(r->req); i++)
        if (r->req[i] != CANARY) return 0;
    return 1;
}

static void abort_one(Req *r, UWORD mn_length, struct MsgPort *pending, struct MsgPort *reply)
{
    struct IOSana2Req *io = (struct IOSana2Req *)r->req;
    struct IOStdReq *std = (struct IOStdReq *)io;

    memset(r, CANARY, sizeof(*r));
    memset(r->req, 0, mn_length);
    io->ios2_Req.io_Message.mn_Length = mn_length;
    io->ios2_Req.io_Message.mn_ReplyPort = reply;
    io->ios2_Req.io_Device = (struct Device *)&fbase;
    WiFi_Open(io, 0, 0);
    expect_eq(std->io_Error, 0, "Open");

    std->io_Actual = ACTUAL;
    std->io_Flags = 0;
    PutMsg(pending, (struct Message *)io);      /* in a queue: NT_MESSAGE */
    WiFi_AbortIO(io);
    expect(GetMsg(reply) == (struct Message *)io, "aborted request replied");
    expect(GetMsg(pending) == NULL, "and taken off its queue");
    expect_eq(std->io_Error, IOERR_ABORTED, "io_Error IOERR_ABORTED");
    if (mn_length < sizeof(struct IOSana2Req))
        expect_eq(std->io_Actual, ACTUAL, "limited: io_Actual preserved");
    else
        expect_eq(io->ios2_WireError, S2WERR_GENERIC_ERROR, "full: ios2_WireError set");
    expect(guards(r, mn_length), "nothing written past the request");
    WiFi_Close(io);
}

int main(void)
{
    static Req r;
    struct MsgPort *pending, *reply;
    ULONG lib0, unit0;

    fbase.w_SysBase = SysBase;
    fbase.w_Unit = &funit;
    fbase.w_UtilityBase = OpenLibrary((CONST_STRPTR)"utility.library", 37);
    funit.wu_Base = &fbase;
    funit.wu_Flags = IFF_STARTED;               /* no StartUnit(): no hardware */
    InitSemaphore(&funit.wu_Lock);
    funit.wu_Openers.mlh_Head = (struct MinNode *)&funit.wu_Openers.mlh_Tail;
    funit.wu_Openers.mlh_Tail = NULL;
    funit.wu_Openers.mlh_TailPred = (struct MinNode *)&funit.wu_Openers.mlh_Head;
    pending = CreateMsgPort();
    reply = CreateMsgPort();

    PutStr("wifipi.device AbortIO on limited and full requests\n");
    if (fbase.w_UtilityBase == NULL || pending == NULL || reply == NULL)
    {
        PutStr("RESULT FAIL setup\n");
        return 20;
    }
    lib0 = fbase.w_Device.dd_Library.lib_OpenCnt;
    unit0 = funit.wu_Unit.unit_OpenCnt;

    PutStr("limited 48-byte request\n");
    abort_one(&r, sizeof(struct IOStdReq), pending, reply);
    PutStr("full 88-byte request\n");
    abort_one(&r, sizeof(struct IOSana2Req), pending, reply);

    expect_eq(fbase.w_Device.dd_Library.lib_OpenCnt, lib0, "device count balanced");
    expect_eq(funit.wu_Unit.unit_OpenCnt, unit0, "unit count balanced");

    PutStr(failures ? "RESULT FAIL " : "RESULT PASS "); num(checks); PutStr(" checks, "); num(failures); PutStr(" failures\n");
    return failures ? 20 : 0;
}
