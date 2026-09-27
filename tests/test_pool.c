/*
 * wifipi.device w_MemPool and the receiver (#94), run under an emulator: no
 * Pi hardware.  An exec pool has no locking of its own on 3.x, and the
 * receiver runs outside wu_Lock, so nothing it runs may touch w_MemPool.
 * The real StartNetworkScan/ProcessEvent/PacketSetVarAsync/PacketCmdIntAsync
 * are linked in; a helper at priority 5 stands in for the receiver and a
 * fake SendPKT takes the frames.
 *
 * The seam: exec's AllocPooled/FreePooled are SetFunction'ed to count the
 * calls on w_MemPool per task.  The driver's AllocVecPooled, FreeVecPooled
 * and AllocPooledClear all end up there.
 *
 * Covered: a scan with and without an SSID tag (the SSID lands in the escan
 * parameters); E_ASSOC with N, 0, N bytes and a failing allocation; both
 * async senders, glommed or not; no w_MemPool call from the receiver; memory
 * back where it started once wu_AssocIE is freed the way expunge does; and a
 * few seconds of the receiver running while a priority-0 task works the pool.
 */
#include <exec/exec.h>
#include <exec/io.h>
#include <devices/sana2.h>
#include <devices/sana2wireless.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/utility.h>
#include <dos/dostags.h>
#include <string.h>

#include "../src/wifipi.h"
#include "../src/packet.h"

/* as in packet.c, which keeps it to itself */
struct PacketEvent {
    UBYTE   e_EthHeader[14];
    UBYTE   e_Header[10];
    UWORD   e_Version;
    UWORD   e_Flags;
    ULONG   e_EventType;
    ULONG   e_Status;
    ULONG   e_Reason;
    ULONG   e_AuthType;
    ULONG   e_DataLen;
    UBYTE   e_Address[6];
    char    e_IFName[16];
    UBYTE   e_IFIdx;
    UBYTE   e_BSSCFgIdx;
} __attribute__((packed));

void ProcessEvent(struct SDIO *sdio, struct PacketEvent *pe);

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

static struct WiFiBase fbase;
static struct WiFiUnit funit;
static struct SDIO fsdio;
static struct Chip fchip;

/* ------------------------------------------------------------------ */
/* The seam: count AllocPooled/FreePooled on w_MemPool, per task      */

static struct Task * volatile mainTask;
static struct Task * volatile helperTask;
static volatile ULONG opsHelper, opsMain, opsOther;
APTR oldAllocPooled, oldFreePooled;

void note_pool(APTR pool)
{
    struct Task *me = SysBase->ThisTask;
    if (pool != fbase.w_MemPool || pool == NULL) return;
    if (me == helperTask) opsHelper++;
    else if (me == mainTask) opsMain++;
    else opsOther++;
}

/* AllocPooled(a0 pool, d0 size), FreePooled(a0 pool, a1 mem, d0 size):
   note the pool, then go on to the original with every register intact */
asm("    .text                          \n"
    "    .globl _newAllocPooled         \n"
    "_newAllocPooled:                   \n"
    "    movem.l %d0-%d1/%a0-%a1,-(%sp)      \n"
    "    move.l  %a0,-(%sp)               \n"
    "    jsr     _note_pool             \n"
    "    addq.l  #4,%sp                 \n"
    "    movem.l (%sp)+,%d0-%d1/%a0-%a1      \n"
    "    move.l  _oldAllocPooled,-(%sp)  \n"
    "    rts                            \n"
    "    .globl _newFreePooled          \n"
    "_newFreePooled:                    \n"
    "    movem.l %d0-%d1/%a0-%a1,-(%sp)      \n"
    "    move.l  %a0,-(%sp)               \n"
    "    jsr     _note_pool             \n"
    "    addq.l  #4,%sp                 \n"
    "    movem.l (%sp)+,%d0-%d1/%a0-%a1      \n"
    "    move.l  _oldFreePooled,-(%sp)  \n"
    "    rts                            \n");
void newAllocPooled(void);
void newFreePooled(void);

#define LVO_AllocPooled (-708)
#define LVO_FreePooled  (-714)

/* ------------------------------------------------------------------ */
/* The fake card                                                       */

static volatile int sends, lenBad;
static volatile ULONG lastLen;
static UBYTE lastFrame[256];

static void fake_sendpkt(UBYTE *pkt, ULONG length, struct SDIO *sdio)
{
    ULONG i;
    (void)sdio;
    if ((ULONG)(pkt[0] | (pkt[1] << 8)) != length) lenBad++;   /* ph_Length, LE */
    lastLen = length;
    for (i = 0; i < length && i < sizeof(lastFrame); i++) lastFrame[i] = pkt[i];
    sends++;
}

/* ------------------------------------------------------------------ */
/* The receiver's side                                                 */

#define N_IE 37
static UBYTE evbuf[sizeof(struct PacketEvent) + 64];

static void assoc(ULONG len)
{
    struct PacketEvent *pe = (struct PacketEvent *)evbuf;
    ULONG i;
    memset(evbuf, 0, sizeof(evbuf));
    pe->e_EventType = BRCMF_E_ASSOC;
    pe->e_DataLen = len;
    for (i = 0; i < 6; i++) pe->e_Address[i] = 0x10 + i;
    for (i = 0; i < 64; i++) evbuf[sizeof(struct PacketEvent) + i] = 0x80 + i;
    ProcessEvent(&fsdio, pe);
}

static struct IOSana2Req scanio;
static struct TagItem ssidTags[] = { { S2INFO_SSID, (ULONG)"pooltest" }, { TAG_DONE, 0 } };

static void scan(int withSSID)
{
    scanio.ios2_Req.io_Unit = &funit.wu_Unit;
    scanio.ios2_StatData = withSSID ? ssidTags : NULL;
    StartNetworkScan(&scanio);
}

/* where the escan parameters start in the last frame: SDPCM header, BCDC
   header, "escan\0" */
#define ESCAN_PARAMS (12 + 16 + 6)

#define H_ONCE      1
#define H_LOOP      2
#define H_QUIT      3
static volatile int helperCmd, helperStop, rounds;
static volatile int ssidOK, noSsidOK, ieOK, failLenOK;

static void round_once(int check)
{
    scan(1);
    if (check)
        ssidOK = lastFrame[ESCAN_PARAMS + 8] == 8 && memcmp(&lastFrame[ESCAN_PARAMS + 12], "pooltest", 8) == 0 &&
                 lastFrame[ESCAN_PARAMS + 12 + 8] == 0;
    scan(0);
    if (check)
        noSsidOK = lastFrame[ESCAN_PARAMS + 8] == 0 && lastFrame[ESCAN_PARAMS + 12] == 0;

    assoc(N_IE);
    if (check)
        ieOK = funit.wu_AssocIELength == N_IE && funit.wu_AssocIE != NULL &&
               funit.wu_AssocIE[0] == 0x80 && funit.wu_AssocIE[N_IE - 1] == 0x80 + N_IE - 1;
    assoc(0);
    if (check)
        ieOK = ieOK && funit.wu_AssocIE == NULL && funit.wu_AssocIELength == 0;
    if (check)
    {
        assoc(0x7fff1234);          /* no such memory: the allocation fails */
        failLenOK = funit.wu_AssocIE == NULL && funit.wu_AssocIELength == 0;
    }
    assoc(N_IE);
    if (check)
        ieOK = ieOK && funit.wu_AssocIELength == N_IE && funit.wu_AssocIE[5] == 0x85;

    PacketSetVarIntAsync(&fsdio, "mpc", 1);
    PacketCmdIntAsync(&fsdio, 2, 1);
    fsdio.s_GlomEnabled = 1;
    PacketSetVarAsync(&fsdio, "bus:txglom", "\1\0\0\0\0\0", 6);
    PacketCmdIntAsync(&fsdio, 3, 0);
    fsdio.s_GlomEnabled = 0;
}

static void helper(void)
{
    helperTask = FindTask(NULL);
    Signal(mainTask, SIGBREAKF_CTRL_E);
    for (;;)
    {
        int c;
        Wait(SIGBREAKF_CTRL_F);
        c = helperCmd;
        if (c == H_ONCE) round_once(1);
        else if (c == H_LOOP)
        {
            while (!helperStop)
            {
                round_once(0);
                rounds++;
                Delay(1);       /* wakes at a tick, wherever the other task is */
            }
        }
        if (c == H_QUIT) break;
        Signal(mainTask, SIGBREAKF_CTRL_E);
    }
    Forbid();
    helperTask = NULL;
    Signal(mainTask, SIGBREAKF_CTRL_E);
}

static void helper_cmd(int c)
{
    helperCmd = c;
    Signal((struct Task *)helperTask, SIGBREAKF_CTRL_F);
}

#define NOW() (DateStamp(&ds), (ULONG)(ds.ds_Minute * 3000 + ds.ds_Tick))   /* ticks */

int main(void)
{
    struct DateStamp ds;
    ULONG avail0, t0, iters = 0, bad = 0;
    int k;

    mainTask = FindTask(NULL);
    fbase.w_SysBase = SysBase;
    fbase.w_Unit = &funit;
    fbase.w_SDIO = &fsdio;
    fbase.w_UtilityBase = OpenLibrary((CONST_STRPTR)"utility.library", 37);
    fbase.w_MemPool = CreatePool(MEMF_ANY, 16384, 4096);        /* as WiFi_Init */
    funit.wu_Base = &fbase;
    fsdio.s_SysBase = SysBase;
    fsdio.s_WiFiBase = &fbase;
    fsdio.SendPKT = fake_sendpkt;
    fsdio.s_Chip = &fchip;

    PutStr("wifipi.device w_MemPool and the receiver\n");
    if (fbase.w_UtilityBase == NULL || fbase.w_MemPool == NULL)
    {
        PutStr("RESULT FAIL setup\n");
        return 20;
    }

    Forbid();
    oldAllocPooled = SetFunction((struct Library *)SysBase, LVO_AllocPooled, (APTR)newAllocPooled);
    oldFreePooled = SetFunction((struct Library *)SysBase, LVO_FreePooled, (APTR)newFreePooled);
    CacheClearU();
    Permit();

    PutStr("step 1 the seam counts\n");
    {
        APTR p = AllocVecPooled(fbase.w_MemPool, 40);
        FreeVecPooled(fbase.w_MemPool, p);
        expect_eq(opsMain, 2, "an AllocVecPooled/FreeVecPooled pair on w_MemPool is seen");
        opsMain = 0;
    }

    SetSignal(0, SIGBREAKF_CTRL_E);
    if (CreateNewProcTags(NP_Entry, (ULONG)helper, NP_Name, (ULONG)"pool-receiver", NP_Priority, 5, TAG_DONE) == NULL)
    {
        /* exec's vectors point into this program: put them back before it goes */
        Forbid();
        SetFunction((struct Library *)SysBase, LVO_AllocPooled, oldAllocPooled);
        SetFunction((struct Library *)SysBase, LVO_FreePooled, oldFreePooled);
        CacheClearU();
        Permit();
        DeletePool(fbase.w_MemPool);
        CloseLibrary(fbase.w_UtilityBase);
        PutStr("RESULT FAIL no helper\n");
        return 20;
    }
    Wait(SIGBREAKF_CTRL_E);

    PutStr("step 2 the receiver's calls, once\n");
    avail0 = AvailMem(MEMF_ANY);
    helper_cmd(H_ONCE);
    Wait(SIGBREAKF_CTRL_E);
    expect_eq(opsHelper, 0, "no w_MemPool call from the receiver");
    expect_eq(opsOther, 0, "nor from anyone else");
    expect(ssidOK, "scan with an SSID: the SSID is in the escan parameters");
    expect(noSsidOK, "scan without one: the parameters as they are");
    expect(ieOK, "E_ASSOC N, 0, N: wu_AssocIE follows");
    expect(failLenOK, "E_ASSOC with no memory: no IE and no length");
    expect_eq(sends, 4 + 4, "every async frame sent");
    expect_eq(lenBad, 0, "each with its own length");
    FreeVec(funit.wu_AssocIE);          /* as WiFi_Expunge */
    funit.wu_AssocIE = NULL;
    expect_eq(AvailMem(MEMF_ANY), avail0, "memory back where it started");

    PutStr("step 3 the receiver and a pool user at once\n");
    opsHelper = opsMain = opsOther = 0;
    helperStop = 0;
    helper_cmd(H_LOOP);
    t0 = NOW();
    while (NOW() - t0 < 200)
    {
        static UBYTE *blk[8];
        static const ULONG sz[8] = { 24, 200, 5000, 48, 17000, 96, 1000, 8 };
        for (k = 0; k < 8; k++)
        {
            ULONG i;
            blk[k] = AllocVecPooled(fbase.w_MemPool, sz[k]);
            if (blk[k] == NULL) { bad++; continue; }
            for (i = 0; i < sz[k]; i++) blk[k][i] = (UBYTE)(k * 37 + i);
        }
        for (k = 0; k < 8; k++)
        {
            ULONG i;
            if (blk[k] == NULL) continue;
            for (i = 0; i < sz[k]; i++) if (blk[k][i] != (UBYTE)(k * 37 + i)) { bad++; break; }
            FreeVecPooled(fbase.w_MemPool, blk[k]);
        }
        iters++;
    }
    helperStop = 1;
    Wait(SIGBREAKF_CTRL_E);
    expect(rounds > 50, "the receiver ran throughout");
    expect(iters > 50, "and so did the pool user");
    expect_eq(bad, 0, "every block came back as it was written");
    expect_eq(opsHelper, 0, "no w_MemPool call from the receiver in the loop");
    expect_eq(opsMain, iters * 16, "the pool user's calls all counted");
    PutStr("rounds "); num(rounds); PutStr(", pool iterations "); num(iters); PutStr("\n");

    helper_cmd(H_QUIT);
    Wait(SIGBREAKF_CTRL_E);

    Forbid();
    SetFunction((struct Library *)SysBase, LVO_AllocPooled, oldAllocPooled);
    SetFunction((struct Library *)SysBase, LVO_FreePooled, oldFreePooled);
    CacheClearU();
    Permit();

    FreeVec(funit.wu_AssocIE);
    DeletePool(fbase.w_MemPool);
    CloseLibrary(fbase.w_UtilityBase);

    PutStr(failures ? "RESULT FAIL " : "RESULT PASS "); num(checks); PutStr(" checks, "); num(failures); PutStr(" failures\n");
    return failures ? 20 : 0;
}
