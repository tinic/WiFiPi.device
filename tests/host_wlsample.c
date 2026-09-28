/*
 * Host test for the in-leg counter sampler (src/wlsample.h, #89): plain cc,
 * no Amiga headers.  The driver runs exactly these functions under Forbid();
 * here one thread plays the receiver, the callers and the firmware.
 *
 *   cc -std=c11 -O2 -Wall -Wextra -Werror -DWIFIPI_RINGTRACE -o host_wlsample tests/host_wlsample.c
 *   ./host_wlsample        -> "RESULT host_wlsample checks=N failures=0"
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t UBYTE;
typedef uint16_t UWORD;
typedef uint32_t ULONG;
typedef int32_t LONG;

#include "../src/wlsample.h"

static int checks, failures;

#define EXPECT(c) do { checks++; if (!(c)) { failures++; printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); } } while (0)
/* inside a long loop: one check however many turns */
static int quietFailed;
#define EXPECT_QUIET(c) do { if (!(c) && !quietFailed++) { failures++; printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); } } while (0)

static struct RtRing *ring;
static struct WsState *ws;
static UWORD cmdID;                 /* s_CmdID */
static UWORD quar[32];              /* s_CtrlQuarantine */
static ULONG now;                   /* CLO */
static ULONG mark;                  /* ring seq at the last reset of the view */
static UBYTE txSeq, maxSeq = 0x40;  /* s_TXSeq, s_MaxTXSeq */
static int glom;
#define MAXW 8
static struct { UWORD id; ULONG cmd; int live; } waiters[MAXW];   /* sync waiters on s_CtrlWaitList */

static void fresh(UWORD startID)
{
    ULONG log2 = 12, size = sizeof(struct RtRing) + (sizeof(struct RtRec) << log2);
    free(ring);
    free(ws);
    ring = malloc(size);
    rt_init(ring, log2, size);
    ws = calloc(1, sizeof(*ws));
    memset(quar, 0, sizeof(quar));
    cmdID = startID;
    now = 1000000;
    mark = 0;
    txSeq = 0; maxSeq = 0x40; glom = 0;
    memset(waiters, 0, sizeof(waiters));
}

/* records written since the last view(), of kind k (0: any) */
static int count(UBYTE k)
{
    int n = 0;
    for (ULONG s = mark; s < ring->rt_Seq; s++)
        if (k == 0 || ring->rt_Rec[s & ring->rt_Mask].r_Kind == k)
            n++;
    return n;
}

static const struct RtRec *last(UBYTE k)
{
    const struct RtRec *e = NULL;
    for (ULONG s = mark; s < ring->rt_Seq; s++)
        if (ring->rt_Rec[s & ring->rt_Mask].r_Kind == k)
            e = &ring->rt_Rec[s & ring->rt_Mask];
    return e;
}

static void view(void) { mark = ring->rt_Seq; }

/*
 * The driver around wlsample.h, line for line where it decides anything:
 *   other_id()   NextCmdID(): ws_next_id's walk, then ws_realloc under Forbid
 *   credit()     PacketTxCredit() (#99), copied
 *   tick()       WsTick(): ws_tick(ctrlBusy, credit), ws_take_id, ws_build
 *                with s_TXSeq++, ws_sent(frame bytes)
 *   dispatch()   PacketCtrlComplete(): ws_ctrl_slot on the raw BCDC reply,
 *                then the wait list (id and command), then ws_ctrl_late
 * Exec (Forbid, AllocMem, SendPKT, ReplyMsg) is what stays out.
 */
static UBYTE lastFrame[2048];
static ULONG lastFrameLen;

static UBYTE credit(void)
{
    UBYTE d = (UBYTE)(maxSeq - txSeq);
    return (d & 0x80) ? 0 : d;
}

static UWORD other_id(void)
{
    cmdID = ws_next_id(ws, ring, now, cmdID, quar);   /* NextCmdID() under WIFIPI_WLSAMPLE, as is */
    ws_realloc(ws, cmdID);
    return cmdID;
}

/* a sync control: its id from NextCmdID, on the wait list until answered */
static UWORD sync_req(ULONG cmd)
{
    UWORD id = other_id();
    for (int i = 0; i < MAXW; i++)
        if (!waiters[i].live)
        {
            waiters[i].id = id; waiters[i].cmd = cmd; waiters[i].live = 1;
            break;
        }
    return id;
}

static int waiting(void)
{
    for (int i = 0; i < MAXW; i++)
        if (waiters[i].live) return 1;
    return 0;
}

static int tick(int ctrlBusy, UWORD *id)
{
    if (!ws_tick(ws, ring, now, ctrlBusy || waiting(), credit()))
        return 0;
    if (!ws_take_id(ws, ring, now, &cmdID, quar, id))
        return 0;
    lastFrameLen = ws_frame_len(glom);
    memset(lastFrame, 0, sizeof(lastFrame));
    ws_build(lastFrame, glom, txSeq++, *id);
    ws_sent(ws, ring, now, *id, lastFrameLen);
    return 1;
}

/* A v10 answer: every counter its offset * 1000 + 3 */
static UBYTE answer[2048];
static void v10(UWORD version, UWORD length)
{
    memset(answer, 0, sizeof(answer));
    answer[0] = version; answer[1] = version >> 8;
    answer[2] = length; answer[3] = length >> 8;
    for (ULONG o = 4; o + 4 <= WS_V10_LEN; o += 4)
    {
        ULONG v = o * 1000 + 3;
        answer[o] = v; answer[o + 1] = v >> 8; answer[o + 2] = v >> 16; answer[o + 3] = v >> 24;
    }
}

enum { NONE = WS_R_NOTMINE, WAITER = 3 };
#define REPLY_FRAME 900

/* the reply as the firmware sends it: BCDC header, then `copied` bytes of the answer */
static int dispatch(UWORD id, ULONG cmd, int fwError, ULONG status, ULONG copied)
{
    static UBYTE b[16 + 2048];
    memset(b, 0, sizeof(b));
    ws_put32(b, cmd); ws_put32(b + 4, WS_V10_LEN);
    ws_put16(b + 8, fwError ? 1 : 0); ws_put16(b + 10, id); ws_put32(b + 12, status);
    memcpy(b + 16, answer, copied);
    if (ws_ctrl_slot(ws, ring, now, b, copied, REPLY_FRAME) != WS_R_NOTMINE)
        return WS_R_TAKEN;
    for (int i = 0; i < MAXW; i++)
        if (waiters[i].live && waiters[i].id == id && waiters[i].cmd == cmd)
        {
            waiters[i].live = 0;
            return WAITER;
        }
    return ws_ctrl_late(ws, ring, now, b, REPLY_FRAME) == WS_R_LATE ? WS_R_LATE : NONE;
}

static int reply(UWORD id, ULONG cmd, ULONG copied)
{
    return dispatch(id, cmd, 0, 0, copied);
}

int main(void)
{
    UWORD s1, s2, sy;
    const struct RtRec *e;

    /* ---- SECOND-ENABLE: refused, and after a disable too ---------------- */
    fresh(100);
    EXPECT(ws_enable(ws, ring, cmdID, now) == 0);
    EXPECT(last(RT_SAMPLER_ENABLE) && last(RT_SAMPLER_ENABLE)->r_B == 100);
    view();
    EXPECT(ws_enable(ws, ring, cmdID, now) == -1);
    EXPECT(count(RT_SAMPLER_REFUSED) == 1 && count(0) == 1);
    ws_disable(ws, ring, now);
    EXPECT(last(RT_SAMPLER_STOP) && last(RT_SAMPLER_STOP)->r_A == WS_STOP_DISABLED);
    EXPECT(ws_enable(ws, ring, cmdID, now) == -1);
    fresh(100);
    ws_disable(ws, ring, now);                      /* disable before any enable: permanent too */
    EXPECT(ws_enable(ws, ring, cmdID, now) == -1 && ws->ws_State == WS_STOPPED);

    /* ---- cadence, slot_busy, ctrl_busy --------------------------------- */
    fresh(100);
    ws_enable(ws, ring, cmdID, now);
    view();
    EXPECT(tick(0, &s1) && s1 == 101);
    e = last(RT_SAMPLE_REQ);
    EXPECT(e && e->r_B == 101 && e->r_Clo == now && e->r_C == 1);
    now += 10000;
    EXPECT(!tick(0, &s2) && count(RT_SAMPLE_SKIP) == 0);          /* not due yet */
    now += 40000;
    EXPECT(!tick(0, &s2));
    e = last(RT_SAMPLE_SKIP);
    EXPECT(e && e->r_A == WS_SKIP_SLOT_BUSY && e->r_B == 101);    /* one outstanding at most */
    now += 1000;
    EXPECT(!tick(0, &s2) && count(RT_SAMPLE_SKIP) == 1);          /* one SKIP per period */
    v10(10, 848);
    EXPECT(reply(101, WS_GET_VAR, 848) == WS_R_TAKEN);
    now += 50000;
    EXPECT(!tick(1, &s2));
    EXPECT(last(RT_SAMPLE_SKIP)->r_A == WS_SKIP_CTRL_BUSY && cmdID == 101);   /* no id used */
    now += 50000;
    EXPECT(tick(0, &s2) && s2 == 102);

    /* ---- ok reply: REP then ten VALs at the proven offsets --------------- */
    fresh(200);
    ws_enable(ws, ring, cmdID, now);
    EXPECT(tick(0, &s1));
    ULONG req = now;
    now += 3456;
    view();
    v10(10, 848);
    EXPECT(reply(s1, WS_GET_VAR, 848) == WS_R_TAKEN);
    e = last(RT_SAMPLE_REP);
    EXPECT(e && e->r_A == (WS_REP_OK | (10 << 2)) && e->r_B == s1 && e->r_C == now - req
           && e->r_D == ((REPLY_FRAME << 16) | 848));
    EXPECT(count(RT_SAMPLE_VAL) == WS_NFIELDS && count(0) == WS_NFIELDS + 1);
    {
        /* tools/wlcnt.py V10 offsets, in VAL index order (tests/test_wlsample.py checks the names) */
        static const ULONG want[22] = { 184, 344, 64, 280, 276, 4, 12, 456, 80, 244,
                                        284, 348, 352, 288, 292, 308, 196, 208, 356, 448, 452, 672 };
        int i = 0, ok = 1;
        for (ULONG s = mark; s < ring->rt_Seq; s++)
        {
            const struct RtRec *v = &ring->rt_Rec[s & ring->rt_Mask];
            if (v->r_Kind != RT_SAMPLE_VAL) continue;
            if (v->r_A != i || v->r_C != want[i] * 1000 + 3 || v->r_B != s1) ok = 0;
            i++;
        }
        EXPECT(ok && i == WS_NFIELDS);
    }
    EXPECT(!ws->ws_SlotLive);

    /* ---- bad layout: wrong version, wrong length, short copy: no values -- */
    fresh(300);
    ws_enable(ws, ring, cmdID, now);
    {
        static const struct { UWORD ver, len; ULONG copied; } bad[3] = {
            { 9, 848, 848 }, { 10, 844, 848 }, { 10, 848, 700 } };
        for (int i = 0; i < 3; i++)
        {
            EXPECT(tick(0, &s1));
            view();
            v10(bad[i].ver, bad[i].len);
            EXPECT(reply(s1, WS_GET_VAR, bad[i].copied) == WS_R_TAKEN);
            EXPECT((last(RT_SAMPLE_REP)->r_A & 3) == WS_REP_BAD_LAYOUT && count(RT_SAMPLE_VAL) == 0);
            EXPECT(last(RT_SAMPLE_REP)->r_A >> 2 == (bad[i].copied >= 2 ? bad[i].ver : 0));
            now += 50000;
        }
        EXPECT(tick(0, &s1));
        view();
        EXPECT(dispatch(s1, WS_GET_VAR, 1, 0xffffffe9u, 0) == WS_R_TAKEN);
        EXPECT(last(RT_SAMPLE_REP)->r_A == WS_REP_FW_ERROR
               && last(RT_SAMPLE_REP)->r_D == ((REPLY_FRAME << 16) | 0xffe9u) && count(RT_SAMPLE_VAL) == 0);
    }

    /* ---- SYNC-DURING-SAMPLE: each reply goes to its owner --------------- */
    fresh(400);
    ws_enable(ws, ring, cmdID, now);
    EXPECT(tick(0, &s1));
    sy = sync_req(WS_GET_VAR);                      /* a sync GET_VAR queued behind it */
    EXPECT(sy == s1 + 1);
    view();
    v10(10, 848);
    EXPECT(reply(sy, WS_GET_VAR, 848) == WAITER);          /* the waiter's */
    EXPECT(count(0) == 0 && ws->ws_SlotLive);
    EXPECT(reply(s1, WS_GET_VAR, 848) == WS_R_TAKEN);      /* the sampler's */
    EXPECT(count(RT_SAMPLE_VAL) == WS_NFIELDS);
    /* the slot's id with another command is not the slot's */
    now += 50000;
    EXPECT(tick(0, &s2));
    EXPECT(reply(s2, 263, 848) == NONE && ws->ws_SlotLive);
    /* a stale sync reply for an id the sampler never issued is never a late sample */
    view();
    EXPECT(reply(sy, WS_GET_VAR, 848) == NONE && count(0) == 0);

    /* ---- LATE-AFTER-TMO: values dropped, latency kept ------------------- */
    fresh(500);
    ws_enable(ws, ring, cmdID, now);
    EXPECT(tick(0, &s1));
    req = now;
    now += 499999;
    EXPECT(!tick(0, &s2) && ws->ws_SlotLive);                     /* 1 us short of the deadline */
    now += 1;
    view();
    EXPECT(!tick(0, &s2));                                        /* LOST; the slot is free */
    e = last(RT_SAMPLE_LOST);
    EXPECT(e && e->r_B == s1 && e->r_C == req && e->r_Clo == now && !ws->ws_SlotLive);
    now += 50000;
    EXPECT(tick(0, &s2));
    EXPECT(ws->ws_SlotLive && ws->ws_SlotId == s1 + 1);           /* a new sample took the slot */
    now += 20000;
    view();
    v10(10, 848);
    EXPECT(reply(s1, WS_GET_VAR, 848) == WS_R_LATE);
    e = last(RT_SAMPLE_LATE);
    EXPECT(e && e->r_A == 1 && e->r_B == s1 && e->r_C == now - req);
    EXPECT(count(RT_SAMPLE_VAL) == 0 && count(RT_SAMPLE_REP) == 0);
    EXPECT(ws->ws_SlotLive && ws->ws_SlotId == s1 + 1);           /* the live slot untouched */

    /* ---- LATE-AFTER-SYNC: a sync completes, then the lost sample's reply - */
    fresh(600);
    ws_enable(ws, ring, cmdID, now);
    EXPECT(tick(0, &s1));
    req = now;
    now += 500000;
    tick(1, &s2);                                   /* LOST; a sync is waiting, so no new sample */
    EXPECT(!ws->ws_SlotLive && last(RT_SAMPLE_LOST) && last(RT_SAMPLE_SKIP)->r_A == WS_SKIP_CTRL_BUSY);
    sy = sync_req(WS_GET_VAR);
    view();
    EXPECT(reply(sy, WS_GET_VAR, 848) == WAITER);          /* the sync gets its own */
    now += 1000;
    EXPECT(reply(s1, WS_GET_VAR, 848) == WS_R_LATE);
    EXPECT(last(RT_SAMPLE_LATE)->r_C == now - req && count(RT_SAMPLE_VAL) == 0);
    /* a second copy of an old sample's reply, after its tombstone was lapped */
    for (int i = 0; i < WS_TOMBS; i++)
    {
        now += 50000;
        EXPECT(tick(0, &s2));
        now += 500000;
        tick(1, &s2);
    }
    view();
    EXPECT(reply(s1, WS_GET_VAR, 848) == WS_R_LATE);
    EXPECT(last(RT_SAMPLE_LATE)->r_A == 0 && last(RT_SAMPLE_LATE)->r_C == 0xffffffffu);

    /* ---- ID-CAP: forced to E+59998; E+59999 is taken, E+60000 never ----- */
    fresh(1000);
    ws_enable(ws, ring, cmdID, now);                /* E = 1000 */
    cmdID = (UWORD)(1000 + 59998);                  /* other callers used 59998 ids */
    EXPECT(tick(0, &s1) && s1 == (UWORD)(1000 + 59999));
    reply(s1, WS_GET_VAR, 848);
    now += 50000;
    view();
    EXPECT(!tick(0, &s2));
    e = last(RT_SAMPLER_STOP);
    EXPECT(e && e->r_A == WS_STOP_IDCAP && e->r_B == (UWORD)(1000 + 60000) && e->r_C == 1000 && e->r_D == 60000);
    EXPECT(cmdID == (UWORD)(1000 + 59999));         /* the capped id was never allocated */
    EXPECT(ws->ws_State == WS_STOPPED && count(RT_SAMPLE_REQ) == 0);
    now += 50000;
    view();
    EXPECT(!tick(0, &s2) && count(RT_SAMPLE_SKIP) == 1 && last(RT_SAMPLE_SKIP)->r_A == WS_SKIP_STOPPED);
    now += 50000;
    view();
    EXPECT(!tick(0, &s2) && count(0) == 0);         /* 'stopped' said once */
    EXPECT(ws_enable(ws, ring, cmdID, now) == -1);  /* and no way back */
    /* the cap counts across the u16 wrap, and quarantined ids are skipped as NextCmdID skips them */
    fresh(65000);
    ws_enable(ws, ring, cmdID, now);
    quar[0] = 65001;
    EXPECT(tick(0, &s1) && s1 == 65002);
    reply(s1, WS_GET_VAR, 848);
    cmdID = 65535;
    now += 50000;
    EXPECT(tick(0, &s1) && s1 == 1);                /* 0 is never an id */
    /* other callers wrapped the counter past E between two samples */
    fresh(10);
    ws_enable(ws, ring, cmdID, now);
    EXPECT(tick(0, &s1));
    reply(s1, WS_GET_VAR, 848);
    cmdID = 20000;
    now += 50000;
    EXPECT(tick(0, &s1));
    reply(s1, WS_GET_VAR, 848);
    cmdID = 20;                                     /* others went all the way round: distance went backwards */
    now += 50000;
    view();
    EXPECT(!tick(0, &s1) && last(RT_SAMPLER_STOP) && last(RT_SAMPLER_STOP)->r_A == WS_STOP_WRAP && cmdID == 20);

    /* ---- STALE-REPLY-AFTER-DISABLE: dropped ----------------------------- */
    fresh(700);
    ws_enable(ws, ring, cmdID, now);
    EXPECT(tick(0, &s1));
    req = now;
    ws_disable(ws, ring, now);
    EXPECT(!ws->ws_SlotLive);
    now += 2000;
    view();
    EXPECT(reply(s1, WS_GET_VAR, 848) == WS_R_LATE);
    EXPECT(count(RT_SAMPLE_VAL) == 0 && last(RT_SAMPLE_LATE)->r_C == 2000);
    now += 50000;
    EXPECT(!tick(0, &s2));
    /* disabled while a request was being built: it goes out, its reply is late */
    fresh(800);
    ws_enable(ws, ring, cmdID, now);
    EXPECT(ws_tick(ws, ring, now, 0, credit()) && ws_take_id(ws, ring, now, &cmdID, quar, &s1));
    ws_disable(ws, ring, now);
    ws_sent(ws, ring, now, s1, ws_frame_len(0));
    EXPECT(!ws->ws_SlotLive);
    view();
    EXPECT(reply(s1, WS_GET_VAR, 848) == WS_R_LATE && count(RT_SAMPLE_VAL) == 0);

    /* ---- the frame: as PacketSetVarAsync lays one out, REQ carries its bytes */
    for (int g = 0; g <= 1; g++)
    {
        fresh(0x1233);
        glom = g;
        ws_enable(ws, ring, cmdID, now);
        txSeq = 0x5a; maxSeq = 0x7a;
        view();
        EXPECT(tick(0, &s1) && s1 == 0x1234 && txSeq == 0x5b);
        ULONG tot = glom ? 884 : 876, h = glom ? 12 : 4;
        UBYTE *c = lastFrame + h + 8;
        EXPECT(lastFrameLen == tot && last(RT_SAMPLE_REQ)->r_D == tot);
        EXPECT(lastFrame[0] == (tot & 0xff) && lastFrame[1] == tot >> 8
               && lastFrame[2] == (UBYTE)~tot && lastFrame[3] == (UBYTE)(~tot >> 8));
        if (glom)
            EXPECT(lastFrame[4] == ((tot - 4) & 0xff) && lastFrame[5] == (tot - 4) >> 8 && lastFrame[6] == 0
                   && lastFrame[7] == 1 && lastFrame[8] == 0 && lastFrame[9] == 0
                   && lastFrame[10] == ((0u - tot) & 3) && lastFrame[11] == 0);
        EXPECT(lastFrame[h] == 0x5a && lastFrame[h + 1] == 0 && lastFrame[h + 2] == 0
               && lastFrame[h + 3] == (glom ? 20 : 12) && lastFrame[h + 4] == 0 && lastFrame[h + 5] == 0);
        EXPECT(ws_le32(c) == 262 && ws_le32(c + 4) == 848 && ws_le16(c + 8) == 0 && ws_le16(c + 10) == 0x1234
               && ws_le32(c + 12) == 0 && memcmp(c + 16, "counters", 9) == 0);
        int zero = 1;
        for (ULONG i = h + 8 + 16 + 9; i < sizeof(lastFrame); i++)
            if (lastFrame[i]) zero = 0;
        EXPECT(zero);
    }
    glom = 0;

    /* ---- NO-CREDIT: skip, no id, no REQ, no slot; recovery on cadence, no burst */
    fresh(2000);
    ws_enable(ws, ring, cmdID, now);
    maxSeq = txSeq;                                 /* window closed */
    view();
    EXPECT(!tick(0, &s1));
    e = last(RT_SAMPLE_SKIP);
    EXPECT(e && e->r_A == WS_SKIP_NO_CREDIT && e->r_Clo == now);
    EXPECT(cmdID == 2000 && count(RT_SAMPLE_REQ) == 0 && !ws->ws_SlotLive && ws->ws_Samples == 0);
    ULONG t0 = now;
    for (int i = 1; i <= 5; i++)                    /* five more periods closed, ticks every 10 ms */
        for (int k = 0; k < 5; k++)
        {
            now += 10000;
            tick(0, &s1);
        }
    EXPECT(count(RT_SAMPLE_SKIP) == 6 && count(RT_SAMPLE_REQ) == 0 && cmdID == 2000);
    maxSeq = txSeq + 0x20;                          /* credit back mid-period */
    now += 5000;
    EXPECT(!tick(0, &s1) && count(RT_SAMPLE_REQ) == 0);           /* waits for its boundary */
    now = t0 + 6 * 50000;
    EXPECT(tick(0, &s1) && s1 == 2001 && count(RT_SAMPLE_REQ) == 1);
    reply(s1, WS_GET_VAR, 848);
    for (int k = 0; k < 4; k++)                     /* no catch-up: nothing before the next boundary */
    {
        now += 10000;
        EXPECT(!tick(0, &s2));
    }
    EXPECT(count(RT_SAMPLE_REQ) == 1);
    now += 10000;
    EXPECT(tick(0, &s2) && s2 == 2002 && count(RT_SAMPLE_REQ) == 2);
    reply(s2, WS_GET_VAR, 848);
    /* a window that points behind the next number is closed too */
    maxSeq = txSeq - 1;
    now += 50000;
    view();
    EXPECT(!tick(0, &s2) && last(RT_SAMPLE_SKIP)->r_A == WS_SKIP_NO_CREDIT && cmdID == 2002);
    /* the sample's own frame takes the last credit; the next finds none */
    maxSeq = txSeq + 1;
    now += 50000;
    EXPECT(tick(0, &s2) && credit() == 0);
    reply(s2, WS_GET_VAR, 848);
    now += 50000;
    view();
    EXPECT(!tick(0, &s2) && last(RT_SAMPLE_SKIP)->r_A == WS_SKIP_NO_CREDIT);

    /* ---- low credit with a sync control: the sync goes first, replies to owners */
    fresh(3000);
    ws_enable(ws, ring, cmdID, now);
    maxSeq = txSeq + 1;
    sy = sync_req(WS_GET_VAR);                      /* 3001, waiting */
    view();
    EXPECT(!tick(0, &s1) && last(RT_SAMPLE_SKIP)->r_A == WS_SKIP_CTRL_BUSY && cmdID == 3001);
    EXPECT(reply(sy, WS_GET_VAR, 848) == WAITER);
    now += 50000;
    EXPECT(tick(0, &s1) && s1 == 3002 && credit() == 0);
    sy = sync_req(WS_GET_VAR);                      /* 3003, while the sample is out */
    view();
    EXPECT(reply(sy, WS_GET_VAR, 848) == WAITER && count(0) == 0 && ws->ws_SlotLive);
    EXPECT(reply(s1, WS_GET_VAR, 848) == WS_R_TAKEN && count(RT_SAMPLE_VAL) == WS_NFIELDS);
    now += 50000;
    view();
    EXPECT(!tick(0, &s1) && last(RT_SAMPLE_SKIP)->r_A == WS_SKIP_NO_CREDIT && cmdID == 3003);

    /* ---- ID-CAP exact with skips in between: a skip takes no id ---------- */
    fresh(4000);
    ws_enable(ws, ring, cmdID, now);
    cmdID = (UWORD)(4000 + 59998);
    maxSeq = txSeq;
    for (int k = 0; k < 3; k++) { now += 50000; tick(0, &s1); }   /* no_credit */
    sy = sync_req(WS_GET_VAR);                      /* E+59999 goes to a sync caller */
    now += 50000;
    view();
    EXPECT(!tick(0, &s1) && last(RT_SAMPLE_SKIP)->r_A == WS_SKIP_CTRL_BUSY);
    EXPECT(sy == (UWORD)(4000 + 59999) && cmdID == sy);
    reply(sy, WS_GET_VAR, 848);
    maxSeq = txSeq + 8;
    now += 50000;
    view();
    EXPECT(!tick(0, &s1));                          /* E+60000 would be next: stop, not taken */
    e = last(RT_SAMPLER_STOP);
    EXPECT(e && e->r_A == WS_STOP_IDCAP && e->r_B == (UWORD)(4000 + 60000) && e->r_D == 60000);
    EXPECT(cmdID == (UWORD)(4000 + 59999) && count(RT_SAMPLE_REQ) == 0);

    /* ---- LOST, then full laps: the lost id is skipped; the answered one is
       handed out again; s_CtrlQuarantine untouched; ws_Lost survives
       disable and refused re-enables ------------------------------------ */
    {
        UWORD qsnap[32];
        fresh(5000);
        quar[0] = 5100; quar[1] = 12345; quar[31] = 60000;
        memcpy(qsnap, quar, sizeof(qsnap));
        ws_enable(ws, ring, cmdID, now);
        EXPECT(tick(0, &s1));                       /* 5001, answered */
        reply(s1, WS_GET_VAR, 848);
        now += 50000;
        EXPECT(tick(0, &s2));                       /* 5002, never answered */
        req = now;
        now += 500000;
        tick(1, &sy);                               /* LOST; a sync waits, so no new sample */
        EXPECT(ws_lost(ws, s2) && !ws_lost(ws, s1) && !ws->ws_SlotLive);
        ws_disable(ws, ring, now);
        EXPECT(ws_enable(ws, ring, cmdID, now) == -1 && ws_enable(ws, ring, cmdID, now) == -1);
        EXPECT(ws_lost(ws, s2));                    /* survives disable and refused enables */
        int seen2 = 0, seen1 = 0;
        for (ULONG n = 0; n < 2 * 65536; n++)       /* two full laps of sync allocations */
        {
            UWORD id = other_id();
            if (id == s2) seen2++;
            if (id == s1) seen1++;
            if (id == 0 || id == 5100 || id == 12345 || id == 60000) seen2 += 1000;   /* base rules still hold */
        }
        EXPECT(seen2 == 0 && seen1 == 2);
        EXPECT(ws_lost(ws, s2) && !ws->ws_LostOff && memcmp(quar, qsnap, sizeof(qsnap)) == 0);
        /* the answered id went to a sync caller: its reply is the waiter's */
        while (cmdID != (UWORD)(s1 - 1))
            other_id();
        sy = sync_req(WS_GET_VAR);
        view();
        EXPECT(sy == s1 && !ws_issued(ws, s1));
        EXPECT(reply(sy, WS_GET_VAR, 848) == WAITER && count(0) == 0);

        /* ---- the lost id's late reply, before it is ever reused: LATE, no
           values, not a waiter's; it clears the bit and the id is reusable */
        while (cmdID != (UWORD)(s2 - 1))
            other_id();
        sy = sync_req(WS_GET_VAR);                  /* skips s2: a waiter with the same command */
        EXPECT(sy == (UWORD)(s2 + 1));
        now += 30000;
        view();
        EXPECT(reply(s2, 263, 848) == NONE && ws_lost(ws, s2));        /* wrong command: bit stays */
        EXPECT(reply(s2, WS_GET_VAR, 848) == WS_R_LATE && count(RT_SAMPLE_VAL) == 0);
        EXPECT(last(RT_SAMPLE_LATE)->r_A == 1 && last(RT_SAMPLE_LATE)->r_C == now - req);
        EXPECT(!ws_lost(ws, s2) && waiters[0].live);                   /* the waiter still waits */
        reply(sy, WS_GET_VAR, 848);
        while (cmdID != (UWORD)(s2 - 1))
            other_id();
        EXPECT(other_id() == s2);                   /* reusable after its one reply */
        EXPECT(memcmp(quar, qsnap, sizeof(qsnap)) == 0);
    }

    /* ---- outstanding at DISABLE: set in ws_Lost; its late reply is never a
       waiter's, even with a same-command waiter queued behind it ---------- */
    fresh(6000);
    ws_enable(ws, ring, cmdID, now);
    EXPECT(tick(0, &s1));
    ws_disable(ws, ring, now);
    EXPECT(ws_lost(ws, s1) && !ws->ws_SlotLive);
    sy = sync_req(WS_GET_VAR);
    EXPECT(sy == s1 + 1);
    for (ULONG n = 0; n < 65536; n++)
        EXPECT_QUIET(other_id() != s1);
    view();
    EXPECT(reply(s1, WS_GET_VAR, 848) == WS_R_LATE && count(RT_SAMPLE_VAL) == 0 && waiters[0].live);
    EXPECT(!ws_lost(ws, s1));

    /* ---- STOP by idcap: the slot is free then (ws_tick hands out a sample
       only with the slot free), and the ids lost before it stay set; the
       stop path retires a live slot if one were there -------------------- */
    fresh(7000);
    ws_enable(ws, ring, cmdID, now);
    EXPECT(tick(0, &s1));
    now += 500000;
    tick(1, &s2);                                   /* s1 LOST */
    cmdID = (UWORD)(7000 + 59999);
    now += 50000;
    EXPECT(!tick(0, &s2) && last(RT_SAMPLER_STOP)->r_A == WS_STOP_IDCAP);
    EXPECT(ws_lost(ws, s1) && ws->ws_State == WS_STOPPED);
    for (ULONG n = 0; n < 65536; n++)
        EXPECT_QUIET(other_id() != s1);
    view();
    EXPECT(reply(s1, WS_GET_VAR, 848) == WS_R_LATE && !ws_lost(ws, s1));
    fresh(7500);                                    /* a live slot at an idcap stop, forced */
    ws_enable(ws, ring, cmdID, now);
    EXPECT(tick(0, &s1));
    cmdID = (UWORD)(7500 + 59999);
    EXPECT(!ws_take_id(ws, ring, now, &cmdID, quar, &s2));
    EXPECT(last(RT_SAMPLER_STOP)->r_A == WS_STOP_IDCAP && ws_lost(ws, s1) && !ws->ws_SlotLive);

    /* ---- worst case under the cap: 60000 ids set in a row, the base
       quarantine right behind them; the walk ends, the guard does not fire */
    fresh(100);
    ws_enable(ws, ring, cmdID, now);
    for (ULONG k = 1; k <= 60000; k++)
        ws->ws_Lost[(UWORD)(100 + k) >> 3] |= (UBYTE)(1 << ((UWORD)(100 + k) & 7));
    for (int q = 0; q < 32; q++)
        quar[q] = (UWORD)(100 + 60001 + q);
    view();
    EXPECT(other_id() == (UWORD)(100 + 60033));
    EXPECT(!ws->ws_LostOff && ws->ws_State == WS_LIVE && count(RT_SAMPLER_STOP) == 0);

    /* ---- every id blocked: the guard stops the sampler (id_space) and the
       walk becomes the base one; no ws_Lost bit is cleared on allocation -- */
    fresh(200);
    ws_enable(ws, ring, cmdID, now);
    memset(ws->ws_Lost, 0xff, sizeof(ws->ws_Lost));
    view();
    EXPECT(other_id() == 201);
    e = last(RT_SAMPLER_STOP);
    EXPECT(e && e->r_A == WS_STOP_ID_SPACE && e->r_D == 65536 && ws->ws_LostOff && ws->ws_State == WS_STOPPED);
    EXPECT(other_id() == 202 && ws_lost(ws, 201) && ws_lost(ws, 202));
    EXPECT(count(RT_SAMPLER_STOP) == 1);           /* once */
    {
        int all = 1;
        for (ULONG k = 0; k < sizeof(ws->ws_Lost); k++)
            if (ws->ws_Lost[k] != 0xff) all = 0;
        EXPECT(all);
    }

    /* ---- never enabled: every reply is the waiters' --------------------- */
    fresh(900);
    EXPECT(reply(901, WS_GET_VAR, 848) == NONE && count(0) == 0);
    EXPECT(!tick(0, &s1) && count(0) == 0);

    EXPECT(sizeof(struct RtRec) == 16);
#ifdef WIFIPI_WLSAMPLE_WIDE
    EXPECT(WS_NFIELDS == 22);
    printf("RESULT host_wlsample_wide checks=%d failures=%d\n", checks, failures);
#else
    EXPECT(WS_NFIELDS == 10);
    printf("RESULT host_wlsample checks=%d failures=%d\n", checks, failures);
#endif
    return failures != 0;
}
