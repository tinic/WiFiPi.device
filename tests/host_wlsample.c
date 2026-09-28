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

static struct RtRing *ring;
static struct WsState *ws;
static UWORD cmdID;                 /* s_CmdID */
static UWORD quar[32];              /* s_CtrlQuarantine */
static ULONG now;                   /* CLO */
static ULONG mark;                  /* ring seq at the last reset of the view */

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

/* NextCmdID() for another caller (a sync or async control) */
static UWORD other_id(void)
{
    cmdID = ws_next_id(cmdID, quar);
    return cmdID;
}

/* The receiver tick: 1 and the id if a sample went out */
static int tick(int ctrlBusy, UWORD *id)
{
    if (!ws_tick(ws, ring, now, ctrlBusy))
        return 0;
    if (!ws_take_id(ws, ring, now, &cmdID, quar, id))
        return 0;
    ws_sent(ws, ring, now, *id);
    return 1;
}

/* A v10 answer: every counter its offset, tbtt 7 */
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

static int reply(UWORD id, ULONG cmd, ULONG copied)
{
    return ws_reply(ws, ring, now, id, cmd, 0, 0, answer, copied);
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
    EXPECT(e && e->r_A == WS_REP_OK && e->r_B == s1 && e->r_C == now - req && e->r_D == ((10u << 16) | 848));
    EXPECT(count(RT_SAMPLE_VAL) == 10 && count(0) == 11);
    {
        static const ULONG want[10] = { 184, 344, 64, 280, 276, 4, 12, 456, 80, 244 };
        int i = 0, ok = 1;
        for (ULONG s = mark; s < ring->rt_Seq; s++)
        {
            const struct RtRec *v = &ring->rt_Rec[s & ring->rt_Mask];
            if (v->r_Kind != RT_SAMPLE_VAL) continue;
            if (v->r_A != i || v->r_C != want[i] * 1000 + 3 || v->r_B != s1) ok = 0;
            i++;
        }
        EXPECT(ok && i == 10);
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
            EXPECT(last(RT_SAMPLE_REP)->r_A == WS_REP_BAD_LAYOUT && count(RT_SAMPLE_VAL) == 0);
            now += 50000;
        }
        EXPECT(tick(0, &s1));
        view();
        EXPECT(ws_reply(ws, ring, now, s1, WS_GET_VAR, 1, 0xffffffe9u, answer, 0) == WS_R_TAKEN);
        EXPECT(last(RT_SAMPLE_REP)->r_A == WS_REP_FW_ERROR && last(RT_SAMPLE_REP)->r_D == 0xffffffe9u
               && count(RT_SAMPLE_VAL) == 0);
    }

    /* ---- SYNC-DURING-SAMPLE: each reply goes to its owner --------------- */
    fresh(400);
    ws_enable(ws, ring, cmdID, now);
    EXPECT(tick(0, &s1));
    sy = other_id();                                /* a sync GET_VAR queued behind it */
    EXPECT(sy == s1 + 1);
    view();
    v10(10, 848);
    EXPECT(reply(sy, WS_GET_VAR, 848) == WS_R_NOTMINE);    /* the waiter's */
    EXPECT(count(0) == 0 && ws->ws_SlotLive);
    EXPECT(reply(s1, WS_GET_VAR, 848) == WS_R_TAKEN);      /* the sampler's */
    EXPECT(count(RT_SAMPLE_VAL) == 10);
    /* the slot's id with another command is not the slot's */
    now += 50000;
    EXPECT(tick(0, &s2));
    EXPECT(reply(s2, 263, 848) == WS_R_NOTMINE && ws->ws_SlotLive);
    /* a stale sync reply for an id the sampler never issued stays the waiters' */
    EXPECT(reply(sy, WS_GET_VAR, 848) == WS_R_NOTMINE);

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
    sy = other_id();
    view();
    EXPECT(reply(sy, WS_GET_VAR, 848) == WS_R_NOTMINE);    /* the sync gets its own */
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
    EXPECT(ws_tick(ws, ring, now, 0) && ws_take_id(ws, ring, now, &cmdID, quar, &s1));
    ws_disable(ws, ring, now);
    ws_sent(ws, ring, now, s1);
    EXPECT(!ws->ws_SlotLive);
    view();
    EXPECT(reply(s1, WS_GET_VAR, 848) == WS_R_LATE && count(RT_SAMPLE_VAL) == 0);

    /* ---- never enabled: every reply is the waiters' --------------------- */
    fresh(900);
    EXPECT(reply(901, WS_GET_VAR, 848) == WS_R_NOTMINE && count(0) == 0);
    EXPECT(!tick(0, &s1) && count(0) == 0);

    EXPECT(sizeof(struct RtRec) == 16);
    printf("RESULT host_wlsample checks=%d failures=%d\n", checks, failures);
    return failures != 0;
}
