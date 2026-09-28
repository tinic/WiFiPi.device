/*
 * Debug-only in-leg firmware counter sampler (AmiNetXDuo #89).  Compiled in
 * only with -DWIFIPI_WLSAMPLE, which needs -DWIFIPI_RINGTRACE: everything it
 * learns goes into the event ring.
 *
 * Enabled once per driver instance by private command 0xF08B; 0xF08C
 * disables it for good.  Every 50 ms, on the receiver's timer tick, one GET
 * 'counters' of exactly 848 bytes (wl_cnt v10) goes out fire-and-forget; one
 * slot, so at most one is outstanding.  Its reply is taken in
 * PacketCtrlComplete() before the synchronous waiters are looked at, only on
 * id AND command AND a live slot; ten fields of it go into the ring.  A slot
 * not answered in 500 ms is LOST and its id tombstoned; a reply to any id
 * the sampler ever issued that is not the live slot is LATE and never read.
 *
 * Ids: E is the command id counter (s_CmdID, the last id handed out) at
 * enable.  Before each sample id is taken, the id NextCmdID() would hand out
 * next is computed; if (id - E) mod 2^16 >= WS_ID_CAP -- the count includes
 * every caller's ids -- or the distance went backwards (a wrap by others),
 * the sampler stops for good and that id is never taken.  Below the cap an
 * id is issued at most once, so ws_Issued names sample ids exactly.
 *
 * The pure part below makes no Exec calls: the driver calls it under
 * Forbid(), a host test links it as is.  Types come from the includer.
 */
#ifndef WIFIPI_WLSAMPLE_H
#define WIFIPI_WLSAMPLE_H

#ifndef WIFIPI_RINGTRACE
#error "WIFIPI_WLSAMPLE needs WIFIPI_RINGTRACE"
#endif

#include "ringtrace.h"

#define WIFIPI_CMD_WLSAMPLE_ENABLE  0xF08B
#define WIFIPI_CMD_WLSAMPLE_DISABLE 0xF08C

#define WS_PERIOD_US    50000UL
#define WS_DEADLINE_US  500000UL
#define WS_ID_CAP       60000UL
#define WS_TOMBS        16
#define WS_GET_VAR      262             /* BRCMF_C_GET_VAR */
#define WS_NFIELDS      10

/* wl_cnt v10 (tools/wlcnt.py V10_FIELDS: WHD wl_cnt_ver_ten_t) */
#define WS_V10_VERSION  10
#define WS_V10_LEN      848
#define WS_OFF_TBTT         184
#define WS_OFF_RXBEACONMBSS 344
#define WS_OFF_RXFRAME      64
#define WS_OFF_RXCRSGLITCH  280
#define WS_OFF_RXBADPLCP    276
#define WS_OFF_TXFRAME      4
#define WS_OFF_TXRETRANS    12
#define WS_OFF_TXNOACK      456
#define WS_OFF_RXNOBUF      80
#define WS_OFF_RXTOOLATE    244

_Static_assert(WS_V10_LEN == 848, "wl_cnt v10 is 848 bytes");
_Static_assert(WS_OFF_TBTT % 4 == 0 && WS_OFF_TBTT + 4 <= WS_V10_LEN, "tbtt inside v10");
_Static_assert(WS_OFF_RXBEACONMBSS % 4 == 0 && WS_OFF_RXBEACONMBSS + 4 <= WS_V10_LEN, "rxbeaconmbss inside v10");
_Static_assert(WS_OFF_RXFRAME % 4 == 0 && WS_OFF_RXFRAME + 4 <= WS_V10_LEN, "rxframe inside v10");
_Static_assert(WS_OFF_RXCRSGLITCH % 4 == 0 && WS_OFF_RXCRSGLITCH + 4 <= WS_V10_LEN, "rxcrsglitch inside v10");
_Static_assert(WS_OFF_RXBADPLCP % 4 == 0 && WS_OFF_RXBADPLCP + 4 <= WS_V10_LEN, "rxbadplcp inside v10");
_Static_assert(WS_OFF_TXFRAME % 4 == 0 && WS_OFF_TXFRAME + 4 <= WS_V10_LEN, "txframe inside v10");
_Static_assert(WS_OFF_TXRETRANS % 4 == 0 && WS_OFF_TXRETRANS + 4 <= WS_V10_LEN, "txretrans inside v10");
_Static_assert(WS_OFF_TXNOACK % 4 == 0 && WS_OFF_TXNOACK + 4 <= WS_V10_LEN, "txnoack inside v10");
_Static_assert(WS_OFF_RXNOBUF % 4 == 0 && WS_OFF_RXNOBUF + 4 <= WS_V10_LEN, "rxnobuf inside v10");
_Static_assert(WS_OFF_RXTOOLATE % 4 == 0 && WS_OFF_RXTOOLATE + 4 <= WS_V10_LEN, "rxtoolate inside v10");

/* Ring records (struct RtRec: clo, kind, a, b, c, d) */
enum {
    RT_SAMPLE_REQ     = 20, /* clo REQ; a 0, b id, c sample number, d 0 */
    RT_SAMPLE_REP     = 21, /* clo REP; a status, b id, c latency us (REP - REQ),
                               d version<<16 | length as read (0 on fw_error: d = firmware status) */
    RT_SAMPLE_VAL     = 22, /* clo REP; a field index, b id, c value, d 0 (after an ok REP only) */
    RT_SAMPLE_SKIP    = 23, /* clo; a reason, b live slot id or 0, c 0, d 0 */
    RT_SAMPLE_LOST    = 24, /* clo; a 0, b id, c original REQ clo, d 0 */
    RT_SAMPLE_LATE    = 25, /* clo REP; a 1 latency known / 0 unknown, b id,
                               c latency us or 0xffffffff, d firmware status */
    RT_SAMPLER_STOP   = 26, /* clo; a reason, b id that was not taken (0: none), c E, d distance */
    RT_SAMPLER_REFUSED = 27, /* clo; a reason (1 used before), b state, c E, d 0 */
    RT_SAMPLER_ENABLE = 28  /* clo; a 0, b E, c 0, d 0 */
};

enum { WS_REP_OK = 0, WS_REP_BAD_LAYOUT = 1, WS_REP_FW_ERROR = 2 };
enum { WS_SKIP_SLOT_BUSY = 1, WS_SKIP_CTRL_BUSY = 2, WS_SKIP_NOMEM = 3, WS_SKIP_STOPPED = 4 };
enum { WS_STOP_IDCAP = 1, WS_STOP_DISABLED = 2, WS_STOP_WRAP = 3 };
enum { WS_IDLE = 0, WS_LIVE = 1, WS_STOPPED = 2 };
enum { WS_R_NOTMINE = 0, WS_R_TAKEN = 1, WS_R_LATE = 2 };

struct WsState {
    UBYTE   ws_State;       /* WS_IDLE never enabled, WS_LIVE, WS_STOPPED for good */
    UBYTE   ws_SlotLive;
    UBYTE   ws_StopSkipLogged;
    UBYTE   ws_TombNext;
    UWORD   ws_E;
    UWORD   ws_SlotId;
    ULONG   ws_LastDist;
    ULONG   ws_SlotReqClo;
    ULONG   ws_NextDue;     /* CLO the next sample is due at */
    ULONG   ws_Samples;
    UWORD   ws_TombId[WS_TOMBS];
    ULONG   ws_TombClo[WS_TOMBS];
    UBYTE   ws_TombUsed[WS_TOMBS];
    UBYTE   ws_Issued[65536 / 8];   /* ids ever sent as samples */
};

static inline void ws_log(struct RtRing *r, ULONG clo, UBYTE k, UBYTE a, UWORD b, ULONG c, ULONG d)
{
    if (r != NULL)
        rt_put(r, clo, k, a, b, c, d);
}

static inline ULONG ws_le32(const UBYTE *p)
{
    return (ULONG)p[0] | ((ULONG)p[1] << 8) | ((ULONG)p[2] << 16) | ((ULONG)p[3] << 24);
}

static inline int ws_issued(const struct WsState *w, UWORD id)
{
    return (w->ws_Issued[id >> 3] >> (id & 7)) & 1;
}

/* One-shot: 0 enabled, -1 refused (used before, or disabled) */
static inline int ws_enable(struct WsState *w, struct RtRing *r, UWORD cmdID, ULONG clo)
{
    if (w->ws_State != WS_IDLE)
    {
        ws_log(r, clo, RT_SAMPLER_REFUSED, 1, w->ws_State, w->ws_E, 0);
        return -1;
    }
    w->ws_State = WS_LIVE;
    w->ws_E = cmdID;
    w->ws_LastDist = 0;
    w->ws_NextDue = clo;
    ws_log(r, clo, RT_SAMPLER_ENABLE, 0, cmdID, 0, 0);
    return 0;
}

static inline void ws_tomb(struct WsState *w, UWORD id, ULONG reqClo)
{
    ULONG i = w->ws_TombNext++ % WS_TOMBS;
    w->ws_TombId[i] = id;
    w->ws_TombClo[i] = reqClo;
    w->ws_TombUsed[i] = 1;
}

static inline void ws_stop(struct WsState *w, struct RtRing *r, ULONG clo, UBYTE reason, UWORD notTaken, ULONG dist)
{
    if (w->ws_SlotLive)
    {
        /* its reply, if it comes, is LATE and never read */
        ws_tomb(w, w->ws_SlotId, w->ws_SlotReqClo);
        w->ws_SlotLive = 0;
    }
    w->ws_State = WS_STOPPED;
    ws_log(r, clo, RT_SAMPLER_STOP, reason, notTaken, w->ws_E, dist);
}

/* Permanent: no enable after it, whether one came before or not */
static inline void ws_disable(struct WsState *w, struct RtRing *r, ULONG clo)
{
    if (w->ws_State != WS_STOPPED)
        ws_stop(w, r, clo, WS_STOP_DISABLED, 0, 0);
}

/* Receiver tick: the slot deadline first, then whether a sample is due.
   1: build one now (then ws_take_id, ws_sent). */
static inline int ws_tick(struct WsState *w, struct RtRing *r, ULONG clo, int ctrlBusy)
{
    if (w->ws_SlotLive && (ULONG)(clo - w->ws_SlotReqClo) >= WS_DEADLINE_US)
    {
        ws_log(r, clo, RT_SAMPLE_LOST, 0, w->ws_SlotId, w->ws_SlotReqClo, 0);
        ws_tomb(w, w->ws_SlotId, w->ws_SlotReqClo);
        w->ws_SlotLive = 0;
    }
    if (w->ws_State == WS_IDLE)
        return 0;
    if (w->ws_State == WS_STOPPED)
    {
        /* said once, not every tick for the rest of the run */
        if (!w->ws_StopSkipLogged)
        {
            w->ws_StopSkipLogged = 1;
            ws_log(r, clo, RT_SAMPLE_SKIP, WS_SKIP_STOPPED, 0, 0, 0);
        }
        return 0;
    }
    if ((LONG)(clo - w->ws_NextDue) < 0)
        return 0;
    /* a skip uses up the period too: at most one SKIP per 50 ms */
    w->ws_NextDue = clo + WS_PERIOD_US;
    if (w->ws_SlotLive)
    {
        ws_log(r, clo, RT_SAMPLE_SKIP, WS_SKIP_SLOT_BUSY, w->ws_SlotId, 0, 0);
        return 0;
    }
    if (ctrlBusy)
    {
        ws_log(r, clo, RT_SAMPLE_SKIP, WS_SKIP_CTRL_BUSY, 0, 0, 0);
        return 0;
    }
    return 1;
}

static inline void ws_nomem(struct WsState *w, struct RtRing *r, ULONG clo)
{
    (void)w;
    ws_log(r, clo, RT_SAMPLE_SKIP, WS_SKIP_NOMEM, 0, 0, 0);
}

/* The id NextCmdID() would hand out next: never 0, never a quarantined one */
static inline UWORD ws_next_id(UWORD cmdID, const UWORD *quarantine)
{
    UWORD id = cmdID;
    ULONG i;
    int used;

    do
    {
        id++;
        used = (id == 0);
        for (i = 0; i < 32 && !used; i++)
            if (quarantine[i] == id)
                used = 1;
    } while (used);
    return id;
}

/* Take the next id for a sample, or stop for good.  Called with *cmdID
   (s_CmdID) under the same Forbid() NextCmdID() takes.  1: *idOut taken. */
static inline int ws_take_id(struct WsState *w, struct RtRing *r, ULONG clo, UWORD *cmdID,
                             const UWORD *quarantine, UWORD *idOut)
{
    UWORD id = ws_next_id(*cmdID, quarantine);
    ULONG dist = (UWORD)(id - w->ws_E);

    if (w->ws_State != WS_LIVE)
        return 0;
    if (dist >= WS_ID_CAP)
    {
        ws_stop(w, r, clo, WS_STOP_IDCAP, id, dist);
        return 0;
    }
    if (dist < w->ws_LastDist)
    {
        ws_stop(w, r, clo, WS_STOP_WRAP, id, dist);
        return 0;
    }
    *cmdID = id;
    w->ws_LastDist = dist;
    *idOut = id;
    return 1;
}

/* The request with this id has gone out */
static inline void ws_sent(struct WsState *w, struct RtRing *r, ULONG clo, UWORD id)
{
    w->ws_Issued[id >> 3] |= (UBYTE)(1 << (id & 7));
    w->ws_Samples++;
    ws_log(r, clo, RT_SAMPLE_REQ, 0, id, w->ws_Samples, 0);
    if (w->ws_State == WS_LIVE)
    {
        w->ws_SlotLive = 1;
        w->ws_SlotId = id;
        w->ws_SlotReqClo = clo;
    }
    else
        ws_tomb(w, id, clo);        /* disabled while it was being built */
}

/* A control reply, before any synchronous waiter sees it.  data/copied: the
   payload after the BCDC header, as far as it arrived and c_Length allows.
   WS_R_NOTMINE: not a sample, the waiters' as before. */
static inline int ws_reply(struct WsState *w, struct RtRing *r, ULONG clo, UWORD id, ULONG cmd,
                           int fwError, ULONG fwStatus, const UBYTE *data, ULONG copied)
{
    /* SAMPLE_VAL a = index here; tools/wlsample.py names them in this order */
    static const UWORD off[WS_NFIELDS] = {
        WS_OFF_TBTT, WS_OFF_RXBEACONMBSS, WS_OFF_RXFRAME, WS_OFF_RXCRSGLITCH, WS_OFF_RXBADPLCP,
        WS_OFF_TXFRAME, WS_OFF_TXRETRANS, WS_OFF_TXNOACK, WS_OFF_RXNOBUF, WS_OFF_RXTOOLATE
    };
    ULONG i;

    if (w->ws_State == WS_IDLE || cmd != WS_GET_VAR)
        return WS_R_NOTMINE;
    if (w->ws_SlotLive && id == w->ws_SlotId)
    {
        ULONG lat = clo - w->ws_SlotReqClo;
        w->ws_SlotLive = 0;
        if (fwError)
        {
            ws_log(r, clo, RT_SAMPLE_REP, WS_REP_FW_ERROR, id, lat, fwStatus);
            return WS_R_TAKEN;
        }
        {
            ULONG ver = copied >= 2 ? (ULONG)data[0] | ((ULONG)data[1] << 8) : 0;
            ULONG len = copied >= 4 ? (ULONG)data[2] | ((ULONG)data[3] << 8) : 0;
            int ok = copied >= WS_V10_LEN && ver == WS_V10_VERSION && len == WS_V10_LEN;

            ws_log(r, clo, RT_SAMPLE_REP, ok ? WS_REP_OK : WS_REP_BAD_LAYOUT, id, lat, (ver << 16) | len);
            if (ok)
                for (i = 0; i < WS_NFIELDS; i++)
                    ws_log(r, clo, RT_SAMPLE_VAL, (UBYTE)i, id, ws_le32(data + off[i]), 0);
        }
        return WS_R_TAKEN;
    }
    if (ws_issued(w, id))
    {
        ULONG lat = 0xffffffffUL;
        UBYTE known = 0;
        for (i = 0; i < WS_TOMBS; i++)
            if (w->ws_TombUsed[i] && w->ws_TombId[i] == id)
            {
                lat = clo - w->ws_TombClo[i];
                known = 1;
            }
        ws_log(r, clo, RT_SAMPLE_LATE, known, id, lat, fwError ? fwStatus : 0);
        return WS_R_LATE;
    }
    return WS_R_NOTMINE;
}

#endif /* WIFIPI_WLSAMPLE_H */
