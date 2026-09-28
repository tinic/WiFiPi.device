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
 * not answered in 500 ms is LOST; a reply to any id the sampler ever issued
 * that is not the live slot, and that no waiter takes, is LATE and never
 * read.
 *
 * Lost ids.  Every sample id that ends LOST, and the one outstanding when
 * the sampler stops (DISABLE, idcap, wrap), is set in ws_Lost: its request
 * may still be answered, so NextCmdID() does not hand it out again -- it
 * skips ws_Lost as it skips s_CtrlQuarantine, one bit test a candidate, and
 * a very late 'counters' reply can never reach a later waiter.  No
 * capacity, no eviction.  A request gets one reply: a late one clears the
 * bit, and the id may be handed out again after it.  If every id were
 * blocked the walk would never end, so after 65536 blocked candidates the
 * sampler stops (id_space) and ws_Lost is no longer consulted: the walk is
 * the base driver's from then on.  At most WS_ID_CAP ids can be set, so
 * this is not reached; it only must not hang.
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
#define WS_TOMBS        16              /* latency lookup only; evicted freely */
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
    RT_SAMPLE_REQ     = 20, /* clo REQ; a 0, b id, c sample number, d frame bytes sent */
    RT_SAMPLE_REP     = 21, /* clo REP; a status | min(version, 63)<<2, b id, c latency us
                               (REP - REQ), d reply frame bytes<<16 | length as read
                               (fw_error: | the firmware status & 0xffff) */
    RT_SAMPLE_VAL     = 22, /* clo REP; a field index, b id, c value, d 0 (after an ok REP only) */
    RT_SAMPLE_SKIP    = 23, /* clo; a reason, b live slot id or 0, c 0, d 0 */
    RT_SAMPLE_LOST    = 24, /* clo; a 0, b id, c original REQ clo, d 0 */
    RT_SAMPLE_LATE    = 25, /* clo REP; a 1 latency known / 0 unknown, b id,
                               c latency us or 0xffffffff,
                               d reply frame bytes<<16 | firmware status & 0xffff */
    RT_SAMPLER_STOP   = 26, /* clo; a reason, b id that was not taken (0: none), c E, d distance */
    RT_SAMPLER_REFUSED = 27, /* clo; a reason (1 used before), b state, c E, d 0 */
    RT_SAMPLER_ENABLE = 28  /* clo; a 0, b E, c 0, d 0 */
};

enum { WS_REP_OK = 0, WS_REP_BAD_LAYOUT = 1, WS_REP_FW_ERROR = 2 };
enum { WS_SKIP_SLOT_BUSY = 1, WS_SKIP_CTRL_BUSY = 2, WS_SKIP_NOMEM = 3, WS_SKIP_STOPPED = 4,
       WS_SKIP_NO_CREDIT = 5 };
enum { WS_STOP_IDCAP = 1, WS_STOP_DISABLED = 2, WS_STOP_WRAP = 3, WS_STOP_ID_SPACE = 4 };
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
    UBYTE   ws_LostOff;             /* the id_space guard fired: ws_Lost not consulted */
    UBYTE   ws_Issued[65536 / 8];   /* ids ever sent as samples */
    UBYTE   ws_Lost[65536 / 8];     /* sample ids whose reply may still come: not handed out */
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

static inline int ws_lost(const struct WsState *w, UWORD id)
{
    return (w->ws_Lost[id >> 3] >> (id & 7)) & 1;
}

/* An id whose request may still be answered: not handed out again until
   that answer comes */
static inline void ws_retire(struct WsState *w, UWORD id, ULONG reqClo)
{
    ws_tomb(w, id, reqClo);
    w->ws_Lost[id >> 3] |= (UBYTE)(1 << (id & 7));
}

static inline void ws_stop(struct WsState *w, struct RtRing *r, ULONG clo, UBYTE reason, UWORD notTaken, ULONG dist)
{
    if (w->ws_SlotLive)
    {
        /* its reply, if it comes, is LATE and never read; its id is never reused */
        ws_retire(w, w->ws_SlotId, w->ws_SlotReqClo);
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
   ctrlBusy: s_CtrlWaitList not empty; credit: PacketTxCredit() (#99), the
   window every frame the receiver sends is held to.  A skip of any kind
   takes no id, makes no REQ and no slot, and uses the period up: the next
   try is WS_PERIOD_US on, never a catch-up.  1: build one now (then
   ws_take_id, ws_sent). */
static inline int ws_tick(struct WsState *w, struct RtRing *r, ULONG clo, int ctrlBusy, UBYTE credit)
{
    if (w->ws_SlotLive && (ULONG)(clo - w->ws_SlotReqClo) >= WS_DEADLINE_US)
    {
        ws_log(r, clo, RT_SAMPLE_LOST, 0, w->ws_SlotId, w->ws_SlotReqClo, 0);
        ws_retire(w, w->ws_SlotId, w->ws_SlotReqClo);
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
    if (credit == 0)
    {
        ws_log(r, clo, RT_SAMPLE_SKIP, WS_SKIP_NO_CREDIT, 0, 0, 0);
        return 0;
    }
    return 1;
}

static inline void ws_nomem(struct WsState *w, struct RtRing *r, ULONG clo)
{
    (void)w;
    ws_log(r, clo, RT_SAMPLE_SKIP, WS_SKIP_NOMEM, 0, 0, 0);
}

/* The walk NextCmdID() makes, and the sampler's own ids: from cmdID, the
   next id that is not 0, not in s_CtrlQuarantine, not set in ws_Lost.
   After 65536 blocked candidates in a row (every id blocked) the sampler
   stops (id_space) and ws_Lost is dropped from the walk, which then ends
   as the base driver's does: at most 33 ids are blocked there. */
static inline UWORD ws_next_id(struct WsState *w, struct RtRing *r, ULONG clo, UWORD cmdID,
                               const UWORD *quarantine)
{
    UWORD id = cmdID;
    ULONG i, blocked = 0;
    int used;

    do
    {
        id++;
        used = (id == 0);
        for (i = 0; i < 32 && !used; i++)
            if (quarantine[i] == id)
                used = 1;
        if (!used && !w->ws_LostOff && ws_lost(w, id))
            used = 1;
        if (used && ++blocked >= 65536 && !w->ws_LostOff)
        {
            w->ws_LostOff = 1;
            ws_stop(w, r, clo, WS_STOP_ID_SPACE, 0, blocked);
        }
    } while (used);
    return id;
}

/* Take the next id for a sample, or stop for good.  Called with *cmdID
   (s_CmdID) under the same Forbid() NextCmdID() takes.  1: *idOut taken. */
static inline int ws_take_id(struct WsState *w, struct RtRing *r, ULONG clo, UWORD *cmdID,
                             const UWORD *quarantine, UWORD *idOut)
{
    UWORD id = ws_next_id(w, r, clo, *cmdID, quarantine);
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

/* NextCmdID() handed id to another caller (under its Forbid()): it is no
   longer a sample id.  Only the ws_Issued mark goes; a ws_Lost bit is
   never cleared here -- ws_next_id does not hand out a ws_Lost id while
   ws_Lost is consulted, and after the id_space guard the bit stays as it
   was.  Only the id's own late reply clears it (ws_reply_late). */
static inline void ws_realloc(struct WsState *w, UWORD id)
{
    w->ws_Issued[id >> 3] &= (UBYTE)~(1 << (id & 7));
}

/* The request with this id has gone out, bytes long */
static inline void ws_sent(struct WsState *w, struct RtRing *r, ULONG clo, UWORD id, ULONG bytes)
{
    w->ws_Issued[id >> 3] |= (UBYTE)(1 << (id & 7));
    w->ws_Samples++;
    ws_log(r, clo, RT_SAMPLE_REQ, 0, id, w->ws_Samples, bytes);
    if (w->ws_State == WS_LIVE)
    {
        w->ws_SlotLive = 1;
        w->ws_SlotId = id;
        w->ws_SlotReqClo = clo;
    }
    else
        ws_retire(w, id, clo);      /* stopped while it was being built */
}

/* A control reply, before the synchronous waiters: taken only if it is the
   live slot's -- id, GET_VAR, slot live.  The live id cannot be a waiter's:
   below the cap no id is handed out twice.  data/copied: the payload after
   the BCDC header, as far as it arrived and c_Length allows; frame: the
   reply's SDIO frame bytes.  WS_R_NOTMINE: the waiters' as before. */
static inline int ws_reply_slot(struct WsState *w, struct RtRing *r, ULONG clo, UWORD id, ULONG cmd,
                                int fwError, ULONG fwStatus, const UBYTE *data, ULONG copied, ULONG frame)
{
    /* SAMPLE_VAL a = index here; tools/wlsample.py names them in this order */
    static const UWORD off[WS_NFIELDS] = {
        WS_OFF_TBTT, WS_OFF_RXBEACONMBSS, WS_OFF_RXFRAME, WS_OFF_RXCRSGLITCH, WS_OFF_RXBADPLCP,
        WS_OFF_TXFRAME, WS_OFF_TXRETRANS, WS_OFF_TXNOACK, WS_OFF_RXNOBUF, WS_OFF_RXTOOLATE
    };
    ULONG i, lat;

    if (!w->ws_SlotLive || id != w->ws_SlotId || cmd != WS_GET_VAR)
        return WS_R_NOTMINE;
    lat = clo - w->ws_SlotReqClo;
    w->ws_SlotLive = 0;
    if (fwError)
    {
        ws_log(r, clo, RT_SAMPLE_REP, WS_REP_FW_ERROR, id, lat, (frame << 16) | (fwStatus & 0xffff));
        return WS_R_TAKEN;
    }
    {
        ULONG ver = copied >= 2 ? (ULONG)data[0] | ((ULONG)data[1] << 8) : 0;
        ULONG len = copied >= 4 ? (ULONG)data[2] | ((ULONG)data[3] << 8) : 0;
        int ok = copied >= WS_V10_LEN && ver == WS_V10_VERSION && len == WS_V10_LEN;

        ws_log(r, clo, RT_SAMPLE_REP, (UBYTE)((ok ? WS_REP_OK : WS_REP_BAD_LAYOUT) | ((ver > 63 ? 63 : ver) << 2)),
               id, lat, (frame << 16) | (len & 0xffff));
        if (ok)
            for (i = 0; i < WS_NFIELDS; i++)
                ws_log(r, clo, RT_SAMPLE_VAL, (UBYTE)i, id, ws_le32(data + off[i]), 0);
    }
    return WS_R_TAKEN;
}

/* A control reply no waiter took: a sample's that came too late (its id
   still a sample id: sent as one, never handed out since), logged LATE and
   never read.  Nothing else is the sampler's. */
static inline int ws_reply_late(struct WsState *w, struct RtRing *r, ULONG clo, UWORD id, ULONG cmd,
                                int fwError, ULONG fwStatus, ULONG frame)
{
    ULONG i, lat = 0xffffffffUL;
    UBYTE known = 0;

    if (w->ws_State == WS_IDLE || cmd != WS_GET_VAR || !ws_issued(w, id))
        return WS_R_NOTMINE;
    /* its one reply -- id and command checked above, under the Forbid()
       NextCmdID() allocates under: the id may be handed out again */
    w->ws_Lost[id >> 3] &= (UBYTE)~(1 << (id & 7));
    for (i = 0; i < WS_TOMBS; i++)
        if (w->ws_TombUsed[i] && w->ws_TombId[i] == id)
        {
            lat = clo - w->ws_TombClo[i];
            known = 1;
        }
    ws_log(r, clo, RT_SAMPLE_LATE, known, id, lat, (frame << 16) | ((fwError ? fwStatus : 0) & 0xffff));
    return WS_R_LATE;
}

static inline UWORD ws_le16(const UBYTE *p) { return (UWORD)(p[0] | (p[1] << 8)); }

/* The same two, from the reply as it lies in the RX buffer: bcdc is the
   16-byte BCDC header (struct PacketCmd), avail the bytes after it that
   arrived, frame the SDPCM frame length.  PacketCtrlComplete() calls these. */
static inline int ws_ctrl_slot(struct WsState *w, struct RtRing *r, ULONG clo, const UBYTE *bcdc,
                               ULONG avail, ULONG frame)
{
    ULONG len = ws_le32(bcdc + 4);
    return ws_reply_slot(w, r, clo, ws_le16(bcdc + 10), ws_le32(bcdc), ws_le16(bcdc + 8) & 1,
                         ws_le32(bcdc + 12), bcdc + 16, avail < len ? avail : len, frame);
}

static inline int ws_ctrl_late(struct WsState *w, struct RtRing *r, ULONG clo, const UBYTE *bcdc, ULONG frame)
{
    return ws_reply_late(w, r, clo, ws_le16(bcdc + 10), ws_le32(bcdc), ws_le16(bcdc + 8) & 1,
                         ws_le32(bcdc + 12), frame);
}

/* The GET 'counters' frame, as PacketSetVarAsync() lays one out: SDPCM
   hardware header, glom header if glomming, software header (control
   channel), BCDC header (GET_VAR, 848, get, id), the name, the zeroed rest.
   pkt: ws_frame_len() bytes rounded up to 4, zeroed. */
static inline ULONG ws_frame_len(int glom)
{
    return 4 + (glom ? 8 : 0) + 8 + 16 + WS_V10_LEN;
}

static inline void ws_put16(UBYTE *p, ULONG v) { p[0] = (UBYTE)v; p[1] = (UBYTE)(v >> 8); }
static inline void ws_put32(UBYTE *p, ULONG v) { ws_put16(p, v); ws_put16(p + 2, v >> 16); }

static inline void ws_build(UBYTE *pkt, int glom, UBYTE seq, UWORD id)
{
    static const char name[9] = "counters";
    ULONG total = ws_frame_len(glom);
    UBYTE *sw = pkt + (glom ? 12 : 4), *c = sw + 8;
    ULONG i;

    ws_put16(pkt, total);
    ws_put16(pkt + 2, ~total);
    if (glom)
    {
        ws_put16(pkt + 4, total - 4);
        pkt[6] = 0;
        pkt[7] = 1;                 /* last item */
        ws_put16(pkt + 8, 0);
        ws_put16(pkt + 10, (0UL - total) & 3);
    }
    sw[0] = seq;
    sw[3] = (UBYTE)(12 + (glom ? 8 : 0));   /* data offset */
    ws_put32(c, WS_GET_VAR);
    ws_put32(c + 4, WS_V10_LEN);
    ws_put16(c + 8, 0);                     /* get */
    ws_put16(c + 10, id);
    ws_put32(c + 12, 0);
    for (i = 0; i < sizeof(name); i++)
        c[16 + i] = (UBYTE)name[i];
}

#endif /* WIFIPI_WLSAMPLE_H */
