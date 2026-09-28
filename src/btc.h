/*
 * Debug-only Bluetooth-coexistence iovar access (AmiNetXDuo #89, hw34).
 * Compiled in only with -DWIFIPI_BTC, which needs -DWIFIPI_RINGTRACE: every
 * operation is a ring record.
 *
 * Private command 0xF08D, synchronous on the unit task: ios2_Data is a
 * struct BtcReq.  GET reads btc_mode, btc_flags or btc_dos_status; SET
 * writes btc_mode and nothing else, so no btc_params* can ever be written.
 * Anything else is S2ERR_BAD_ARGUMENT.  The firmware is asked through
 * PacketGetVarMin / PacketSetVarInt with their own deadlines; br_Rc is
 * their result (0, the firmware's BCME status, or PACKET_CTRL_*).
 *
 * The pure part below makes no Exec calls; a host test links it as is.
 * Types come from the includer.
 */
#ifndef WIFIPI_BTC_H
#define WIFIPI_BTC_H

#if defined(WIFIPI_BTC) && !defined(WIFIPI_RINGTRACE)
#error "WIFIPI_BTC needs WIFIPI_RINGTRACE"
#endif

#define WIFIPI_CMD_BTC      0xF08D
#define RT_BTC              29      /* clo; a op, b name id (0 refused), c value, d rc */
#define BTC_RC_REFUSED      0x7fff0100UL    /* refused by the driver: never sent */
#define BTC_NAME_MAX        20

enum { BTC_OP_GET = 1, BTC_OP_SET = 2 };
enum { BTC_NAME_MODE = 1, BTC_NAME_FLAGS = 2, BTC_NAME_DOS_STATUS = 3, BTC_NAME_ANTDT = 4, BTC_NAME_EXTGPIO = 5 };

struct BtcReq {
    ULONG   br_Op;                  /* BTC_OP_GET / BTC_OP_SET */
    ULONG   br_Value;               /* SET: in; GET: out */
    LONG    br_Rc;                  /* out */
    char    br_Name[BTC_NAME_MAX];  /* NUL-terminated inside */
};

_Static_assert(sizeof(struct BtcReq) == 32, "struct BtcReq is 32 bytes");

static inline const char *btc_name(ULONG id)
{
    static const char *const names[6] = { 0, "btc_mode", "btc_flags", "btc_dos_status", "ant_dt", "ext_gpio" };
    return id >= 1 && id <= 5 ? names[id] : 0;
}

/* The name's id if the op is allowed on it, else 0 */
static inline ULONG btc_check(ULONG op, const char *name)
{
    ULONG id, i;

    if (op != BTC_OP_GET && op != BTC_OP_SET)
        return 0;
    for (id = 1; id <= 5; id++)
    {
        const char *n = btc_name(id);
        for (i = 0; i < BTC_NAME_MAX && name[i] == n[i] && n[i]; i++)
            ;
        if (i < BTC_NAME_MAX && name[i] == 0 && n[i] == 0)
            return (op == BTC_OP_GET || id == BTC_NAME_MODE) ? id : 0;
    }
    return 0;
}

#ifdef WIFIPI_RINGTRACE
#include "ringtrace.h"
static inline void btc_log(struct RtRing *r, ULONG clo, ULONG op, ULONG id, ULONG value, ULONG rc)
{
    if (r != 0)
        rt_put(r, clo, RT_BTC, (UBYTE)op, (UWORD)id, value, rc);
}
#endif

#endif /* WIFIPI_BTC_H */
