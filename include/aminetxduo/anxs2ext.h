/*
 * AmiNetXDuo, private SANA-II buffer-management extensions.
 * SPDX-License-Identifier: MIT
 */
#ifndef AMINETXDUO_ANXS2EXT_H
#define AMINETXDUO_ANXS2EXT_H

#include <exec/types.h>

#define ANXD_S2_RXF_SUMMED      0x01
#define ANXD_S2_RXF_VERIFIED    0x02

#define ANXD_S2_TXF_TCP         0x01
#define ANXD_S2_TXF_UDP         0x02

typedef UBYTE *(*AnxdS2RxDirect)(APTR ios2_data, ULONG len);
typedef VOID   (*AnxdS2RxFilled)(APTR ios2_data, ULONG len, ULONG sum,
                                 UBYTE flags);
typedef UBYTE  (*AnxdS2TxFlags)(APTR ios2_data);

/* One versioned TAG_USER negotiation record shared with AmiNetXDuo. */
#define ANXD_S2_EXTENSION       (0x80000000UL | 0x00414e58UL)
#define ANXD_S2_ABI_VERSION     2u

#define ANXD_S2F_RX_DIRECT      (1UL << 0)
#define ANXD_S2F_RX_LINK_HDR    (1UL << 1)
#define ANXD_S2F_RX_VERIFIED    (1UL << 2)
#define ANXD_S2F_TX_CSUM_TCP    (1UL << 3)
#define ANXD_S2F_TX_CSUM_UDP    (1UL << 4)
#define ANXD_S2F_RX_POLL        (1UL << 5)
#define ANXD_S2F_RX_CAPACITY    (1UL << 6)
#define ANXD_S2F_TX_QUICK       (1UL << 7)

typedef struct AnxdS2Extension
{
    UWORD           Version;
    UWORD           Size;
    ULONG           Request;
    ULONG           Accepted;
    AnxdS2RxDirect  RxDirect;
    AnxdS2RxFilled  RxFilled;
    AnxdS2TxFlags   TxFlags;
} AnxdS2Extension;

#define ANXD_CMD_RX_POLL        0x8190
#define ANXD_CMD_RX_CAPACITY    0x8192

#endif /* AMINETXDUO_ANXS2EXT_H */
