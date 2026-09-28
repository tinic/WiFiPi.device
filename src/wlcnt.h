/*
 * Debug-only firmware counter snapshot (AmiNetXDuo #89).  Compiled in only
 * with -DWIFIPI_WLCNT; a build without it has none of this.
 *
 * On demand, never from the RX/TX path: private command 0xF08A issues one
 * 'counters' iovar GET (the PacketGetVarMin() path, bounded by the 2.5 s
 * control deadline) and returns this header, then wd_Asked bytes of the
 * firmware's answer exactly as it came (little-endian, zero past
 * wd_Copied).  The header is the host's (big-endian).  tools/wlcntdump.c
 * writes it to a file; tools/wlcnt.py decodes and diffs two of them.
 */
#ifndef WIFIPI_WLCNT_H
#define WIFIPI_WLCNT_H

#define WIFIPI_CMD_WLCNT    0xF08A
#define WC_DUMP_MAGIC       0x574C4331UL    /* 'WLC1' */
#define WC_DUMP_VERSION     1
#define WC_GET_SIZE         2048            /* asked of the firmware */

struct WcDumpHeader {
    ULONG   wd_Magic;
    UWORD   wd_Version;
    UWORD   wd_HeaderSize;  /* sizeof(struct WcDumpHeader) */
    ULONG   wd_CloBefore;   /* CLO (1 MHz) just before the GET */
    ULONG   wd_CloAfter;    /* CLO once it returned */
    ULONG   wd_Error;       /* 0, the firmware's BCME status, or PACKET_CTRL_* */
    ULONG   wd_Asked;       /* bytes asked for = bytes that follow */
    ULONG   wd_Copied;      /* bytes of the answer that arrived */
    ULONG   wd_UnitFlags;   /* wu_Flags at the snapshot */
};

_Static_assert(sizeof(struct WcDumpHeader) == 32, "wlcnt dump header is 32 bytes");

#endif /* WIFIPI_WLCNT_H */
