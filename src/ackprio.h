/*
 * #89 R-class holds: under a saturated downlink the chip gets no chance to send our TCP ACKs, which
 * go out at 802.11 best effort beside the AP's bulk data.  A pure TCP ACK is marked with 802.1D
 * priority 5 (AC_VI: shorter AIFS/CW than the AP's AC_BE burst, and still aggregated), written into
 * the BDC header's priority byte; everything else keeps priority 0 as before.
 *
 * Pure C, no Exec calls: a host test links it as is.
 */
#ifndef WIFIPI_ACKPRIO_H
#define WIFIPI_ACKPRIO_H

#define ACKPRIO_PRIORITY    5

/* ip: the IP header (after the Ethernet header), len: bytes available from ip */
static inline unsigned char ackprio_of(const unsigned char *ip, unsigned long len)
{
    unsigned long ihl, tot, doff;
    const unsigned char *tcp;

    if (len < 20)
        return 0;
    if ((ip[0] >> 4) == 4)
    {
        ihl = (unsigned long)(ip[0] & 15) * 4;
        tot = ((unsigned long)ip[2] << 8) | ip[3];
        if (ip[9] != 6 || ihl < 20 || len < ihl + 20 || ((ip[6] & 0x3f) | ip[7]))    /* TCP, not a fragment */
            return 0;
        tcp = ip + ihl;
        doff = (unsigned long)(tcp[12] >> 4) * 4;
        if (doff < 20 || tot != ihl + doff)          /* no payload */
            return 0;
    }
    else if ((ip[0] >> 4) == 6)
    {
        if (len < 60 || ip[6] != 6)                  /* TCP as the first next header */
            return 0;
        tot = ((unsigned long)ip[4] << 8) | ip[5];   /* payload length */
        tcp = ip + 40;
        doff = (unsigned long)(tcp[12] >> 4) * 4;
        if (doff < 20 || tot != doff)
            return 0;
    }
    else
        return 0;
    /* ACK set; SYN, FIN, RST clear */
    return (tcp[13] & 0x10) && !(tcp[13] & 0x07) ? ACKPRIO_PRIORITY : 0;
}

#endif /* WIFIPI_ACKPRIO_H */
