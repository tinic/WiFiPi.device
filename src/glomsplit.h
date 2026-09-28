/*
 * TX glom head split (AmiNetXDuo #89).  Pure: no Amiga headers, so the host
 * test in tests/test_glomsplit.c builds it with cc.
 *
 * In a glom of three or more frames whose first two are pure ACKs of one TCP
 * flow, the head ACK was absent from the peer's capture (A11: 21 of 21); in
 * two-frame gloms of such a pair it was not (A11 0 of 44, G2 0 of 54).  Where
 * it is lost after CMD53 is not established.  The driver never sends such a
 * glom: it ends the glom after the pair, so a same-flow ACK run goes in pairs.
 *
 * Pure ACK: IPv4 (not a fragment, options allowed) or IPv6 (TCP as the first
 * next header), TCP with no payload, ACK set, SYN, FIN and RST clear.  TCP
 * options (timestamps, SACK) do not count as payload.  Same flow: equal
 * source and destination addresses and ports.
 */
#ifndef WIFIPI_GLOMSPLIT_H
#define WIFIPI_GLOMSPLIT_H

/* frame: from the Ethernet header, len bytes; *key and *keyLen give the
   address pair, *ports the port pair */
static inline int wifipi_pure_ack(const unsigned char *f, unsigned long len,
                                  const unsigned char **key, unsigned int *keyLen,
                                  const unsigned char **ports)
{
    const unsigned char *ip = f + 14, *tcp;
    unsigned long hl, iplen, thl;
    unsigned int type;

    if (f == 0 || len < 14 + 20) return 0;
    type = (f[12] << 8) | f[13];

    if (type == 0x0800)
    {
        if ((ip[0] >> 4) != 4 || ip[9] != 6) return 0;
        if ((ip[6] & 0x3f) | ip[7]) return 0;               /* MF or offset */
        hl = (ip[0] & 15) * 4;
        iplen = (ip[2] << 8) | ip[3];
        if (hl < 20) return 0;
        *key = ip + 12; *keyLen = 8;
    }
    else if (type == 0x86dd)
    {
        if (len < 14 + 40 || (ip[0] >> 4) != 6 || ip[6] != 6) return 0;
        hl = 40;
        iplen = 40 + ((ip[4] << 8) | ip[5]);
        *key = ip + 8; *keyLen = 32;
    }
    else return 0;

    if (iplen < hl + 20 || 14 + iplen > len) return 0;
    tcp = ip + hl;
    thl = (tcp[12] >> 4) * 4;
    if (thl < 20 || hl + thl != iplen) return 0;            /* payload */
    if ((tcp[13] & 0x17) != 0x10) return 0;                 /* ACK; no FIN/SYN/RST */
    *ports = tcp;
    return 1;
}

/* frames[0..1] and lens[0..1]: the head of a glom of count frames */
static inline int wifipi_glom_head_split(const unsigned char *const *frames,
                                         const unsigned long *lens,
                                         unsigned long count)
{
    const unsigned char *k0, *k1, *p0, *p1;
    unsigned int n0, n1, i;

    if (count < 3) return 0;
    if (!wifipi_pure_ack(frames[0], lens[0], &k0, &n0, &p0)) return 0;
    if (!wifipi_pure_ack(frames[1], lens[1], &k1, &n1, &p1)) return 0;
    if (n0 != n1) return 0;
    for (i = 0; i < n0; i++) if (k0[i] != k1[i]) return 0;
    for (i = 0; i < 4; i++) if (p0[i] != p1[i]) return 0;
    return 1;
}

/* frames the next transfer takes from a queue of count */
static inline unsigned long wifipi_glom_take(const unsigned char *const *frames,
                                             const unsigned long *lens,
                                             unsigned long count)
{
    return wifipi_glom_head_split(frames, lens, count) ? 2 : count;
}

#endif
