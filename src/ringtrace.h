/*
 * Debug-only event ring (AmiNetXDuo #89).  Compiled in only with
 * -DWIFIPI_RINGTRACE; a build without it has none of this.
 *
 * Fixed 16-byte records in a power-of-two ring, oldest overwritten.  Every
 * writer runs in a task and writes under Forbid(), and the dump copies under
 * Forbid() too, so a dump never sees half a record.  rt_Seq counts every
 * record ever written; a dump says how many it does not contain.
 *
 * The pure part below (put, snapshot) has no Exec calls, so a host test can
 * link it as is.  The types (UBYTE, UWORD, ULONG) come from the includer.
 */
#ifndef WIFIPI_RINGTRACE_H
#define WIFIPI_RINGTRACE_H

#define RT_RING_MAGIC   0x52545231UL    /* 'RTR1' */
#define RT_DUMP_MAGIC   0x52544431UL    /* 'RTD1' */
#define RT_DUMP_VERSION 1

#ifndef WIFIPI_RINGTRACE_LOG2
#define WIFIPI_RINGTRACE_LOG2   22      /* 4 Mi records, 64 MB; halved until it fits */
#endif
#define RT_MIN_LOG2             12

/* Private device command: ios2_Data/ios2_DataLength take the dump */
#define WIFIPI_CMD_RINGDUMP     0xF089

/* Record kinds.  Field use per kind is in tools/ringtrace.py. */
enum {
    RT_START  = 1,      /* ring allocated */
    RT_WAKE   = 2,      /* receiver back from Wait() */
    RT_READ   = 3,      /* one SDIO header read (look) and what it found */
    RT_TICK   = 4,      /* receiver timer completed or taken back */
    RT_RXQ    = 5,      /* end of a wake that read frames: queue depths */
    RT_TX     = 6,      /* one glom sent */
    RT_CREDIT = 7,      /* TX credit state: initial, reached 0, left 0 */
    RT_EVENT  = 8,      /* firmware event frame (ethertype 0x886c) */
    RT_SCAN   = 9,      /* S2_GETNETWORKS queued, escan started, scan done */
    RT_CTRL   = 10,     /* firmware control transaction */
    RT_MARK   = 11,     /* alignment ping seen (RX request, TX reply) */
    RT_POLL   = 12,     /* poller: line seen, write wake, grace ran out */
    RT_TXID1  = 13,     /* TX frame identity, IPv4 TCP, first of a pair */
    RT_TXID2  = 14,     /* ... second of the pair, always the next record */
    RT_TXO    = 15,     /* TX frame identity, anything else */
    RT_TXRC   = 16,     /* one glom's CMD53 write: result and time */
    RT_RXID1  = 17,     /* RX frame identity at the handoff to the stack, IPv4 TCP, first of a pair */
    RT_RXID2  = 18,     /* ... second of the pair, always the next record */
    RT_RXO    = 19      /* RX frame identity, anything else */
};

/* RX outcome at the handoff (RXID2/RXO b high byte) */
enum {
    RT_RX_READ     = 1, /* copied into a posted read, replied without error */
    RT_RX_READERR  = 2, /* a posted read took it but was replied with an error */
    RT_RX_ORPHAN   = 3, /* no read of its type: given to an orphan listener */
    RT_RX_DROPPED  = 4, /* no read and no orphan listener */
    RT_RX_FILTERED = 5  /* multicast not in the accepted ranges */
};

struct RtRec {
    ULONG   r_Clo;      /* CLO (1 MHz) when written */
    UBYTE   r_Kind;
    UBYTE   r_A;
    UWORD   r_B;
    ULONG   r_C;
    ULONG   r_D;
};

struct RtRing {
    ULONG   rt_Magic;
    ULONG   rt_Mask;    /* capacity - 1 */
    ULONG   rt_Seq;     /* records ever written */
    ULONG   rt_Size;    /* bytes allocated, this header included */
    struct RtRec rt_Rec[];
};

/* Dump header, followed by rd_Count records, oldest first */
struct RtDumpHeader {
    ULONG   rd_Magic;
    UWORD   rd_Version;
    UWORD   rd_RecSize;
    ULONG   rd_Capacity;
    ULONG   rd_Seq;     /* records ever written, at the dump */
    ULONG   rd_First;   /* sequence number of the first record here */
    ULONG   rd_Count;
    ULONG   rd_Lost;    /* written but not here: overwritten or no room */
    ULONG   rd_Clo;     /* CLO at the dump */
};

_Static_assert(sizeof(struct RtRec) == 16, "record is 16 bytes");
_Static_assert(sizeof(struct RtDumpHeader) == 32, "dump header is 32 bytes");

/*
 * Per-frame TX identity (#89), taken as each frame is copied into the glom
 * buffer.  IPv4 TCP gives two records written together:
 *   TXID1  a TCP flags, b IP id, c ACK number, d sequence number
 *   TXID2  a glom index, b count<<8 | SDPCM seq, c sport<<16 | dport,
 *          d src last octet<<24 | dst last octet<<16 | TCP payload length
 * anything else one:
 *   TXO    a glom index, b count<<8 | SDPCM seq, c ethertype<<16 | IP protocol
 *          (0xff: not IPv4, or the header does not parse), d frame length
 * The address discriminator is each address's last octet: the rig is one
 * /24, the join key is (IP id, ACK), and the octets only tell flows apart.
 * Header fields are read a byte at a time (network order on any host).
 */
struct RtTx {
    UWORD   tx_Proto;   /* 6 = a parsed TCP header, else the protocol or 0xff */
    UBYTE   tx_Flags;
    UBYTE   tx_Src, tx_Dst;
    UWORD   tx_IPId, tx_SPort, tx_DPort, tx_Payload;
    ULONG   tx_Seq, tx_Ack;
};

static inline ULONG rt_be16(const UBYTE *p) { return ((ULONG)p[0] << 8) | p[1]; }
static inline ULONG rt_be32(const UBYTE *p)
{
    return ((ULONG)p[0] << 24) | ((ULONG)p[1] << 16) | ((ULONG)p[2] << 8) | p[3];
}

/* l3: the IP header, len: bytes there.  Returns 1 for a whole IPv4 TCP
   header (first fragment, header inside both len and the IP length). */
static inline int rt_parse_tx(const UBYTE *l3, ULONG len, UWORD ethertype, struct RtTx *t)
{
    ULONG ihl, tot, doff;

    t->tx_Proto = 0xff;
    if (ethertype != 0x0800 || len < 20 || (l3[0] >> 4) != 4)
        return 0;
    ihl = (l3[0] & 15) * 4;
    tot = rt_be16(&l3[2]);
    if (ihl < 20 || ihl > len || tot < ihl)
        return 0;
    t->tx_Proto = l3[9];
    if (tot > len)
        tot = len;
    if (l3[9] != 6 || (rt_be16(&l3[6]) & 0x1fff) != 0 || ihl + 20 > tot)
        return 0;
    doff = (l3[ihl + 12] >> 4) * 4;
    t->tx_IPId = rt_be16(&l3[4]);
    t->tx_Src = l3[15];
    t->tx_Dst = l3[19];
    t->tx_SPort = rt_be16(&l3[ihl]);
    t->tx_DPort = rt_be16(&l3[ihl + 2]);
    t->tx_Seq = rt_be32(&l3[ihl + 4]);
    t->tx_Ack = rt_be32(&l3[ihl + 8]);
    t->tx_Flags = l3[ihl + 13];
    t->tx_Payload = (doff >= 20 && ihl + doff <= tot) ? tot - ihl - doff : 0;
    return 1;
}

static inline void rt_init(struct RtRing *r, ULONG log2, ULONG size)
{
    r->rt_Magic = RT_RING_MAGIC;
    r->rt_Mask = (1UL << log2) - 1;
    r->rt_Seq = 0;
    r->rt_Size = size;
}

static inline void rt_put(struct RtRing *r, ULONG clo, UBYTE kind, UBYTE a, UWORD b, ULONG c, ULONG d)
{
    struct RtRec *e = &r->rt_Rec[r->rt_Seq & r->rt_Mask];

    e->r_Clo = clo;
    e->r_Kind = kind;
    e->r_A = a;
    e->r_B = b;
    e->r_C = c;
    e->r_D = d;
    r->rt_Seq++;
}

/* One frame's identity: two records (TCP) or one; the caller holds Forbid,
   so a pair is never split by another writer (a dump or a lap can still cut
   one at the ring's oldest end: readers pair TXID1 with the very next record) */
static inline void rt_put_tx(struct RtRing *r, ULONG clo, const struct RtTx *t, int tcp,
                             UBYTE idx, UBYTE count, UBYTE sdpcmSeq, UWORD ethertype, ULONG flen)
{
    UWORD b = ((UWORD)count << 8) | sdpcmSeq;

    if (tcp)
    {
        rt_put(r, clo, RT_TXID1, t->tx_Flags, t->tx_IPId, t->tx_Ack, t->tx_Seq);
        rt_put(r, clo, RT_TXID2, idx, b, ((ULONG)t->tx_SPort << 16) | t->tx_DPort,
               ((ULONG)t->tx_Src << 24) | ((ULONG)t->tx_Dst << 16) | t->tx_Payload);
    }
    else
        rt_put(r, clo, RT_TXO, idx, b, ((ULONG)ethertype << 16) | t->tx_Proto, flen);
}

/* One received frame's identity at the handoff (#89): as rt_put_tx, with
   b = outcome<<8 | SDPCM rx seq, a = index in its glom (0 if not glommed) */
static inline void rt_put_rx(struct RtRing *r, ULONG clo, const struct RtTx *t, int tcp,
                             UBYTE idx, UBYTE outcome, UBYTE sdpcmSeq, UWORD ethertype, ULONG flen)
{
    UWORD b = ((UWORD)outcome << 8) | sdpcmSeq;

    if (tcp)
    {
        rt_put(r, clo, RT_RXID1, t->tx_Flags, t->tx_IPId, t->tx_Ack, t->tx_Seq);
        rt_put(r, clo, RT_RXID2, idx, b, ((ULONG)t->tx_SPort << 16) | t->tx_DPort,
               ((ULONG)t->tx_Src << 24) | ((ULONG)t->tx_Dst << 16) | t->tx_Payload);
    }
    else
        rt_put(r, clo, RT_RXO, idx, b, ((ULONG)ethertype << 16) | t->tx_Proto, flen);
}

/* Header plus the newest records that fit in `size` bytes, oldest first.
   Returns the bytes written; 0 if not even the header fits. */
static inline ULONG rt_snapshot(const struct RtRing *r, ULONG clo, void *out, ULONG size)
{
    struct RtDumpHeader *h = out;
    struct RtRec *dst = (struct RtRec *)(h + 1);
    ULONG cap = r->rt_Mask + 1;
    ULONG held = r->rt_Seq < cap ? r->rt_Seq : cap;
    ULONG room, n, i, s;

    if (size < sizeof(*h))
        return 0;
    room = (size - sizeof(*h)) / sizeof(struct RtRec);
    n = held < room ? held : room;

    h->rd_Magic = RT_DUMP_MAGIC;
    h->rd_Version = RT_DUMP_VERSION;
    h->rd_RecSize = sizeof(struct RtRec);
    h->rd_Capacity = cap;
    h->rd_Seq = r->rt_Seq;
    h->rd_First = r->rt_Seq - n;
    h->rd_Count = n;
    h->rd_Lost = r->rt_Seq - n;
    h->rd_Clo = clo;

    /* field by field: a struct assignment may become a memcpy call, and
       longword casts over the record would break strict aliasing */
    for (i = 0, s = h->rd_First; i < n; i++, s++)
    {
        const struct RtRec *from = &r->rt_Rec[s & r->rt_Mask];
        dst[i].r_Clo = from->r_Clo;
        dst[i].r_Kind = from->r_Kind;
        dst[i].r_A = from->r_A;
        dst[i].r_B = from->r_B;
        dst[i].r_C = from->r_C;
        dst[i].r_D = from->r_D;
    }
    return sizeof(*h) + n * sizeof(struct RtRec);
}

#endif /* WIFIPI_RINGTRACE_H */
