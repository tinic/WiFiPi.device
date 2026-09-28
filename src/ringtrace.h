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
    RT_POLL   = 12      /* poller: line seen, write wake, grace ran out */
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

    /* longword copies: a struct assignment may become a memcpy call */
    for (i = 0, s = h->rd_First; i < n; i++, s++)
    {
        const ULONG *from = (const ULONG *)&r->rt_Rec[s & r->rt_Mask];
        ULONG *to = (ULONG *)&dst[i];
        to[0] = from[0]; to[1] = from[1]; to[2] = from[2]; to[3] = from[3];
    }
    return sizeof(*h) + n * sizeof(struct RtRec);
}

#endif /* WIFIPI_RINGTRACE_H */
