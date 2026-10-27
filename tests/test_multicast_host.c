/* Included production handlers run against this small Exec/firmware stand-in.
 * This tests allocation failures and software filter bookkeeping only. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t UBYTE;
typedef uint16_t UWORD;
/* m68k long accesses require two-byte alignment, including packed MACs. */
typedef uint32_t ULONG __attribute__((aligned(2)));
typedef int32_t LONG;
typedef int BOOL;
#define TRUE 1
#define FALSE 0
#define D(x) ((void)0)
#define LE32(x) ((ULONG)(x))
#define CMD_NONSTD 9
#include "multicast-constants.inc"

struct Node { struct Node *ln_Succ, *ln_Pred; };
struct List { struct Node *lh_Head, *lh_Tail, *lh_TailPred; };
struct MulticastRange {
    struct Node node;
    ULONG mr_UseCount;
    uint64_t mr_LowerBound, mr_UpperBound;
};
struct ExecBase { int unused; };
struct SDIO { int unused; };
struct WiFiBase { struct ExecBase *w_SysBase; struct SDIO *w_SDIO; void *w_MemPool; };
struct WiFiUnit { struct WiFiBase *wu_Base; struct List wu_MulticastRanges; };
struct IOSana2Req {
    struct { void *io_Unit; int io_Command, io_Error; } ios2_Req;
    UBYTE ios2_SrcAddr[6], ios2_DstAddr[6];
    int ios2_WireError;
};
#define ForeachNode(list, node) \
    for ((node) = (void *)(list)->lh_Head; \
         ((struct Node *)(node))->ln_Succ; \
         (node) = (void *)((struct Node *)(node))->ln_Succ)
static void AddHead(struct List *list, struct Node *node)
{
    node->ln_Succ = list->lh_Head;
    node->ln_Pred = (struct Node *)&list->lh_Head;
    list->lh_Head->ln_Pred = node;
    list->lh_Head = node;
}
static void Remove(struct Node *node)
{
    node->ln_Pred->ln_Succ = node->ln_Succ;
    node->ln_Succ->ln_Pred = node->ln_Pred;
}
static int fail_range, fail_list, allocations, firmware_calls, list_calls;
static ULONG firmware_count;
static int allmulti_value, allmulti_error, list_allocations;
static void *AllocPooledClear(void *pool, size_t size)
{
    (void)pool;
    if (fail_range) return NULL;
    allocations++;
    return calloc(1, size);
}
static void *AllocVecPooled(void *pool, size_t size)
{
    (void)pool;
    if (fail_list) return NULL;
    assert(size <= PACKET_CTRL_MAX_MSG);
    list_allocations++;
    allocations++;
    return calloc(1, size);
}
static void FreePooled(void *pool, void *ptr, size_t size)
{
    (void)pool; (void)size;
    assert(ptr);
    allocations--;
    free(ptr);
}
static void FreeVecPooled(void *pool, void *ptr) { FreePooled(pool, ptr, 0); }
static int PacketSetVar(struct SDIO *sdio, const char *name, const void *data, int size)
{
    (void)sdio;
    assert(!strcmp(name, "mcast_list"));
    firmware_calls++;
    list_calls++;
    firmware_count = *(const ULONG *)data;
    assert(size == (int)(firmware_count * 6 + 4));
    return 0;
}
static int PacketSetVarInt(struct SDIO *sdio, const char *name, int value)
{
    (void)sdio;
    assert(!strcmp(name, "allmulti"));
    assert(value == 0 || value == 1);
    allmulti_value = value;
    firmware_calls++;
    return allmulti_error;
}
#include "multicast-under-test.inc"

static struct WiFiBase base;
static struct WiFiUnit unit;
static struct IOSana2Req io;
static int groups(void)
{
    int n = 0;
    struct MulticastRange *r;
    ForeachNode(&unit.wu_MulticastRanges, r) { assert(++n < 20); }
    return n;
}
static struct MulticastRange *first(void) { return (void *)unit.wu_MulticastRanges.lh_Head; }
static void request(int command, int address)
{
    memset(&io, 0, sizeof(io));
    io.ios2_Req.io_Unit = &unit;
    io.ios2_Req.io_Command = command;
    io.ios2_SrcAddr[0] = 1;
    io.ios2_SrcAddr[5] = (UBYTE)address;
}
static void add(int address) { request(S2_ADDMULTICASTADDRESS, address); assert(Do_S2_ADDMULTICASTADDRESSES(&io) == 1); }
static void del(int address) { request(S2_DELMULTICASTADDRESS, address); assert(Do_S2_DELMULTICASTADDRESSES(&io) == 1); }
static void noresources(void)
{
    assert(io.ios2_Req.io_Error == S2ERR_NO_RESOURCES);
    assert(io.ios2_WireError == S2WERR_BUFF_ERROR);
}
static void empty_list(void)
{
    unit.wu_MulticastRanges.lh_Head = (void *)&unit.wu_MulticastRanges.lh_Tail;
    unit.wu_MulticastRanges.lh_Tail = NULL;
    unit.wu_MulticastRanges.lh_TailPred = (void *)&unit.wu_MulticastRanges.lh_Head;
}
static void range_bounds(void)
{
    const ULONG maxCount = (PACKET_CTRL_MAX_MSG - sizeof(ULONG)) / 6;
    struct MulticastRange a = { 0 }, b = { 0 };
    empty_list();
    a.mr_UpperBound = UINT64_C(1) << 31;
    AddHead(&unit.wu_MulticastRanges, &a.node);
    int lists = list_allocations;
    assert(UpdateMCastList(&unit) == 0);
    assert(allmulti_value == 1 && list_allocations == lists && allocations == 0);
    a.mr_UpperBound = UINT64_C(1) << 32;
    assert(UpdateMCastList(&unit) == 0 && list_allocations == lists);
    a.mr_UpperBound = (UINT64_C(1) << 48) - 1;
    assert(UpdateMCastList(&unit) == 0 && list_allocations == lists);
    a.mr_UpperBound = maxCount - 1;
    assert(UpdateMCastList(&unit) == 0 && firmware_count == maxCount);
    assert(allmulti_value == 0 && allocations == 0);
    lists = list_allocations;
    a.mr_UpperBound = maxCount;
    assert(UpdateMCastList(&unit) == 0 && allmulti_value == 1);
    assert(list_allocations == lists);
    a.mr_UpperBound = maxCount / 2 - 1;
    b.mr_UpperBound = maxCount / 2;
    AddHead(&unit.wu_MulticastRanges, &b.node);
    assert(UpdateMCastList(&unit) == 0 && list_allocations == lists);
    allmulti_error = PACKET_CTRL_NORES;
    assert(UpdateMCastList(&unit) == S2ERR_NO_RESOURCES);
    allmulti_error = PACKET_CTRL_TIMEOUT;
    assert(UpdateMCastList(&unit) == S2ERR_OUTOFSERVICE);
    allmulti_error = 0;
    empty_list();
    firmware_calls = list_calls = 0;
}
static void wide_request(int command)
{
    request(command, 0);
    /* These endpoints describe a huge range on either host byte order. */
    memset(io.ios2_SrcAddr, 0, 6);
    memset(io.ios2_DstAddr, 255, 6);
}
static void wide_commands(void)
{
    allmulti_error = PACKET_CTRL_NORES;
    wide_request(S2_ADDMULTICASTADDRESSES);
    assert(Do_S2_ADDMULTICASTADDRESSES(&io) == 1);
    noresources();
    assert(groups() == 0 && allocations == 0);
    allmulti_error = PACKET_CTRL_TIMEOUT;
    wide_request(S2_ADDMULTICASTADDRESSES);
    assert(Do_S2_ADDMULTICASTADDRESSES(&io) == 1);
    assert(io.ios2_Req.io_Error == S2ERR_OUTOFSERVICE);
    assert(groups() == 0 && allocations == 0);
    allmulti_error = 0;
    wide_request(S2_ADDMULTICASTADDRESSES);
    assert(Do_S2_ADDMULTICASTADDRESSES(&io) == 1);
    assert(!io.ios2_Req.io_Error && groups() == 1 && allocations == 1);
    assert(allmulti_value == 1);
    /* Removing a different group while a wide range remains needs fallback;
       failure must put the removed group back. */
    add(1);
    assert(groups() == 2 && allocations == 2);
    allmulti_error = PACKET_CTRL_NORES;
    del(1); noresources();
    assert(groups() == 2 && allocations == 2);
    allmulti_error = 0;
    del(1);
    wide_request(S2_DELMULTICASTADDRESSES);
    assert(Do_S2_DELMULTICASTADDRESSES(&io) == 1);
    assert(!io.ios2_Req.io_Error && groups() == 0 && allocations == 0);
    assert(allmulti_value == 0);
    wide_request(S2_ADDMULTICASTADDRESSES);
    memset(io.ios2_SrcAddr, 255, 6);
    memset(io.ios2_DstAddr, 0, 6);
    int sent = firmware_calls;
    assert(Do_S2_ADDMULTICASTADDRESSES(&io) == 1);
    assert(io.ios2_Req.io_Error == S2ERR_BAD_ADDRESS);
    assert(io.ios2_WireError == S2WERR_BAD_MULTICAST);
    assert(groups() == 0 && allocations == 0 && firmware_calls == sent);
    io.ios2_Req.io_Command = S2_DELMULTICASTADDRESSES;
    assert(Do_S2_DELMULTICASTADDRESSES(&io) == 1);
    assert(io.ios2_Req.io_Error == S2ERR_BAD_ADDRESS && firmware_calls == sent);
}
int main(void)
{
    unit.wu_Base = &base;
    range_bounds();
    empty_list();

    fail_range = 1;
    add(1); noresources();
    assert(groups() == 0 && allocations == 0 && firmware_calls == 0);
    fail_range = 0; fail_list = 1;
    add(1); noresources();
    assert(groups() == 0 && allocations == 0 && firmware_calls == 0);
    fail_list = 0;
    add(1);
    assert(!io.ios2_Req.io_Error && groups() == 1 && allocations == 1);
    assert(list_calls == 1 && firmware_count == 1 && first()->mr_UseCount == 1);

    /* Existing subscriptions survive another group's failed allocation. */
    struct MulticastRange *original = first();
    int sent = firmware_calls;
    fail_list = 1;
    add(2); noresources();
    assert(groups() == 1 && first() == original && original->mr_UseCount == 1);
    assert(allocations == 1 && firmware_calls == sent);
    fail_range = 1;
    add(1);
    assert(!io.ios2_Req.io_Error && original->mr_UseCount == 2);
    del(1);
    assert(!io.ios2_Req.io_Error && original->mr_UseCount == 1);
    assert(firmware_calls == sent && allocations == 1);
    fail_range = 0;

    del(1); noresources();
    assert(groups() == 1 && first() == original && original->mr_UseCount == 1);
    assert(firmware_calls == sent && allocations == 1);
    fail_list = 0;
    add(2);
    assert(groups() == 2 && firmware_count == 2 && allocations == 2);
    fail_list = 1;
    sent = firmware_calls;
    del(1); noresources();
    assert(groups() == 2 && original->mr_UseCount == 1);
    assert(allocations == 2 && firmware_calls == sent);
    fail_list = 0;
    del(1);
    assert(groups() == 1 && firmware_count == 1 && allocations == 1);
    del(2);
    assert(groups() == 0 && firmware_count == 0 && allocations == 0);
    sent = firmware_calls;
    del(2);
    assert(!io.ios2_Req.io_Error && firmware_calls == sent);
    wide_commands();
    puts("PASS: multicast allocation failures, range bounds, fallback, rollback and retry");
    return 0;
}
