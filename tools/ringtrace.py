#!/usr/bin/env python3
"""Read a ringdump file (AmiNetXDuo #89), align it to a peer pcap, and list
what the driver did inside a silence.

  ringtrace.py decode DUMP                       one line per record
  ringtrace.py pcapmarks PCAP > MARKS            the alignment pings in a peer capture
  ringtrace.py align  DUMP MARKS                 clock model from paired pings
  ringtrace.py window DUMP MARKS START END       records and verdicts for a gap

MARKS is the peer capture's alignment pings (ICMP echo, IP length 1139,
ping -s 1111), one per line: epoch type id seq.  pcapmarks writes it from a
classic Ethernet pcap; tshark -Y 'icmp && ip.len==1139' -T fields -e
frame.time_epoch -e icmp.type -e icmp.ident -e icmp.seq gives the same.
START and END are peer epoch seconds.  Output is key=value, one fact a line.

Record fields (r_A, r_B, r_C, r_D) per kind:
  START  log2 capacity, timer present, bytes, 0
  WAKE   reasons (1 timer, 2 ctrl, 4 card irq, 8 poller, 16 ctrl-c),
         TX credit, frames received (cumulative), frames sent (cumulative)
  READ   index in the wake (0 = first look), frames in it (glom count,
         1 plain, 0 nothing), SDPCM length in bytes (0 = nothing),
         header: channel<<24 | rx seq<<16 | window end<<8 | flow bits
  TICK   unit (0 MICROHZ, 1 VBLANK) | 0x80 if taken back for a control
         request, 0, delay asked (us), time from arming to the wake (us)
  RXQ    openers, reads posted, frames delivered this wake, orphans this wake
  TX     frames in the glom, credit at the wake, frames sent (cumulative),
         s_TXSeq<<8 | s_MaxTXSeq after
  CREDIT 0 left zero, 1 reached zero, 2 initial non-zero, 3 initial zero;
         writes waiting, s_TXSeq, s_MaxTXSeq
  EVENT  event type (255 = 255 or more), BSS count for ESCAN_RESULT else
         flags, status, reason
  SCAN   0 S2_GETNETWORKS queued, 1 escan sent, 2 scan done; SSID given; status
  CTRL   0 sync entry, 1 sync exit, 2 async sent, 3 reply read, 4 sync sent;
         id, command, (entry/sent: first 4 payload bytes; exit: status;
         reply: firmware status)
  MARK   0 ping request read, 1 reply sent; ICMP type, id<<16 | seq,
         frame length (RX) or glom size<<16 | index (TX)
  POLL   1 line seen, 2 woke receiver for a write, 3 grace ran out,
         4 woken; 0, us since the poller last looked, counter
"""
import struct
import sys

KINDS = {1: "START", 2: "WAKE", 3: "READ", 4: "TICK", 5: "RXQ", 6: "TX",
         7: "CREDIT", 8: "EVENT", 9: "SCAN", 10: "CTRL", 11: "MARK", 12: "POLL"}
E_ESCAN_RESULT = 69
SCAN_EVENTS = {E_ESCAN_RESULT, 26, 19, 32, 37, 36, 38, 9, 11, 12, 5, 6, 16}
# 26 SCAN_COMPLETE, 19 ROAM, 32 ROAM_PREP, 37 ROAM_START, 36 JOIN_START,
# 38 ASSOC_START, 9 REASSOC, 11/12 DISASSOC(_IND), 5/6 DEAUTH(_IND), 16 LINK


def load(path):
    b = open(path, "rb").read()
    (magic, ver, rsz, cap, seq, first, count, lost, clo) = struct.unpack(">IHHIIIIII", b[:32])
    if magic != 0x52544431 or ver != 1 or rsz != 16:
        sys.exit("ringtrace=fail reason=not_a_dump")
    if len(b) != 32 + 16 * count:
        sys.exit("ringtrace=fail reason=truncated")
    recs, wrap, prev = [], 0, None
    for i in range(count):
        c, k, a, bb, cc, dd = struct.unpack(">IBBHII", b[32 + 16 * i:48 + 16 * i])
        if prev is not None and c < prev:
            wrap += 1               # CLO is monotonic in write order: a drop is a wrap
        prev = c
        recs.append({"seq": first + i, "clo": c, "t": c + (wrap << 32), "k": k,
                     "a": a, "b": bb, "c": cc, "d": dd})
    tail = clo + ((wrap + (1 if prev is not None and clo < prev else 0)) << 32)
    return {"cap": cap, "seq": seq, "first": first, "count": count, "lost": lost,
            "clo": clo, "t_dump": tail}, recs


def fmt(r):
    return "seq=%d t_us=%d kind=%s a=%d b=%d c=%d d=%d" % (
        r["seq"], r["t"], KINDS.get(r["k"], str(r["k"])), r["a"], r["b"], r["c"], r["d"])


def pcap_marks(path):
    m = {}
    for line in open(path):
        f = line.split()
        if len(f) < 4:
            continue
        ep, typ = float(f[0]), int(f[1], 0)
        ident, sq = int(f[2].split(",")[0], 0), int(f[3].split(",")[0], 0)
        m.setdefault((ident, sq), {})[typ] = ep
    return m


def cmd_pcapmarks(path):
    b = open(path, "rb").read()
    magic = b[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        e = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        e = ">"
    else:
        sys.exit("ringtrace=fail reason=not_a_pcap")
    frac = 1e9 if magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1e6
    if struct.unpack(e + "I", b[20:24])[0] != 1:
        sys.exit("ringtrace=fail reason=not_ethernet")
    o = 24
    while o + 16 <= len(b):
        sec, sub, incl, _ = struct.unpack(e + "IIII", b[o:o + 16])
        f = b[o + 16:o + 16 + incl]
        o += 16 + incl
        if len(f) < 42 or f[12:14] != b"\x08\x00" or f[14] != 0x45 or f[23] != 1:
            continue
        if struct.unpack(">H", f[16:18])[0] != 1139 or f[34] not in (0, 8):
            continue
        ident, sq = struct.unpack(">HH", f[38:42])
        print("%d.%06d\t%d\t%d\t%d" % (sec, int(sub * 1e6 / frac), f[34], ident, sq))


def pings(recs, pm):
    """(A2, A3, T1, T4) in seconds for each ping seen at both ends"""
    rx, tx = {}, {}
    for r in recs:
        if r["k"] == 11:
            key = (r["c"] >> 16, r["c"] & 0xffff)
            (rx if r["a"] == 0 else tx).setdefault(key, r["t"] / 1e6)
    out = []
    for key, p in pm.items():
        if key in rx and key in tx and 8 in p and 0 in p:
            out.append((rx[key], tx[key], p[8], p[0]))
    return sorted(out)


def model(ps):
    """Offset and drift from the tightest ping at each end of the run"""
    if not ps:
        sys.exit("ringtrace=fail reason=no_paired_pings")
    def est(p):
        a2, a3, t1, t4 = p
        return ((a2 - t1) + (a3 - t4)) / 2, (t4 - t1) - (a3 - a2)
    mid = (ps[0][0] + ps[-1][0]) / 2
    head = [p for p in ps if p[0] <= mid]
    tail = [p for p in ps if p[0] > mid] or head
    s = min(head, key=lambda p: est(p)[1])
    e = min(tail, key=lambda p: est(p)[1])
    (ts, ds), (te, de) = est(s), est(e)
    drift = (te - ts) / (e[0] - s[0]) if e[0] != s[0] else 0.0
    return {"a_s": s[0], "theta_s": ts, "drift": drift, "bound": max(ds, de) / 2,
            "delta_s": ds, "delta_e": de, "paired": e is not s}


def to_peer(m, a):
    return a - (m["theta_s"] + m["drift"] * (a - m["a_s"]))


def cmd_align(dump, marks):
    h, recs = load(dump)
    ps = pings(recs, pcap_marks(marks))
    m = model(ps)
    bad = 0
    for a2, a3, t1, t4 in ps:           # causality: the Amiga's read and reply lie inside the ping
        if not (t1 - m["bound"] <= to_peer(m, a2) <= to_peer(m, a3) <= t4 + m["bound"]):
            bad += 1
    print("pings=%d paired=%d theta_s=%.6f theta_rate_ppm=%.3f bound_ms=%.3f delta_start_ms=%.3f "
          "delta_end_ms=%.3f causality_violations=%d lost=%d" % (
              len(ps), m["paired"], m["theta_s"], m["drift"] * 1e6, m["bound"] * 1e3,
              m["delta_s"] * 1e3, m["delta_e"] * 1e3, bad, h["lost"]))
    return m, h, recs


def cmd_window(dump, marks, start, end):
    m, h, recs = cmd_align(dump, marks)
    # listed with the bound either side; judged on the gap proper
    lo, hi = float(start), float(end)
    wide = [r for r in recs if lo - m["bound"] <= to_peer(m, r["t"] / 1e6) <= hi + m["bound"]]
    inw = [r for r in recs if lo <= to_peer(m, r["t"] / 1e6) <= hi]
    before = [r for r in recs if to_peer(m, r["t"] / 1e6) < lo]
    first_t = to_peer(m, recs[0]["t"] / 1e6) if recs else None
    covered = h["lost"] == 0 or (first_t is not None and first_t < lo - m["bound"])
    print("window_s=%.6f..%.6f bound_ms=%.3f records=%d listed=%d covered=%d" % (
        lo, hi, m["bound"] * 1e3, len(inw), len(wide), covered))
    for r in wide:
        print("peer_t=%.6f %s" % (to_peer(m, r["t"] / 1e6), fmt(r)))

    def kind(k): return [r for r in inw if r["k"] == k]
    # (a) scan or roam: host-started scan, or a scan/roam/link event, inside or spanning
    scan_open = False
    for r in before:
        if r["k"] == 9 and r["a"] == 1: scan_open = True
        if r["k"] == 9 and r["a"] == 2: scan_open = False
    ev = [r for r in kind(8) if r["a"] in SCAN_EVENTS]
    sc = kind(9)
    a = "yes" if (ev or sc or scan_open) else "no_host_or_reported"
    # (c) credit held at 0 with nothing read
    cred = None
    for r in before:
        if r["k"] == 7: cred = r["a"] in (1, 3)
    zero_all = cred is True and not [r for r in kind(7) if r["a"] == 0]
    reads = [r for r in kind(3) if r["c"]]
    looks = [r for r in kind(3) if r["c"] == 0]
    c = "yes" if zero_all and not reads else ("partial" if cred or [r for r in kind(7) if r["a"] == 1] else "no")
    # late wake-ups: tick lateness and the longest stretch with no receiver wake
    late = max([r["d"] - r["c"] for r in kind(4)] or [0])
    wakes = [r["t"] for r in kind(2)]
    edges = [to_peer(m, x / 1e6) for x in wakes]
    stretch = max([b - a_ for a_, b in zip([lo] + edges, edges + [hi])] or [hi - lo])
    ctrl_open = [r for r in kind(10) if r["a"] == 0]
    print("candidate_a_scan=%s scan_events=%d scan_records=%d scan_open_at_start=%d" % (
        a, len(ev), len(sc), scan_open))
    print("candidate_c_credit=%s credit_zero_at_start=%s credit_records=%d reads_with_data=%d empty_looks=%d" % (
        c, cred, len(kind(7)), len(reads), len(looks)))
    print("late_wakeups tick_late_max_us=%d longest_no_wake_ms=%.3f poll_records=%d sync_ctrl_entries=%d" % (
        late, stretch * 1e3, len(kind(12)), len(ctrl_open)))
    if reads:
        r = reads[0]
        print("first_read_with_data peer_t=%.6f frames=%d bytes=%d" % (
            to_peer(m, r["t"] / 1e6), r["b"], r["c"]))


def main():
    if len(sys.argv) >= 3 and sys.argv[1] == "decode":
        h, recs = load(sys.argv[2])
        print("capacity=%d seq=%d first=%d count=%d lost=%d clo_dump=%d t_dump_us=%d" % (
            h["cap"], h["seq"], h["first"], h["count"], h["lost"], h["clo"], h["t_dump"]))
        for r in recs:
            print(fmt(r))
    elif len(sys.argv) == 3 and sys.argv[1] == "pcapmarks":
        cmd_pcapmarks(sys.argv[2])
    elif len(sys.argv) == 4 and sys.argv[1] == "align":
        cmd_align(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 6 and sys.argv[1] == "window":
        cmd_window(*sys.argv[2:6])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
