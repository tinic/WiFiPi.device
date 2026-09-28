#!/usr/bin/env python3
"""Read a ringdump file (AmiNetXDuo #89), align it to a peer pcap, and list
what the driver did inside a silence.

  ringtrace.py decode DUMP                       one line per record
  ringtrace.py pcapmarks PCAP > MARKS            the alignment pings in a peer capture
  ringtrace.py align  DUMP MARKS                 clock model from paired pings
  ringtrace.py window DUMP MARKS START END       records and verdicts for a gap
  ringtrace.py txjoin DUMP PCAP START END [W] [--times TIMES]
                                                 each TX TCP frame the host produced in the gap:
                                                 SEEN / UNSEEN / AMBIGUOUS / CENSORED at the peer
  ringtrace.py rxjoin DUMP PCAP START END [W] [--times TIMES]
                                                 each TCP frame the host received in the gap, matched
                                                 to the peer's send; the gap's exit frame and release ACK
  ringtrace.py gaps   PCAP PORT [GAP_MS]         peer-capture silences (data and ACK) > GAP_MS

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
  TXID1  (IPv4 TCP frame copied into the glom, then TXID2 as the very next
         record) TCP flags, IP id, ACK number, sequence number
  TXID2  glom index, count<<8 | SDPCM seq, sport<<16 | dport,
         src last octet<<24 | dst last octet<<16 | TCP payload length
  TXO    (any other frame) glom index, count<<8 | SDPCM seq,
         ethertype<<16 | IP protocol (0xff not parsed), frame length
  TXRC   (after each glom's CMD53 write) status: 1 block part issued,
         2 it succeeded, 4 remainder part issued, 8 it succeeded (no retries
         exist); first SDPCM seq<<8 | frames; us in the write; interrupt
         status of the part that failed (0 none)
  RXID1  (IPv4 TCP frame at the handoff to the stack, then RXID2 as the very
         next record) TCP flags, IP id, ACK number, sequence number
  RXID2  index in its glom, outcome<<8 | SDPCM rx seq, sport<<16 | dport,
         src last octet<<24 | dst last octet<<16 | TCP payload length;
         outcome 1 read, 2 read replied with an error, 3 orphan listener,
         4 dropped (no read, no orphan listener), 5 filtered multicast
  RXO    (any other frame) index, outcome<<8 | SDPCM seq,
         ethertype<<16 | IP protocol (0xff not parsed), frame length
"""
import struct
import sys

KINDS = {1: "START", 2: "WAKE", 3: "READ", 4: "TICK", 5: "RXQ", 6: "TX",
         7: "CREDIT", 8: "EVENT", 9: "SCAN", 10: "CTRL", 11: "MARK", 12: "POLL",
         13: "TXID1", 14: "TXID2", 15: "TXO", 16: "TXRC", 17: "RXID1", 18: "RXID2", 19: "RXO"}
RX_OUT = {1: "read", 2: "read_error", 3: "orphan", 4: "dropped", 5: "filtered"}
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


def pcap_frames(path):
    """(epoch seconds, frame bytes) from a classic Ethernet pcap (us or ns)"""
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
        yield sec, int(sub * 1e6 / frac), b[o + 16:o + 16 + incl]
        o += 16 + incl


def ping_rows(path):
    for sec, us, f in pcap_frames(path):
        if len(f) < 42 or f[12:14] != b"\x08\x00" or f[14] != 0x45 or f[23] != 1:
            continue
        if struct.unpack(">H", f[16:18])[0] != 1139 or f[34] not in (0, 8):
            continue
        ident, sq = struct.unpack(">HH", f[38:42])
        yield sec + us / 1e6, "%d.%06d\t%d\t%d\t%d" % (sec, us, f[34], ident, sq), (f[34], ident, sq)


def cmd_pcapmarks(path):
    for _, line, _ in ping_rows(path):
        print(line)


def marks_from_pcap(path):
    m = {}
    for ep, _, (typ, ident, sq) in ping_rows(path):
        m.setdefault((ident, sq), {})[typ] = ep
    return m


def txrc_state(a):
    if not a & 5:
        return "unknown"
    return "failed" if (a & 1 and not a & 2) or (a & 4 and not a & 8) else "ok"


def tx_frames(recs):
    """TX TCP frames: a TXID1 and the TXID2 written right after it.  A frame takes
    its glom's write result only from the FIRST TXRC after it in record order, and
    only if that TXRC is its glom's: same frame count, SDPCM range holding its seq.
    A glom ends at that TXRC, or at the next glom's first frame (index 0) when its
    TXRC is missing; its frames then stay write=unknown, never a later glom's."""
    out, pending = [], []
    for i, r in enumerate(recs):
        n = recs[i + 1] if i + 1 < len(recs) else None
        k = r["k"]
        if (k == 13 and n is not None and n["k"] == 14 and n["seq"] == r["seq"] + 1 and n["a"] == 0) or \
           (k == 15 and r["a"] == 0):
            pending = []                    # a new glom call: the last one's TXRC never came
        if k == 13 and n is not None and n["k"] == 14 and n["seq"] == r["seq"] + 1:
            fr = {"t": r["t"], "flags": r["a"], "ipid": r["b"], "ack": r["c"], "seq": r["d"],
                  "idx": n["a"], "count": n["b"] >> 8, "sdpcm": n["b"] & 0xff,
                  "sport": n["c"] >> 16, "dport": n["c"] & 0xffff,
                  "src": n["d"] >> 24, "dst": (n["d"] >> 16) & 0xff, "len": n["d"] & 0xffff,
                  "write": "unknown", "write_us": None}
            out.append(fr)
            pending.append(fr)
        elif k == 16:
            first, cnt = r["b"] >> 8, r["b"] & 0xff
            for fr in pending:
                if fr["count"] == cnt and (fr["sdpcm"] - first) & 0xff < cnt and \
                   (fr["sdpcm"] - first) & 0xff == fr["idx"]:
                    fr["write"], fr["write_us"] = txrc_state(r["a"]), r["c"]
            pending = []
    return out


def peer_tcp(path):
    """Every IPv4 TCP frame in the peer capture, with all the fields the host records"""
    out = []
    for sec, us, f in pcap_frames(path):
        if len(f) < 34 or f[12:14] != b"\x08\x00" or f[14] >> 4 != 4 or f[23] != 6:
            continue
        ihl = (f[14] & 15) * 4
        if ihl < 20 or len(f) < 14 + ihl + 14:
            continue
        tot = struct.unpack(">H", f[16:18])[0]
        if (struct.unpack(">H", f[20:22])[0] & 0x1fff) or tot < ihl + 20:
            continue
        th = 14 + ihl
        doff = (f[th + 12] >> 4) * 4
        mss = None
        if f[th + 13] & 0x02:                       # SYN: the MSS option, if captured
            o, oe = th + 20, min(th + doff, len(f))
            while o < oe:
                if f[o] == 0:
                    break
                if f[o] == 1:
                    o += 1; continue
                if o + 1 >= oe or f[o + 1] < 2:
                    break
                if f[o] == 2 and f[o + 1] == 4 and o + 4 <= oe:
                    mss = struct.unpack(">H", f[o + 2:o + 4])[0]
                o += f[o + 1]
        out.append({"ep": sec + us / 1e6, "src": bytes(f[26:30]), "dst": bytes(f[30:34]),
                    "sport": struct.unpack(">H", f[th:th + 2])[0], "dport": struct.unpack(">H", f[th + 2:th + 4])[0],
                    "ipid": struct.unpack(">H", f[18:20])[0], "seq": struct.unpack(">I", f[th + 4:th + 8])[0],
                    "ack": struct.unpack(">I", f[th + 8:th + 12])[0], "flags": f[th + 13], "doff": doff, "mss": mss,
                    "len": tot - ihl - doff if doff >= 20 and ihl + doff <= tot else 0})
    return out


def peer_segments(peer):
    """The peer capture as wire segments.  A peer frame is captured before the
    NIC's segmentation (GSO/TSO): one longer than a segment is split into
    segments of (MSS the receiver advertised in its SYN, else 1460) minus the
    frame's TCP option bytes.  Segment k: seq + k*size, len min(size, rest),
    the same ACK and ports; every segment carries the frame's flags but FIN
    and PSH, which only the last carries (as TSO does)."""
    adv = {}
    for p in peer:
        if p["mss"]:
            adv[(p["src"], p["sport"])] = p["mss"]
    out = []
    for n, p in enumerate(peer):
        size = adv.get((p["dst"], p["dport"]), 1460) - max(p["doff"] - 20, 0)
        if p["len"] <= size or size <= 0:
            q = dict(p); q["super"] = n; q["k"] = 0; q["super_len"] = p["len"]
            out.append(q)
            continue
        k, off = 0, 0
        while off < p["len"]:
            q = dict(p)
            q["seq"] = (p["seq"] + off) & 0xffffffff
            q["len"] = min(size, p["len"] - off)
            last = off + q["len"] >= p["len"]
            q["flags"] = p["flags"] if last else p["flags"] & ~0x09
            q["super"], q["k"], q["super_len"] = n, k, p["len"]
            out.append(q)
            off += q["len"]; k += 1
    return out


def rxkey(x):
    """The RX match key: flow, flags, seq, payload length (IP id and ACK are not matched)"""
    src, dst = x["src"], x["dst"]
    if isinstance(src, bytes):
        src, dst = src[3], dst[3]
    return (src, dst, x["sport"], x["dport"], x["flags"], x["seq"], x["len"])


def txkey(x):
    """All the discriminators a TX identity pair records; last octets for the addresses"""
    src, dst = x["src"], x["dst"]
    if isinstance(src, bytes):
        src, dst = src[3], dst[3]
    return (src, dst, x["sport"], x["dport"], x["flags"], x["ipid"], x["ack"], x["seq"], x["len"])


FLAGS = "FSRPAUEC"
# Join window W, PROVISIONAL at 1 s.  It should be the clock bound plus the
# host-copy-to-peer delay, which no run has measured yet: delays of frames
# matched inside W are truncated at W and do not calibrate it.  (The 464 ms of
# hw20 is the longest inter-arrival silence, not a latency bound.)  txjoin
# prints the bound, the largest SEEN delay and how many UNSEEN frames would
# match with W = 5 s; W is never below 0.5 s.
TXJOIN_W = 1.0
TXJOIN_W_MIN = 0.5
TXJOIN_W_WIDE = 5.0


def flagstr(v):
    return "".join(c for i, c in enumerate(FLAGS) if v & (1 << i)) or "-"


def ipstr(b):
    return ".".join(str(x) for x in b)


def capture_span(peer_first, peer_last, times=None):
    """The time the capture certainly covers: its first to last packet, cut to
    ph3cap.sh's capture_start .. capture_stop_req when the times file is given"""
    lo, hi = peer_first, peer_last
    if times:
        for line in open(times):
            f = line.split()
            if len(f) >= 2 and f[0] == "capture_start":
                lo = max(lo, float(f[1]))
            elif len(f) >= 2 and f[0] == "capture_stop_req":
                hi = min(hi, float(f[1]))
    return lo, hi


def cmd_txjoin(dump, pcap, start, end, w=TXJOIN_W, times=None):
    """SEEN: exactly one peer frame with every recorded field equal, at peer time in
    [host_t - bound, host_t + w]; AMBIGUOUS: more than one; UNSEEN: none, with that
    whole window inside the capture; CENSORED: none, the window not all captured."""
    h, recs = load(dump)
    m = model(pings(recs, marks_from_pcap(pcap)))
    lo, hi, w = float(start), float(end), max(float(w), TXJOIN_W_MIN)
    t_end = to_peer(m, h["t_dump"] / 1e6)
    eps = [sec + us / 1e6 for sec, us, _ in pcap_frames(pcap)]
    c_lo, c_hi = capture_span(min(eps), max(eps), times)
    peer = peer_tcp(pcap)
    byk = {}
    for p in peer:
        byk.setdefault(txkey(p), []).append(p)
    first_t = to_peer(m, recs[0]["t"] / 1e6) if recs else None
    covered = h["lost"] == 0 or (first_t is not None and first_t < lo - m["bound"])
    print("window_s=%.6f..%.6f bound_ms=%.3f join_window=[host_t-%.3f ms, host_t+%.3f s] (W provisional) "
          "capture=%.6f..%.6f covered=%d lost=%d dump_end=%.6f" % (
              lo, hi, m["bound"] * 1e3, m["bound"] * 1e3, w, c_lo, c_hi, covered, h["lost"], t_end))
    print("note=UNSEEN means absent at the peer within the join window after the host write shown; "
          "with write=ok it does not locate where the frame was lost.  CENSORED: the window is not all in the capture")
    frames = [fr for fr in tx_frames(recs) if lo <= to_peer(m, fr["t"] / 1e6) <= hi]
    # endpoint mapping: recorded octets and ports -> the capture's full addresses
    pflows = {}
    for p in peer:
        pflows.setdefault((p["src"][3], p["dst"][3], p["sport"], p["dport"]), set()).add(
            (ipstr(p["src"]), ipstr(p["dst"]), p["sport"], p["dport"]))
    hflows = sorted({(f["src"], f["dst"], f["sport"], f["dport"]) for f in frames})
    for hf in hflows:
        full = sorted(pflows.get(hf, ()))
        tag = "flow=.%d:%d>.%d:%d" % (hf[0], hf[2], hf[1], hf[3])
        if not full:
            print("flow_map %s UNMAPPED (no capture flow has these octets and ports)" % tag)
        for f in full:
            print("flow_map %s pcap=%s:%d>%s:%d%s" % (tag, f[0], f[2], f[1], f[3], " AMBIGUOUS_MAP" if len(full) > 1 else ""))
    K = {"SEEN": 1, "UNSEEN": 2, "AMBIGUOUS": 3, "CENSORED": 4}
    stats, tot, wstats, delays, wide = {}, [0, 0, 0, 0, 0], {}, [], []
    for fr in frames:
        pt = to_peer(m, fr["t"] / 1e6)
        cands = byk.get(txkey(fr), [])
        cand = [p for p in cands if pt - m["bound"] <= p["ep"] <= pt + w]
        if len(cand) == 1:
            cls = "SEEN"
        elif cand:
            cls = "AMBIGUOUS"
        elif c_lo <= pt - m["bound"] and pt + w <= c_hi:
            cls = "UNSEEN"
        else:
            cls = "CENSORED"
        what = cls + (" peer_t=%.6f delay_ms=%.3f" % (cand[0]["ep"], (cand[0]["ep"] - pt) * 1e3) if cls == "SEEN"
                      else " candidates=%d" % len(cand) if cls == "AMBIGUOUS"
                      else " to_dump_end_s=%.3f" % (t_end - pt))
        if cls == "SEEN":
            delays.append((cand[0]["ep"] - pt) * 1e3)
        if cls == "UNSEEN":
            late = [p for p in cands if pt - m["bound"] <= p["ep"] <= pt + TXJOIN_W_WIDE]
            if late:
                wide.append((len(late), (late[0]["ep"] - pt) * 1e3))
        flow = ".%d:%d>.%d:%d" % (fr["src"], fr["sport"], fr["dst"], fr["dport"])
        st = stats.setdefault(flow, [0, 0, 0, 0, 0])
        for a in (st, tot):
            a[0] += 1; a[K[cls]] += 1
        wr = fr["write"] + ("" if fr["write_us"] is None else " write_us=%d" % fr["write_us"])
        print("host_t=%.6f flow=%s ip_id=%d ack=%d seq=%d flags=%s len=%d sdpcm=%d glom=%d/%d write=%s %s" % (
            pt, flow, fr["ipid"], fr["ack"], fr["seq"], flagstr(fr["flags"]), fr["len"],
            fr["sdpcm"], fr["idx"], fr["count"], wr, what))
        wst = wstats.setdefault(flow, {"ok": 0, "failed": 0, "unknown": 0})
        wst[fr["write"]] += 1
    for flow, st in sorted(stats.items()):
        print("flow=%s write_ok=%d write_failed=%d write_unknown=%d" % (flow, wstats[flow]["ok"], wstats[flow]["failed"], wstats[flow]["unknown"]))
        print("flow=%s produced_at_host=%d seen=%d unseen=%d ambiguous=%d censored=%d" % ((flow,) + tuple(st)))
    print("bound_ms=%.3f seen_delay_max_ms=%s seen_n=%d (delays inside W only: not a calibration of W)" % (
        m["bound"] * 1e3, "%.3f" % max(delays) if delays else "none", len(delays)))
    print("sensitivity W=%.1f s: unseen_matching=%d unique=%d delays_ms=%s" % (
        TXJOIN_W_WIDE, len(wide), sum(1 for n, _ in wide if n == 1),
        ",".join("%.1f" % d for _, d in wide) or "-"))
    print("produced_at_host=%d seen=%d unseen=%d ambiguous=%d censored=%d" % tuple(tot))


def rx_frames(recs):
    """RX TCP frames at the stack handoff: an RXID1 and the RXID2 right after it"""
    out = []
    for r, n in zip(recs, recs[1:]):
        if r["k"] == 17 and n["k"] == 18 and n["seq"] == r["seq"] + 1:
            out.append({"t": r["t"], "flags": r["a"], "ipid": r["b"], "ack": r["c"], "seq": r["d"],
                        "idx": n["a"], "outcome": RX_OUT.get(n["b"] >> 8, "unknown"), "sdpcm": n["b"] & 0xff,
                        "sport": n["c"] >> 16, "dport": n["c"] & 0xffff,
                        "src": n["d"] >> 24, "dst": (n["d"] >> 16) & 0xff, "len": n["d"] & 0xffff})
    return out


def seq_after(a, b):
    """a is at or after b in 32-bit sequence space"""
    return ((a - b) & 0xffffffff) < 0x80000000


def cmd_rxjoin(dump, pcap, start, end, w=TXJOIN_W, times=None):
    """Each TCP frame the host handed to the stack with host_t in [START, END], matched
    to a peer wire segment (super-frames split, see peer_segments) with the same flow,
    flags, seq and length, sent in [host_t - W, host_t + bound]: SEEN (unique; delay =
    host_t - peer_t: air, AP, chip and driver), AMBIGUOUS (retx_candidates=N: the seq was
    sent more than once in the window, each copy listed with its delay), UNSEEN (none, the window inside the capture) or
    CENSORED.  A SEEN frame names its copy by send order among all the capture's copies
    of that key: original, or retx N (the original may lie outside the window).
    The edge: the release ACK (first host ACK whose unique peer arrival is in (START, END]),
    its trigger (latest SEEN host data read before it that it covers), their delays; the
    resume segment (the peer's frame at END) apart.  Exits no_rx_identity when the ring
    holds no RX identity records within [START - W, END + W]."""
    h, recs = load(dump)
    m = model(pings(recs, marks_from_pcap(pcap)))
    lo, hi, w = float(start), float(end), max(float(w), TXJOIN_W_MIN)
    eps = [sec + us / 1e6 for sec, us, _ in pcap_frames(pcap)]
    c_lo, c_hi = capture_span(min(eps), max(eps), times)
    peer = peer_tcp(pcap)
    segs = peer_segments(peer)
    byk = {}
    for p in segs:
        byk.setdefault(rxkey(p), []).append(p)
    for v in byk.values():
        v.sort(key=lambda p: p["ep"])
        for i, p in enumerate(v):
            p["copy"] = i
    # a ring without RX identity near the window (a pre-RX driver, a pre-arm ring) cannot answer
    near = [r for r in recs if r["k"] in (17, 18, 19) and lo - w <= to_peer(m, r["t"] / 1e6) <= hi + w]
    if not near:
        sys.exit("ringtrace=fail reason=no_rx_identity (no RXID/RXO record within [START - W, END + W])")
    rxs = rx_frames(recs)
    # covered: nothing lost, or the first kept record precedes the earliest send a frame here could match
    first_t = to_peer(m, recs[0]["t"] / 1e6) if recs else None
    covered = h["lost"] == 0 or (first_t is not None and first_t < lo - w)
    for fr in rxs:
        fr["pt"] = to_peer(m, fr["t"] / 1e6)
        cand = [p for p in byk.get(rxkey(fr), []) if fr["pt"] - w <= p["ep"] <= fr["pt"] + m["bound"]]
        fr["cand"] = cand
        if len(cand) == 1:
            fr["cls"] = "SEEN"
        elif cand:
            fr["cls"] = "AMBIGUOUS"
        elif c_lo <= fr["pt"] - w and fr["pt"] + m["bound"] <= c_hi:
            fr["cls"] = "UNSEEN"
        else:
            fr["cls"] = "CENSORED"
    print("window_s=%.6f..%.6f bound_ms=%.3f join_window=[host_t-%.3f s, host_t+%.3f ms] (W provisional) capture=%.6f..%.6f covered=%d lost=%d" % (
        lo, hi, m["bound"] * 1e3, w, m["bound"] * 1e3, c_lo, c_hi, covered, h["lost"]))
    print("note=key flow+flags+seq+len on the peer's wire segments (super-frames split); ip_id and ack shown, not matched. "
          "delay_ms is host handoff minus peer send: air, AP, chip and driver together")
    inw = [fr for fr in rxs if lo <= fr["pt"] <= hi]
    tot = {"SEEN": 0, "UNSEEN": 0, "AMBIGUOUS": 0, "CENSORED": 0}
    outc, delays = {}, []
    for fr in inw:
        tot[fr["cls"]] += 1
        outc[fr["outcome"]] = outc.get(fr["outcome"], 0) + 1
        extra = ""
        if fr["cls"] == "SEEN":
            c = fr["cand"][0]
            d = (fr["pt"] - c["ep"]) * 1e3
            delays.append(d)
            extra = " peer_tx_t=%.6f delay_ms=%.3f segment=%d/%dB copy=%s" % (
                c["ep"], d, c["k"], c["super_len"], "original" if c["copy"] == 0 else "retx%d" % c["copy"])
        elif fr["cls"] == "AMBIGUOUS":
            extra = " retx_candidates=%d copies=%s" % (len(fr["cand"]), ",".join(
                "%s@%.3fms" % ("original" if c["copy"] == 0 else "retx%d" % c["copy"], (fr["pt"] - c["ep"]) * 1e3)
                for c in fr["cand"]))
        print("host_rx_t=%.6f flow=.%d:%d>.%d:%d ip_id=%d seq=%d ack=%d flags=%s len=%d sdpcm=%d glom_idx=%d outcome=%s %s%s" % (
            fr["pt"], fr["src"], fr["sport"], fr["dst"], fr["dport"], fr["ipid"], fr["seq"], fr["ack"],
            flagstr(fr["flags"]), fr["len"], fr["sdpcm"], fr["idx"], fr["outcome"], fr["cls"], extra))
    data = [fr for fr in inw if fr["len"]]
    if data:
        s0 = min(data, key=lambda f: f["pt"])
        sent = [f["cand"][0]["ep"] for f in data if f["cls"] == "SEEN"]
        print("arrived frames=%d bytes=%d seq_first=%d seq_last_end=%d peer_sent=%s outcomes=%s" % (
            len(data), sum(f["len"] for f in data), s0["seq"],
            max(((f["seq"] + f["len"]) & 0xffffffff for f in data), key=lambda v: (v - s0["seq"]) & 0xffffffff),
            "%.6f..%.6f" % (min(sent), max(sent)) if sent else "-",
            ",".join("%s=%d" % kv for kv in sorted(outc.items()))))
    if delays:
        print("rx_delay_ms n=%d max=%.3f (inside W only)" % (len(delays), max(delays)))
    # the edge, anchored on the release ACK: the first host ACK whose unique peer arrival is in
    # (START, END]; its trigger is the latest SEEN host data read before that ACK which it covers.
    # END is the peer's first frame after the gap: the last peer segment at or before END is the
    # resume, reported apart and not used for the edge.  Clocks: host_* values are the ring's CLO
    # (us) and their peer mapping; peer_* values are the capture's.  A delay across the two carries
    # the alignment bound; one inside the ring carries ~0.  Without an edge rxjoin exits 3.
    bms = m["bound"] * 1e3
    dflows = {(p["dst"][3], p["src"][3], p["dport"], p["sport"]) for p in segs if p["len"] > 0}
    ptx = byk_tx(peer)
    rel, cand_rel = None, []
    for a in sorted(tx_frames(recs), key=lambda f: f["t"]):
        if not a["flags"] & 0x10 or (a["src"], a["dst"], a["sport"], a["dport"]) not in dflows:
            continue
        at = to_peer(m, a["t"] / 1e6)
        cand = [p for p in ptx.get(txkey(a), []) if at - m["bound"] <= p["ep"] <= at + w]
        if any(lo < p["ep"] <= hi for p in cand):
            rel, cand_rel = a, cand
            break
    why = None
    if rel is None:
        why = "no host ACK with a peer arrival in (START, END]"
    elif len(cand_rel) != 1:
        why = "release ACK ambiguous: %d peer copies of its identity in the join window" % len(cand_rel)
    else:
        at = to_peer(m, rel["t"] / 1e6)
        print("release_ack host_tx_clo_us=%d host_tx_peer=%.6f ack=%d ip_id=%d peer_rx_peer=%.6f write=%s "
              "unique=one peer copy of its full identity in [host_tx-bound, host_tx+W]; first host ACK arriving in (START, END]" % (
                  rel["t"], at, rel["ack"], rel["ipid"], cand_rel[0]["ep"], rel["write"]))
        covd = [fr for fr in rxs if fr["len"] > 0 and fr["pt"] < at
                and fr["src"] == rel["dst"] and fr["dst"] == rel["src"]
                and fr["sport"] == rel["dport"] and fr["dport"] == rel["sport"]
                and seq_after(rel["ack"], (fr["seq"] + fr["len"]) & 0xffffffff)]
        seen = [fr for fr in covd if fr["cls"] == "SEEN"]
        if not seen:
            why = "no SEEN host data read before the release ACK that it covers"
        else:
            r = max(seen, key=lambda f: f["pt"])
            c = r["cand"][0]
            rival = [fr for fr in covd if fr is not r and fr["pt"] >= r["pt"]]
            print("trigger_evidence seq_end=%d <= ack=%d; other covered reads between it and the ACK: %d%s" % (
                (r["seq"] + r["len"]) & 0xffffffff, rel["ack"], len(rival),
                "" if not rival else " (%s)" % ",".join("seq=%d:%s" % (f["seq"], f["cls"]) for f in rival)))
            if rival:
                why = "trigger ambiguous: %d other covered read(s) at or after the chosen read" % len(rival)
            else:
                rd = (r["pt"] - c["ep"]) * 1e3          # across clocks: carries the bound
                ap = (rel["t"] - r["t"]) / 1e3          # same clock: straight from the ring
                print("trigger_segment peer_tx_peer=%.6f seq=%d len=%d segment=%d/%dB host_rx_clo_us=%d host_rx_peer=%.6f outcome=%s" % (
                    c["ep"], r["seq"], r["len"], c["k"], c["super_len"], r["t"], r["pt"], r["outcome"]))
                larger = "unresolved" if abs(rd - ap) <= bms else ("upstream_delivery" if rd > ap else "host_ack_production")
                print("edge read_delay_ms=%.3f+-%.3f (peer_tx to host_rx, across clocks) "
                      "ack_production_ms=%.3f+-0.001 (host_rx to host_tx, ring clock) larger=%s" % (rd, bms, ap, larger))
    if why:
        print("edge unavailable (%s)" % why)
    ex = [p for p in segs if p["len"] > 0 and lo - w <= p["ep"] <= hi]
    if ex:
        e = max(ex, key=lambda p: (p["ep"], p["super"], p["k"]))
        got = [fr for fr in rxs if fr["cls"] == "SEEN" and fr["cand"][0] is e]
        print("resume_segment peer_tx_peer=%.6f seq=%d len=%d segment=%d/%dB host_rx=%s (the peer's frame at END, after the gap; not the edge)" % (
            e["ep"], e["seq"], e["len"], e["k"], e["super_len"],
            "clo_us=%d peer=%.6f" % (got[0]["t"], got[0]["pt"]) if got else "unavailable"))
    print("received_at_host=%d seen=%d unseen=%d ambiguous=%d censored=%d" % (
        len(inw), tot["SEEN"], tot["UNSEEN"], tot["AMBIGUOUS"], tot["CENSORED"]))
    if why:
        sys.stderr.write("ringtrace=fail reason=edge_unavailable (%s)\n" % why)
        sys.exit(3)


def byk_tx(peer):
    """peer frames by the full TX identity (the Amiga sends no GSO)"""
    k = {}
    for p in peer:
        k.setdefault(txkey(p), []).append(p)
    return k


def cmd_gaps(pcap, port, gap_ms=150.0):
    """Silences in the peer capture, as ackab.py counts them: data = peer->Amiga TCP to
    PORT with payload; ack = Amiga->peer TCP from PORT.  One line per gap > gap_ms."""
    port, gap_ms = int(port), float(gap_ms)
    t = {"data": [], "ack": []}
    for p in peer_tcp(pcap):
        if p["dport"] == port and p["len"] > 0:
            t["data"].append(p["ep"])
        elif p["sport"] == port and p["flags"] & 0x10:
            t["ack"].append(p["ep"])
    for d in ("data", "ack"):
        v = sorted(t[d])
        for a, b in zip(v, v[1:]):
            if (b - a) * 1e3 > gap_ms:
                print("gap dir=%s start=%.6f end=%.6f ms=%.1f" % (d, a, b, (b - a) * 1e3))


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
    elif len(sys.argv) in (4, 5) and sys.argv[1] == "gaps":
        cmd_gaps(*sys.argv[2:])
    elif len(sys.argv) >= 6 and sys.argv[1] == "rxjoin":
        a = sys.argv[2:]
        times = None
        if "--times" in a:
            i = a.index("--times"); times = a[i + 1]; del a[i:i + 2]
        cmd_rxjoin(*a, times=times)
    elif len(sys.argv) >= 6 and sys.argv[1] == "txjoin":
        a = sys.argv[2:]
        times = None
        if "--times" in a:
            i = a.index("--times"); times = a[i + 1]; del a[i:i + 2]
        cmd_txjoin(*a, times=times)
    elif len(sys.argv) == 6 and sys.argv[1] == "window":
        cmd_window(*sys.argv[2:6])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
