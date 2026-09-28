#!/usr/bin/env python3
"""Host test for ringtrace.py rxjoin (#89): RX identity records against a
synthetic peer pcap.

  python3 tests/test_rxjoin.py   -> "RESULT test_rxjoin checks=N failures=0"

Two gaps.  In A the peer's exit frame is read at the host 1 ms after it was
sent and the release ACK leaves 100 ms later (host ACK production).  In B the
exit frame itself is read 100 ms after it was sent (delivery upstream of the
host handoff).  Also: an orphaned and a dropped frame, a frame the peer never
sent (unseen), and a near miss in payload length that must not match.
Gap C: the peer's GSO super-frames (captured before segmentation) matched
segment by segment; a retransmit whose original lies outside the window
(SEEN, retx1); two copies inside the window (AMBIGUOUS, both listed); and an
exit edge whose last frame is a 2920 B super-frame (exit = its 2nd segment).
"""
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "..", "tools", "ringtrace.py")
sys.path.insert(0, os.path.join(HERE, "..", "tools"))
import ringtrace  # noqa: E402

checks = failures = 0


def expect(ok, what):
    global checks, failures
    checks += 1
    if not ok:
        failures += 1
        print("FAIL", what)


OFF, DRIFT, BASE = 1_790_100_000.0, 20e-6, 1_000_000_000


def peer(t_us):
    return OFF + (t_us / 1e6) * (1 + DRIFT)


recs, frames = [], []          # ring records; peer pcap (epoch, bytes)


def put(t, k, a, b, c, d):
    recs.append((t & 0xFFFFFFFF, k, a, b, c, d))


def ping(t, s):
    put(t, 11, 0, 8, (0x4242 << 16) | s, 1153)
    put(t + 300, 11, 1, 0, (0x4242 << 16) | s, (1 << 16) | 1)
    for ep, typ in ((peer(t) - 0.0012, 8), (peer(t + 300) + 0.0011, 0)):
        ip = bytearray(20); ip[0] = 0x45; ip[2:4] = struct.pack(">H", 1139); ip[9] = 1
        frames.append((ep, b"\0" * 12 + b"\x08\x00" + bytes(ip) + bytes([typ, 0, 0, 0]) + struct.pack(">HH", 0x4242, s)))


def tcp(ipid, ack, seq, flags, src, dst, sport, dport, plen, mss=None):
    opt = struct.pack(">BBH", 2, 4, mss) if mss else b""
    ip = bytearray(20); ip[0] = 0x45; ip[2:4] = struct.pack(">H", 40 + len(opt) + plen)
    ip[4:6] = struct.pack(">H", ipid); ip[9] = 6
    ip[12:16] = bytes([192, 168, 1, src]); ip[16:20] = bytes([192, 168, 1, dst])
    return (b"\0" * 12 + b"\x08\x00" + bytes(ip) +
            struct.pack(">HHIIBBHHH", sport, dport, seq, ack, (5 + len(opt) // 4) << 4, flags, 1000, 0, 0) + opt)


def data(t_rx, read_ms, ipid, seq, outcome=1, sent=True, plen=1448, peer_plen=None):
    """a peer->Amiga data frame read at the host at t_rx, sent read_ms earlier"""
    put(t_rx, 17, 0x10, ipid, 1, seq)
    put(t_rx, 18, 0, (outcome << 8) | (ipid & 0xff), (40462 << 16) | 7502, (136 << 24) | (137 << 16) | plen)
    if sent:
        frames.append((peer(t_rx) - read_ms / 1000.0, tcp(ipid, 1, seq, 0x10, 136, 137, 40462, 7502, peer_plen or plen)))


def ack(t_tx, ipid, ackno, seen_ms):
    put(t_tx, 13, 0x10, ipid, ackno, 1)
    put(t_tx, 14, 0, (1 << 8) | (ipid & 0xff), (7502 << 16) | 40462, (137 << 24) | (136 << 16))
    put(t_tx + 200, 16, 3, ((ipid & 0xff) << 8) | 1, 200, 0)
    frames.append((peer(t_tx) + seen_ms / 1000.0, tcp(ipid, ackno, 1, 0x10, 137, 136, 7502, 40462, 0)))


def rxseg(t_rx, seq, plen, flags, ipid):
    """one wire segment handed to the stack at t_rx (no peer frame: the caller adds the super-frame)"""
    put(t_rx, 17, flags, ipid, 1, seq)
    put(t_rx, 18, 0, (1 << 8) | (ipid & 0xff), (40462 << 16) | 7502, (136 << 24) | (137 << 16) | plen)


def superframe(ep, seq, total, flags=0x18, ipid=0x900):
    frames.append((ep, tcp(ipid, 1, seq, flags, 136, 137, 40462, 7502, total)))


t = BASE
frames.append((peer(t) - 0.5, tcp(1, 1, 0, 0x12, 137, 136, 7502, 40462, 0, mss=1460)))   # SYN-ACK: the Amiga's MSS
for s in range(5):
    ping(t + s * 100_000, s)
t += 1_000_000
# gap A: data up to A0, then the exit frame read 1 ms after its send, release ACK 100 ms later
A0 = t
data(A0 + 1_000, 2, 0x100, 1000)
data(A0 + 2_000, 2, 0x101, 2448, outcome=3)                # orphaned
data(A0 + 3_000, 2, 0x102, 3896, outcome=4)                # dropped
data(A0 + 4_000, 2, 0x103, 99999, sent=False)              # the peer never sent it
data(A0 + 5_000, 2, 0x104, 5344, peer_plen=1447)           # near miss: payload length
EXA = A0 + 200_000
data(EXA, 1, 0x105, 6792)                                  # exit frame A
ack(EXA + 100_000, 0x500, 6792 + 1448, 3)                  # release ACK A, host 100 ms after the read
A_END = EXA + 103_000
# gap B: the exit frame is read 100 ms after the peer sent it, release ACK 1 ms after the read
t += 1_000_000
EXB = t + 200_000
data(EXB, 100, 0x200, 20000)
ack(EXB + 1_000, 0x501, 20000 + 1448, 3)
B_END = EXB + 4_000
# gap C
t += 1_000_000
C0 = t
superframe(peer(C0) - 0.002, 30000, 4380)                  # 4380 B: three segments
rxseg(C0, 30000, 1460, 0x10, 0x901); rxseg(C0 + 100, 31460, 1460, 0x10, 0x902); rxseg(C0 + 200, 32920, 1460, 0x18, 0x903)
R1 = C0 + 1_600_000                                        # retransmit read 2 ms after its send; original 1.5 s earlier
superframe(peer(R1) - 1.502, 40000, 1460, flags=0x10)
superframe(peer(R1) - 0.002, 40000, 1460, flags=0x10)
rxseg(R1, 40000, 1460, 0x10, 0x904)
R2 = R1 + 300_000                                          # two copies 200 ms apart, both inside the window
superframe(peer(R2) - 0.202, 50000, 1460, flags=0x10)
superframe(peer(R2) - 0.002, 50000, 1460, flags=0x10)
rxseg(R2, 50000, 1460, 0x10, 0x905)
T2 = R2 + 100_000                                          # 2736 B: 1460 + a 1276 B tail
superframe(peer(T2) - 0.002, 70000, 2736)
rxseg(T2, 70000, 1460, 0x10, 0x908); rxseg(T2 + 50, 71460, 1276, 0x18, 0x909)
EXC = R2 + 300_000                                         # exit: a 2920 B super-frame, read 1 ms later
superframe(peer(EXC) - 0.001, 60000, 2920)
rxseg(EXC, 60000, 1460, 0x10, 0x906); rxseg(EXC + 50, 61460, 1460, 0x18, 0x907)
ack(EXC + 100_000, 0x502, 62920, 3)
C_END = EXC + 103_000
t += 2_000_000 + 1_000_000
for s in range(5, 10):
    ping(t + (s - 5) * 100_000, s)

d = tempfile.mkdtemp()
dump, pcap = os.path.join(d, "ring.bin"), os.path.join(d, "peer.pcap")
body = b"".join(struct.pack(">IBBHII", *r) for r in recs)
open(dump, "wb").write(struct.pack(">IHHIIIIII", 0x52544431, 1, 16, 1 << 22, len(recs), 0, len(recs), 0, (t + 900_000) & 0xFFFFFFFF) + body)
pk = [struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 128, 1)]
for ep, f in sorted(frames):
    sec = int(ep); us = int(round((ep - sec) * 1e6))
    pk.append(struct.pack("<IIII", sec, us, len(f), len(f)) + f)
open(pcap, "wb").write(b"".join(pk))

h, rs = ringtrace.load(dump)
rx = ringtrace.rx_frames(rs)
expect(len(rx) == 16 and [f["outcome"] for f in rx[:3]] == ["read", "orphan", "dropped"], "RX pairs and outcomes decoded")


def run(lo, hi):
    return subprocess.run([sys.executable, TOOL, "rxjoin", dump, pcap, "%.6f" % lo, "%.6f" % hi],
                          capture_output=True, text=True).stdout.splitlines()


a = run(peer(A0), peer(A_END))
print("\n".join(a))
def has(lines, *parts):
    return any(all(p in l for p in parts) for l in lines)


def num(lines, key, *parts, near=None, tol=0.2):
    """the value of key= on the line holding every part, within tol of near"""
    for l in lines:
        if all(p in l for p in parts) and key + "=" in l:
            v = float(l.split(key + "=")[1].split()[0])
            return near is None or abs(v - near) <= tol
    return False
expect(num(a, "delay_ms", "ip_id=256 ", "outcome=read SEEN", near=2.0), "A: data frame seen, 2 ms")
expect(has(a, "ip_id=257 ", "outcome=orphan SEEN"), "A: orphaned frame reported")
expect(has(a, "ip_id=258 ", "outcome=dropped SEEN"), "A: dropped frame reported")
expect(has(a, "ip_id=259 ", "UNSEEN"), "A: frame the peer never sent is unseen")
expect(has(a, "ip_id=260 ", "UNSEEN"), "A: payload-length near miss does not match")
expect(has(a, "exit_segment peer_tx_t=", "seq=6792 len=1448"), "A: exit frame found")
expect(num(a, "read_delay_ms", "exit_segment host_rx_t=", "outcome=read", near=1.0), "A: exit frame read 1 ms after its send")
expect(num(a, "ack_production_ms", "release_ack host_tx_t=", "ack=8240", "write=ok", near=100.0), "A: release ACK 100 ms after the read")
expect(has(a, "edge read_delay_ms=", "larger=host_ack_production"), "A: host ACK production")
expect(a[-1] == "received_at_host=6 seen=4 unseen=2 ambiguous=0 censored=0", "A: summary")
expect(" covered=1 lost=0" in a[0], "A: coverage in the header")
early = run(peer(BASE) - 5, peer(A_END))
expect(" covered=1 " in early[0], "nothing lost: covered even before the first record")
lossy = os.path.join(d, "lossy.bin")                       # same records, 5 counted as lost before them
raw = bytearray(open(dump, "rb").read()); raw[12:16] = struct.pack(">I", len(recs) + 5); raw[16:20] = struct.pack(">I", 5); raw[24:28] = struct.pack(">I", 5)
open(lossy, "wb").write(bytes(raw))
lo_early = subprocess.run([sys.executable, TOOL, "rxjoin", lossy, pcap, "%.6f" % (peer(BASE) - 5), "%.6f" % peer(A_END)],
                          capture_output=True, text=True).stdout.splitlines()
lo_late = subprocess.run([sys.executable, TOOL, "rxjoin", lossy, pcap, "%.6f" % peer(A0), "%.6f" % peer(A_END)],
                         capture_output=True, text=True).stdout.splitlines()
expect(" covered=0 lost=5" in lo_early[0] and " covered=1 lost=5" in lo_late[0], "records lost: covered only once the window starts after the first kept record")
expect(has(a, "arrived frames=6 ", "outcomes=dropped=1,orphan=1,read=4"), "A: arrival summary")

b = run(peer(EXB) - 0.2, peer(B_END))
print("\n".join(b))
expect(num(b, "read_delay_ms", "exit_segment host_rx_t=", near=100.0), "B: exit frame read 100 ms after its send")
expect(num(b, "ack_production_ms", "release_ack host_tx_t=", near=1.0), "B: release ACK 1 ms after the read")
expect(has(b, "edge read_delay_ms=", "larger=upstream_delivery"), "B: delivery upstream of the host")

c = run(peer(C0) - 0.01, peer(C_END))
print("\n".join(c))
for sq, k in ((30000, 0), (31460, 1), (32920, 2)):
    expect(has(c, "seq=%d " % sq, "SEEN", "segment=%d/4380B" % k, "copy=original") and num(c, "delay_ms", "seq=%d " % sq, "SEEN", near=2.0, tol=0.3),
           "C: 4380 B super-frame segment %d matched, 2 ms" % k)
expect(has(c, "seq=32920 ", "flags=PA", "SEEN"), "C: PSH only on the last segment")
expect(has(c, "seq=40000 ", "SEEN", "copy=retx1") and num(c, "delay_ms", "seq=40000 ", near=2.0, tol=0.3), "C: retransmit, original outside W: SEEN retx1")
expect(has(c, "seq=50000 ", "AMBIGUOUS retx_candidates=2 copies=original@", ",retx1@"), "C: two copies inside W: AMBIGUOUS, both listed")
expect(has(c, "exit_segment peer_tx_t=", "seq=61460 len=1460 segment=1/2920B"), "C: exit = the 2920 B super-frame's second segment")
expect(num(c, "read_delay_ms", "exit_segment host_rx_t=", near=1.0, tol=0.3), "C: exit segment read 1 ms after its send")
expect(num(c, "ack_production_ms", "release_ack host_tx_t=", "ack=62920", near=100.0, tol=0.3), "C: release ACK covers the whole super-frame, 100 ms")
expect(has(c, "seq=71460 ", "len=1276", "SEEN", "segment=1/2736B"), "C: 2736 B super-frame's 1276 B tail matched")
segs = ringtrace.peer_segments(ringtrace.peer_tcp(pcap))
expect([(p["seq"], p["len"], p["flags"]) for p in segs if p["super_len"] == 2736] == [(70000, 1460, 0x10), (71460, 1276, 0x18)],
       "peer_segments: the last segment is the payload minus (n-1) x 1460")
sf = [p for p in segs if p["super_len"] == 4380]
expect([(p["seq"], p["len"], p["flags"]) for p in sf] == [(30000, 1460, 0x10), (31460, 1460, 0x10), (32920, 1460, 0x18)], "peer_segments split rule")

print("RESULT test_rxjoin checks=%d failures=%d" % (checks, failures))
sys.exit(1 if failures else 0)
