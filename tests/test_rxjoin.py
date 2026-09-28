#!/usr/bin/env python3
"""Host test for ringtrace.py rxjoin (#89): RX identity records against a
synthetic peer pcap.

  python3 tests/test_rxjoin.py   -> "RESULT test_rxjoin checks=N failures=0"

Two gaps.  In A the peer's exit frame is read at the host 1 ms after it was
sent and the release ACK leaves 100 ms later (host ACK production).  In B the
exit frame itself is read 100 ms after it was sent (delivery upstream of the
host handoff).  Also: an orphaned and a dropped frame, a frame the peer never
sent (unseen), and a near miss in payload length that must not match.
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


def tcp(ipid, ack, seq, flags, src, dst, sport, dport, plen):
    ip = bytearray(20); ip[0] = 0x45; ip[2:4] = struct.pack(">H", 40 + plen)
    ip[4:6] = struct.pack(">H", ipid); ip[9] = 6
    ip[12:16] = bytes([192, 168, 1, src]); ip[16:20] = bytes([192, 168, 1, dst])
    return b"\0" * 12 + b"\x08\x00" + bytes(ip) + struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 1000, 0, 0)


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


t = BASE
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
t += 2_000_000
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
expect(len(rx) == 7 and [f["outcome"] for f in rx[:3]] == ["read", "orphan", "dropped"], "RX pairs and outcomes decoded")


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
expect(has(a, "exit_frame peer_tx_t=", "seq=6792 len=1448"), "A: exit frame found")
expect(num(a, "read_delay_ms", "exit_frame host_rx_t=", "outcome=read", near=1.0), "A: exit frame read 1 ms after its send")
expect(num(a, "ack_production_ms", "release_ack host_tx_t=", "ack=8240", "write=ok", near=100.0), "A: release ACK 100 ms after the read")
expect(has(a, "edge read_delay_ms=", "larger=host_ack_production"), "A: host ACK production")
expect(a[-1] == "received_at_host=6 seen=4 unseen=2 ambiguous=0 censored=0", "A: summary")
expect(has(a, "arrived frames=6 ", "outcomes=dropped=1,orphan=1,read=4"), "A: arrival summary")

b = run(peer(EXB) - 0.2, peer(B_END))
print("\n".join(b))
expect(num(b, "read_delay_ms", "exit_frame host_rx_t=", near=100.0), "B: exit frame read 100 ms after its send")
expect(num(b, "ack_production_ms", "release_ack host_tx_t=", near=1.0), "B: release ACK 1 ms after the read")
expect(has(b, "edge read_delay_ms=", "larger=upstream_delivery"), "B: delivery upstream of the host")

print("RESULT test_rxjoin checks=%d failures=%d" % (checks, failures))
sys.exit(1 if failures else 0)
