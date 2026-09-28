#!/usr/bin/env python3
"""Host test for tools/ringtrace.py (#89): decode, the pcap reader, align and
txjoin on a synthetic dump and a synthetic peer pcap.

  python3 tests/test_ringtrace.py   -> "RESULT test_ringtrace checks=N failures=0"

The records are packed exactly as src/ringtrace.h lays them out (the C side
of the encoding is covered by tests/host_ringtrace.c).
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


OFF = 1_790_000_000.0          # peer epoch = Amiga seconds + OFF + 30 ppm
DRIFT = 30e-6
BASE = 0xFFFFFFFF - 3_000_000  # CLO wraps 3 s in


def peer(t_us):
    return OFF + (t_us / 1e6) * (1 + DRIFT)


recs = []


def put(t, k, a, b, c, d):
    recs.append((t & 0xFFFFFFFF, k, a, b, c, d))


marks, tcp = [], []           # peer pcap: (epoch, frame bytes)


def ping(t, s):
    put(t, 11, 0, 8, (0x4242 << 16) | s, 1153)
    put(t + 300, 11, 1, 0, (0x4242 << 16) | s, (1 << 16) | 1)
    marks.append((peer(t) - 0.0012, 8, s))
    marks.append((peer(t + 300) + 0.0011, 0, s))


def icmp_frame(typ, s):
    ip = bytearray(20); ip[0] = 0x45; ip[2:4] = struct.pack(">H", 1139); ip[9] = 1
    return b"\0" * 12 + b"\x08\x00" + bytes(ip) + bytes([typ, 0, 0, 0]) + struct.pack(">HH", 0x4242, s)


def tcp_frame(ipid, ack, seq, flags, src=137, dst=136, ihl=5):
    ip = bytearray(ihl * 4); ip[0] = 0x40 | ihl; ip[2:4] = struct.pack(">H", ihl * 4 + 20)
    ip[4:6] = struct.pack(">H", ipid); ip[9] = 6
    ip[12:16] = bytes([192, 168, 1, src]); ip[16:20] = bytes([192, 168, 1, dst])
    th = struct.pack(">HHIIBBHHH", 7502, 40462, seq, ack, 5 << 4, flags, 1000, 0, 0)
    return b"\0" * 12 + b"\x08\x00" + bytes(ip) + th


def txid(t, ipid, ack, seq, flags, idx, count, sdpcm, plen=0):
    put(t, 13, flags, ipid, ack, seq)
    put(t, 14, idx, (count << 8) | sdpcm, (7502 << 16) | 40462, (137 << 24) | (136 << 16) | plen)


t = BASE
put(t, 14, 0, 0, 0, 0)                              # orphan TXID2 (its TXID1 lapped out)
for s in range(5):
    ping(t + s * 100_000, s)
t += 1_000_000
gap_start_t = t
# the gap: three ACKs produced at the host; the peer sees two (the second one late)
txid(t + 10_000, 0x1000, 5000, 1, 0x10, 0, 2, 0x31)
put(t + 10_000, 15, 1, (2 << 8) | 0x32, (0x0806 << 16) | 0xff, 42)   # an ARP in the same glom
txid(t + 60_000, 0x1001, 6460, 1, 0x10, 0, 1, 0x33)
txid(t + 120_000, 0x1002, 7920, 1, 0x18, 0, 1, 0x34, 100)
tcp.append((peer(t + 10_000) + 0.002, tcp_frame(0x1000, 5000, 1, 0x10)))
tcp.append((peer(t + 60_000) + 0.150, tcp_frame(0x1001, 6460, 1, 0x10, ihl=6)))
tcp.append((peer(t + 60_000) + 0.001, tcp_frame(0x1001, 6460, 1, 0x10, src=99)))  # other host, same key
gap_end_t = t + 160_000
txid(t + 400_000, 0x1003, 9380, 1, 0x10, 0, 1, 0x35)                 # outside the window
t += 5_000_000                                                       # past the CLO wrap
for s in range(5, 10):
    ping(t + (s - 5) * 100_000, s)

body = b"".join(struct.pack(">IBBHII", *r) for r in recs)
hdr = struct.pack(">IHHIIIIII", 0x52544431, 1, 16, 1 << 22, len(recs) + 7, 7, len(recs), 7, (t + 900_000) & 0xFFFFFFFF)
pk = [struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 128, 1)]
frames = [(ep, icmp_frame(typ, s)) for ep, typ, s in marks] + tcp
for ep, f in sorted(frames):
    sec = int(ep); us = int(round((ep - sec) * 1e6))
    pk.append(struct.pack("<IIII", sec, us, len(f), len(f)) + f)

d = tempfile.mkdtemp()
dump, pcap = os.path.join(d, "ring.bin"), os.path.join(d, "peer.pcap")
open(dump, "wb").write(hdr + body)
open(pcap, "wb").write(b"".join(pk))

# decode: header, wrap, pairing
h, rs = ringtrace.load(dump)
expect(h["lost"] == 7 and h["count"] == len(recs), "header lost/count")
expect(rs[-1]["t"] > 1 << 32, "CLO unwrapped past the wrap")
fr = ringtrace.tx_frames(rs)
expect(len(fr) == 4, "four TX TCP frames paired (orphan TXID2 skipped): %d" % len(fr))
f0 = fr[0]
expect((f0["ipid"], f0["ack"], f0["flags"], f0["sport"], f0["dport"], f0["src"], f0["dst"], f0["sdpcm"], f0["idx"], f0["count"])
       == (0x1000, 5000, 0x10, 7502, 40462, 137, 136, 0x31, 0, 2), "first frame fields")
expect(fr[2]["len"] == 100 and ringtrace.flagstr(fr[2]["flags"]) == "PA", "payload length and flags")

# the pcap reader: pings and TCP frames (IP options included)
pm = ringtrace.marks_from_pcap(pcap)
expect(len(pm) == 10 and all(set(v) == {0, 8} for v in pm.values()), "ten pings both ways")
seen = ringtrace.peer_tcp(pcap)
expect((0x1001, 6460, 137) in seen and (0x1001, 6460, 99) in seen, "TCP keys incl. IP options and source octet")

# txjoin over the gap
out = subprocess.run([sys.executable, TOOL, "txjoin", dump, pcap, "%.6f" % peer(gap_start_t), "%.6f" % peer(gap_end_t)],
                     capture_output=True, text=True).stdout
print(out, end="")
lines = out.splitlines()
expect(lines[-1] == "produced_at_host=3 seen_at_peer=2 missing=1", "summary")
expect(any("ip_id=4096 " in l and "delay_ms=2.0" in l for l in lines), "first ACK seen 2 ms later")
expect(any("ip_id=4097 " in l and "delay_ms=150.0" in l for l in lines), "second ACK seen 150 ms later, not the other host's")
expect(any("ip_id=4098 " in l and l.endswith("MISSING") for l in lines), "third ACK missing")
expect(not any("ip_id=4099 " in l for l in lines), "frame outside the window not listed")
expect("flow=7502>40462 produced_at_host=3 seen_at_peer=2 missing=1" in lines, "per-flow summary")
expect(lines[0].startswith("window_s=") and " covered=1 lost=7" in lines[0], "covered: records lost, but the first kept one precedes the window")
early = subprocess.run([sys.executable, TOOL, "txjoin", dump, pcap, "%.6f" % (peer(BASE) - 5), "%.6f" % peer(gap_end_t)],
                       capture_output=True, text=True).stdout.splitlines()
expect(" covered=0 " in early[0], "not covered: the window starts before the first kept record")

print("RESULT test_ringtrace checks=%d failures=%d" % (checks, failures))
sys.exit(1 if failures else 0)
