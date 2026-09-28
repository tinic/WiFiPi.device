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


def tcp_frame(ipid, ack, seq, flags, src=137, dst=136, ihl=5, sport=7502, dport=40462, plen=0):
    ip = bytearray(ihl * 4); ip[0] = 0x40 | ihl; ip[2:4] = struct.pack(">H", ihl * 4 + 20 + plen)
    ip[4:6] = struct.pack(">H", ipid); ip[9] = 6
    ip[12:16] = bytes([192, 168, 1, src]); ip[16:20] = bytes([192, 168, 1, dst])
    th = struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 1000, 0, 0)
    return b"\0" * 12 + b"\x08\x00" + bytes(ip) + th          # payload not captured (snaplen)


def txid(t, ipid, ack, seq, flags, idx, count, sdpcm, plen=0, sport=7502, dport=40462):
    put(t, 13, flags, ipid, ack, seq)
    put(t, 14, idx, (count << 8) | sdpcm, (sport << 16) | dport, (137 << 24) | (136 << 16) | plen)


def txrc(t, status, first, count, us=300, irq=0):
    put(t, 16, status, (first << 8) | count, us, irq)


t = BASE
put(t, 14, 0, 0, 0, 0)                              # orphan TXID2 (its TXID1 lapped out)
for s in range(5):
    ping(t + s * 100_000, s)
t += 1_000_000
gap_start_t = t
G = t
# F1 seen 2 ms later, in a glom of two with an ARP
txid(G + 10_000, 0x1000, 5000, 1, 0x10, 0, 2, 0x31)
put(G + 10_000, 15, 1, (2 << 8) | 0x32, (0x0806 << 16) | 0xff, 42)
txrc(G + 10_400, 15, 0x31, 2)
tcp.append((peer(G + 10_000) + 0.002, tcp_frame(0x1000, 5000, 1, 0x10)))
# F2 seen 150 ms later (IP options at the peer); another host's frame with the same id/ack/seq ignored
txid(G + 20_000, 0x1001, 6460, 1, 0x10, 0, 1, 0x33); txrc(G + 20_300, 3, 0x33, 1)
tcp.append((peer(G + 20_000) + 0.150, tcp_frame(0x1001, 6460, 1, 0x10, ihl=6)))
tcp.append((peer(G + 20_000) + 0.001, tcp_frame(0x1001, 6460, 1, 0x10, src=99)))
# F3 near miss: the peer's frame differs only in seq; and its glom's write failed
txid(G + 30_000, 0x1002, 7920, 1, 0x18, 0, 1, 0x34, 100); txrc(G + 30_300, 1, 0x34, 1, us=5_000_000, irq=0x00100000)
tcp.append((peer(G + 30_000) + 0.002, tcp_frame(0x1002, 7920, 2, 0x18, plen=100)))
# F4 near miss: differs only in payload length
txid(G + 40_000, 0x1003, 9380, 101, 0x18, 0, 1, 0x35, 100); txrc(G + 40_300, 12, 0x35, 1)
tcp.append((peer(G + 40_000) + 0.002, tcp_frame(0x1003, 9380, 101, 0x18, plen=99)))
# F5 the same id/ack/seq from another source port
txid(G + 50_000, 0x1004, 9380, 201, 0x10, 0, 1, 0x36); txrc(G + 50_300, 3, 0x36, 1)
tcp.append((peer(G + 50_000) + 0.002, tcp_frame(0x1004, 9380, 201, 0x10, sport=7503)))
# F6 an exact frame, but 1.5 s later: outside the 1 s join window
txid(G + 60_000, 0x1005, 9380, 301, 0x10, 0, 1, 0x37); txrc(G + 60_300, 3, 0x37, 1)
tcp.append((peer(G + 60_000) + 1.5, tcp_frame(0x1005, 9380, 301, 0x10)))
# F7/F8 across the IP id wrap, both seen; an older frame with F8's whole key 3 s earlier is ignored
txid(G + 70_000, 0xFFFF, 10840, 1, 0x10, 0, 2, 0x38)
txid(G + 70_000, 0x0000, 12300, 1, 0x10, 1, 2, 0x39); txrc(G + 70_300, 3, 0x38, 2)
tcp.append((peer(G + 70_000) + 0.003, tcp_frame(0xFFFF, 10840, 1, 0x10)))
tcp.append((peer(G + 70_000) + 0.004, tcp_frame(0x0000, 12300, 1, 0x10)))
tcp.append((peer(G + 70_000) - 3.0, tcp_frame(0x0000, 12300, 1, 0x10)))
# F9 two exact copies in the window: ambiguous
txid(G + 80_000, 0x1006, 13760, 1, 0x10, 0, 1, 0x3a); txrc(G + 80_300, 3, 0x3a, 1)
tcp.append((peer(G + 80_000) + 0.002, tcp_frame(0x1006, 13760, 1, 0x10)))
tcp.append((peer(G + 80_000) + 0.300, tcp_frame(0x1006, 13760, 1, 0x10)))
# F10 a flow the capture never had; no TXRC follows it (write unknown)
txid(G + 90_000, 0x1007, 1, 1, 0x10, 0, 1, 0x3b, sport=5555, dport=6666)
gap_end_t = G + 160_000
txid(G + 400_000, 0x1008, 9380, 1, 0x10, 0, 1, 0x3c)               # outside the window
t += 5_000_000                                                      # past the CLO wrap
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

# decode: header, wrap, pairing, write results
h, rs = ringtrace.load(dump)
expect(h["lost"] == 7 and h["count"] == len(recs), "header lost/count")
expect(rs[-1]["t"] > 1 << 32, "CLO unwrapped past the wrap")
fr = ringtrace.tx_frames(rs)
expect(len(fr) == 11, "eleven TX TCP frames paired (orphan TXID2 skipped): %d" % len(fr))
f0 = fr[0]
expect((f0["ipid"], f0["ack"], f0["flags"], f0["sport"], f0["dport"], f0["src"], f0["dst"], f0["sdpcm"], f0["idx"], f0["count"], f0["write"])
       == (0x1000, 5000, 0x10, 7502, 40462, 137, 136, 0x31, 0, 2, "ok"), "first frame fields")
expect(fr[2]["len"] == 100 and ringtrace.flagstr(fr[2]["flags"]) == "PA" and fr[2]["write"] == "failed", "F3 fields, write failed")
expect([ringtrace.txrc_state(a) for a in (3, 12, 15, 1, 4, 7, 13, 0)] == ["ok", "ok", "ok", "failed", "failed", "failed", "failed", "unknown"],
       "TXRC status decode")

# the pcap reader
pm = ringtrace.marks_from_pcap(pcap)
expect(len(pm) == 10 and all(set(v) == {0, 8} for v in pm.values()), "ten pings both ways")
pt = ringtrace.peer_tcp(pcap)
expect(any(p["ipid"] == 0x1001 and p["src"][3] == 137 for p in pt), "TCP frame with IP options read")
expect(any(p["ipid"] == 0x1003 and p["len"] == 99 for p in pt), "payload length from the IP header")

# txjoin over the gap
out = subprocess.run([sys.executable, TOOL, "txjoin", dump, pcap, "%.6f" % peer(gap_start_t), "%.6f" % peer(gap_end_t)],
                     capture_output=True, text=True).stdout
print(out, end="")
lines = out.splitlines()
def line(ipid):
    return next((l for l in lines if " ip_id=%d " % ipid in l), "")
expect(lines[-1] == "produced_at_host=10 seen=4 unseen=5 ambiguous=1", "summary")
expect("SEEN" in line(0x1000) and "delay_ms=2.0" in line(0x1000) and "write=ok" in line(0x1000), "F1 seen 2 ms, write ok")
expect("SEEN" in line(0x1001) and "delay_ms=150.0" in line(0x1001), "F2 seen 150 ms, not the other host's frame")
expect(line(0x1002).endswith("UNSEEN") and "write=failed" in line(0x1002), "F3 near miss in seq: unseen; write failed")
expect(line(0x1003).endswith("UNSEEN"), "F4 near miss in payload length: unseen")
expect(line(0x1004).endswith("UNSEEN"), "F5 same id/ack/seq from another port: unseen")
expect(line(0x1005).endswith("UNSEEN"), "F6 exact frame outside the window: unseen")
expect("SEEN" in line(0xFFFF) and "SEEN" in line(0x0000) and "delay_ms=4.0" in line(0x0000), "F7/F8 across the id wrap, older reuse ignored")
expect("AMBIGUOUS candidates=2" in line(0x1006), "F9 two copies: ambiguous")
expect(line(0x1007).endswith("UNSEEN") and "write=unknown" in line(0x1007), "F10 unseen, write unknown")
expect(line(0x1008) == "", "frame outside the gap not listed")
expect("flow_map flow=.137:7502>.136:40462 pcap=192.168.1.137:7502>192.168.1.136:40462" in lines, "flow mapped to full addresses")
expect(any(l.startswith("flow_map flow=.137:5555>.136:6666 UNMAPPED") for l in lines), "unmapped flow reported")
expect("flow=.137:7502>.136:40462 produced_at_host=9 seen=4 unseen=4 ambiguous=1" in lines, "per-flow counts")
expect("flow=.137:5555>.136:6666 produced_at_host=1 seen=0 unseen=1 ambiguous=0" in lines, "per-flow counts, unmapped flow")
expect("flow=.137:7502>.136:40462 write_ok=8 write_failed=1 write_unknown=0" in lines, "per-flow write results")
expect(lines[0].startswith("window_s=") and "join_window=[host_t-" in lines[0] and "1.000 s]" in lines[0] and " covered=1 lost=7" in lines[0],
       "header: join window, covered with records lost")
early = subprocess.run([sys.executable, TOOL, "txjoin", dump, pcap, "%.6f" % (peer(BASE) - 5), "%.6f" % peer(gap_end_t)],
                       capture_output=True, text=True).stdout.splitlines()
expect(" covered=0 " in early[0], "not covered: the window starts before the first kept record")

print("RESULT test_ringtrace checks=%d failures=%d" % (checks, failures))
sys.exit(1 if failures else 0)
