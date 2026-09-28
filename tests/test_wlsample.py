#!/usr/bin/env python3
"""Host test for tools/wlsample.py (#89): in-leg counter samples in a ring.

  python3 tests/test_wlsample.py   -> "RESULT test_wlsample checks=N failures=0"

A synthetic ringdump (records as src/ringtrace.h and src/wlsample.h lay them
out) with alignment pings, and the MARKS the peer would have seen.  Also
ties src/wlsample.h's offsets to tools/wlcnt.py's proven v10 table.
"""
import os
import re
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "..", "tools", "wlsample.py")
sys.path.insert(0, os.path.join(HERE, "..", "tools"))
import wlcnt  # noqa: E402
import wlsample  # noqa: E402

checks = failures = 0


def expect(ok, what):
    global checks, failures
    checks += 1
    if not ok:
        failures += 1
        print("FAIL", what)


# --- the C table is the proven table --------------------------------------
hdr = open(os.path.join(HERE, "..", "src", "wlsample.h")).read()
coff = {m.group(1).lower(): int(m.group(2)) for m in re.finditer(r"#define WS_OFF_(\w+)\s+(\d+)", hdr)}
v10 = {n: o for n, o, w in wlcnt.V10_FIELDS}
expect(set(coff) == set(wlsample.FIELDS), "C and decoder name the same ten fields")
expect(all(coff[f] == v10[f] for f in wlsample.FIELDS), "every C offset is wlcnt.py's v10 offset")
order = re.search(r"off\[WS_NFIELDS\] = \{(.*?)\};", hdr, re.S).group(1)
expect([x.strip()[7:].lower() for x in order.split(",") if x.strip()] == list(wlsample.FIELDS),
       "VAL index order in C is the decoder's")
kinds = {m.group(1): int(m.group(2)) for m in re.finditer(r"RT_(SAMPLE\w*|SAMPLER\w*)\s*=\s*(\d+)", hdr)}
expect(kinds == {"SAMPLE_REQ": 20, "SAMPLE_REP": 21, "SAMPLE_VAL": 22, "SAMPLE_SKIP": 23, "SAMPLE_LOST": 24,
                 "SAMPLE_LATE": 25, "SAMPLER_STOP": 26, "SAMPLER_REFUSED": 27, "SAMPLER_ENABLE": 28},
       "record kinds as the decoder reads them: %s" % kinds)

# --- a synthetic run --------------------------------------------------------
OFF = 1_790_000_000.0
recs, marks = [], []


def peer(t_us):
    return OFF + t_us / 1e6


def put(t, k, a, b, c, d):
    recs.append((t & 0xFFFFFFFF, k, a, b, c, d))


def ping(t, s):
    put(t, 11, 0, 8, (0x4242 << 16) | s, 1153)
    put(t + 300, 11, 1, 0, (0x4242 << 16) | s, (1 << 16) | 1)
    marks.append((peer(t) - 0.0002, 8, s))
    marks.append((peer(t + 300) + 0.0002, 0, s))


state = {"n": 0, "id": 100, "c": {f: 1000 * i for i, f in enumerate(wlsample.FIELDS)}}


def sample(t, lat=2000, status=0, lost=False, late=None, rise=None, vals=True):
    """one sample: REQ at t, REP at t+lat (unless lost); counters rise by `rise`"""
    state["n"] += 1
    state["id"] += 1
    i = state["id"]
    put(t, 20, 0, i, state["n"], 0)
    for f, v in (rise or {}).items():
        state["c"][f] = (state["c"][f] + v) & 0xFFFFFFFF
    if lost:
        put(t + 500_000, 24, 0, i, t & 0xFFFFFFFF, 0)
        if late is not None:
            put(t + late, 25, 1, i, late, 0)
        return i
    put(t + lat, 21, status, i, lat, (10 << 16) | 848)
    if status == 0 and vals:
        for k, f in enumerate(wlsample.FIELDS):
            put(t + lat, 22, k, i, state["c"][f], 0)
    return i


put(0, 28, 0, 99, 0, 0)                     # enable, E = 99
for s in range(5):
    ping(1_000_000 + s * 100_000, s)
T0 = 2_000_000
BEAC = {"rxbeaconmbss": 0, "tbtt": 0}
# 0..9 every 50 ms before the gap (baseline), beacons at 102.4 ms
t = T0
for k in range(10):
    sample(t, rise={"rxbeaconmbss": 1 if k % 2 else 0, "rxframe": 50})
    t += 50_000
GAP_LO = peer(t) - 0.010                    # the gap opens 10 ms before sample 10's REQ
for k in range(10):                         # 10..19 inside the gap, beacons stop
    sample(t, rise={"rxcrsglitch": 7, "rxnobuf": 3 if k == 4 else 0})
    t += 50_000
GAP_HI = peer(t - 50_000) + 0.020           # closes 20 ms after sample 19's REQ: its REP (2 ms) inside
SIDX = state["id"]
# a bad-layout sample and a lost-then-late one in a second gap
t += 200_000
G2_LO = peer(t) - 0.001
sample(t); t += 50_000
sample(t, status=1); t += 50_000            # bad layout: both of its pairs ineligible
sample(t); t += 50_000
sample(t); t += 50_000                      # one eligible pair here
sample(t, lost=True, late=600_000); t += 550_000
sample(t); t += 50_000
G2_HI = peer(t - 50_000) + 0.010          # F's REP inside, the next REQ outside
# third gap with no complete interval inside (straddles only)
G3_LO = peer(t - 50_000 + 1000)
G3_HI = peer(t + 1000)
sample(t); t += 50_000
# an overlapping pair (REP of one after the next REQ), outside every gap
t += 1_000_000
sample(t, lat=60_000); sample(t + 50_000); t += 150_000
sample(t); t += 50_000
put(t, 23, 1, 0, 0, 0); put(t, 23, 2, 0, 0, 0); put(t, 23, 2, 0, 0, 0)   # skips
for s in range(5, 10):
    ping(t + 1_000_000 + (s - 5) * 100_000, s)
put(t + 2_000_000, 26, 2, 0, 99, 0)        # stop: disabled

tmp = tempfile.mkdtemp(prefix="wlsample-test-")
dump = os.path.join(tmp, "ring.bin")
recs.sort(key=lambda r: r[0])                # the ring is in write order, and so CLO order
body = b"".join(struct.pack(">IBBHII", *r) for r in recs)
with open(dump, "wb") as f:
    f.write(struct.pack(">IHHIIIIII", 0x52544431, 1, 16, 1 << 22, len(recs), 0, len(recs), 0,
                        recs[-1][0]) + body)
mk = os.path.join(tmp, "marks.txt")
with open(mk, "w") as f:
    for ep, typ, s in marks:
        f.write("%.6f %d 0x4242 %d\n" % (ep, typ, s))
gp = os.path.join(tmp, "gaps.txt")
with open(gp, "w") as f:
    f.write("gap dir=data start=%.6f end=%.6f ms=1\n" % (GAP_LO, GAP_HI))
    f.write("gap dir=ack start=%.6f end=%.6f ms=1\n" % (G2_LO, G2_HI))
    f.write("junk line\n")

r = subprocess.run([sys.executable, TOOL, "samples", dump, mk, gp, "--gap", "%.6f" % G3_LO, "%.6f" % G3_HI],
                   capture_output=True, text=True)
out = r.stdout.splitlines()
expect(r.returncode == 0, "exit 0: %s" % r.stderr)


def kv(line):
    return dict(t.split("=", 1) for t in line.split() if "=" in t)


gaps = [kv(x) for x in out if x.startswith("gap=") and "eligible_count" in x]
elig = [kv(x) for x in out if " eligible " in x]
lats = [kv(x) for x in out if " latency " in x]
base = [kv(x) for x in out if x.startswith("baseline ")]
summ = kv([x for x in out if x.startswith("summary ")][0])

expect(len(gaps) == 3, "three gaps read (file + --gap), junk ignored")
# gap 0: samples 10..19 inside; REQ(10) inside, REP(19) inside -> 9 intervals (10-11 .. 18-19);
# 9-10 straddles the opening (REQ(9) before it) and 19-20 the close
expect(gaps[0]["eligible_count"] == "9", "gap 0: 9 eligible, straddlers excluded: %s" % gaps[0])
g0 = [e for e in elig if e["gap"] == "0"]
expect(all(float(e["window_start"]) >= GAP_LO and float(e["window_end"]) <= GAP_HI for e in g0),
       "gap 0: every window inside [START, END]")
expect(all(e["delta.rxcrsglitch"] == "7" and e["delta.rxbeaconmbss"] == "0" for e in g0),
       "gap 0: deltas exact")
expect(sum(int(e["delta.rxnobuf"]) for e in g0) == 3, "gap 0: the one rxnobuf rise is in one interval")
e0 = g0[0]
w = float(e0["window_end"]) - float(e0["window_start"])
expect(abs(float(e0["beacon_expected"]) - w / 0.1024) < 0.002, "beacon expected = window / 102.4 ms")
expect(e0["beacon_observed"] == "0" and e0["beacon_observed_over_expected"] == "0.000",
       "beacon observed stated as a ratio")
expect(all(x.endswith("label=descriptive_association_not_a_falsifier") for x in out
           if x.startswith(("gap=", "baseline "))), "every reading labelled")
# gap 1: A, BAD, C, D, LOST, F: pairs A-BAD, BAD-C invalid; C-D ok; D-LOST, LOST-F invalid
expect(gaps[1]["eligible_count"] == "1", "gap 1: only the pair with both ends valid: %s" % gaps[1])
# gap 2: no whole interval inside
expect(gaps[2]["eligible_count"] == "0" and gaps[2].get("result") == "inconclusive",
       "gap 2: zero eligible -> inconclusive")
# latency lines: gap 1 has the lost-then-late one, latency kept from the tombstone
g1l = [x for x in lats if x["gap"] == "1"]
expect(len(g1l) == 6 and [x["status"] for x in g1l] == ["ok", "bad_layout", "ok", "ok", "late", "ok"],
       "gap 1 latency lines: %s" % [x["status"] for x in g1l])
expect(g1l[4]["latency_us"] == "600000" and g1l[0]["latency_us"] == "2000", "latencies as recorded")
# baseline: pairs wholly outside every gap
for b in base:
    lo, hi = float(b["window_start"]), float(b["window_end"])
    for glo, ghi in ((GAP_LO, GAP_HI), (G2_LO, G2_HI), (G3_LO, G3_HI)):
        expect(hi < glo or lo > ghi, "baseline window %s..%s clear of gap %s..%s" % (lo, hi, glo, ghi))
# before gap 0: pairs 0-1 .. 8-9 are clear (9 of them); after: the overlapping pair is excluded
expect(len([b for b in base if float(b["window_end"]) < GAP_LO]) == 9, "baseline: the 9 pairs before gap 0")
b0 = base[0]
wb = float(b0["window_end"]) - float(b0["window_start"])
expect(b0["delta.rxframe"] == "50" and abs(float(b0["rate_per_s.rxframe"]) - 50 / wb) < 0.01,
       "baseline delta and per-second rate")
expect(summ["overlap_excluded"] == "1", "overlapping pair excluded: %s" % summ)
expect(summ["samples_total"] == str(state["n"]) and summ["lost"] == "1" and summ["late"] == "1",
       "summary totals")
expect(summ["skipped_slot_busy"] == "1" and summ["skipped_ctrl_busy"] == "2" and summ["skipped_nomem"] == "0",
       "summary skips by reason")
expect(summ["eligible_per_gap"] == "9,1,0", "summary eligible per gap")
expect(any(x.startswith("event=enable") and "E=99" in x for x in out)
       and any("event=stop" in x and "reason=disabled" in x for x in out), "enable and stop events")
expect(not any("verdict" in x or "rose" in x for x in out), "no verdicts")

print("RESULT test_wlsample checks=%d failures=%d" % (checks, failures))
sys.exit(1 if failures else 0)
