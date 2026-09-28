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
expect(set(coff) == set(wlsample.WIDE_FIELDS), "C and decoder name the same 22 fields: %s" % sorted(coff))
expect(all(coff[f] == v10[f] for f in wlsample.WIDE_FIELDS), "every C offset is wlcnt.py's v10 offset")
expect("txphycrs" not in coff, "txphycrs is not sampled")
order = re.search(r"off\[WS_NFIELDS\] = \{(.*?)\};", hdr, re.S).group(1)
narrow, _, wide_part = order.partition("#ifdef WIFIPI_WLSAMPLE_WIDE")
names = lambda t: [x.strip()[7:].lower() for x in t.replace("#endif", "").split(",") if x.strip()]   # noqa: E731
expect(names(narrow) == list(wlsample.FIELDS), "VAL index order in C is the decoder's (the ten)")
expect(names(narrow) + names(wide_part) == list(wlsample.WIDE_FIELDS), "VAL index order, wide: the ten first")
expect(wlsample.WIDE_FIELDS[:10] == wlsample.FIELDS and len(wlsample.WIDE_FIELDS) == 22, "wide extends, order stable")
expect(re.search(r"#ifdef WIFIPI_WLSAMPLE_WIDE\s*#define WS_NFIELDS\s+22\s*#else\s*#define WS_NFIELDS\s+10", hdr) is not None,
       "WS_NFIELDS 22 wide, 10 without")
kinds = {m.group(1): int(m.group(2)) for m in re.finditer(r"RT_(SAMPLE\w*|SAMPLER\w*)\s*=\s*(\d+)", hdr)}
expect(kinds == {"SAMPLE_REQ": 20, "SAMPLE_REP": 21, "SAMPLE_VAL": 22, "SAMPLE_SKIP": 23, "SAMPLE_LOST": 24,
                 "SAMPLE_LATE": 25, "SAMPLER_STOP": 26, "SAMPLER_REFUSED": 27, "SAMPLER_ENABLE": 28},
       "record kinds as the decoder reads them: %s" % kinds)

skips_c = {int(m.group(2)): m.group(1).lower() for m in re.finditer(r"WS_SKIP_(\w+)\s*=\s*(\d+)", hdr)}
expect(skips_c == wlsample.SKIP_REASON, "skip reasons as the decoder names them: %s" % skips_c)
stops_c = {int(m.group(2)): m.group(1).lower() for m in re.finditer(r"WS_STOP_(\w+)\s*=\s*(\d+)", hdr)}
expect(stops_c == wlsample.STOP_REASON, "stop reasons as the decoder names them: %s" % stops_c)

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


REQ_BYTES, REP_BYTES = 876, 880
state = {"n": 0, "id": 100, "c": {f: 1000 * i for i, f in enumerate(wlsample.FIELDS)}}


def sample(t, lat=2000, status=0, lost=False, late=None, rise=None, vals=True):
    """one sample: REQ at t, REP at t+lat (unless lost); counters rise by `rise`"""
    state["n"] += 1
    state["id"] += 1
    i = state["id"]
    put(t, 20, 0, i, state["n"], REQ_BYTES)
    for f, v in (rise or {}).items():
        state["c"][f] = (state["c"][f] + v) & 0xFFFFFFFF
    if lost:
        put(t + 500_000, 24, 0, i, t & 0xFFFFFFFF, 0)
        if late is not None:
            put(t + late, 25, 1, i, late, REP_BYTES << 16)
        return i
    put(t + lat, 21, status | (10 << 2), i, lat, (REP_BYTES << 16) | 848)
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
    if k == 5:
        put(t + 50_000, 23, 5, 0, 0, 0)     # no_credit at the next boundary: that period taken
        t += 60_000                         # ... and the tick that follows is 60 ms on
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


LABEL_S = "label=descriptive_association_not_a_falsifier"


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

# cadence and skips per hold, from the recorded REQ CLOs
hold0 = kv([x for x in out if x.startswith("gap=0 hold")][0])
expect(hold0["samples"] == "10" and hold0["cadence_mean_ms"] == "%.3f" % ((8 * 50 + 110) / 9)
       and hold0["cadence_max_ms"] == "110.000", "gap 0 hold: cadence from REQ spacing: %s" % hold0)
expect(hold0["skipped_no_credit"] == "1" and hold0["skipped_slot_busy"] == "0", "gap 0 hold: skips by reason")
hold2 = kv([x for x in out if x.startswith("gap=2 hold")][0])
expect(hold2["samples"] == "1" and hold2["cadence_mean_ms"] == "none", "one REQ: no cadence")
# the leg: overall cadence, skips, and SDIO bytes from the records themselves
leg = kv([x for x in out if x.startswith("leg ")][0])
reqs = sorted(r[0] for r in recs if r[1] == 20)
sp = [b - a for a, b in zip(reqs, reqs[1:])]
nrep = len([r for r in recs if r[1] == 21])
nlate = len([r for r in recs if r[1] == 25])
last = max(r[0] for r in recs if r[1] in (20, 21, 25))
want = len(reqs) * REQ_BYTES + (nrep + nlate) * REP_BYTES
expect(leg["cadence_mean_ms"] == "%.3f" % (sum(sp) / len(sp) / 1e3) and leg["cadence_max_ms"] == "%.3f" % (max(sp) / 1e3),
       "leg cadence: %s" % leg)
expect(leg["skipped_no_credit"] == "1" and leg["skipped_ctrl_busy"] == "2" and leg["skipped_slot_busy"] == "1",
       "leg skips by reason")
expect(leg["sdio_bytes"] == str(want) and leg["span_s"] == "%.3f" % ((last - reqs[0]) / 1e6)
       and leg["sdio_bytes_per_s"] == "%.1f" % (want / ((last - reqs[0]) / 1e6)), "leg SDIO bytes from the records")
expect(summ["skipped_no_credit"] == "1", "summary carries no_credit")

# --- BTC records (kind 29): listed by `btc`, invisible to `samples` -------
btc = [(t + 10, 29, 2, 1, 1, 0), (t + 20, 29, 1, 3, 0, 0xFFFFFFE9), (t + 30, 29, 2, 0, 0, 0x7FFF0100),
       (t + 40, 29, 1, 1, 0, 0x7FFF0001)]
recs2 = sorted(recs + btc, key=lambda r: r[0])
dump2 = os.path.join(tmp, "ring_btc.bin")
with open(dump2, "wb") as f:
    f.write(struct.pack(">IHHIIIIII", 0x52544431, 1, 16, 1 << 22, len(recs2), 0, len(recs2), 0,
                        recs2[-1][0]) + b"".join(struct.pack(">IBBHII", *r) for r in recs2))
r2 = subprocess.run([sys.executable, TOOL, "samples", dump2, mk, gp, "--gap", "%.6f" % G3_LO, "%.6f" % G3_HI],
                    capture_output=True, text=True)
expect(r2.returncode == 0 and r2.stdout == r.stdout, "samples output byte-identical with BTC records in the ring")
rb = subprocess.run([sys.executable, TOOL, "btc", dump2], capture_output=True, text=True)
bl = rb.stdout.splitlines()
expect(rb.returncode == 0 and len(bl) == 5 and bl[-1] == "btc_records=4", "btc lists the four: %s" % bl)
expect(bl[0].endswith("op=set name=btc_mode value=1 rc=0"), bl[0])
expect(bl[1].endswith("op=get name=btc_dos_status value=0 rc=-23"), bl[1])
expect(bl[2].endswith("op=set name=refused value=0 rc=driver_refused"), bl[2])
expect(bl[3].endswith("op=get name=btc_mode value=0 rc=ctrl_timeout"), bl[3])
rb0 = subprocess.run([sys.executable, TOOL, "btc", dump], capture_output=True, text=True)
expect(rb0.stdout == "btc_records=0\n", "no BTC records: btc_records=0")
bh = open(os.path.join(HERE, "..", "src", "btc.h")).read()
expect(re.search(r"#define RT_BTC\s+29\b", bh) is not None and wlsample.K_BTC == 29, "RT_BTC is kind 29 on both sides")

# --- a ten-field dump decodes as the 792bc57 decoder decoded it ------------
FX = os.path.join(HERE, "fixtures", "wlsample10")
lo3, hi3 = open(os.path.join(FX, "gap3.txt")).read().split()
rf = subprocess.run([sys.executable, TOOL, "samples", os.path.join(FX, "ring.bin"), os.path.join(FX, "marks.txt"),
                     os.path.join(FX, "gaps.txt"), "--gap", lo3, hi3], capture_output=True, text=True)
expect(rf.returncode == 0 and rf.stdout == open(os.path.join(FX, "expected.txt")).read(),
       "ten-field fixture: byte-identical to the 792bc57 decoder's output")

# --- a 22-field dump: obss, rxstrt_other (approx, clamped), baseline medians --
recs, marks = [], []
state = {"n": 0, "id": 500, "c": {f: 0 for f in wlsample.WIDE_FIELDS}}


def wsample(t, rise):
    state["n"] += 1
    state["id"] += 1
    i = state["id"]
    put(t, 20, 0, i, state["n"], REQ_BYTES)
    for f, v in rise.items():
        state["c"][f] += v
    put(t + 2000, 21, 0 | (10 << 2), i, 2000, (REP_BYTES << 16) | 848)
    for k, f in enumerate(wlsample.WIDE_FIELDS):
        put(t + 2000, 22, k, i, state["c"][f], 0)


for s_ in range(5):
    ping(1_000_000 + s_ * 100_000, s_)
t = 2_000_000
# baseline windows: obss 3,5,7,9,0; rxstrt_other 40,50,60,70 and one clamped (mbss subsets 20 each)
base_rises = [(1, 2, 60, 10, 5, 3, 2), (2, 3, 70, 10, 5, 3, 2), (3, 4, 80, 10, 5, 3, 2), (4, 5, 90, 10, 5, 3, 2),
              (0, 0, 10, 10, 5, 3, 2)]
wsample(t, {}); t += 50_000
for ob_d, ob_b, strt, dmb, mmb, bmb, ack in base_rises:
    wsample(t, {"rxdfrmucastobss": ob_d, "rxbeaconobss": ob_b, "rxstrt": strt, "rxdfrmucastmbss": dmb,
                "rxmfrmucastmbss": mmb, "rxbeaconmbss": bmb, "rxackucast": ack})
    t += 50_000
WG_LO = peer(t) - 0.001
wsample(t, {}); t += 50_000                 # the gap: one window with others, one clamped
wsample(t, {"rxdfrmucastobss": 6, "rxbeaconobss": 1, "rxstrt": 100, "rxdfrmucastmbss": 40,
            "rxmfrmucastmbss": 5, "rxbeaconmbss": 0, "rxackucast": 20})
t += 50_000
wsample(t, {"rxstrt": 5, "rxdfrmucastmbss": 9})
WG_HI = peer(t) + 0.010
t += 1_000_000
for s_ in range(5, 10):
    ping(t + (s_ - 5) * 100_000, s_)
recs.sort(key=lambda r: r[0])
dw = os.path.join(tmp, "wide.bin")
with open(dw, "wb") as f:
    f.write(struct.pack(">IHHIIIIII", 0x52544431, 1, 16, 1 << 22, len(recs), 0, len(recs), 0, recs[-1][0])
            + b"".join(struct.pack(">IBBHII", *r) for r in recs))
mw = os.path.join(tmp, "wmarks.txt")
with open(mw, "w") as f:
    for ep, typ, s_ in marks:
        f.write("%.6f %d 0x4242 %d\n" % (ep, typ, s_))
rw = subprocess.run([sys.executable, TOOL, "samples", dw, mw, "--gap", "%.6f" % WG_LO, "%.6f" % WG_HI],
                    capture_output=True, text=True)
wo = rw.stdout.splitlines()
expect(rw.returncode == 0, "wide dump decodes: %s" % rw.stderr)
we = [kv(x) for x in wo if " eligible " in x]
expect(len(we) == 2, "wide gap: two eligible windows")
expect(we[0]["obss"] == "7" and we[0]["rxstrt_other"] == "35" and we[0]["rxstrt_other_clamped"] == "0"
       and we[0]["rxstrt_other_approx"] == "1", "obss = 6+1, rxstrt_other = 100-(40+5+0+20) = 35: %s" % we[0])
expect(we[1]["rxstrt_other"] == "0" and we[1]["rxstrt_other_clamped"] == "1" and we[1]["obss"] == "0",
       "5-9 < 0: clamped at 0 and flagged")
expect(all(("delta." + f) in we[0] for f in wlsample.WIDE_FIELDS), "all 22 deltas per window")
gw = kv([x for x in wo if x.startswith("gap=0 wide")][0])
expect(gw["eligible"] == "2" and gw["rxstrt_other_clamped_count"] == "1", "per gap: clamps counted")
bm = kv([x for x in wo if x.startswith("baseline_median")][0])
# baseline windows: first..fifth rise (the gap's opening window straddles and is out)
expect(bm["windows"] == "5", "baseline windows: %s" % bm)
expect(bm["obss_median"] == "5.000" and bm["rxstrt_other_median"] == "50.000"
       and bm["rxstrt_other_clamped_count"] == "1",
       "medians of obss (3,5,7,9,0) and rxstrt_other (60,70,80,90,10 less 20 each; -10 clamped): %s" % bm)
expect(all(x.endswith(LABEL_S) for x in wo if x.startswith(("gap=", "baseline"))), "wide readings labelled")
expect(not any("obss" in x for x in rf.stdout.splitlines()), "ten-field output carries no wide keys")

# --- ring capacity: a 180 s leg at hw33's rate with 20 samples/s ------------
rh = open(os.path.join(HERE, "..", "src", "ringtrace.h")).read()
cap = 1 << int(re.search(r"#define WIFIPI_RINGTRACE_LOG2\s+(\d+)", rh).group(1))
per_sample = 2 + len(wlsample.WIDE_FIELDS)                 # REQ, REP, one VAL a field
HW33_RECORDS, HW33_SPAN_S, LEG_S = 1402206, 226.874, 180.0  # hw33-ring24 G: whole dump, first to last record
traffic = HW33_RECORDS / LEG_S                              # all of it inside the leg: the high bound
samp = 20 * per_sample
leg = (traffic + samp) * LEG_S
print("RING capacity=%d per_sample=%d sample_records_per_s=%d traffic_records_per_s=%.1f "
      "(hw33 %d over %.0f s taken as %.0f s) leg_records=%d fill=%.1f%% seconds_to_full=%.1f" % (
          cap, per_sample, samp, traffic, HW33_RECORDS, HW33_SPAN_S, LEG_S, leg, 100 * leg / cap,
          cap / (traffic + samp)))
expect(leg <= 0.9 * cap, "a 180 s leg stays within 90%% of the ring (%.1f%%)" % (100 * leg / cap))

print("RESULT test_wlsample checks=%d failures=%d" % (checks, failures))
sys.exit(1 if failures else 0)
