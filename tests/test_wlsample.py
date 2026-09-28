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

# --- 22-field dumps: the RTS readout, chip_init_tx ---------------------------
def wide_leg(name, plan, gaps_of):
    """plan: list of (spacing_us, rises) -- one sample each, REQ spacing before it;
    gaps_of(times) -> [(lo, hi)] in peer seconds.  Returns the decoder's lines."""
    global recs, marks
    recs, marks = [], []
    st = {"n": 0, "id": 500, "c": {f: 1000 for f in wlsample.WIDE_FIELDS}}
    for s_ in range(5):
        ping(1_000_000 + s_ * 100_000, s_)
    t, times = 2_000_000, []
    for sp, rise in plan:
        t += sp
        st["n"] += 1
        st["id"] += 1
        i = st["id"]
        put(t, 20, 0, i, st["n"], REQ_BYTES)
        for f, v in rise.items():
            st["c"][f] += v
        put(t + 2000, 21, 0 | (10 << 2), i, 2000, (REP_BYTES << 16) | 848)
        for k, f in enumerate(wlsample.WIDE_FIELDS):
            put(t + 2000, 22, k, i, st["c"][f], 0)
        times.append(t)
    for s_ in range(5, 10):
        ping(t + 1_000_000 + (s_ - 5) * 100_000, s_)
    recs.sort(key=lambda r: r[0])
    dw = os.path.join(tmp, name + ".bin")
    with open(dw, "wb") as f:
        f.write(struct.pack(">IHHIIIIII", 0x52544431, 1, 16, 1 << 22, len(recs), 0, len(recs), 0, recs[-1][0])
                + b"".join(struct.pack(">IBBHII", *r) for r in recs))
    mw = os.path.join(tmp, name + ".marks")
    with open(mw, "w") as f:
        for ep, typ, s_ in marks:
            f.write("%.6f %d 0x4242 %d\n" % (ep, typ, s_))
    args = []
    for lo, hi in gaps_of(times):
        args += ["--gap", "%.6f" % lo, "%.6f" % hi]
    rr = subprocess.run([sys.executable, TOOL, "samples", dw, mw] + args, capture_output=True, text=True)
    expect(rr.returncode == 0, "%s decodes: %s" % (name, rr.stderr))
    return rr.stdout.splitlines()


def rts_line(out, g):
    x = [kv(l) for l in out if l.startswith("gap=%d rts " % g)]
    return x[0] if x else None


RTS_ON = {"txrts": 4, "txnocts": 1, "rxrsptmout": 2, "txallfrm": 30, "txackfrm": 10, "rxbeaconobss": 1}
QUIET = {"txallfrm": 5, "txackfrm": 5}
# 10 control windows of 50 ms (8 with RTS), gap A (3 windows with RTS), 5 more control, gap B (no RTS,
# one window where txackfrm outruns txallfrm), 5 control
plan = [(50_000, RTS_ON if k < 8 else QUIET) for k in range(11)]
plan += [(50_000, {"txrts": 2, "txnocts": 1, "rxrsptmout": 1, "txallfrm": 40, "txackfrm": 12,
                   "rxbeaconobss": 3}) for _ in range(3)]
plan += [(50_000, RTS_ON) for _ in range(5)]
plan += [(50_000, {"txallfrm": 3, "txackfrm": 3}), (50_000, {"txallfrm": 2, "txackfrm": 6})]
plan += [(50_000, RTS_ON) for _ in range(5)]


def gaps_ab(times):
    return [(peer(times[10]) - 0.001, peer(times[13]) + 0.010),     # windows 10-11, 11-12, 12-13
            (peer(times[18]) - 0.001, peer(times[20]) + 0.010)]     # windows 18-19, 19-20


out_w = wide_leg("wideA", plan, gaps_ab)
A, B = rts_line(out_w, 0), rts_line(out_w, 1)
expect(A is not None and A["eligible"] == "3", "gap A: rts line over its 3 eligible windows")
secsA = float(A["in_hold_ms"]) / 1e3
expect(A["txrts"] == "6" and A["txnocts"] == "3" and A["rxrsptmout"] == "3", "gap A sums: %s" % A)
expect(A["txrts_per_s"] == "%.3f" % (6 / secsA) and A["rxrsptmout_per_s"] == "%.3f" % (3 / secsA),
       "gap A: per-second rates over the eligible windows' own lengths")
expect(A["unanswered_fraction"] == "0.500", "unanswered = txnocts/txrts = 3/6")
expect(A["rxrsptmout_note"] == "supporting_not_ap_attribution" and A["rxbeaconobss"] == "9"
       and A["rxbeaconobss_note"] == "chip_hears_channel", "notes and rxbeaconobss reported only")
# control: every out-of-hold window of matching length: 10 + 4 + 4 (edges straddle), 8+4+4 with RTS
expect(A["rts_sensitivity"] == "ok" and float(A["control_txrts_positive_fraction"]) >= 0.5,
       "control mostly with RTS: sensitivity ok (%s)" % A["control_txrts_positive_fraction"])
expect(A["reading"] == "chip_attempted_channel_access_rules_out_complete_tx_silence_only"
       and "txrts0_note" not in A, "txrts > 0: attempted channel access")
expect(A["chip_init_tx"] == "84" and A["chip_init_tx_clamped"] == "0" and A["chip_init_tx_approx"] == "1"
       and A["chip_init_tx_reading"] == "chip_mac_transmitted_non_ack_frames_in_hold_approx_may_include_cts_ba_responses",
       "chip_init_tx = 3 x (40 - 12)")
expect(A["control_chip_init_tx_per_s_median"] != "none", "chip_init_tx control median")
expect(B is not None and B["txrts"] == "0" and B["unanswered_fraction"] == "n/a", "gap B: no RTS, unanswered n/a")
expect(B["reading"] == "no_rts_cannot_distinguish_internal_hold_from_cca_backoff"
       and B["txrts0_note"] == "cannot_separate_internal_hold_from_cca_deferral_deferral_precedes_rts",
       "txrts = 0: reading and the deferral note")
expect(B["chip_init_tx"] == "0" and B["chip_init_tx_clamped"] == "1" and B["chip_init_tx_reading"] == "none",
       "2 - 6 < 0: clamped at 0 and counted")
ew = [kv(x) for x in out_w if x.startswith("gap=1 eligible")]
expect([e["chip_init_tx"] for e in ew] == ["0", "0"] and [e["chip_init_tx_clamped"] for e in ew] == ["0", "1"],
       "per window chip_init_tx and clamp flag")
bl = [kv(x) for x in out_w if x.startswith("baseline ")]
expect(bl and all("chip_init_tx" in b and "obss" not in b and "rxstrt_other" not in b for b in bl),
       "baseline windows carry chip_init_tx; no obss, no rxstrt_other anywhere")
expect(not any("rxstrt_other" in x or " obss=" in x or "baseline_median" in x for x in out_w),
       "the OBSS contention reading is gone")
expect(all(x.endswith(LABEL_S) for x in out_w if x.startswith(("gap=", "baseline"))), "wide readings labelled")

# sensitivity low: under half the control windows carry RTS
plan_low = [(50_000, RTS_ON if k < 4 else QUIET) for k in range(11)] + \
    [(50_000, {"txrts": 2, "txallfrm": 9, "txackfrm": 1}) for _ in range(3)] + [(50_000, QUIET) for _ in range(6)]
out_l = wide_leg("wideLow", plan_low, lambda t: [(peer(t[10]) - 0.001, peer(t[13]) + 0.010)])
L = rts_line(out_l, 0)
expect(L["rts_sensitivity"] == "low" and L["reading"] == "none" and float(L["control_txrts_positive_fraction"]) < 0.5,
       "under half the control with RTS: rts_sensitivity=low, no reading: %s" % L)
expect(L["txrts"] == "6" and L["unanswered_fraction"] == "0.000", "the numbers are still printed")

# no control of matching length: in-hold windows 150 ms, every other window 50 ms
plan_nc = [(50_000, RTS_ON) for _ in range(11)] + [(150_000, RTS_ON) for _ in range(3)] + \
    [(50_000, RTS_ON) for _ in range(6)]
out_n = wide_leg("wideNC", plan_nc, lambda t: [(peer(t[11]) - 0.001, peer(t[13]) + 0.010)])
N = rts_line(out_n, 0)
expect(N["control_windows"] == "0" and N["rts_sensitivity"] == "no_control" and N["reading"] == "none",
       "no duration-matched control: no reading: %s" % N)

expect(not any(" rts " in x or "chip_init_tx" in x for x in rf.stdout.splitlines()),
       "ten-field output carries no wide keys")

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
