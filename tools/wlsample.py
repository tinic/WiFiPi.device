#!/usr/bin/env python3
"""In-leg firmware counter samples from a ringdump (AmiNetXDuo #89).

  wlsample.py samples DUMP MARKS [GAPS] [--gap START END]...

DUMP is a ringdump from a driver built with -DWIFIPI_WLSAMPLE
-DWIFIPI_RINGTRACE after `wlsample ENABLE`; MARKS the peer's alignment pings
(as ringtrace.py align); GAPS the output of `ringtrace.py gaps` (every line
with start= and end=, peer epoch seconds), --gap adds one by hand.

Output is key=value.  Every reading is a descriptive association, not a
falsifier: there are no verdicts and nothing is counted across gaps.

  sample ...        each sample: REQ/REP CLO and peer time, status, latency
  interval          two consecutive samples i-1, i (REQ order): the window is
                    [REQ(i-1), REP(i)] -- the firmware read each set of
                    counters somewhere inside its own REQ..REP.  Only when
                    both are valid -- REP status ok (v10, 848 bytes), all
                    ten values, never lost or late -- and they do not
                    overlap (REP(i-1) <= REQ(i)).
  gap ... eligible  intervals wholly inside [START, END]: the ten deltas
                    (mod 2^32), and beacons observed against the window /
                    102.4 ms (100 TU) expected, as a ratio -- not a rate.
                    None: result=inconclusive.
  gap ... latency   samples whose REQ lies in the gap, descriptive only
  baseline ...      intervals wholly outside every gap, deltas and per-second
                    rate over their window
  summary ...       samples_total, skips by reason, lost, late, eligible per gap

tbtt is reported, never used as an anchor.  Record fields: src/wlsample.h.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ringtrace as rt  # noqa: E402

FIELDS = ("tbtt", "rxbeaconmbss", "rxframe", "rxcrsglitch", "rxbadplcp",
          "txframe", "txretrans", "txnoack", "rxnobuf", "rxtoolate")
(K_REQ, K_REP, K_VAL, K_SKIP, K_LOST, K_LATE, K_STOP, K_REFUSED, K_ENABLE) = range(20, 29)
REP_STATUS = {0: "ok", 1: "bad_layout", 2: "fw_error"}
SKIP_REASON = {1: "slot_busy", 2: "ctrl_busy", 3: "nomem", 4: "stopped"}
STOP_REASON = {1: "idcap", 2: "disabled", 3: "wrap"}
BEACON_S = 0.1024
LABEL = "label=descriptive_association_not_a_falsifier"


def collect(recs):
    """(samples by REQ order, skips by reason, lost, late, other events)"""
    by_id, order, skips, events = {}, [], {k: 0 for k in SKIP_REASON.values()}, []
    lost = late = 0
    for r in recs:
        k = r["k"]
        if k == K_REQ:
            s = {"id": r["b"], "n": r["c"], "req": r["t"], "req_clo": r["clo"], "rep": None,
                 "status": None, "lat": None, "vals": {}, "lost": None, "late": []}
            by_id[r["b"]] = s
            order.append(s)
        elif k == K_REP and r["b"] in by_id:
            s = by_id[r["b"]]
            s.update(rep=r["t"], rep_clo=r["clo"], status=r["a"], lat=r["c"], verlen=r["d"])
        elif k == K_VAL and r["b"] in by_id and r["a"] < len(FIELDS):
            s = by_id[r["b"]]
            if s["status"] == 0:
                s["vals"][FIELDS[r["a"]]] = r["c"]
        elif k == K_SKIP:
            skips[SKIP_REASON.get(r["a"], str(r["a"]))] = skips.get(SKIP_REASON.get(r["a"], str(r["a"])), 0) + 1
        elif k == K_LOST:
            lost += 1
            if r["b"] in by_id:
                by_id[r["b"]]["lost"] = r["t"]
        elif k == K_LATE:
            late += 1
            if r["b"] in by_id:
                by_id[r["b"]]["late"].append((r["t"], r["a"], r["c"]))
        elif k in (K_STOP, K_REFUSED, K_ENABLE):
            events.append(r)
    return order, skips, lost, late, events


def valid(s):
    return (s["rep"] is not None and s["status"] == 0 and len(s["vals"]) == len(FIELDS)
            and s["lost"] is None and not s["late"])


def intervals(samples, peer):
    """consecutive samples i-1, i (REQ order), both valid and not overlapping;
    (list, overlaps excluded, pairs with an invalid end)"""
    out, overlap, invalid = [], 0, 0
    for a, b in zip(samples, samples[1:]):
        if not (valid(a) and valid(b)):
            invalid += 1
            continue
        if a["rep"] > b["req"]:
            overlap += 1
            continue
        lo, hi = peer(a["req"]), peer(b["rep"])
        out.append({"a": a, "b": b, "lo": lo, "hi": hi,
                    "d": {f: (b["vals"][f] - a["vals"][f]) & 0xFFFFFFFF for f in FIELDS},
                    "wrap": [f for f in FIELDS if b["vals"][f] < a["vals"][f]]})
    return out, overlap, invalid


def read_gaps(path, extra):
    gaps = []
    if path:
        for line in open(path):
            kv = dict(t.split("=", 1) for t in line.split() if "=" in t)
            if "start" in kv and "end" in kv:
                gaps.append((float(kv["start"]), float(kv["end"]), kv.get("dir", "")))
    for lo, hi in extra:
        gaps.append((float(lo), float(hi), "manual"))
    return gaps


def status_of(s):
    if s["late"]:
        return "late"
    if s["lost"] is not None:
        return "lost"
    if s["rep"] is None:
        return "no_reply_in_ring"
    return REP_STATUS.get(s["status"], str(s["status"]))


def deltas(iv):
    return " ".join("delta.%s=%d" % (f, iv["d"][f]) for f in FIELDS)


def beacons(iv):
    w = iv["hi"] - iv["lo"]
    exp = w / BEACON_S
    return "beacon_observed=%d beacon_expected=%.3f beacon_observed_over_expected=%s" % (
        iv["d"]["rxbeaconmbss"], exp, ("%.3f" % (iv["d"]["rxbeaconmbss"] / exp)) if exp > 0 else "undefined")


def cmd_samples(dump, marks, gaps_path=None, extra=()):
    h, recs = rt.load(dump)
    m = rt.model(rt.pings(recs, rt.pcap_marks(marks)))
    peer = lambda t: rt.to_peer(m, t / 1e6)        # noqa: E731
    samples, skips, lost, late, events = collect(recs)
    gaps = read_gaps(gaps_path, extra)
    out = ["align theta_s=%.6f theta_rate_ppm=%.3f bound_ms=%.3f ring_lost=%d" % (
        m["theta_s"], m["drift"] * 1e6, m["bound"] * 1e3, h["lost"])]
    for r in events:
        if r["k"] == K_ENABLE:
            out.append("event=enable clo=%d E=%d" % (r["clo"], r["b"]))
        elif r["k"] == K_STOP:
            out.append("event=stop clo=%d reason=%s id_not_taken=%d E=%d distance=%d" % (
                r["clo"], STOP_REASON.get(r["a"], str(r["a"])), r["b"], r["c"], r["d"]))
        else:
            out.append("event=refused clo=%d state=%d E=%d" % (r["clo"], r["b"], r["c"]))
    for s in samples:
        lat = s["lat"] if s["rep"] is not None else (
            s["late"][0][2] if s["late"] and s["late"][0][1] else None)
        out.append("sample id=%d n=%d req_clo=%d req_peer=%.6f rep_clo=%s rep_peer=%s status=%s latency_us=%s" % (
            s["id"], s["n"], s["req_clo"], peer(s["req"]),
            s.get("rep_clo", "none") if s["rep"] is not None else "none",
            "%.6f" % peer(s["rep"]) if s["rep"] is not None else "none",
            status_of(s), "unknown" if lat is None else lat))
    ivs, overlap, invalid = intervals(samples, peer)
    eligible = []
    for g, (lo, hi, d) in enumerate(gaps):
        inside = [iv for iv in ivs if lo <= iv["lo"] and iv["hi"] <= hi]
        eligible.append(len(inside))
        out.append("gap=%d dir=%s start=%.6f end=%.6f eligible_count=%d%s %s" % (
            g, d or "none", lo, hi, len(inside), " result=inconclusive" if not inside else "", LABEL))
        for iv in inside:
            out.append("gap=%d eligible from_id=%d to_id=%d window_start=%.6f window_end=%.6f window_ms=%.3f "
                       "%s %s wrapped=%s %s" % (
                           g, iv["a"]["id"], iv["b"]["id"], iv["lo"], iv["hi"], (iv["hi"] - iv["lo"]) * 1e3,
                           deltas(iv), beacons(iv), ",".join(iv["wrap"]) or "none", LABEL))
        for s in samples:
            if lo <= peer(s["req"]) <= hi:
                lat = s["lat"] if s["rep"] is not None else (
                    s["late"][0][2] if s["late"] and s["late"][0][1] else None)
                out.append("gap=%d latency id=%d req_peer=%.6f status=%s latency_us=%s %s" % (
                    g, s["id"], peer(s["req"]), status_of(s), "unknown" if lat is None else lat, LABEL))
    for iv in ivs:
        if all(iv["hi"] < lo or iv["lo"] > hi for lo, hi, _ in gaps):
            w = iv["hi"] - iv["lo"]
            out.append("baseline from_id=%d to_id=%d window_start=%.6f window_end=%.6f window_ms=%.3f %s %s %s %s" % (
                iv["a"]["id"], iv["b"]["id"], iv["lo"], iv["hi"], w * 1e3, deltas(iv),
                " ".join("rate_per_s.%s=%.3f" % (f, iv["d"][f] / w) for f in FIELDS) if w > 0 else "rate=undefined",
                beacons(iv), LABEL))
    out.append("summary samples_total=%d %s lost=%d late=%d valid=%d overlap_excluded=%d invalid_end_excluded=%d eligible_per_gap=%s" % (
        len(samples), " ".join("skipped_%s=%d" % kv for kv in sorted(skips.items())), lost, late,
        len([s for s in samples if valid(s)]), overlap, invalid, ",".join(str(n) for n in eligible) or "none"))
    return out


def main(argv):
    if len(argv) >= 3 and argv[0] == "samples":
        pos, extra, i = [], [], 1
        while i < len(argv):
            if argv[i] == "--gap" and i + 2 < len(argv):
                extra.append((argv[i + 1], argv[i + 2]))
                i += 3
            else:
                pos.append(argv[i])
                i += 1
        if len(pos) in (2, 3):
            for line in cmd_samples(pos[0], pos[1], pos[2] if len(pos) == 3 else None, extra):
                print(line)
            return 0
    print(__doc__.split("\n\n")[1], file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
