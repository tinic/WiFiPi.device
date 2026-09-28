#!/usr/bin/env python3
"""In-leg firmware counter samples from a ringdump (AmiNetXDuo #89).

  wlsample.py samples DUMP MARKS [GAPS] [--gap START END]...
  wlsample.py btc DUMP                  the BT-coexistence records (hw34)

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
  gap ... hold      per gap: REQ spacing (mean, max) and skips by reason
  leg ...           the whole dump: REQ spacing, skips by reason, and the
                    sampler's own SDIO traffic -- request frame bytes (REQ d)
                    plus reply frame bytes (REP, LATE d>>16) -- over the span
                    from the first REQ to the last sample record
  gap ... rts       22-field dumps, per gap, over its eligible windows only.
                    RTS from the dot11 pair: answered = txrts
                    (dot11RTSSuccessCount), unanswered = txnocts
                    (dot11RTSFailureCount), attempts = both; sums and per
                    second; unanswered_fraction = txnocts / attempts, only
                    when attempts > 0, else n/a.  rxrsptmout: supporting, not
                    AP attribution.  rxbeaconobss reported only (the chip
                    hears the channel).  Control: this leg's out-of-hold
                    windows within [0.8 x shortest, 1.2 x longest] of the
                    gap's windows -- median rates and the fraction with an
                    attempt.  Under half (or no control): rts_sensitivity
                    low (or no_control) and no reading.  Else attempts > 0
                    reads "chip attempted channel access (RTS)" (rules out
                    complete TX silence only; reading_unanswered=N when
                    txnocts > 0), attempts = 0 reads "no RTS attempt in the
                    sampled windows: cannot tell an internal hold from CCA
                    deferral".
                    chip_init_tx = txallfrm - txackfrm, per window and per
                    gap against the control median, approx (txallfrm also
                    counts CTS and block-ack responses to received frames)
                    and clamped at 0 with clamps counted; > 0 in the gap
                    reads "chip MAC transmitted non-ACK frames".
  summary ...       samples_total, skips by reason, lost, late, eligible per gap

Every time here is a recorded CLO: eligibility and coverage use each
sample's own REQ and REP records (intervals(): a["req"], b["rep"]), the
beacon expectation that window's length (beacons()), cadence the REQ
records' spacing.  Nothing assumes the 50 ms target.

tbtt is reported, never used as an anchor.  Record fields: src/wlsample.h.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ringtrace as rt  # noqa: E402

FIELDS = ("tbtt", "rxbeaconmbss", "rxframe", "rxcrsglitch", "rxbadplcp",
          "txframe", "txretrans", "txnoack", "rxnobuf", "rxtoolate")
# -DWIFIPI_WLSAMPLE_WIDE: the ten, then these; a dump is read by the count it carries
WIDE_FIELDS = FIELDS + ("rxstrt", "rxdfrmucastobss", "rxbeaconobss", "rxdfrmucastmbss",
                        "rxmfrmucastmbss", "rxackucast", "txallfrm", "txackfrm", "rxrsptmout",
                        "txrts", "txnocts", "txexptime")
FIELD_SETS = {len(FIELDS): FIELDS, len(WIDE_FIELDS): WIDE_FIELDS}
(K_REQ, K_REP, K_VAL, K_SKIP, K_LOST, K_LATE, K_STOP, K_REFUSED, K_ENABLE) = range(20, 29)
REP_STATUS = {0: "ok", 1: "bad_layout", 2: "fw_error"}
SKIP_REASON = {1: "slot_busy", 2: "ctrl_busy", 3: "nomem", 4: "stopped", 5: "no_credit"}
STOP_REASON = {1: "idcap", 2: "disabled", 3: "wrap", 4: "id_space"}
K_BTC = 29                                  # src/btc.h RT_BTC
BTC_OP = {1: "get", 2: "set"}
BTC_NAME = {1: "btc_mode", 2: "btc_flags", 3: "btc_dos_status"}
BTC_RC_REFUSED = 0x7fff0100
BEACON_S = 0.1024
LABEL = "label=descriptive_association_not_a_falsifier"


def collect(recs):
    """(samples by REQ order, skip records, lost, late, other events, SDIO bytes, last sample record t)"""
    by_id, order, skips, events = {}, [], [], []
    lost = late = sdio_bytes = 0
    last_t = None
    for r in recs:
        k = r["k"]
        if k == K_REQ:
            s = {"id": r["b"], "n": r["c"], "req": r["t"], "req_clo": r["clo"], "rep": None,
                 "status": None, "lat": None, "vals": {}, "lost": None, "late": []}
            sdio_bytes += r["d"]                    # the request frame
            last_t = r["t"]
            by_id[r["b"]] = s
            order.append(s)
        elif k == K_REP and r["b"] in by_id:
            s = by_id[r["b"]]
            s.update(rep=r["t"], rep_clo=r["clo"], status=r["a"] & 3, version=r["a"] >> 2, lat=r["c"],
                     length=r["d"] & 0xFFFF)
            sdio_bytes += r["d"] >> 16              # the reply frame
            last_t = r["t"]
        elif k == K_VAL and r["b"] in by_id and r["a"] < len(WIDE_FIELDS):
            s = by_id[r["b"]]
            if s["status"] == 0:
                s["vals"][WIDE_FIELDS[r["a"]]] = r["c"]
        elif k == K_SKIP:
            skips.append((r["t"], SKIP_REASON.get(r["a"], str(r["a"]))))
        elif k == K_LOST:
            lost += 1
            if r["b"] in by_id:
                by_id[r["b"]]["lost"] = r["t"]
        elif k == K_LATE:
            late += 1
            sdio_bytes += r["d"] >> 16
            last_t = r["t"]
            if r["b"] in by_id:
                by_id[r["b"]]["late"].append((r["t"], r["a"], r["c"]))
        elif k in (K_STOP, K_REFUSED, K_ENABLE):
            events.append(r)
    return order, skips, lost, late, events, sdio_bytes, last_t


def skip_counts(skips):
    c = {k: 0 for k in SKIP_REASON.values()}
    for _, reason in skips:
        c[reason] = c.get(reason, 0) + 1
    return " ".join("skipped_%s=%d" % kv for kv in sorted(c.items()))


def cadence(reqs):
    """mean and max REQ spacing in ms, from the recorded REQ CLOs (us)"""
    d = [b - a for a, b in zip(reqs, reqs[1:])]
    if not d:
        return "cadence_mean_ms=none cadence_max_ms=none"
    return "cadence_mean_ms=%.3f cadence_max_ms=%.3f" % (sum(d) / len(d) / 1e3, max(d) / 1e3)


def valid(s):
    return (s["rep"] is not None and s["status"] == 0 and s["vals"] and
            tuple(s["vals"]) == FIELD_SETS.get(len(s["vals"]))
            and s["lost"] is None and not s["late"])


def intervals(samples, peer):
    """consecutive samples i-1, i (REQ order), both valid and not overlapping;
    (list, overlaps excluded, pairs with an invalid end)"""
    out, overlap, invalid = [], 0, 0
    for a, b in zip(samples, samples[1:]):
        if not (valid(a) and valid(b)) or len(a["vals"]) != len(b["vals"]):
            invalid += 1
            continue
        if a["rep"] > b["req"]:
            overlap += 1
            continue
        lo, hi = peer(a["req"]), peer(b["rep"])
        fs = FIELD_SETS[len(a["vals"])]
        out.append({"a": a, "b": b, "lo": lo, "hi": hi, "f": fs,
                    "d": {f: (b["vals"][f] - a["vals"][f]) & 0xFFFFFFFF for f in fs},
                    "wrap": [f for f in fs if b["vals"][f] < a["vals"][f]]})
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
    return " ".join("delta.%s=%d" % (f, iv["d"][f]) for f in iv["f"])


def chip_init_tx(iv):
    """txallfrm - txackfrm, clamped at 0: (value, clamped), or None for ten
    fields.  Approx: txallfrm also counts CTS and block-ack responses to
    received frames, which are not host-queue TX."""
    d = iv["d"]
    if "txallfrm" not in d:
        return None
    v = d["txallfrm"] - d["txackfrm"]
    return max(v, 0), v < 0


def wide_str(iv):
    x = chip_init_tx(iv)
    return "" if x is None else " chip_init_tx=%d chip_init_tx_approx=1 chip_init_tx_clamped=%d" % x


RTS_MATCH = (0.8, 1.2)           # control window length vs the gap's eligible windows
RTS_SENSITIVE = 0.5              # control windows with an RTS attempt, at least

# RTS attempts come from the dot11 pair (WHD whd_wlioctl.h:2061-2062):
# txrts = dot11RTSSuccessCount (a CTS came back), txnocts =
# dot11RTSFailureCount (none did).  attempts = txrts + txnocts.  txrtsfrm
# (RTS frames the MAC sent, :2278) is not sampled.


def rts_attempts(iv):
    return iv["d"]["txrts"] + iv["d"]["txnocts"]


def rts_readout(g, inside, base):
    """the gap=N rts line, or None for a ten-field dump"""
    if not inside or "txrts" not in inside[0]["d"]:
        return None
    total = lambda f: sum(iv["d"][f] for iv in inside)          # noqa: E731
    secs = sum(iv["hi"] - iv["lo"] for iv in inside)
    answered, unanswered, rsp = total("txrts"), total("txnocts"), total("rxrsptmout")
    attempts = answered + unanswered
    lens = [iv["hi"] - iv["lo"] for iv in inside]
    lo, hi = min(lens) * RTS_MATCH[0], max(lens) * RTS_MATCH[1]
    ctl = [iv for iv in base if "txrts" in iv["d"] and lo <= iv["hi"] - iv["lo"] <= hi and iv["hi"] > iv["lo"]]

    def med(get):
        v = median([get(iv) / (iv["hi"] - iv["lo"]) for iv in ctl])
        return "none" if v is None else "%.3f" % v
    pos = sum(1 for iv in ctl if rts_attempts(iv) > 0)
    frac = pos / len(ctl) if ctl else None
    cit = [chip_init_tx(iv) for iv in inside]
    cit_sum = sum(x[0] for x in cit)
    cit_ctl = median([chip_init_tx(iv)[0] / (iv["hi"] - iv["lo"]) for iv in ctl])
    detail = ""
    if not ctl:
        sens, reading = "no_control", "none"
    elif frac < RTS_SENSITIVE:
        sens, reading = "low", "none"
    else:
        sens = "ok"
        if attempts > 0:
            reading = "chip_attempted_channel_access_rts_rules_out_complete_tx_silence_only"
            if unanswered > 0:
                detail = " reading_unanswered=%d" % unanswered
        else:
            reading = "no_rts_attempt_in_sampled_windows_cannot_distinguish_internal_hold_from_cca_deferral"
    return ("gap=%d rts eligible=%d in_hold_ms=%.3f rts_attempts=%d rts_answered=%d rts_unanswered=%d "
            "rxrsptmout=%d rts_attempts_per_s=%.3f rts_answered_per_s=%.3f rts_unanswered_per_s=%.3f "
            "rxrsptmout_per_s=%.3f unanswered_fraction=%s "
            "rxrsptmout_note=supporting_not_ap_attribution rxbeaconobss=%d rxbeaconobss_note=chip_hears_channel "
            "control_windows=%d control_len_ms=%.3f..%.3f control_rts_attempts_per_s_median=%s "
            "control_rts_answered_per_s_median=%s control_rts_unanswered_per_s_median=%s "
            "control_rxrsptmout_per_s_median=%s control_rts_attempt_positive_fraction=%s "
            "rts_sensitivity=%s reading=%s%s "
            "chip_init_tx=%d chip_init_tx_per_s=%.3f chip_init_tx_approx=1 chip_init_tx_clamped=%d "
            "control_chip_init_tx_per_s_median=%s control_chip_init_tx_clamped=%d chip_init_tx_reading=%s %s" % (
                g, len(inside), secs * 1e3, attempts, answered, unanswered, rsp,
                attempts / secs, answered / secs, unanswered / secs, rsp / secs,
                "%.3f" % (unanswered / attempts) if attempts > 0 else "n/a", total("rxbeaconobss"),
                len(ctl), lo * 1e3, hi * 1e3, med(rts_attempts), med(lambda iv: iv["d"]["txrts"]),
                med(lambda iv: iv["d"]["txnocts"]), med(lambda iv: iv["d"]["rxrsptmout"]),
                "none" if frac is None else "%.3f" % frac, sens, reading, detail,
                cit_sum, cit_sum / secs, sum(1 for x in cit if x[1]),
                "none" if cit_ctl is None else "%.3f" % cit_ctl, sum(1 for iv in ctl if chip_init_tx(iv)[1]),
                "chip_mac_transmitted_non_ack_frames_in_hold_approx_may_include_cts_ba_responses" if cit_sum > 0
                else "none", LABEL))


def median(v):
    v = sorted(v)
    n = len(v)
    return None if not n else (v[n // 2] if n % 2 else (v[n // 2 - 1] + v[n // 2]) / 2)


def beacons(iv):
    w = iv["hi"] - iv["lo"]
    exp = w / BEACON_S
    return "beacon_observed=%d beacon_expected=%.3f beacon_observed_over_expected=%s" % (
        iv["d"]["rxbeaconmbss"], exp, ("%.3f" % (iv["d"]["rxbeaconmbss"] / exp)) if exp > 0 else "undefined")


def cmd_samples(dump, marks, gaps_path=None, extra=()):
    h, recs = rt.load(dump)
    m = rt.model(rt.pings(recs, rt.pcap_marks(marks)))
    peer = lambda t: rt.to_peer(m, t / 1e6)        # noqa: E731
    samples, skips, lost, late, events, sdio_bytes, last_t = collect(recs)
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
    base = [iv for iv in ivs if all(iv["hi"] < lo or iv["lo"] > hi for lo, hi, _ in gaps)]
    eligible = []
    for g, (lo, hi, d) in enumerate(gaps):
        inside = [iv for iv in ivs if lo <= iv["lo"] and iv["hi"] <= hi]
        eligible.append(len(inside))
        out.append("gap=%d dir=%s start=%.6f end=%.6f eligible_count=%d%s %s" % (
            g, d or "none", lo, hi, len(inside), " result=inconclusive" if not inside else "", LABEL))
        reqs = [s["req"] for s in samples if lo <= peer(s["req"]) <= hi]
        out.append("gap=%d hold samples=%d %s %s %s" % (
            g, len(reqs), cadence(reqs), skip_counts([x for x in skips if lo <= peer(x[0]) <= hi]), LABEL))
        for iv in inside:
            out.append("gap=%d eligible from_id=%d to_id=%d window_start=%.6f window_end=%.6f window_ms=%.3f "
                       "%s %s wrapped=%s %s" % (
                           g, iv["a"]["id"], iv["b"]["id"], iv["lo"], iv["hi"], (iv["hi"] - iv["lo"]) * 1e3,
                           deltas(iv) + wide_str(iv), beacons(iv), ",".join(iv["wrap"]) or "none", LABEL))
        rl = rts_readout(g, inside, base)
        if rl:
            out.append(rl)
        for s in samples:
            if lo <= peer(s["req"]) <= hi:
                lat = s["lat"] if s["rep"] is not None else (
                    s["late"][0][2] if s["late"] and s["late"][0][1] else None)
                out.append("gap=%d latency id=%d req_peer=%.6f status=%s latency_us=%s %s" % (
                    g, s["id"], peer(s["req"]), status_of(s), "unknown" if lat is None else lat, LABEL))
    for iv in base:
        w = iv["hi"] - iv["lo"]
        out.append("baseline from_id=%d to_id=%d window_start=%.6f window_end=%.6f window_ms=%.3f %s %s %s %s" % (
            iv["a"]["id"], iv["b"]["id"], iv["lo"], iv["hi"], w * 1e3, deltas(iv) + wide_str(iv),
            " ".join("rate_per_s.%s=%.3f" % (f, iv["d"][f] / w) for f in iv["f"]) if w > 0 else "rate=undefined",
            beacons(iv), LABEL))
    span = (last_t - samples[0]["req"]) / 1e6 if samples and last_t is not None else 0.0
    out.append("leg samples=%d %s %s sdio_bytes=%d span_s=%.3f sdio_bytes_per_s=%s" % (
        len(samples), cadence([s["req"] for s in samples]), skip_counts(skips), sdio_bytes, span,
        "%.1f" % (sdio_bytes / span) if span > 0 else "undefined"))
    out.append("summary samples_total=%d %s lost=%d late=%d valid=%d overlap_excluded=%d invalid_end_excluded=%d eligible_per_gap=%s" % (
        len(samples), skip_counts(skips), lost, late,
        len([s for s in samples if valid(s)]), overlap, invalid, ",".join(str(n) for n in eligible) or "none"))
    return out


def cmd_btc(dump):
    """one line per RT_BTC record: op, name, value, rc (a signed firmware status,
    ctrl_* for no answer, driver_refused for a request never sent)"""
    h, recs = rt.load(dump)
    out = []
    for r in recs:
        if r["k"] != K_BTC:
            continue
        rc = r["d"]
        if rc == BTC_RC_REFUSED:
            rcs = "driver_refused"
        elif 0x7fff0001 <= rc <= 0x7fff0004:
            rcs = ("ctrl_timeout", "ctrl_nores", "ctrl_short", "ctrl_toobig")[rc - 0x7fff0001]
        else:
            rcs = str(rc - (1 << 32) if rc & 0x80000000 else rc)
        out.append("btc t_us=%d clo=%d op=%s name=%s value=%d rc=%s" % (
            r["t"], r["clo"], BTC_OP.get(r["a"], "invalid"), BTC_NAME.get(r["b"], "refused"), r["c"], rcs))
    out.append("btc_records=%d" % len(out))
    return out


def main(argv):
    if len(argv) == 2 and argv[0] == "btc":
        for line in cmd_btc(argv[1]):
            print(line)
        return 0
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
