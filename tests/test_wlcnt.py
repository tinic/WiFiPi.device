#!/usr/bin/env python3
"""Host test for tools/wlcnt.py (#89): firmware 'counters' snapshots.

  python3 tests/test_wlcnt.py   -> "RESULT test_wlcnt checks=N failures=0"

Blobs are built from the decoder's own offset tables and wrapped in the
32-byte struct WcDumpHeader of src/wlcnt.h (big-endian); the firmware's
answer inside is little-endian, as it comes off the chip.
"""
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "..", "tools", "wlcnt.py")
sys.path.insert(0, os.path.join(HERE, "..", "tools"))
import wlcnt  # noqa: E402

checks = failures = 0


def expect(ok, what):
    global checks, failures
    checks += 1
    if not ok:
        failures += 1
        print("FAIL", what)


def fill(fields, size, seed, override=None):
    """A struct image with every field a distinct value; returns (bytes, {name: value})"""
    b = bytearray(size)
    vals = {}
    for i, (name, off, w) in enumerate(fields):
        v = (seed * 0x9E3779B1 + i * 0x01000193) & (0xFFFF if w == 2 else 0xFFFFFFFF)
        if override and name in override:
            v = override[name]
        struct.pack_into("<H" if w == 2 else "<I", b, off, v)
        vals[name] = v
    return b, vals


def legacy(ver, ln, seed=1, override=None, fields=wlcnt.V10_FIELDS):
    b, vals = fill(fields, max(ln, 4), seed, override)
    struct.pack_into("<HH", b, 0, ver, ln)
    return bytes(b), vals


def xtlv(blocks, datalen=None):
    body = b""
    for xid, data in blocks:
        t = struct.pack("<HH", xid, len(data)) + data
        body += t + b"\0" * (-len(t) & 3)
    return struct.pack("<HH", 30, len(body) if datalen is None else datalen) + body


def dump(answer, copied=None, err=0, asked=2048, clo0=1000, clo1=1200):
    a = answer + b"\0" * (asked - len(answer))
    c = len(answer) if copied is None else copied
    return wlcnt.WC_HEADER.pack(wlcnt.WC_DUMP_MAGIC, 1, 32, clo0, clo1, err, asked, c,
                                0x80000) + a[:asked]


tmp = tempfile.mkdtemp(prefix="wlcnt-test-")


def put(name, blob):
    p = os.path.join(tmp, name)
    with open(p, "wb") as f:
        f.write(blob)
    return p


def run(*args):
    r = subprocess.run([sys.executable, TOOL] + list(args), capture_output=True, text=True)
    kv = {}
    for line in r.stdout.splitlines():
        k, _, v = line.partition("=")
        kv[k] = v
    return r.returncode, kv, r.stdout


def refused(data, copied=None):
    try:
        wlcnt.decode(data, len(data) if copied is None else copied)
    except wlcnt.Refused as r:
        return r.reason
    return None


# --- tables: contiguous, and the documented sizes -------------------------
expect(wlcnt.WC_HEADER.size == 32, "WcDumpHeader is 32 bytes")
expect(wlcnt.V10_FIELDS_SIZE == 848 and wlcnt.V10_FIELDS[-1][1] + 4 == 848, "v10 table ends at 848")
expect(len(wlcnt.V10_FIELDS) == 2 + 211, "v10: version, length and 211 u32")
expect(wlcnt.WLC_FIELDS_SIZE == 864 and len(wlcnt.WLC_FIELDS) == 216, "wl_cnt_wlc_t: 216 u32")
for t in (wlcnt.GE40_FIELDS, wlcnt.LT40_FIELDS, wlcnt.LE10_FIELDS):
    expect(sum(w for _, _, w in t) == 256 and len(t) == 64, "MACSTAT table is 64 u32")
expect(dict((n, o) for n, o, _ in wlcnt.V10_FIELDS)["rxframe"] == 64, "v10 rxframe at 64")
expect(dict((n, o) for n, o, _ in wlcnt.V10_FIELDS)["rxbadfcs"] == 272, "v10 rxbadfcs at 272")
expect(dict((n, o) for n, o, _ in wlcnt.V10_FIELDS)["rxf0ovfl"] == 364, "v10 rxf0ovfl at 364")
expect(dict((n, o) for n, o, _ in wlcnt.GE40_FIELDS)["rxbadfcs"] == 84, "ge40 rxbadfcs at 84")
try:
    wlcnt._check((("a", 0, 4), ("b", 8, 4)), 12)
    expect(False, "a gap in a table is caught")
except AssertionError:
    expect(True, "a gap in a table is caught")

# --- v10, 848: every field round-trips exactly ----------------------------
blob, vals = legacy(10, 848, seed=7)
layout, got = wlcnt.decode(blob, len(blob))
expect(layout == "v10_848", "v10/848 layout")
want = {k: v for k, v in vals.items() if k not in ("version", "length")}
expect(got == want, "v10/848: every field exact")
expect(len(got) == 211, "v10/848: 211 counters")

# --- v10, 844: the same without rxrtry -------------------------------------
blob844, vals844 = legacy(10, 844, seed=9, fields=wlcnt.V10_FIELDS[:-1])
layout, got = wlcnt.decode(blob844, len(blob844))
expect(layout == "v10_844" and "rxrtry" not in got, "v10/844 layout, no rxrtry")
expect(got == {k: v for k, v in vals844.items() if k not in ("version", "length")},
       "v10/844: every field exact")

# --- refusals ---------------------------------------------------------------
r = refused(legacy(9, 848)[0])
expect(r is not None and "version 9" in r, "wrong version (9) refused: %s" % r)
r = refused(legacy(11, 1004)[0])
expect(r is not None and "version 11" in r, "v11 refused (no table built): %s" % r)
r = refused(legacy(0x1234, 848)[0])
expect(r is not None and "version 4660" in r, "unknown version refused: %s" % r)
r = refused(legacy(10, 900)[0])
expect(r is not None and "length 900" in r, "v10 with an unproven length refused: %s" % r)
r = refused(blob, copied=600)
expect(r is not None and "short" in r and "600" in r, "v10/848 with 600 bytes arrived refused: %s" % r)
r = refused(blob[:2], copied=2)
expect(r is not None and "short" in r, "2-byte answer refused")

rc, kv, out = run("show", put("v9.bin", dump(legacy(9, 848)[0])))
expect(rc == 2 and kv.get("refused", "").startswith("no proven table for version 9"),
       "CLI: wrong version exit 2, refused= line")
expect(kv.get("hex.0000", "").startswith("09 00 50 03"), "CLI: refusal carries a hex dump")
rc, kv, _ = run("show", put("short.bin", dump(blob, copied=600)))
expect(rc == 2 and "short" in kv.get("refused", ""), "CLI: short answer exit 2")
rc, kv, _ = run("show", put("fwerr.bin", dump(b"", copied=0, err=0xFFFFFFE9)))
expect(rc == 2 and "error 0xffffffe9" in kv.get("refused", ""), "CLI: firmware refusal exit 2")
rc, kv, _ = run("show", put("junk.bin", b"\0" * 40))
expect(rc == 2 and "not a wlcnt dump" in kv.get("refused", ""), "CLI: not a dump")
rc, kv, _ = run("show", put("trunc.bin", dump(blob)[:1000]))
expect(rc == 2 and "header says" in kv.get("refused", ""), "CLI: truncated file")

# --- show -------------------------------------------------------------------
rc, kv, _ = run("show", put("v10.bin", dump(blob)))
expect(rc == 0 and kv.get("layout") == "v10_848", "CLI show v10: exit 0")
expect(kv.get("field.rxbadfcs") == str(vals["rxbadfcs"]), "CLI show v10: rxbadfcs")
expect(kv.get("copied") == "848" and kv.get("clo_after") == "1200", "CLI show: header fields")

# --- delta, with a wrap -----------------------------------------------------
pre, pv = legacy(10, 848, seed=3, override={"rxbadfcs": 0xFFFFFFF0, "rxframe": 100, "rxf0ovfl": 5,
                                            "rxnobuf": 0, "rxcrc": 0})
post, qv = legacy(10, 848, seed=3, override={"rxbadfcs": 0x10, "rxframe": 350, "rxf0ovfl": 5,
                                             "rxnobuf": 0, "rxcrc": 0})
rc, kv, out = run("delta", put("pre.bin", dump(pre, clo1=0xFFFFFF00)),
                  put("post.bin", dump(post, clo0=0x100)))
expect(rc == 0 and kv.get("layout") == "v10_848", "delta v10: exit 0")
expect(kv.get("delta.rxbadfcs") == "32" and kv.get("wrap.rxbadfcs") == "1", "delta: wrapped u32 = 32, flagged")
expect(kv.get("delta.rxframe") == "250" and "wrap.rxframe" not in kv, "delta: plain rise")
expect(kv.get("delta.rxf0ovfl") == "0", "delta: flat field is 0")
expect(kv.get("wrapped") == "rxbadfcs", "delta: wrapped list")
expect(kv.get("elapsed_us") == "512", "delta: CLO elapsed across its wrap")
expect(kv.get("fields") == ",".join(wlcnt.RX_V10), "delta: the explicit field list")
expect(kv.get("snapshot_rule") == "pre_and_post_only (Do_WlCnt holds wu_Lock; never mid-leg)",
       "delta: snapshot rule line")
expect(kv.get("ambient_rf_fields") == ",".join(wlcnt.AMBIENT_V10)
       and kv.get("host_drop_fields") == ",".join(wlcnt.DROP_V10), "delta: both group lists printed")
expect(kv.get("other_fields", "").split(",") ==
       [n for n in wlcnt.RX_V10 if n not in wlcnt.AMBIENT_V10 + wlcnt.DROP_V10],
       "delta: the rest listed, no verdict")
expect(all(("delta." + n) in kv for n in wlcnt.RX_V10), "delta: every listed field printed")
# ambient-only rise (rxbadfcs +32 over 512 us): descriptive, no drop verdict
expect(kv.get("ambient_rf_delta.rxbadfcs") == "32" and kv.get("ambient_rf_rate.rxbadfcs") == "62500.000",
       "delta: ambient delta and per-second rate")
expect(kv.get("ambient_rf_verdict") == "descriptive_only", "ambient-only rise: descriptive_only")
expect(kv.get("host_drop_rose") == "0" and kv.get("host_drop_rose_fields") == "none",
       "ambient-only rise: host_drop_rose=0")
expect(not any(k.startswith(("ambient_rf_excess", "rx_errors", "baseline")) for k in kv),
       "delta: no excess, no baseline, no combined verdict")

# a host drop rise
dpre, _ = legacy(10, 848, seed=4, override={"rxnobuf": 10, "rxf0ovfl": 2})
dpost, _ = legacy(10, 848, seed=4, override={"rxnobuf": 17, "rxf0ovfl": 2})
rc, kv, _ = run("delta", put("dpre.bin", dump(dpre)), put("dpost.bin", dump(dpost)))
expect(rc == 0 and kv.get("host_drop_rose") == "1" and kv.get("host_drop_rose_fields") == "rxnobuf"
       and kv.get("host_drop_delta.rxnobuf") == "7" and kv.get("host_drop_delta.rxf0ovfl") == "0",
       "drop rise: host_drop_rose=1, exact field deltas")

# fail closed: a timed-out or short snapshot on either side prints no delta
rc, kv, out = run("delta", put("tmo.bin", dump(b"", copied=0, err=0x7FFF0001)), put("dpost2.bin", dump(dpost)))
expect(rc == 2 and "error 0x7fff0001" in kv.get("refused", "") and "delta." not in out,
       "delta: timed-out pre snapshot refused")
rc, kv, out = run("delta", put("dpre2.bin", dump(dpre)), put("dshort.bin", dump(dpost, copied=700)))
expect(rc == 2 and "short" in kv.get("refused", "") and "delta." not in out,
       "delta: short post copy refused")

flat, _ = legacy(10, 848, seed=3, override={"rxbadfcs": 0x10, "rxframe": 350, "rxf0ovfl": 5,
                                            "rxnobuf": 0, "rxcrc": 0})
rc, kv, _ = run("delta", put("post2.bin", dump(post)), put("flat.bin", dump(flat)))
expect(rc == 0 and kv.get("host_drop_rose") == "0" and kv.get("wrapped") == "none",
       "delta: identical snapshots are flat")
rc, kv, _ = run("delta", put("a844.bin", dump(blob844)), put("b848.bin", dump(post)))
expect(rc == 2 and "layouts differ" in kv.get("refused", ""), "delta: layouts must match")

# --- XTLV v30 ---------------------------------------------------------------
wlc, wv = fill(wlcnt.WLC_FIELDS, 864, 11)
ge40, gv = fill(wlcnt.GE40_FIELDS, 256, 12)
x = xtlv([(0x55, b"\1\2\3\4\5\6"), (0x100, bytes(wlc)), (0x400, bytes(ge40))])
layout, got = wlcnt.decode(x, len(x))
expect(layout == "xtlv_v30:0x55/6,0x100/864,0x400/256", "xtlv layout lists blocks: %s" % layout)
expect(all(got["wlc." + n] == v for n, v in wv.items()), "xtlv: every WLC field exact")
expect(all(got["mcst." + n] == v for n, v in gv.items() if not n.startswith("pad_")),
       "xtlv: every GE40 MACSTAT field exact")
expect(not any(k.startswith("0x55") for k in got), "xtlv: unknown id skipped, not read")

short_wlc = bytes(wlc[:732])                       # Cypress bcmdhd's wl_cnt_wlc_t
le10, lv = fill(wlcnt.LE10_FIELDS, 256, 13)
x2 = xtlv([(0x100, short_wlc), (0x200, bytes(le10))])
layout, got = wlcnt.decode(x2, len(x2))
expect(got.get("wlc.rxframe") == wv["rxframe"] and got.get("wlc.rxrtry") == wv["rxrtry"]
       and "wlc.rxback" not in got and "wlc.p2p_tbtt" not in got,
       "xtlv: a shorter WLC block is read only as far as it goes")
expect(got.get("mcst.rxf0ovfl") == lv["rxf0ovfl"], "xtlv: LE10 MACSTAT read")

r = refused(xtlv([(0x100, bytes(wlc)), (0x400, bytes(ge40[:200]))]))
expect(r is not None and "len 200" in r, "xtlv: MACSTAT of the wrong size refused")
r = refused(xtlv([(0x100, bytes(wlc))], datalen=2000))
expect(r is not None and "datalen" in r, "xtlv: datalen past the answer refused")
r = refused(xtlv([(0x55, b"\0" * 8)]))
expect(r is not None and "without a block" in r, "xtlv: no known block refused")
r = refused(xtlv([(0x100, bytes(wlc)), (0x100, bytes(wlc))]))
expect(r is not None and "twice" in r, "xtlv: repeated id refused")
r = refused(xtlv([(0x100, bytes(wlc))])[:500], copied=500)
expect(r is not None and "short" in r, "xtlv: cut answer refused")
bad = bytearray(xtlv([(0x100, bytes(wlc))]))
struct.pack_into("<H", bad, 6, 2000)                # WLC len past datalen
r = refused(bytes(bad))
expect(r is not None and "runs past" in r, "xtlv: block past datalen refused")

xpre = xtlv([(0x100, bytes(fill(wlcnt.WLC_FIELDS, 864, 20, {"rxnobuf": 7})[0])),
             (0x400, bytes(fill(wlcnt.GE40_FIELDS, 256, 21, {"rxbadfcs": 1})[0]))])
xpost = xtlv([(0x100, bytes(fill(wlcnt.WLC_FIELDS, 864, 20, {"rxnobuf": 9})[0])),
              (0x400, bytes(fill(wlcnt.GE40_FIELDS, 256, 21, {"rxbadfcs": 4})[0]))])
rc, kv, _ = run("delta", put("xpre.bin", dump(xpre)), put("xpost.bin", dump(xpost)))
expect(rc == 0 and kv.get("delta.wlc.rxnobuf") == "2" and kv.get("delta.mcst.rxbadfcs") == "3",
       "xtlv delta: WLC and MACSTAT fields")
expect(kv.get("delta.mcst.rxinvmachdr") == "absent", "xtlv delta: a field the block lacks is absent")
expect(kv.get("host_drop_rose") == "1" and kv.get("host_drop_rose_fields") == "wlc.rxnobuf",
       "xtlv delta: host drop rise reported")
expect(kv.get("ambient_rf_delta.mcst.rxbadfcs") == "3" and kv.get("ambient_rf_verdict") == "descriptive_only",
       "xtlv delta: ambient group descriptive")

print("RESULT test_wlcnt checks=%d failures=%d" % (checks, failures))
sys.exit(1 if failures else 0)
