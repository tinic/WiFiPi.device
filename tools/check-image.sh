#!/usr/bin/env bash
# check-image.sh <wifipi.device> <link map>
#
# What -flto can do to an AmigaOS device without failing the link: nothing in
# the image references the ROMTag (exec finds it by scanning for RTC_MATCHWORD),
# so the linker plugin may treat the ROMTag, its init table, the LVO vector
# table and every function they point at as dead and drop them -- the link
# succeeds and the device is empty.  The link names _RomTag as a root; this
# script proves the result in the BYTES of the hunk file, because under LTO the
# map places only the ROMTag itself (the per-file "symbol from plugin" lines
# sit at the section end and mean nothing): the match word is where the map
# says, rt_MatchTag points at itself, the flags/type are a device's, rt_Name
# reaches "wifipi.device", rt_Init is inside the hunk; and no libc/libgcc
# archive took part in the link (a late-invented memcpy would have come from
# one).
set -eu
img=$1; map=$2
fail() { echo "check-image: FAIL $*" >&2; exit 1; }
[ -s "$img" ] || fail "no image"
[ -s "$map" ] || fail "no map"
romtag=$(grep -E '[[:space:]]_?RomTag$' "$map" | awk '{print $1}' | head -1)
[ -n "$romtag" ] || fail "RomTag missing from the link map: LTO dropped the ROMTag chain"
if grep -qE '(libc|libgcc|libnix)\.a' "$map"; then
    fail "a libc/libgcc archive is in the link: a late-invented call was resolved from it"
fi
python3 - "$img" "$romtag" <<'PY' || exit 1
import struct, sys
d = open(sys.argv[1], 'rb').read()
off = int(sys.argv[2], 16)
# walk the hunk file to the first HUNK_CODE's data
p = 0
def u32(i): return struct.unpack('>I', d[i:i+4])[0]
if u32(0) != 0x3F3: print("check-image: FAIL not a hunk file"); sys.exit(1)
p = 4
while u32(p) != 0: p += 4 + u32(p) * 4       # resident library names (none)
p += 4
first, last = u32(p + 4), u32(p + 8); p += 12
p += (last - first + 1) * 4                    # hunk sizes
code = None
while p < len(d):
    t = u32(p) & 0x3FFFFFFF
    if t == 0x3E9:                             # HUNK_CODE
        n = u32(p + 4); code = d[p + 8:p + 8 + n * 4]; break
    if t in (0x3EA,):                          # HUNK_DATA
        n = u32(p + 4); p += 8 + n * 4; continue
    if t == 0x3EB: p += 8 + u32(p + 4) * 4; continue   # HUNK_BSS (size only)
    print("check-image: FAIL unexpected hunk %#x before the code" % t); sys.exit(1)
if code is None: print("check-image: FAIL no HUNK_CODE"); sys.exit(1)
if off + 26 > len(code): print("check-image: FAIL RomTag offset %#x outside the code hunk (%#x)" % (off, len(code))); sys.exit(1)
rt = struct.unpack('>HIIBBBbIII', code[off:off+26])
match, self_, endskip, flags, ver, ntype, pri, name, idstr, init = rt
if match != 0x4AFC: print("check-image: FAIL no RTC_MATCHWORD at %#x (found %#06x)" % (off, match)); sys.exit(1)
if self_ != off: print("check-image: FAIL rt_MatchTag %#x does not point at the ROMTag %#x" % (self_, off)); sys.exit(1)
if ntype != 3: print("check-image: FAIL rt_Type %d is not NT_DEVICE" % ntype); sys.exit(1)
if not (flags & 0x80): print("check-image: FAIL RTF_AUTOINIT missing from rt_Flags %#x" % flags); sys.exit(1)
if not (0 < name < len(code)) or code[name:name+14] != b'wifipi.device\0':
    print("check-image: FAIL rt_Name %#x does not reach \"wifipi.device\"" % name); sys.exit(1)
if not (0 < init < len(code)): print("check-image: FAIL rt_Init %#x outside the code hunk" % init); sys.exit(1)
if not (0 < endskip <= len(code)): print("check-image: FAIL rt_EndSkip %#x outside the code hunk" % endskip); sys.exit(1)
# RTF_AUTOINIT: rt_Init -> {size, vectors, structinit, initfunc}; the vectors must be in the hunk
size, vec, sinit, ifunc = struct.unpack('>IIII', code[init:init+16])
if not (0 < vec < len(code)) or not (0 < ifunc < len(code)):
    print("check-image: FAIL init table points outside the hunk (vectors %#x, init %#x)" % (vec, ifunc)); sys.exit(1)
print("check-image: PASS %s: %d bytes, ROMTag at %#x v%d pri %d, base %d bytes, vectors at %#x, init at %#x"
      % (sys.argv[1], len(d), off, ver, pri, size, vec, ifunc))
PY
