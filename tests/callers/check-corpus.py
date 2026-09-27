#!/usr/bin/env python3
"""Check a caller corpus (.tsv) against the caller's binary.

usage: check-corpus.py <corpus.tsv> <binary>

The binary must match the sha256 in the corpus header, and every row's
`bin` offset must hold `move.w #<value>,28(An)` -- the store of that
command into io_Command.  The binary must also have no such store for any
known command (exec, SANA-II, wireless, NSD) that no row accounts for, so
a call site missing from the table fails too.  Exit 0 = the table matches the binary.
"""
import hashlib
import re
import sys

COMMANDS_SEEN = re.compile(rb'[\x31\x33\x35\x37\x39\x3b\x3d\x3f]\x7c(..)\x00\x1c', re.S)

# every exec, SANA-II, SANA-II wireless and NSD command a caller could send
KNOWN = set(range(2, 10)) | set(range(9, 9 + 19)) | {0x4000, 0xc000, 0xc001} | set(range(0xc010, 0xc019))


def main(corpus, binary):
    text = open(corpus).read()
    data = open(binary, 'rb').read()
    want = re.search(r'sha256 ([0-9a-f]{64})', text).group(1)
    got = hashlib.sha256(data).hexdigest()
    bad = 0
    if got != want:
        print(f'FAIL binary sha256 {got}, corpus names {want}')
        return 1
    rows = [l.split('\t') for l in text.splitlines() if l and not l.startswith('#')]
    offsets = set()
    for r in rows:
        value, off = int(r[2], 0), int(r[3], 0)
        offsets.add(off)
        m = COMMANDS_SEEN.match(data, off)
        if not m or int.from_bytes(m.group(1), 'big') != value:
            print(f'FAIL row {r[0]} {r[1]}: no move.w #{value:#x},28(An) at {off:#x}')
            bad += 1
    for m in COMMANDS_SEEN.finditer(data):
        v = int.from_bytes(m.group(1), 'big')
        if v in KNOWN and m.start() not in offsets:
            print(f'FAIL store of {v:#x} at {m.start():#x} is in no row')
            bad += 1
    print(f'RESULT {"FAIL" if bad else "PASS"} {len(rows)} rows, {bad} failures')
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1], sys.argv[2]))
