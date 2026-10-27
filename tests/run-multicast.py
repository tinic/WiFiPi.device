#!/usr/bin/env python3
"""Host regression for the actual multicast handlers, with fake Exec/firmware.

No Pi/emulator is involved. Extracts the three adjacent static handlers from
src/unit.c, without rewriting their bodies. The C shim models only allocation,
list operations and firmware SETs, not Exec scheduling or firmware delivery.
Run: python3 tests/run-multicast.py --build-dir <anxd>/build/wifi-multicast
Use --source <old-unit.c> for the failing-parent negative control.
"""
import argparse
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--build-dir", type=Path, required=True)
parser.add_argument("--source", type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
source = (args.source or root / "src/unit.c").read_text()
# Locate by function name, so both the old void and new BOOL form work.
start = source.rfind("static ", 0, source.index("UpdateMCastList("))
end = source.index("static int Do_S2_GETNETWORKS", start)
args.build_dir.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix="case-", dir=args.build_dir) as work:
    work = Path(work)
    (work / "multicast-under-test.inc").write_text(source[start:end])
    binary = work / "multicast-test"
    subprocess.run(["clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-Wno-unused-variable", "-fsanitize=address,undefined",
                    "-fno-sanitize-recover=all", "-g", "-I", str(work),
                    str(root / "tests/test_multicast_host.c"), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
