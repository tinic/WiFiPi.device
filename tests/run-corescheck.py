#!/usr/bin/env python3
"""Host regression for brcm_chip_cores_check(): a chip is refused, not probed,
when a core that chip_init() and SetActive/SetPassive use unchecked is absent.

No Pi/emulator is involved. Extracts the function from src/wifipi.c unchanged
and runs it on fake core lists under ASan/UBSan.
Run: python3 tests/run-corescheck.py --build-dir <anxd>/build/wifi-corescheck
Use --source <old-wifipi.c> for the failing-parent negative control.
"""
import argparse
import os
import re
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--build-dir", type=Path, required=True)
parser.add_argument("--source", type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
source = (args.source or root / "src/wifipi.c").read_text()
start = source.index("static int brcm_chip_cores_check(")
end = source.index("static int sdio_buscoreprep", start)
args.build_dir.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix="case-", dir=args.build_dir) as work:
    work = Path(work)
    (work / "corescheck-under-test.inc").write_text(source[start:end])
    constants = [line for line in (root / "include/brcm.h").read_text().splitlines()
                 if re.match(r"#define\s+BCMA_CORE_\w+\s", line)]
    (work / "corescheck-constants.inc").write_text("\n".join(constants) + "\n")
    binary = work / "corescheck-test"
    subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra",
                    "-Werror", "-Wno-unused-variable",
                    "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                    "-g", "-I", str(work),
                    str(root / "tests/test_corescheck_host.c"), "-o", str(binary)],
                   check=True)
    subprocess.run([str(binary)], check=True)
