"""Print the failed tests recorded in the verifier's JUnit files. Run from the repository root."""
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

folder = Path(sys.argv[1] if len(sys.argv) > 1 else "experiments/results/chapter15")
for xml in sorted(folder.glob("junit_*.xml")):
    for tc in ET.parse(xml).getroot().iter("testcase"):
        for tag in ("failure", "error"):
            bad = tc.find(tag)
            if bad is not None:
                print(f"[{xml.stem}] {tc.get('classname')}::{tc.get('name')}  ({tag})")
                text = (bad.text or bad.get("message") or "").strip().splitlines()
                print("    " + "\n    ".join(text[-25:]))
                print()
