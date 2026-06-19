import json
from pathlib import Path

regs = json.loads((Path(__file__).resolve().parents[1] / "tools/output/dump/iat_full.json").read_text())
main = max(regs, key=lambda r: sum(1 for s in r["slots"] if s.get("name")))
print("main region", hex(main["lo"]), "-", hex(main["hi"]))
prev = None
for s in main["slots"]:
    if not s.get("n") and not s.get("name") and not s.get("bad"):
        print(f"  UNRES {hex(s['rva'])} dll={s.get('dll')} off={s.get('off')}  (prev={prev})")
    if s.get("name"):
        prev = f"{s['dll']}!{s['name']}"
    elif s.get("n"):
        prev = "<NULL>"
