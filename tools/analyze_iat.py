import json
from pathlib import Path

regs = json.loads((Path(__file__).resolve().parents[1] / "tools/output/dump/iat_full.json").read_text())
for r in regs:
    slots = r["slots"]
    named = sum(1 for s in slots if s.get("name"))
    nulls = sum(1 for s in slots if s.get("n"))
    unres = sum(1 for s in slots if not s.get("n") and not s.get("name") and not s.get("bad"))
    flag = "REAL" if named > max(unres, 1) else "SUSPECT"
    print(f"{flag} {hex(r['lo'])}-{hex(r['hi'])} slots={len(slots)} named={named} null={nulls} unres={unres}")

# detail of main region
main = max(regs, key=lambda r: sum(1 for s in r["slots"] if s.get("name")))
print("\n--- main region detail (first 40 slots) ---", hex(main["lo"]))
for s in main["slots"][:40]:
    if s.get("n"):
        tag = "<NULL>"
    elif s.get("name"):
        tag = f"{s['dll']}!{s['name']}"
    elif s.get("bad"):
        tag = "<BAD>"
    else:
        tag = f"{s.get('dll')}!?off={s.get('off')}"
    print(f"  {hex(s['rva'])} {tag}")
