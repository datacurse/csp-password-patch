"""Bake the de-itzmx suppression into CLIPStudioPaint.exe (no external launcher).

Design: import-inject a tiny helper DLL (deitzmx_helper.dll) that does nothing at
loader-lock time except schedule a worker thread. After process init completes,
the worker late-loads the renamed frida-gadget (deitzmx.dll), which reads
deitzmx.config and runs the proven hook script. Late load == the timing that
frida.spawn validated, so it sidesteps the early anti-tamper that killed the
gadget-as-static-import attempt.

Staged payload (all live next to the exe in the install dir):
  CLIPStudioPaint.exe   - import-injected to load deitzmx_helper.dll
  deitzmx_helper.dll    - deferred loader (this repo, MinGW-built)
  deitzmx.dll           - frida-gadget, renamed
  deitzmx.config        - gadget config (script mode -> deitzmx_hook.js)
  deitzmx_hook.js       - frida_deitzmx.js (+ optional marker for smoke tests)
"""
from __future__ import annotations

import argparse
import shutil
from pathlib import Path

import lief

REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINE_EXE = REPO_ROOT / "backups" / "v420_patch1_868bbc56" / "CLIPStudioPaint.exe"
HELPER_DLL = REPO_ROOT / "tools" / "native" / "deitzmx_helper.dll"
GADGET = REPO_ROOT / "tools" / "bin" / "frida-gadget.dll"
HOOK_JS = REPO_ROOT / "tools" / "frida_deitzmx.js"
OUT_DIR = REPO_ROOT / "tools" / "output" / "baked"

HELPER_NAME = "deitzmx_helper.dll"
HELPER_SYMBOL = "deitzmx_anchor"
GADGET_NAME = "deitzmx.dll"
INSTALL_DIR = Path(r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT")


def inject(exe_in: Path, exe_out: Path) -> None:
    b = lief.PE.parse(str(exe_in))
    lib = b.add_import(HELPER_NAME)
    lib.add_entry(HELPER_SYMBOL)
    config = lief.PE.Builder.config_t()
    config.imports = True
    builder = lief.PE.Builder(b, config)
    builder.build()
    exe_out.parent.mkdir(parents=True, exist_ok=True)
    builder.write(str(exe_out))
    print(f"  import-injected -> {exe_out}")


def build_config(out_dir: Path, hook_dest: Path) -> None:
    cfg = out_dir / "deitzmx.config"
    cfg.write_text(
        "{\n"
        '  "interaction": {\n'
        '    "type": "script",\n'
        f'    "path": "{str(hook_dest).replace(chr(92), chr(92) * 2)}",\n'
        '    "on_change": "reload"\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )


def build_hook(out_dir: Path, marker_path: Path | None) -> None:
    body = HOOK_JS.read_text(encoding="utf-8")
    if marker_path is not None:
        esc = str(marker_path).replace("\\", "\\\\")
        preamble = (
            "// smoke-test marker: proves the gadget loaded and ran this script\n"
            "try { var __m = new File('%s', 'w'); __m.write('deitzmx hook ran @ ' + Date.now()); __m.flush(); __m.close(); } catch (e) {}\n\n"
            % esc
        )
        body = preamble + body
    (out_dir / "deitzmx_hook.js").write_text(body, encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe-in", type=Path, default=BASELINE_EXE)
    ap.add_argument("--out-dir", type=Path, default=OUT_DIR)
    ap.add_argument("--install-dir", type=Path, default=INSTALL_DIR)
    ap.add_argument("--marker", type=Path, default=None,
                    help="if set, hook writes this file on load (smoke test)")
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    print("Staging baked payload:")
    inject(args.exe_in, args.out_dir / "CLIPStudioPaint.exe")
    shutil.copy2(HELPER_DLL, args.out_dir / HELPER_NAME)
    shutil.copy2(GADGET, args.out_dir / GADGET_NAME)
    build_config(args.out_dir, args.install_dir / "deitzmx_hook.js")
    build_hook(args.out_dir, args.marker)

    print("\nStaged in", args.out_dir)
    for f in sorted(args.out_dir.iterdir()):
        print(f"  {f.name:24} {f.stat().st_size}")
    print("\nDeploy: copy these 5 files into the install dir (back up the real exe first).")


if __name__ == "__main__":
    main()
