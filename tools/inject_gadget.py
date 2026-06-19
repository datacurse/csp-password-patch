"""Bake the de-itzmx hook into CLIPStudioPaint.exe via import-table injection.

Adds an import of `deitzmx.dll` (a renamed frida-gadget) so Windows loads it at
startup. The gadget reads `deitzmx.config` (script mode) and runs `deitzmx_hook.js`,
which auto-enters the start password and suppresses the splash/anti-resale popups -
all internally, with no external launcher.
"""
from __future__ import annotations

import argparse
import shutil
from pathlib import Path

import lief

REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINE_EXE = REPO_ROOT / "backups" / "v420_patch1_868bbc56" / "CLIPStudioPaint.exe"
GADGET = REPO_ROOT / "tools" / "bin" / "frida-gadget.dll"
HOOK_JS = REPO_ROOT / "tools" / "frida_deitzmx.js"
OUT_DIR = REPO_ROOT / "tools" / "output" / "baked"

INJECTED_DLL_NAME = "deitzmx.dll"


def pick_export(gadget_path: Path) -> str:
    b = lief.parse(str(gadget_path))
    for exp in b.exported_functions:
        if exp.name:
            return exp.name
    raise RuntimeError("gadget has no named exports")


def inject(exe_in: Path, exe_out: Path, import_symbol: str) -> None:
    b = lief.PE.parse(str(exe_in))
    lib = b.add_import(INJECTED_DLL_NAME)
    lib.add_entry(import_symbol)

    config = lief.PE.Builder.config_t()
    config.imports = True
    builder = lief.PE.Builder(b, config)
    builder.build()
    exe_out.parent.mkdir(parents=True, exist_ok=True)
    builder.write(str(exe_out))
    print(f"Wrote {exe_out}")


def build_config(out_dir: Path, hook_dest: Path) -> Path:
    cfg = out_dir / "deitzmx.config"
    cfg.write_text(
        '{\n'
        '  "interaction": {\n'
        '    "type": "script",\n'
        f'    "path": "{str(hook_dest).replace(chr(92), chr(92) * 2)}",\n'
        '    "on_change": "reload"\n'
        '  }\n'
        '}\n',
        encoding="utf-8",
    )
    return cfg


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe-in", type=Path, default=BASELINE_EXE)
    parser.add_argument("--out-dir", type=Path, default=OUT_DIR)
    parser.add_argument(
        "--install-dir",
        type=Path,
        default=Path(r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT"),
    )
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    sym = pick_export(GADGET)
    print(f"Importing symbol from gadget: {sym}")

    exe_out = args.out_dir / "CLIPStudioPaint.exe"
    inject(args.exe_in, exe_out, sym)

    # Stage the payload files alongside the exe (final hook path = install dir).
    hook_dest = args.install_dir / "deitzmx_hook.js"
    shutil.copy2(GADGET, args.out_dir / INJECTED_DLL_NAME)
    shutil.copy2(HOOK_JS, args.out_dir / "deitzmx_hook.js")
    build_config(args.out_dir, hook_dest)

    print("\nStaged in:", args.out_dir)
    for f in args.out_dir.iterdir():
        print("  ", f.name, f.stat().st_size)
    print("\nNext: run deploy_baked.py to copy these into the install dir (with backup).")


if __name__ == "__main__":
    main()
