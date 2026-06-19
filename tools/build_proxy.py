"""Build a search-order-proxy DLL for an app-local CSP dependency.

Instead of editing the (integrity-checked) exe, we shadow a DLL that CSP already
loads from its own folder. The proxy forwards every export to the renamed real
DLL (<stem>_orig.dll) AND runs the deferred gadget loader (DllMain -> worker ->
late LoadLibrary deitzmx.dll), which runs the proven suppression hooks.

The exe is left byte-identical, so the protector's PE/import integrity check
(which rejected import-table injection with exit code 1) never fires.

Staged payload (deployed into the install dir):
  <stem>.dll        - the proxy (this build)
  <stem>_orig.dll   - the real DLL, renamed
  deitzmx.dll       - frida-gadget, renamed
  deitzmx.config    - gadget config (script mode -> deitzmx_hook.js)
  deitzmx_hook.js   - frida_deitzmx.js (+ optional marker)
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path

import lief

REPO_ROOT = Path(__file__).resolve().parents[1]
PROXY_SRC = REPO_ROOT / "tools" / "native" / "deitzmx_helper.c"
GADGET = REPO_ROOT / "tools" / "bin" / "frida-gadget.dll"
HOOK_JS = REPO_ROOT / "tools" / "frida_deitzmx.js"
OUT_DIR = REPO_ROOT / "tools" / "output" / "proxy"
INSTALL_DIR = Path(r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT")

PASSWORD_PLACEHOLDER = "__DEITZMX_PASSWORD__"

# The daily itzmx password phrase differs by word order between CSP builds.
PASSWORDS: dict[str, str] = {
    "5.0.0": (
        "lai2 zi4 bbs.itzmx.com mian3 fei4 fen1 xiang3 fa1 xian4 fan4 mai4 "
        "tui4 kuan3 ju3 bao4 cha4 ping2 bbs.itzmx.com Always Free"
    ),
    "4.2.0": (
        "lai2 zi4 bbs.itzmx.com mian3 fei4 fen1 xiang3 fa1 xian4 fan4 mai4 "
        "ju3 bao4 cha4 ping2 tui4 kuan3 bbs.itzmx.com Always Free"
    ),
}

_GCC_CANDIDATES = [
    Path(r"C:\ProgramData\mingw64\mingw64\bin\gcc.exe"),
    Path(r"C:\msys64\mingw64\bin\gcc.exe"),
    Path(r"C:\mingw64\bin\gcc.exe"),
]


def find_gcc() -> Path:
    import shutil

    found = shutil.which("gcc")
    if found:
        return Path(found)
    for p in _GCC_CANDIDATES:
        if p.is_file():
            return p
    raise RuntimeError(
        "gcc not found — install MinGW and add it to PATH, or set GCC env var"
    )


def read_exports(dll: Path):
    b = lief.parse(str(dll))
    exp = b.get_export()
    if exp is None:
        raise RuntimeError(f"{dll} has no export table")
    out = []
    for e in exp.entries:
        out.append((e.ordinal, e.name, e.is_forwarded,
                    e.forward_information if e.is_forwarded else None))
    return out


def write_def(def_path: Path, stem: str, orig_stem: str, exports) -> None:
    lines = [f"LIBRARY {stem}", "EXPORTS"]
    for ordinal, name, is_fwd, fwd in exports:
        if not name:
            # ordinal-only export: forward by ordinal
            lines.append(f"  ord{ordinal}={orig_stem}.#{ordinal} @{ordinal} NONAME")
        else:
            lines.append(f"  {name}={orig_stem}.{name} @{ordinal}")
    def_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_hook(out_dir: Path, marker_path: Path | None, password: str) -> None:
    body = HOOK_JS.read_text(encoding="utf-8")
    if PASSWORD_PLACEHOLDER not in body:
        raise RuntimeError(
            f"{HOOK_JS.name} is missing the {PASSWORD_PLACEHOLDER} placeholder"
        )
    body = body.replace(PASSWORD_PLACEHOLDER, password)
    if marker_path is not None:
        esc = str(marker_path).replace("\\", "\\\\")
        body = (
            "try { var __m = new File('%s', 'w'); __m.write('deitzmx hook ran @ ' + Date.now()); __m.flush(); __m.close(); } catch (e) {}\n\n"
            % esc
        ) + body
    (out_dir / "deitzmx_hook.js").write_text(body, encoding="utf-8")


def build_config(out_dir: Path, hook_dest: Path) -> None:
    (out_dir / "deitzmx.config").write_text(
        "{\n"
        '  "interaction": {\n'
        '    "type": "script",\n'
        f'    "path": "{str(hook_dest).replace(chr(92), chr(92) * 2)}",\n'
        '    "on_change": "reload"\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="ailia_blas", help="DLL stem to proxy")
    ap.add_argument("--install-dir", type=Path, default=INSTALL_DIR)
    ap.add_argument("--source-dir", type=Path, default=None,
                    help="where the real DLL currently lives (default: install dir). "
                         "Use C:\\Windows\\System32 to shadow a non-KnownDLL system DLL.")
    ap.add_argument("--out-dir", type=Path, default=OUT_DIR)
    ap.add_argument("--marker", type=Path, default=None)
    ap.add_argument("--csp-version", default="5.0.0",
                    help="selects the per-version itzmx password baked into the hook")
    args = ap.parse_args()

    password = PASSWORDS.get(args.csp_version)
    if password is None:
        raise SystemExit(
            f"no password configured for CSP version '{args.csp_version}' "
            f"(known: {', '.join(sorted(PASSWORDS))})"
        )

    stem = args.target
    orig_stem = f"{stem}_orig"
    source_dir = args.source_dir or args.install_dir
    real_dll = source_dir / f"{stem}.dll"
    args.out_dir.mkdir(parents=True, exist_ok=True)

    exports = read_exports(real_dll)
    print(f"Proxying {stem}.dll ({len(exports)} exports) -> {orig_stem}.dll")
    for o, n, f, fi in exports:
        print(f"  @{o} {n}{' (already fwd)' if f else ''}")

    def_path = args.out_dir / f"{stem}.def"
    write_def(def_path, stem, orig_stem, exports)

    proxy_out = args.out_dir / f"{stem}.dll"
    gcc = find_gcc()
    cmd = [
        str(gcc), "-O2", "-s", "-shared", "-nostdlib", "-nodefaultlibs",
        "-nostartfiles", "-Wl,-eDllMain",
        "-o", str(proxy_out), str(PROXY_SRC), str(def_path), "-lkernel32",
    ]
    print("\n$", " ".join(cmd))
    subprocess.run(cmd, check=True)

    # Stage payload
    shutil.copy2(real_dll, args.out_dir / f"{orig_stem}.dll")
    shutil.copy2(GADGET, args.out_dir / "deitzmx.dll")
    build_config(args.out_dir, args.install_dir / "deitzmx_hook.js")
    print(f"Hook password: CSP {args.csp_version}")
    build_hook(args.out_dir, args.marker, password)

    # Verify proxy exports/imports
    b = lief.parse(str(proxy_out))
    exp = b.get_export()
    print("\nProxy export table:", exp.name)
    for e in exp.entries:
        fwd = f" -> {e.forward_information}" if e.is_forwarded else ""
        print(f"  @{e.ordinal} {e.name}{fwd}")
    print("Proxy imports:", [i.name for i in b.imports])

    print("\nStaged in", args.out_dir)
    for f in sorted(args.out_dir.iterdir()):
        print(f"  {f.name:24} {f.stat().st_size}")


if __name__ == "__main__":
    main()
