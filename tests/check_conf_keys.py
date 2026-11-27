#!/usr/bin/env python3
"""Audit shipped conf files for keys the C++ code never reads.

A key is "unread" if no conf.get / get_bool / get_int / get_int_clamped /
get_size / get_double call in server/src or client/src names it.

Unread keys that default to true over-claim a feature. This script fails
when that happens, with one documented exception: hunt_enabled (POST
/api/hunt is live; the key itself is not read and cannot turn hunt off).

Usage (from the repo root or any cwd):
    python3 tests/check_conf_keys.py
    python3 tests/check_conf_keys.py --root /path/to/SecureSeaHorseSIEM
"""
from __future__ import annotations

import argparse, re, sys
from pathlib import Path

# Feature is live; the tuning key is not read. Do not treat true as an overclaim.
# hunt_enabled: /api/hunt is live; the key itself is not read.
# soar_verify_tls: safe default (verify on) for an unwired SOAR client;
#   soar_enabled is already false, so this does not advertise SOAR as on.
ALLOW_UNREAD_TRUE = {"hunt_enabled", "soar_verify_tls"}

GET_RX = re.compile(
    r'conf\.get(?:_bool|_int|_int_clamped|_size|_double)?\(\s*"([^"]+)"'
)
KEY_RX = re.compile(r"^([A-Za-z0-9_.-]+)\s*=\s*(.*?)\s*$")


def conf_assignments(path: Path):
    rows = []
    for i, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
        s = line.split("#", 1)[0].strip()
        if not s:
            continue
        m = KEY_RX.match(s)
        if m:
            rows.append((m.group(1), m.group(2).strip(), i))
    return rows


def is_true(val: str) -> bool:
    return val.lower() in {"true", "yes", "on", "1"}


def code_get_keys(root: Path) -> set[str]:
    keys = set()
    for folder in (root / "server" / "src", root / "client" / "src"):
        if not folder.exists():
            continue
        for p in folder.rglob("*"):
            if p.suffix in {".cpp", ".h", ".hpp"}:
                text = p.read_text(errors="replace")
                keys.update(GET_RX.findall(text))
    return keys


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=None)
    args = ap.parse_args()
    root = (args.root or Path(__file__).resolve().parents[1]).resolve()

    shipped = [
        root / "server" / "config" / "server.conf",
        root / "client" / "config" / "client.conf",
    ]
    for p in shipped:
        if not p.is_file():
            print(f"MISSING {p}", file=sys.stderr)
            return 2

    got = code_get_keys(root)
    unread = []
    overclaim = []
    for path in shipped:
        rel = path.relative_to(root)
        for key, val, line in conf_assignments(path):
            if key in got:
                continue
            unread.append((str(rel), line, key, val))
            if is_true(val) and key not in ALLOW_UNREAD_TRUE:
                overclaim.append((str(rel), line, key, val))

    print(f"Shipped conf audit ({root})")
    print(f"  conf.get* keys in server/src + client/src: {len(got)}")
    print(f"  unread shipped keys: {len(unread)}")
    for rel, line, key, val in unread:
        flag = "OVERCLAIM" if (rel, line, key, val) in overclaim else (
            "ok-true (allow-listed)" if key in ALLOW_UNREAD_TRUE and is_true(val) else "unread"
        )
        print(f"    [{flag}] {rel}:{line}  {key} = {val}")

    if overclaim:
        print("\nFAIL: unread keys default to true (would over-claim a feature):")
        for rel, line, key, val in overclaim:
            print(f"  {rel}:{line}  {key} = {val}")
        return 1
    print("\nOK: no unread shipped key defaults to true (except documented hunt_enabled).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
