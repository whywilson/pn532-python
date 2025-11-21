#!/usr/bin/env python3
"""Helper harness for proxmark-style `hf mf nested` flows.

This script is intentionally decoupled from the interactive CLI so that the
nesting workflow can be validated in isolation. It parses the familiar proxmark
arguments, translates them into an `mfoc` invocation, and mirrors a subset of
the proxmark UX (dump inspection, slow mode knobs, etc.). Once this proves
stable it can be wired into the CLI command tree.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional

CARD_BLOCKS = {
    "mini": 20,
    "0": 0,  # auto detect
    "1": 64,
    "2": 128,
    "4": 256,
    "o": 4,  # one sector only
}

ANSI_RESET = "\033[0m"
ANSI_GREEN = "\033[32m"
ANSI_RED = "\033[31m"
ANSI_CYAN = "\033[36m"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run a proxmark-style 'hf mf nested' sequence via the mfoc binary. "
            "Example: python test_nested.py 1 7 B ffffffffffff d"
        )
    )
    parser.add_argument("card", help="Card size flag (0,1,2,4,mini,o)")
    parser.add_argument(
        "block",
        help="Known block index (decimal) or * to let mfoc search automatically",
    )
    parser.add_argument(
        "key_type",
        choices=["A", "a", "B", "b"],
        help="Known key type for the provided block",
    )
    parser.add_argument("key", help="Known 6-byte key (12 hex chars)")
    parser.add_argument(
        "flags",
        nargs="?",
        default="",
        help="Optional flags: d (dump), s/ss (slow modes), t (reserved)",
    )
    parser.add_argument(
        "--mfoc",
        dest="mfoc_path",
        help="Path to the mfoc executable (defaults to first match in PATH)",
    )
    parser.add_argument(
        "-O",
        "--output",
        dest="output_path",
        help="Destination dump file (.mfd). Defaults to ./mf_nested_<timestamp>.mfd",
    )
    parser.add_argument(
        "--working-dir",
        dest="workdir",
        help="Directory used as the mfoc working directory (defaults to current)",
    )
    parser.add_argument(
        "--keep-on-failure",
        action="store_true",
        help="Do not delete the dump file if mfoc exits with a non-zero code",
    )
    parser.add_argument(
        "--extra",
        nargs=argparse.REMAINDER,
        help="Additional arguments passed verbatim to mfoc",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the derived mfoc command but do not execute it",
    )
    return parser.parse_args()


def resolve_card_blocks(flag: str) -> int:
    normalized = flag.lower()
    if normalized not in CARD_BLOCKS:
        raise SystemExit(f"Unsupported card size flag '{flag}'. Use one of: {', '.join(CARD_BLOCKS)}")
    return CARD_BLOCKS[normalized]


def parse_block(value: str, max_blocks: int) -> Optional[int]:
    if value in ("*", "auto"):
        return None
    try:
        block = int(value, 10)
    except ValueError as exc:
        raise SystemExit(f"Block must be decimal or '*' but got '{value}'") from exc
    if block < 0 or block >= 256:
        raise SystemExit("Block index must be between 0 and 255")
    if max_blocks and block >= max_blocks:
        raise SystemExit(f"Block {block} is outside the expected size ({max_blocks} blocks)")
    return block


def normalize_key(key: str) -> str:
    key_upper = key.upper()
    if not re.fullmatch(r"[0-9A-F]{12}", key_upper):
        raise SystemExit("Key must include exactly 12 hexadecimal characters")
    return key_upper


def resolve_mfoc_path(provided: Optional[str]) -> str:
    if provided:
        expanded = Path(provided).expanduser()
        if not expanded.exists():
            raise SystemExit(f"mfoc executable '{provided}' not found")
        if not os.access(expanded, os.X_OK):
            raise SystemExit(f"mfoc executable '{expanded}' is not executable")
        return str(expanded)
    detected = shutil.which("mfoc")
    if not detected:
        raise SystemExit(
            "mfoc executable not found. Install mfoc or pass --mfoc /path/to/mfoc"
        )
    return detected


def default_output_path() -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path.cwd() / f"mf_nested_{timestamp}.mfd"


def build_mfoc_command(
    mfoc_path: str,
    key: str,
    slow_level: int,
    output_path: Path,
    block: Optional[int],
    extra: Optional[Iterable[str]],
) -> List[str]:
    cmd: List[str] = [mfoc_path, "-O", str(output_path), "-k", key]
    if slow_level == 1:
        cmd += ["-P", "50", "-T", "30"]
    elif slow_level >= 2:
        cmd += ["-P", "75", "-T", "40"]
    if block is not None:
        # mfoc lacks an explicit block selector. Preserve the info for logs so we
        # can surface it to the operator and revisit if future versions add this.
        print(
            f"[info] Known block {block} specified. mfoc will probe sectors until the key matches."
        )
    if extra:
        cmd += list(extra)
    return cmd


def run_command(cmd: List[str], workdir: Optional[str]) -> int:
    print(f"[exec] {' '.join(cmd)}")
    process = subprocess.Popen(
        cmd,
        cwd=workdir or None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert process.stdout is not None
    for line in process.stdout:
        print(line.rstrip())
    return process.wait()


def is_trailer_block(index: int) -> bool:
    if index < 128:
        return (index + 1) % 4 == 0
    return ((index - 128) + 1) % 16 == 0


def summarize_dump(path: Path, expected_blocks: int, verbose: bool) -> None:
    raw = path.read_bytes()
    if not raw:
        print(f"{ANSI_RED}Dump file is empty{ANSI_RESET}")
        return
    block_count = len(raw) // 16
    print(
        f"{ANSI_GREEN}Dump saved to {path} ({block_count} blocks, {len(raw)} bytes).{ANSI_RESET}"
    )
    if expected_blocks and block_count != expected_blocks:
        print(
            f"{ANSI_RED}Warning:{ANSI_RESET} expected {expected_blocks} blocks but file contains {block_count}."
        )
    uid = raw[0:4].hex().upper()
    print(f"UID (from block 0): {uid}")
    if verbose:
        for idx in range(block_count):
            data = raw[idx * 16 : (idx + 1) * 16].hex().upper()
            if is_trailer_block(idx):
                key_a = data[0:12]
                access_bits = data[12:20]
                key_b = data[20:32]
                print(
                    f"{idx:03d}: KeyA={key_a} Access={access_bits} KeyB={key_b}"
                )
            else:
                print(f"{idx:03d}: {data}")


def main() -> None:
    args = parse_args()
    block_budget = resolve_card_blocks(args.card)
    block_idx = parse_block(args.block, block_budget)
    known_key = normalize_key(args.key)
    mfoc_path = resolve_mfoc_path(args.mfoc_path)
    flags = (args.flags or "").lower()
    dump_verbose = "d" in flags
    slow_level = flags.count("s")
    if "t" in flags:
        print("[warn] 't' flag is reserved for future emulator transfer logic")
    output_path = Path(args.output_path).expanduser() if args.output_path else default_output_path()
    if output_path.exists():
        raise SystemExit(f"Output file {output_path} already exists; pick another path")

    cmd = build_mfoc_command(
        mfoc_path=mfoc_path,
        key=known_key,
        slow_level=slow_level,
        output_path=output_path,
        block=block_idx,
        extra=args.extra,
    )

    if args.dry_run:
        print(f"[dry-run] {' '.join(cmd)}")
        return

    rc = run_command(cmd, args.workdir)
    if rc != 0:
        if not args.keep_on_failure and output_path.exists():
            output_path.unlink(missing_ok=True)
        raise SystemExit(f"mfoc exited with code {rc}")

    try:
        summarize_dump(output_path, block_budget, verbose=dump_verbose)
    except Exception as exc:  # pragma: no cover - defensive
        print(f"{ANSI_RED}Failed to parse dump: {exc}{ANSI_RESET}")


if __name__ == "__main__":
    main()
