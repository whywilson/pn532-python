import binascii
import os
import re
import subprocess
import argparse
import timeit
import sys
import time
from datetime import datetime
import serial.tools.list_ports
import json
import threading
import struct
import shutil
from unit.calc import str_to_bytes
from unit.calc import is_hex
from unit.preset import FactoryPreset
from unit.mifare_classic import get_block_size_by_sector, get_block_index_by_sector, is_trailer_block
from multiprocessing import Pool, cpu_count
from typing import Union
from pathlib import Path
from platform import uname
from datetime import datetime
from pn532_enum import Command, MfcKeyType, MifareCommand, PN532KillerMode, PN532KillerTagType, Status

from pn532_utils import CLITree

from pn532_utils import ArgumentParserNoExit, ArgsParserError, CG, CR, C0, CY, CM


import pn532_com
import pn532_cmd
import pn532_dfu

# NXP IDs based on https://www.nxp.com/docs/en/application-note/AN10833.pdf
type_id_SAK_dict = {
    0x00: "MIFARE Ultralight Classic/C/EV1/Nano | NTAG 2xx",
    0x08: "MIFARE Classic 1K | Plus SE 1K | Plug S 2K | Plus X 2K",
    0x09: "MIFARE Mini 0.3k",
    0x10: "MIFARE Plus 2K",
    0x11: "MIFARE Plus 4K",
    0x18: "MIFARE Classic 4K | Plus S 4K | Plus X 4K",
    0x19: "MIFARE Classic 2K",
    0x20: "MIFARE Plus EV1/EV2 | DESFire EV1/EV2/EV3 | DESFire Light | NTAG 4xx | "
    "MIFARE Plus S 2/4K | MIFARE Plus X 2/4K | MIFARE Plus SE 1K",
    0x28: "SmartMX with MIFARE Classic 1K",
    0x38: "SmartMX with MIFARE Classic 4K",
}

block_size_dict = {
    0x08: 64,
    0x09: 20,
    0x18: 256,
    0x19: 128,
}

hf_tag_type_dict = {
    # 14A tags
    0x01: "NTAG 213",
    0x02: "NTAG 215",
    0x03: "NTAG 216",
    0x11: "MIFARE Classic 4B1K (ATQA: 0x0400, SAK: 0x08)",
    0x12: "MIFARE Classic 4B4K (ATQA: 0x0200, SAK: 0x18)",
    0x13: "MIFARE Classic 7B1K (ATQA: 0x4400, SAK: 0x08)",
    0x14: "MIFARE Classic 7B4K (ATQA: 0x4200, SAK: 0x18)",
    # 15 tags
    0x81: "ISO15693 (4 bytes/block)",
}
default_cwd = Path(__file__).resolve().parent
tool_build_dir = Path(__file__).resolve().parent.parent / "build"
legacy_mfkey_dir = tool_build_dir / "mfkey"


def _helper_binary(name: str) -> Union[Path, None]:
    suffix = ".exe" if os.name == "nt" else ""
    candidates = [
        tool_build_dir / f"{name}{suffix}",
        tool_build_dir / name,
        legacy_mfkey_dir / f"{name}{suffix}",
        legacy_mfkey_dir / name,
    ]
    for path in candidates:
        if path.exists():
            return path
    alt = shutil.which(f"{name}{suffix}")
    return Path(alt) if alt else None


def _run_mfkey(name: str, args: list[str], verbose: bool = False):
    tool_path = _helper_binary(name)
    if tool_path is None:
        print(
            f"{CR}Missing {name} binary. Run script/build_helpers.sh first to compile the helpers.{C0}"
        )
        return None, None
    env = os.environ.copy()
    env[f"{name.upper()}_VERBOSE"] = "1" if verbose else "0"
    try:
        completed = subprocess.run(
            [str(tool_path), *args], capture_output=True, text=True, check=False, env=env
        )
    except FileNotFoundError:
        print(
            f"{CR}Cannot execute {tool_path}. Rebuild helpers via script/build_helpers.sh.{C0}"
        )
        return None, None
    output = (completed.stdout or "") + (completed.stderr or "")
    key_match = re.search(r"Found Key:\s*\[([0-9a-fA-F]{12})\]", output)
    key_hex = key_match.group(1).upper() if key_match else None
    if completed.returncode != 0 and key_hex is None:
        print(f"{CR}{name} exited with code {completed.returncode}{C0}")
        if output:
            print(output.strip())
    return key_hex, output


def _keytype_label(key_byte: int) -> str:
    return "A" if key_byte == 0x60 else "B"


def _fmt32(value: int) -> str:
    return f"{value:08X}"


DEFAULT_MF_KEYS = [
    bytes.fromhex("FFFFFFFFFFFF"),
    bytes.fromhex("000000000000"),
    bytes.fromhex("A0A1A2A3A4A5"),
    bytes.fromhex("B0B1B2B3B4B5"),
    bytes.fromhex("4D3A99C351DD"),
    bytes.fromhex("1A982C7E459A"),
    bytes.fromhex("D3F7D3F7D3F7"),
    bytes.fromhex("AABBCCDDEEFF"),
    bytes.fromhex("714C5C886E97"),
    bytes.fromhex("587EE5F9350F"),
    bytes.fromhex("A0478CC39091"),
    bytes.fromhex("533CB6C723F6"),
    bytes.fromhex("8FD0A4F256E9"),
    bytes.fromhex("0004A5B7C909"),
    bytes.fromhex("B578F38A5C61"),
    bytes.fromhex("96A301BCE267"),
]


def _sector_count_from_sak(sak_byte: int) -> int:
    if sak_byte == 0x09:
        return 5
    if sak_byte == 0x08:
        return 16
    if sak_byte == 0x19:
        return 32
    if sak_byte == 0x18:
        return 40
    return 0


def _block_count_from_sector_count(sector_count: int) -> int:
    if sector_count <= 0:
        return 0
    block_count = 0
    for sector in range(sector_count):
        block_count += get_block_size_by_sector(sector)
    return block_count


def _sector_from_block(block: int) -> int:
    if block < 0:
        return -1
    if block < 128:
        return block // 4
    if block < 256:
        return 32 + ((block - 128) // 16)
    return -1


def _trailer_block_for_sector(sector: int) -> int:
    first = get_block_index_by_sector(sector)
    size = get_block_size_by_sector(sector)
    if size <= 0:
        return -1
    return first + size - 1


def _normalize_key_hex(key_hex: str) -> Union[bytes, None]:
    if not key_hex:
        return None
    key_hex = key_hex.strip().upper()
    if not re.fullmatch(r"[0-9A-F]{12}", key_hex):
        return None
    return bytes.fromhex(key_hex)


def _prepend_unique_keys(dst: list[bytes], keys: list[bytes]):
    seen = set(dst)
    for key in keys:
        if key in seen:
            continue
        dst.insert(0, key)
        seen.add(key)


def _build_key_pool(args: argparse.Namespace) -> list[bytes]:
    pool: list[bytes] = []
    if not getattr(args, "no_default_keys", False):
        pool.extend(DEFAULT_MF_KEYS)

    manual_keys = getattr(args, "key", None) or []
    for key_hex in manual_keys:
        key_bytes = _normalize_key_hex(key_hex)
        if key_bytes is None:
            raise ArgsParserError(f"Invalid key format: {key_hex}")
        if key_bytes not in pool:
            pool.insert(0, key_bytes)

    key_file = getattr(args, "k", None)
    if key_file:
        for line in key_file:
            key_bytes = _normalize_key_hex(line)
            if key_bytes and key_bytes not in pool:
                pool.append(key_bytes)
    return pool


def _try_auth_read_trailer(
    cmd: pn532_cmd.Pn532CMD, trailer_block: int, key: bytes, key_type: MfcKeyType
):
    try:
        resp = cmd.mf1_read_one_block(trailer_block, key_type, key)
    except Exception:
        return None
    if (
        resp
        and hasattr(resp, "parsed")
        and isinstance(resp.parsed, (bytes, bytearray))
        and len(resp.parsed) == 16
    ):
        return bytes(resp.parsed)
    return None


def _try_auth_read_trailer_with_uid(
    cmd: pn532_cmd.Pn532CMD,
    trailer_block: int,
    key: bytes,
    key_type: MfcKeyType,
    uid: bytes,
):
    try:
        auth_ok = cmd.mf1_auth_one_key_block(trailer_block, key_type, key, uid)
        if not auth_ok:
            return None
        data = struct.pack("!BBB", 0x01, MifareCommand.MfReadBlock, trailer_block)
        resp = cmd.device.send_cmd_sync(Command.InDataExchange, data)
        if resp and len(resp.data) >= 16:
            parsed = bytes(resp.data[:16])
            if key_type == MfcKeyType.A:
                parsed = key + parsed[6:]
            else:
                parsed = parsed[0:10] + key
            return parsed
        return None
    except Exception:
        return None


def _recover_staticnested_key(
    cmd: pn532_cmd.Pn532CMD,
    known_key: bytes,
    known_block: int,
    known_key_type: MfcKeyType,
    target_block: int,
    target_key_type: MfcKeyType,
    show_raw: bool = False,
):
    datakey = b"\x00\x00" + known_key
    session = cmd.read_userdef_staticnested(
        datakey=datakey,
        known_block=known_block,
        known_key_type=int(known_key_type),
        target_block=target_block,
        target_key_type=int(target_key_type),
    )
    if not session:
        return None, None
    args_list = [
        _fmt32(session["uid"]),
        f"{session['key_type']:02X}",
        _fmt32(session["nt0"]),
        _fmt32(session["ks0"]),
        _fmt32(session["nt1"]),
        _fmt32(session["ks1"]),
    ]
    key_hex, output = _run_mfkey("staticnested", args_list, verbose=show_raw)
    if key_hex:
        return bytes.fromhex(key_hex), output
    return None, output


def _run_nestedattack_impl(cli_obj, args: argparse.Namespace):
    if cli_obj.device_com.get_device_name() != "PN532Killer":
        print(f"{CR}nestedattack requires PN532Killer firmware staticnested helper.{C0}")
        return {}, ["device is not PN532Killer"], False

    known_key = _normalize_key_hex(args.known_key)
    if known_key is None:
        raise ArgsParserError("--known-key must be exactly 12 hex characters")
    if args.known_block < 0 or args.known_block > 0xFF:
        raise ArgsParserError("--known-block must be between 0 and 255")

    known_type = MfcKeyType.B if args.known_key_type.upper() == "B" else MfcKeyType.A
    show_raw = getattr(args, "show_raw", False) or pn532_com.DEBUG

    scan = cli_obj.cmd.hf_14a_scan()
    if scan is None or len(scan) == 0:
        print("No tag found")
        return {}, ["no tag found"], False
    sak = int.from_bytes(scan[0]["sak"], "big")
    sector_count = _sector_count_from_sak(sak)
    if sector_count == 0:
        print(f"{CR}Not a supported MIFARE Classic card (SAK=0x{sak:02X}).{C0}")
        return {}, ["unsupported SAK"], False

    start_sector = max(0, args.start_sector)
    end_sector = (
        sector_count - 1
        if args.end_sector is None
        else min(args.end_sector, sector_count - 1)
    )
    if start_sector > end_sector:
        raise ArgsParserError("Invalid sector range")

    known_sector = _sector_from_block(args.known_block)
    if known_sector < 0 or known_sector >= sector_count:
        raise ArgsParserError("--known-block does not belong to this card size")

    known_pairs: dict[tuple[int, str], bytes] = {
        (known_sector, args.known_key_type.upper()): known_key
    }
    failures: list[str] = []
    unsupported_static_nonce = False

    if args.target_key_type.lower() == "both":
        wanted_types = ["A", "B"]
    else:
        wanted_types = [args.target_key_type.upper()]

    print(f"UID: {scan[0]['uid'].hex().upper()} | sectors: {sector_count}")
    print(
        f"Known seed: sector {known_sector:02d} key {args.known_key_type.upper()} = {known_key.hex().upper()}"
    )

    for sector in range(start_sector, end_sector + 1):
        target_block = _trailer_block_for_sector(sector)
        for target_letter in wanted_types:
            if (sector, target_letter) in known_pairs:
                continue
            target_type = MfcKeyType.A if target_letter == "A" else MfcKeyType.B

            seed_items = list(known_pairs.items())
            recovered = None
            for (seed_sector, seed_letter), seed_key in seed_items:
                seed_block = _trailer_block_for_sector(seed_sector)
                seed_type = MfcKeyType.A if seed_letter == "A" else MfcKeyType.B
                key_bytes, output = _recover_staticnested_key(
                    cli_obj.cmd,
                    known_key=seed_key,
                    known_block=seed_block,
                    known_key_type=seed_type,
                    target_block=target_block,
                    target_key_type=target_type,
                    show_raw=show_raw,
                )
                if show_raw and output:
                    for line in output.strip().splitlines():
                        print(f"    {line}")
                if output and "unsupported static tag nonce" in output.lower():
                    unsupported_static_nonce = True
                    print(
                        f"{CR}Card nonce is not compatible with staticnested helper. Use hf mf mfoc / mfkey workflows for non-static PRNG tags.{C0}"
                    )
                    break
                if key_bytes:
                    recovered = key_bytes
                    break

            if unsupported_static_nonce:
                break

            if recovered:
                known_pairs[(sector, target_letter)] = recovered
                print(f"Sector {sector:02d} Key{target_letter}: {CG}{recovered.hex().upper()}{C0}")
            else:
                failures.append(f"sector {sector:02d} key {target_letter}")
                print(f"Sector {sector:02d} Key{target_letter}: {CR}not found{C0}")
                if args.stop_on_fail:
                    break
        if args.stop_on_fail and failures:
            break
        if unsupported_static_nonce:
            break

    print("\nRecovered keys summary:")
    for sector in range(start_sector, end_sector + 1):
        key_a = known_pairs.get((sector, "A"))
        key_b = known_pairs.get((sector, "B"))
        ka = key_a.hex().upper() if key_a else "------------"
        kb = key_b.hex().upper() if key_b else "------------"
        print(f"  Sector {sector:02d} | A={ka} | B={kb}")

    if failures:
        print(f"{CY}Missing {len(failures)} key(s): {', '.join(failures)}{C0}")

    return known_pairs, failures, unsupported_static_nonce


def _card_profile_from_scan(scan):
    if scan is None or len(scan) == 0:
        return None
    uid = scan[0]["uid"]
    sak = int.from_bytes(scan[0]["sak"], "big")
    sector_count = _sector_count_from_sak(sak)
    if sector_count == 0:
        return None
    block_count = _block_count_from_sector_count(sector_count)
    return {
        "uid": uid,
        "sak": sak,
        "sector_count": sector_count,
        "block_count": block_count,
    }


def _require_mfc_profile(scan):
    """Return MIFARE Classic profile if card matches; otherwise print a clear hint and return None."""
    if scan is None or len(scan) == 0:
        print("No tag found")
        return None
    profile = _card_profile_from_scan(scan)
    if profile is not None:
        return profile

    sak = int.from_bytes(scan[0]["sak"], "big")
    atqa = scan[0]["atqa"].hex().upper()
    if sak == 0x00:
        print(
            f"{CR}Detected non-MIFARE Classic tag (SAK=0x00, ATQA={atqa}), likely Ultralight/NTAG.{C0}"
        )
        print(f"{CY}Try using: hf mfu rdbl / hf mfu dump{C0}")
    else:
        print(
            f"{CR}Detected ISO14443-A tag is not a supported MIFARE Classic card (SAK=0x{sak:02X}, ATQA={atqa}).{C0}"
        )
    return None


def _discover_sector_keys(
    cmd: pn532_cmd.Pn532CMD,
    key_pool: list[bytes],
    start_sector: int,
    end_sector: int,
    uid: Union[bytes, None] = None,
    print_progress: bool = True,
):
    sector_keys: dict[int, dict[str, Union[bytes, None]]] = {
        s: {"A": None, "B": None} for s in range(start_sector, end_sector + 1)
    }

    for sector in range(start_sector, end_sector + 1):
        trailer = _trailer_block_for_sector(sector)
        trailer_a = None
        found_a = None

        for key in key_pool:
            if uid is not None:
                trailer_a = _try_auth_read_trailer_with_uid(cmd, trailer, key, MfcKeyType.A, uid)
            else:
                trailer_a = _try_auth_read_trailer(cmd, trailer, key, MfcKeyType.A)
            if trailer_a:
                found_a = key
                break

        if found_a:
            sector_keys[sector]["A"] = found_a
            maybe_b = trailer_a[10:16]
            if maybe_b != b"\x00" * 6:
                sector_keys[sector]["B"] = maybe_b
                _prepend_unique_keys(key_pool, [found_a, maybe_b])
            else:
                _prepend_unique_keys(key_pool, [found_a])

        if sector_keys[sector]["B"] is None:
            for key in key_pool:
                if uid is not None:
                    trailer_b = _try_auth_read_trailer_with_uid(cmd, trailer, key, MfcKeyType.B, uid)
                else:
                    trailer_b = _try_auth_read_trailer(cmd, trailer, key, MfcKeyType.B)
                if trailer_b:
                    sector_keys[sector]["B"] = key
                    maybe_a = trailer_b[0:6]
                    if maybe_a != b"\x00" * 6:
                        sector_keys[sector]["A"] = sector_keys[sector]["A"] or maybe_a
                        _prepend_unique_keys(key_pool, [key, maybe_a])
                    else:
                        _prepend_unique_keys(key_pool, [key])
                    break

        if print_progress:
            ka = sector_keys[sector]["A"]
            kb = sector_keys[sector]["B"]
            ka_text = ka.hex().upper() if isinstance(ka, bytes) else "------------"
            kb_text = kb.hex().upper() if isinstance(kb, bytes) else "------------"
            print(f"Sector {sector:02d} keys: A={ka_text} B={kb_text}")

    return sector_keys


def _pick_seed_from_sector_keys(sector_keys: dict[int, dict[str, Union[bytes, None]]]):
    for sector in sorted(sector_keys.keys()):
        key_a = sector_keys[sector].get("A")
        if isinstance(key_a, bytes):
            return _trailer_block_for_sector(sector), "A", key_a
        key_b = sector_keys[sector].get("B")
        if isinstance(key_b, bytes):
            return _trailer_block_for_sector(sector), "B", key_b
    return None


def _dump_with_sector_keys(
    cmd: pn532_cmd.Pn532CMD,
    uid: bytes,
    block_count: int,
    sector_keys: dict[int, dict[str, Union[bytes, None]]],
    key_pool: list[bytes],
):
    dump_blocks: dict[int, Union[bytes, None]] = {}
    missing_blocks: list[int] = []

    for block in range(block_count):
        sector = _sector_from_block(block)
        candidates = []
        key_a = sector_keys.get(sector, {}).get("A")
        key_b = sector_keys.get(sector, {}).get("B")
        if isinstance(key_a, bytes):
            candidates.append((MfcKeyType.A, key_a))
        if isinstance(key_b, bytes):
            candidates.append((MfcKeyType.B, key_b))
        if not candidates:
            candidates.extend([(MfcKeyType.A, key) for key in key_pool])
            candidates.extend([(MfcKeyType.B, key) for key in key_pool])

        block_data = None
        for key_type, key in candidates:
            resp = cmd.mf1_read_one_block(block, key_type, key)
            if (
                resp
                and hasattr(resp, "parsed")
                and isinstance(resp.parsed, (bytes, bytearray))
                and len(resp.parsed) == 16
            ):
                block_data = bytes(resp.parsed)
                break

        dump_blocks[block] = block_data
        if block_data is None:
            missing_blocks.append(block)
            print(f"{block:03d}: {CR}<unreadable>{C0}")
            continue

        line = block_data.hex().upper()
        if block == 0:
            if len(uid) == 7:
                print(f"{block:03d}: {CY}{line[0:14]}{C0}{line[14:]}{C0}")
            else:
                print(
                    f"{block:03d}: {CY}{line[0:8]}{CR}{line[8:10]}{CG}{line[10:12]}{CY}{line[12:16]}{C0}{line[16:]}{C0}"
                )
        elif is_trailer_block(block):
            print(f"{block:03d}: {CG}{line[0:12]}{CR}{line[12:20]}{CG}{line[20:]}{C0}")
        else:
            print(f"{block:03d}: {line}")

    return dump_blocks, missing_blocks


def check_tools():
    tools = ["staticnested", "mfkey32v2", "mfkey64"]
    if sys.platform == "win32":
        tools = [x + ".exe" for x in tools]
    missing_tools = [tool for tool in tools if not (default_cwd / tool).exists()]
    if len(missing_tools) > 0:
        print(
            f'{CR}Warning, tools {", ".join(missing_tools)} not found. '
            f"Corresponding commands will not work as intended.{C0}"
        )


root = CLITree(root=True)
hw = root.subgroup("hw", "Hardware-related commands")
hw_led = hw.subgroup("led", "LED control commands")
hw_mode = hw.subgroup("mode", "Mode-related commands")
hf = root.subgroup("hf", "High-frequency commands")
hf_14a = hf.subgroup("14a", "ISO 14443-A commands")
hf_mf = hf.subgroup("mf", "MIFARE Classic commands")
hf_mf_sniffer = hf_mf.subgroup("sniffer", "MIFARE Classic sniffer helper commands")
hf_mfu = hf.subgroup("mfu", "MIFARE Ultralight commands")

hf_14b = hf.subgroup("14b", "ISO 14443-B commands")
hf_15 = hf.subgroup("15", "ISO 15693 commands")

lf = root.subgroup("lf", "Low Frequency commands")
lf_em = lf.subgroup("em", "EM commands")
lf_em_410x = lf_em.subgroup("410x", "EM410x commands")

ntag = root.subgroup("ntag", "NTAG commands")


class BaseCLIUnit:
    def __init__(self):
        # new a device command transfer and receiver instance(Send cmd and receive response)
        self._device_com: Union[pn532_com.Pn532Com, None] = None
        self._device_cmd: Union[pn532_cmd.Pn532CMD, None] = None

    @property
    def device_com(self) -> pn532_com.Pn532Com:
        assert self._device_com is not None
        return self._device_com

    @device_com.setter
    def device_com(self, com):
        self._device_com = com
        self._device_cmd = pn532_cmd.Pn532CMD(self._device_com)

    @property
    def cmd(self) -> pn532_cmd.Pn532CMD:
        assert self._device_cmd is not None
        return self._device_cmd

    def args_parser(self) -> ArgumentParserNoExit:
        """
            CMD unit args.

        :return:
        """
        raise NotImplementedError("Please implement this")

    def before_exec(self, args: argparse.Namespace):
        return True

    def on_exec(self, args: argparse.Namespace):
        """
            Call a function on cmd match.

        :return: function references
        """
        raise NotImplementedError("Please implement this")

    def after_exec(self, args: argparse.Namespace):
        """
            Call a function after exec cmd.

        :return: function references
        """
        return True

    @staticmethod
    def sub_process(cmd, cwd=default_cwd):
        class ShadowProcess:
            def __init__(self):
                self.output = ""
                self.time_start = timeit.default_timer()
                self._process = subprocess.Popen(
                    cmd,
                    cwd=cwd,
                    shell=True,
                    stderr=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                )
                threading.Thread(target=self.thread_read_output).start()

            def thread_read_output(self):
                while self._process.poll() is None:
                    assert self._process.stdout is not None
                    data = self._process.stdout.read(1024)
                    if len(data) > 0:
                        self.output += data.decode(encoding="utf-8")

            def get_time_distance(self, ms=True):
                if ms:
                    return round((timeit.default_timer() - self.time_start) * 1000, 2)
                else:
                    return round(timeit.default_timer() - self.time_start, 2)

            def is_running(self):
                return self._process.poll() is None

            def is_timeout(self, timeout_ms):
                time_distance = self.get_time_distance()
                if time_distance > timeout_ms:
                    return True
                return False

            def get_output_sync(self):
                return self.output

            def get_ret_code(self):
                return self._process.poll()

            def stop_process(self):
                # noinspection PyBroadException
                try:
                    self._process.kill()
                except Exception:
                    pass

            def get_process(self):
                return self._process

            def wait_process(self):
                return self._process.wait()

        return ShadowProcess()


class DeviceRequiredUnit(BaseCLIUnit):
    """
    Make sure of device online
    """

    def before_exec(self, args: argparse.Namespace):
        ret = self.device_com.isOpen()
        if not ret:
            last_port = getattr(self.device_com, "port_string", None)
            if last_port:
                try:
                    print(f"{CY}Device offline, trying auto reconnect: {last_port}{C0}")
                    self.device_com.open(last_port)
                    ret = self.device_com.isOpen()
                    if ret:
                        print(f"{CG}Auto reconnect success.{C0}")
                except Exception as e:
                    print(f"{CR}Auto reconnect failed: {e}{C0}")
                    ret = False

        if not ret:
            # Fallback: try the same auto-detect logic as `hw connect` when no last port is available.
            try:
                print(f"{CY}Device offline, trying auto connect...{C0}")
                connector_cls = globals().get("HWConnect")
                if connector_cls is not None:
                    connector = connector_cls()
                    connector.device_com = self.device_com
                    connector.on_exec(argparse.Namespace(port=None))
                    ret = self.device_com.isOpen()
                    if ret:
                        print(f"{CG}Auto connect success.{C0}")
            except Exception as e:
                print(f"{CR}Auto connect failed: {e}{C0}")
                ret = False

        if ret:
            if not self.device_com.is_support_cmd(self.__class__.__name__):
                print(
                    f"{CR}{self.__class__.__name__} not support by {self.device_com.get_device_name()}{C0}"
                )
                return False
            return True

        print("Please connect to pn532 device first(use 'hw connect').")
        return False


class MF1AuthArgsUnit(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.add_argument(
            "--blk",
            "--block",
            type=int,
            required=False,
            default=0,
            metavar="<dec>",
            help="The block where the key of the card is known",
        )
        type_group = parser.add_mutually_exclusive_group()
        type_group.add_argument(
            "-a", action="store_true", help="Known key is A key (default)"
        )
        type_group.add_argument("-b", action="store_true", help="Known key is B key")
        parser.add_argument(
            "-k",
            "--key",
            type=str,
            required=False,
            default="FFFFFFFFFFFF",
            metavar="<hex>",
            help="Mifare Sector key (12 HEX symbols)",
        )
        return parser

    def get_param(self, args):
        class Param:
            def __init__(self):
                self.block = args.blk
                self.type = MfcKeyType.B if args.b else MfcKeyType.A
                key: str = args.key
                if not re.match(r"^[a-fA-F0-9]{12}$", key):
                    raise ArgsParserError("key must include 12 HEX symbols")
                self.key: bytearray = bytearray.fromhex(key)

        return Param()


class MF1WriteBlockArgsUnit(MF1AuthArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = super().args_parser()
        parser.add_argument(
            "-d", "--data", type=str, required=False, help="32 HEX symbols to write"
        )
        return parser

    def get_param(self, args):
        param = super().get_param(args)
        param.data = bytearray.fromhex(args.data)
        return param


@root.command("clear")
class RootClear(BaseCLIUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Clear screen"
        return parser

    def on_exec(self, args: argparse.Namespace):
        os.system("clear" if os.name == "posix" else "cls")


@root.command("debug")
class RootDebug(BaseCLIUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Toggle debug logging (debug on|off)."
        # Accept on/off (case-insensitive)
        def to_lower(v: str) -> str:
            return v.lower()
        parser.add_argument(
            "state",
            nargs="?",
            type=to_lower,
            choices=["on", "off"],
            help="Enable (on) or disable (off) debug output",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        if getattr(args, "state", None) is None:
            print(f"Debug is currently: {CG if pn532_com.DEBUG else CR}{'ON' if pn532_com.DEBUG else 'OFF'}{C0}")
            return
        if args.state == "on":
            pn532_com.DEBUG = True
            print(f"Debug switched {CG}ON{C0}")
        elif args.state == "off":
            pn532_com.DEBUG = False
            print(f"Debug switched {CR}OFF{C0}")


@hw_mode.command("r")
class HWModeReader(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Set device to reader mode"
        return parser

    def on_exec(self, args: argparse.Namespace):
        self.device_com.set_work_mode()
        print("Switch to {  Reader  } mode successfully.")


@hw_mode.command("e")
class HWModeEmulator(DeviceRequiredUnit):
    # support -type Mifare Classic, MIFARE Ultralight, 15693, EM4100 and -slot 1-8
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Set device to emulator mode"
        parser.add_argument(
            "-t",
            "--type",
            default=1,
            type=int,
            required=False,
            help="1 - MFC, 2 - MFU, 3 - 15693, 4 - EM4100",
        )
        parser.add_argument(
            "-s", "--slot", default=1, type=int, help="Emulator slot(1-8)"
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        type = args.type
        slot = args.slot
        self.device_com.set_work_mode(PN532KillerMode.EMULATOR, type, slot - 1)
        print("Switch to {  Emulator  } mode successfully.")
        
        # Get emulator block 0 data and tag type
        emulator_data = self.cmd.get_emulator_block0_and_type(type=type, slot=slot - 1)
        if emulator_data is not None:
            print(f"\n{CG}Slot {slot} Information:{C0}")
            print(f"  Tag Type: {CY}{emulator_data['tag_type_name']}{C0} (0x{emulator_data['tag_type']:02X})")
            # block0_data is bytes, convert to hex if needed
            block0_hex = emulator_data['block0'].hex().upper() if isinstance(emulator_data['block0'], bytes) else emulator_data['block0']
            print(f"  Block 0:  {CG}{block0_hex}{C0}")
            
            # For MIFARE Classic types, parse block 0 info
            if emulator_data['tag_type'] in [0x11, 0x12, 0x13, 0x14]:
                print(f"\n{CG}MIFARE Classic Block 0 Details:{C0}")
                block0_bytes = emulator_data['block0']
                uid = block0_bytes[:4].hex().upper()
                bcc = block0_bytes[4]
                sak = block0_bytes[5]
                atqa = block0_bytes[6:8].hex().upper()
                print(f"  UID:      {CY}{uid}{C0}")
                print(f"  BCC:      {bcc:02X}")
                print(f"  SAK:      {sak:02X}")
                print(f"  ATQA:     {atqa}")
        else:
            print(f"{CR}Failed to read emulator data{C0}")


@hw_mode.command("s")
class HWModeSniffer(DeviceRequiredUnit):
    # support -type for 14a with tag, 14a without tag, 15
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Set device to sniffer mode"
        parser.add_argument(
            "-t",
            "--type",
            default=0,
            type=int,
            required=False,
            help="0 - Without tag, 1 - With tag",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        self.device_com.set_work_mode(PN532KillerMode.SNIFFER, PN532KillerTagType.MFC, args.type)
        print("Switch to {  Sniffer  } mode successfully.")


@hw.command("raw")
class HWRaw(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Send raw data to device"
        parser.add_argument(
            "-d",
            "--data",
            type=str,
            required=False,
            help="Hex data to send",
            default="00",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.data is None:
            print("usage: hw raw [-h] [-d DATA]")
            print("hw raw: error: the following arguments are required: -d")
            return
        data = args.data
        if not re.match(r"^[0-9a-fA-F]+$", data):
            print("Data must be a HEX string")
            return
        if len(data) % 2 != 0:
            data = "0" + data
        data_bytes = bytes.fromhex(data)
        # 如果用户输入的是完整帧 (以 0000FF 开头) 或 唤醒序列(55000...)，直接发送不封装
        if data_bytes.startswith(b"\x00\x00\xFF") or data_bytes.startswith(b"\x55\x00"):
            self.device_com.send_raw_frame(data_bytes)
            print("Frame sent (raw, no wrapping)")
            return
        # 否则按命令格式: 第一个字节是cmd，其余是data
        resp = self.device_com.send_raw(data_bytes)
        print(f"Response: {' '.join(f'{byte:02X}' for byte in resp)}")


@hf_14a.command("scan")
class HF14AScan(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Scan 14a tag, and print basic information"
        return parser

    def sak_info(self, data_tag):
        int_sak = data_tag["sak"]
        if int_sak in type_id_SAK_dict:
            print(f"- Guessed type(s) from SAK: {type_id_SAK_dict[int_sak]}")

    def scan(self):
        resp = self.cmd.hf_14a_scan()
        if resp is not None and len(resp) > 0:
            for data_tag in resp:
                print(f"- UID: {data_tag['uid'].hex().upper()}")
                print(
                    f"- ATQA: {data_tag['atqa'].hex().upper()} "
                    f"(0x{int.from_bytes(data_tag['atqa'], byteorder='little'):04x})"
                )
                print(f"- SAK: {data_tag['sak'].hex().upper()}")
                self.sak_info(data_tag)
                if "ats" in data_tag and len(data_tag["ats"]) > 0:
                    print(f"- ATS: {data_tag['ats'].hex().upper()}")
        else:
            print("ISO14443-A Tag not found")

    def on_exec(self, args: argparse.Namespace):
        self.scan()


@hf_14a.command("raw")
class HF14ARaw(DeviceRequiredUnit):
    def bool_to_bit(self, value):
        return 1 if value else 0

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.formatter_class = argparse.RawDescriptionHelpFormatter
        parser.description = "Send iso1444a raw command"
        parser.add_argument(
            "-a",
            "--activate-rf",
            help="Active signal field ON without select",
            action="store_true",
            default=False,
        )
        parser.add_argument(
            "-s",
            "--select-tag",
            help="Active signal field ON with select",
            action="store_true",
            default=False,
        )
        parser.add_argument(
            "-d", type=str, metavar="<hex>", required=False, help="Hex data to be sent"
        )
        parser.add_argument(
            "-b",
            type=int,
            metavar="<dec>",
            help="Number of bits to send. Useful for send partial byte",
        )
        parser.add_argument(
            "-c",
            "--crc",
            help="Calculate and append CRC",
            action="store_true",
            default=False,
        )
        parser.add_argument(
            "-r",
            "--no-response",
            help="Do not read response",
            action="store_true",
            default=False,
        )
        parser.add_argument(
            "-cc",
            "--crc-clear",
            help="Verify and clear CRC of received data",
            action="store_true",
            default=False,
        )
        parser.add_argument(
            "-k",
            "--keep-rf",
            help="Keep signal field ON after receive",
            action="store_true",
            default=False,
        )
        parser.add_argument(
            "-t", type=int, metavar="<dec>", help="Timeout in ms", default=100
        )
        parser.epilog = (
            parser.epilog
        ) = """
examples/notes:
  hf 14a raw -a -k -b 7 -d 40
  hf 14a raw -d 43 -k
  hf 14a raw -d 3000 -c
  hf 14a raw -sc -d 6000
"""
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.d is None:
            print("usage: hf 14a raw [-h] -d <hex> [-c] [-sc] [-r]")
            print("hf 14a raw: error: the following arguments are required: -d")
            return
        options = {
            "activate_rf_field": self.bool_to_bit(args.activate_rf),
            "wait_response": self.bool_to_bit(not args.no_response),
            "append_crc": self.bool_to_bit(args.crc),
            "auto_select": self.bool_to_bit(args.select_tag),
            "keep_rf_field": self.bool_to_bit(args.keep_rf),
            "check_response_crc": self.bool_to_bit(args.crc_clear),
            # 'auto_type3_select': self.bool_to_bit(args.type3-select-tag),
        }
        data: str = args.d
        if data is not None:
            data = data.replace(" ", "")
            if re.match(r"^[0-9a-fA-F]+$", data):
                if len(data) % 2 != 0:
                    print(
                        f" [!] {CR}The length of the data must be an integer multiple of 2.{C0}"
                    )
                    return
                else:
                    data_bytes = bytes.fromhex(data)
            else:
                print(f" [!] {CR}The data must be a HEX string{C0}")
                return
        else:
            data_bytes = []
        if args.b is not None and args.crc:
            print(f" [!] {CR}--bits and --crc are mutually exclusive{C0}")
            return
        resp = self.cmd.hf14a_raw(options, args.t, data_bytes, args.b)
        if len(resp) > 0:
            print(
                " - "
                + " ".join(
                    [hex(byte).replace("0x", "").rjust(2, "0").upper() for byte in resp]
                )
            )
        else:
            print(f" [*] {CY}No response{C0}")


@hf_15.command("scan")
class HF15Scan(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Scan ISO15693 tag, and print basic information"
        return parser

    def scan(self):
        resp = self.cmd.hf_15_scan()
        if resp is not None:
            for data_tag in resp:
                print(f"- UID: {data_tag['uid'].upper()}")
        else:
            print("ISO15693 Tag no found")

    def on_exec(self, args: argparse.Namespace):
        self.scan()


@hf_15.command("info")
class HF15Info(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Get ISO15693 tag information"
        return parser

    def on_exec(self, args: argparse.Namespace):
        resp = self.cmd.hf_15_scan()
        if resp is None:
            print("ISO15693 Tag no found")
            return
        resp = self.cmd.hf_15_info()
        if resp is not None:
            print(f"UID: {resp['uid'].hex().upper()}")
            print(f"AFI: 0x{resp['afi']:02X}")
            print(f"DSFID: 0x{resp['dsfid']:02X}")
            print(f"IC Reference: 0x{resp['ic_reference']:02X}")
            print(f"Block size: {resp['block_size']}")
        else:
            print("Get ISO15693 tag information failed")


@hf_15.command("rdbl")
class HF15Rdbl(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Read block data from ISO15693 tag"
        parser.add_argument(
            "-b",
            "--block",
            type=int,
            required=False,
            default=0,
            metavar="<dec>",
            help="Block to read",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        resp = self.cmd.hf_15_scan()
        if resp is None:
            print("ISO15693 Tag no found")
            return
        block = args.block
        resp = self.cmd.hf_15_read_block(block)
        if resp is not None:
            print(f"Block {block}: {resp.hex().upper()}")
        else:
            print(f"Read block {block} failed")


@hf_15.command("wrbl")
class HF15Wrbl(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Write block data to ISO15693 tag"
        parser.add_argument(
            "-b",
            "--block",
            type=int,
            required=False,
            default=0,
            metavar="<dec>",
            help="Block to write",
        )
        parser.add_argument(
            "-d",
            "--data",
            type=str,
            required=False,
            default="00000000",
            metavar="<hex>",
            help="Data to write (4 bytes)",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        resp = self.cmd.hf_15_scan()
        if resp is None:
            print("ISO15693 Tag no found")
            return
        block = args.block
        data = args.data
        if not re.match(r"^[a-fA-F0-9]{8}$", data):
            print("Data must be 4 bytes hex")
            return
        resp = self.cmd.hf_15_write_block(block, bytes.fromhex(data))
        print(f"Write block {block} {CY}{'Success' if resp else 'Fail'}{C0}")

# scan, get info, and read block. if add --json, save as json, if add --bin, save as bin
@hf_15.command("dump")
class HF15Dump(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Dump ISO15693 tag data"
        parser.add_argument(
            "--json", action="store_true", help="Save to json file"
        )
        parser.add_argument(
            "--bin", action="store_true", help="Save to bin file"
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        resp = self.cmd.hf_15_scan()
        if resp is None:
            print("ISO15693 Tag no found")
            return
        resp_info = self.cmd.hf_15_info()
        if resp_info is None:
            print("Get ISO15693 tag information failed")
            return
        else:
            print(f"UID: {resp_info['uid'].hex().upper()}")
            print(f"AFI: 0x{resp_info['afi']:02X}")
            print(f"DSFID: 0x{resp_info['dsfid']:02X}")
            print(f"IC Reference: 0x{resp_info['ic_reference']:02X}")
            print(f"Block size: {resp_info['block_size']}")
            
        data = {}
        for block in range(0, resp_info["block_size"]):
            resp = self.cmd.hf_15_read_block(block)
            if resp is not None:
                data[block] = resp.hex().upper()
                print(f"Block {block}: {data[block]}")
            else:
                data[block] 
                print(f"Block {block}: Failed to read")
                
        if args.json:
            dump_data = {}
            dump_data["Card"] = resp_info
            dump_data["blocks"] = data
            file_name = "hf_15_" + resp_info['uid'].hex().upper() + ".json"
            with open(file_name, "w") as f:
                json.dump(dump_data, f)
            print("Dump saved to " + file_name)
        
        if args.bin:
            file_name = "hf_15_" + resp_info['uid'].hex().upper() + ".bin"
            with open(file_name, "wb") as f:
                for block in range(0, len(data)):
                    if block in data:
                        f.write(data[block].encode())
                    else:
                        f.write(b'\x00\x00\x00\x00')
            print("Dump saved to " + file_name)
        

@hf_15.command("raw")
class HF15Raw(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.formatter_class = argparse.RawDescriptionHelpFormatter
        parser.description = "Send iso15693 raw command"
        parser.add_argument(
            "-d", type=str, metavar="<hex>", required=False, help="Hex data to be sent"
        )
        # add crc
        parser.add_argument(
            "-c",
            "--crc",
            help="Calculate and append CRC",
            action="store_true",
            default=False,
        ),
        parser.add_argument(
            "-r",
            "--no-response",
            help="Do not read response",
            action="store_true",
            default=True,
        ),
        # add select_tag
        parser.add_argument(
            "-sc",
            "--select-tag",
            help="Active signal field ON with select",
            action="store_true",
            default=False,
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.d is None:
            print("usage: hf 15 raw [-h] -d <hex> [-c] [-sc] [-r]")
            print("hf 15 raw: error: the following arguments are required: -d")
            return
        data: str = args.d
        if data is not None:
            data = data.replace(" ", "")
            if re.match(r"^[0-9a-fA-F]+$", data):
                if len(data) % 2 != 0:
                    print(
                        f" [!] {CR}The length of the data must be an integer multiple of 2.{C0}"
                    )
                    return
                else:
                    data_bytes = bytes.fromhex(data)
            else:
                print(f" [!] {CR}The data must be a HEX string{C0}")
                return
        else:
            data_bytes = []
        options = {"append_crc": 0, "no_check_response": 0}
        if args.select_tag:
            options["select_tag"] = 1
        if args.crc:
            options["append_crc"] = 1
        if args.no_response:
            options["no_check_response"] = 1
        resp = self.cmd.hf_15_raw(options, data=data_bytes)
        if args.no_response:
            print(f" [*] {CY}No response{C0}")
        else:
            print(
                " - "
                + " ".join(
                    [
                        hex(byte).replace("0x", "").rjust(2, "0").upper()
                        for byte in resp.data
                    ]
                )
            )


@hf_15.command("gen1uid")
class HF15Gen1Uid(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Set UID of Gen1 Magic ISO15693 tag"
        parser.add_argument(
            "-u",
            type=str,
            required=False,
            help="UID to set (8 bytes, start with E0)",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.u is None:
            print("usage: hf 15 gen1uid [-h] -u <hex>")
            print("hf 15 gen1uid: error: the following arguments are required: -u")
            return
        uid = args.u
        if not re.match(r"^[a-fA-F0-9]{16}$", uid):
            print("UID must be 8 bytes hex")
            return
        if uid[0:2].lower() != "e0":
            print("UID must start with E0")
            return
        resp_scan = self.cmd.hf_15_scan()
        if resp_scan is None:
            print("ISO15693 Tag no found")
            return
        resp_info = self.cmd.hf_15_info()
        block_size = resp_info["block_size"]
        resp = self.cmd.hf_15_set_gen1_uid(bytes.fromhex(uid), block_size)
        print(f"Set UID to {uid} {CY}{'Success' if resp else 'Fail'}{C0}")


@hf_15.command("gen2uid")
class HF15Gen2Uid(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Set UID of Gen2 Magic ISO15693 tag"
        parser.add_argument(
            "-u",
            type=str,
            required=False,
            help="UID to set (8 bytes, start with E0)",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.u is None:
            print("usage: hf 15 gen2uid [-h] -u <hex>")
            print("hf 15 gen2uid: error: the following arguments are required: -u")
            return
        resp_scan = self.cmd.hf_15_scan()
        if resp_scan is None:
            print("ISO15693 Tag no found")
            return
        uid = args.u
        if not re.match(r"^[a-fA-F0-9]{16}$", uid):
            print("UID must be 8 bytes hex")
            return
        if uid[0:2].lower() != "e0":
            print("UID must start with E0")
            return
        resp = self.cmd.hf_15_set_gen2_uid(bytes.fromhex(uid))
        print(f"Set UID to {uid} {CY}{'Success' if resp else 'Fail'}{C0}")


@hf_15.command("gen2config")
class HF15Gen2Config(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Set block size of Gen2 Magic ISO15693 tag"
        parser.add_argument(
            "-s",
            "--size",
            default=64,
            type=int,
            required=True,
            metavar="<dec>",
            help="Block size to set",
        )
        parser.add_argument(
            "-a",
            "--afi",
            default="00",
            type=str,
            required=False,
            metavar="<hex>",
            help="AFI on hex value",
        )
        parser.add_argument(
            "-d",
            "--dsfid",
            default="00",
            type=str,
            required=False,
            metavar="<hex>",
            help="DSFID on hex value",
        )
        parser.add_argument(
            "-i",
            "--ic",
            default="00",
            type=str,
            required=False,
            metavar="<hex>",
            help="IC on hex value",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        resp_scan = self.cmd.hf_15_scan()
        if resp_scan is None:
            print("ISO15693 Tag no found")
            return
        # block size must between 4 to 256
        if args.size < 0 or args.size > 256:
            print("Block size must between 0 to 256")
            return
        if args.afi is not None:
            if not re.match(r"^[a-fA-F0-9]{2}$", args.afi):
                print("AFI must be 1 byte hex")
                return

        args.afi = int(args.afi, 16) if args.afi is not None else 0
        if args.dsfid is not None:
            if not re.match(r"^[a-fA-F0-9]{2}$", args.dsfid):
                print("DSFID must be 1 byte hex")
                return

        args.dsfid = int(args.dsfid, 16) if args.dsfid is not None else 0
        if args.ic is not None:
            if not re.match(r"^[a-fA-F0-9]{2}$", args.ic):
                print("IC must be 1 byte hex")
                return

        args.ic = int(args.ic, 16) if args.ic is not None else 0

        resp = self.cmd.hf_15_set_gen2_config(args.size, args.afi, args.dsfid, args.ic)
        print(f"Config Gen2 Magic ISO15693 tag {CY}{'Success' if resp else 'Fail'}{C0}")


@hf_15.command("eSetUid")
class HF15ESetUid(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Set UID of ISO15693 Emulation"
        parser.add_argument(
            "-u",
            type=str,
            metavar="<hex>",
            required=False,
            help="UID to set (8 bytes)",
        )
        parser.add_argument(
            "-s", "--slot", default=1, type=int, help="Emulator slot(1-8)"
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.u is None:
            print("usage: hf 15 eSetUid [-h] -u <hex> [-s SLOT]")
            print("hf 15 eSetUid: error: the following arguments are required: -u")
            return
        uid = args.u
        if not re.match(r"^[a-fA-F0-9]{16}$", uid):
            print("UID must be 8 bytes hex")
            return
        # if not start with e0 or E0
        if uid[0:2].lower() != "e0":
            print("UID must start with E0")
            return
        resp = self.cmd.hf_15_eset_uid(args.slot - 1, bytes.fromhex(uid))
        print(
            f"Set Slot {args.slot} UID to {uid} {CY}{'Success' if resp else 'Fail'}{C0}"
        )


@hf_15.command("eSetBlock")
class HF15ESetBlock(DeviceRequiredUnit):
    # add parameter -b <hex> to set block data(4 bytes)
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Set block data of ISO15693 Emulation"
        parser.add_argument(
            "-b",
            type=int,
            metavar="<dec>",
            help="Block to set",
        )
        parser.add_argument(
            "-s", "--slot", default=1, type=int, help="Emulator slot(1-8)"
        )
        # add data block
        parser.add_argument(
            "-d",
            "--data",
            metavar="<hex>",
            type=str,
            required=False,
            help="Data block (4 bytes)",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        block = args.data
        if not re.match(r"^[a-fA-F0-9]{8}$", block):
            print("Block must be 4 bytes hex")
            return
        resp = self.cmd.hf_15_eset_block(args.slot - 1, args.b, bytes.fromhex(block))
        print(
            f"Set Slot {args.slot} block {args.b} to {block} {CY}{'Success' if resp else 'Fail'}{C0}"
        )

@hf_15.command("eSetDump")
class HF15ESetDump(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Set dump data of ISO15693 Emulation"
        parser.add_argument(
            "--json",
            type=str,
            required=False,
            metavar="<file>",
            help="JSON file to load dump data",
        )
        parser.add_argument(
            "--bin",
            type=str,
            required=False,
            metavar="<file>",
            help="BIN file to load dump data",
        )
        parser.add_argument(
            "-s", "--slot", default=1, type=int, help="Emulator slot(1-8)"
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        if not args.json and not args.bin:
            print("Please choose either json file or bin file")
            return

        data = b""
        if args.json:
            if not os.path.exists(args.json):
                print(f"File {args.json} not exists")
                return
            with open(args.json, "r") as f:
                dump_data = json.load(f)
                if "blocks" in dump_data:
                    for block in range(len(dump_data["blocks"])):
                        if str(block) in dump_data["blocks"]:
                            data += bytes.fromhex(dump_data["blocks"][str(block)])
                        else:
                            data += b'\x00\x00\x00\x00'
        elif args.bin:
            if not os.path.exists(args.bin):
                print(f"File {args.bin} not exists")
                return
            with open(args.bin, "rb") as f:
                data = f.read()

        resp = self.cmd.hf_15_eset_dump(args.slot - 1, data)
        print(
            f"Set Slot {args.slot} dump data {CY}{'Success' if resp else 'Fail'}{C0}"
        )
        
@hf_15.command("eSetwriteprotect")
class HF15ESetWriteProtect(DeviceRequiredUnit):
    # add parameter -b <hex> to set block data(4 bytes)
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Set write protect of ISO15693 Emulation"
        parser.add_argument(
            "-s", "--slot", default=1, type=int, help="Emulator slot(1-8)"
        )
        parser.add_argument(
            "-w",
            "--write",
            action="store_true",
            help="Enable write protect",
            default=False,
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        resp = self.cmd.hf_15_eset_write_protect(
            args.slot - 1, b"\x01" if args.write else b"\x00"
        )
        print(
            f"Set Slot {args.slot} write protect to {args.write} {CY}{'Success' if resp else 'Fail'}{C0}"
        )


@hf_15.command("eSetResvEasAfiDsfid")
class HF15ESetResvEasAfiDsfid(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Set Resv, EAS, AFI, DSFID of ISO15693 Emulation"
        parser.add_argument(
            "-s", "--slot", default=1, type=int, help="Emulator slot(1-8)"
        )
        parser.add_argument(
            "-r",
            "--resv",
            type=str,
            metavar="<hex>",
            help="Resv",
        )
        parser.add_argument(
            "-e",
            "--eas",
            type=str,
            metavar="<hex>",
            help="EAS",
        )
        parser.add_argument(
            "-a",
            "--afi",
            type=str,
            metavar="<hex>",
            help="AFI",
        )
        parser.add_argument(
            "-d",
            "--dsfid",
            type=str,
            metavar="<hex>",
            help="DSFID",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        # pack resv, eas, afi, dsfid
        data = b""
        if args.resv is not None:
            if not re.match(r"^[a-fA-F0-9]{2}$", args.resv):
                print("Resv must be 1 byte hex")
                return
            data += bytes.fromhex(args.resv)
        else:
            data += b"\x00"
        if args.eas is not None:
            if not re.match(r"^[a-fA-F0-9]{2}$", args.eas):
                print("EAS must be 1 byte hex")
                return
            data += bytes.fromhex(args.eas)
        else:
            data += b"\x00"
        if args.afi is not None:
            if not re.match(r"^[a-fA-F0-9]{2}$", args.afi):
                print("AFI must be 1 byte hex")
                return
            data += bytes.fromhex(args.afi)
        else:
            data += b"\x00"
        if args.dsfid is not None:
            if not re.match(r"^[a-fA-F0-9]{2}$", args.dsfid):
                print("DSFID must be 1 byte hex")
                return
            data += bytes.fromhex(args.dsfid)
        else:
            data += b"\x00"
        resp = self.cmd.hf_15_eset_resv_eas_afi_dsfid(args.slot - 1, data)
        print(
            f"Set Slot {args.slot} Resv, EAS, AFI, DSFID {CY}{'Success' if resp else 'Fail'}{C0}"
        )


@root.command("exit")
class RootExit(BaseCLIUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Exit client"
        return parser

    def on_exec(self, args: argparse.Namespace):
        print("Bye, thank you.  ^.^ ")
        self.device_com.close()
        sys.exit(996)


@hw.command("wakeup")
class HWWakeUp(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Wake up device"
        return parser

    def on_exec(self, args: argparse.Namespace):
        self.device_com.set_normal_mode()
        print("Device wake up")


@hw.command("connect")
class HWConnect(BaseCLIUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Connect to pn532 by serial port, TCP or UDP"
        parser.add_argument("-p", "--port", type=str, required=False, 
                          help="Connection string: /dev/ttyUSB0, COM3, tcp:192.168.1.100:1234, udp:192.168.1.100:2345")
        return parser

    def on_exec(self, args: argparse.Namespace):
        try:
            if args.port is None:  # PN532 auto-detect if no port is supplied
                platform_name = uname().release
                if "Microsoft" in platform_name:
                    path = os.environ["PATH"].split(os.pathsep)
                    path.append("/mnt/c/Windows/System32/WindowsPowerShell/v1.0/")
                    powershell_path = None
                    for prefix in path:
                        fn = os.path.join(prefix, "powershell.exe")
                        if not os.path.isdir(fn) and os.access(fn, os.X_OK):
                            powershell_path = fn
                            break
                    if powershell_path:
                        process = subprocess.Popen(
                            [
                                powershell_path,
                                "Get-PnPDevice -Class Ports -PresentOnly |"
                                " where {$_.DeviceID -like '*VID_6868&PID_8686*'} |"
                                " Select-Object -First 1 FriendlyName |"
                                " % FriendlyName |"
                                " select-string COM\\d+ |"
                                "% { $_.matches.value }",
                            ],
                            stdout=subprocess.PIPE,
                        )
                        res = process.communicate()[0]
                        _comport = res.decode("utf-8").strip()
                        if _comport:
                            args.port = _comport.replace("COM", "/dev/ttyS")
                else:
                    # loop through all ports and find pn532
                    for port in serial.tools.list_ports.comports():
                        if port.vid == 6790:
                            args.port = port.device
                            break
                        # if device name contains PN532Killer, it's a PN532Killer
                        if "PN532Killer" in port.description:
                            args.port = port.device
                            # set_device_name
                            self.device_com.set_device_name(port.description)
                            break
                if args.port is None:  # If no pn532 was found, exit
                    print(
                        "PN532 not found, please connect the device or try connecting manually with the -p flag."
                    )
                    print("Examples:")
                    print("  hw connect -p /dev/ttyUSB0        # Serial connection")
                    print("  hw connect -p COM3               # Windows serial connection")
                    print("  hw connect -p tcp:192.168.1.100:1234  # TCP connection")
                    print("  hw connect -p udp:192.168.1.100:2345  # UDP connection")
                    return
                # print connecting to device name
            
            if args.port.startswith('tcp:'):
                print(f"Connecting to device via TCP: {args.port[4:]}")
            elif args.port.startswith('udp:'):
                print(f"Connecting to device via UDP: {args.port[4:]}")
            else:
                print(f"Connecting to device on serial port: {args.port}")
                
            self.device_com.open(args.port)
            print("Device:", self.device_com.get_device_name())
            print("Connection:", self.device_com.get_connection_info())
        except Exception as e:
            print(f"{CR}PN532 Connect fail: {str(e)}{C0}")
            self.device_com.close()


@hw.command("version")
class HWVersion(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Get firmware version"
        return parser

    def on_exec(self, args: argparse.Namespace):
        version = self.cmd.get_firmware_version()
        if version is not None:
            print(f"Version: {version}")
        else:
            print("Failed to get firmware version")


@hw.command("fw")
class HwFirmwareUpgrade(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Upgrade PN532Killer firmware from .bin file"
        parser.add_argument("--bin", required=True, help="Path to firmware .bin file")
        return parser

    def before_exec(self, args: argparse.Namespace):
        # Bypass capability filtering; this is PN532Killer-only but not a core PN532 command
        # Force mode doesn't require device to be connected first
        return True

    def on_exec(self, args: argparse.Namespace):
        from unit.ad15_firmware_util import DeviceInitInfo
        
        bin_path = Path(args.bin)
        if not bin_path.exists():
            print(f"Firmware file not found: {bin_path}")
            return

        firmware_data = bin_path.read_bytes()
        if not firmware_data:
            print("Firmware file is empty.")
            return

        # Always use force mode in CLI
        port = getattr(self.device_com, "port_string", None)
        if not port:
            print(f"{CR}Please connect to device first with: hw connect -p <port>{C0}")
            print("Example: hw connect -p /dev/cu.wchusbserial000000011")
            return
        
        print(f"\n{'='*60}")
        print(f"{CY}DFU Mode - Firmware Update{C0}")
        print(f"{'='*60}")
        print(f"1. HOLD the button on the device")
        print(f"2. While holding, PLUG IN the USB cable")
        print(f"3. Release the button after USB is connected")
        print(f"4. The device should now be in DFU mode")
        print(f"5. Press ENTER to start firmware update")
        print(f"{'='*60}\n")
        
        try:
            input("Press ENTER when device is in DFU mode...")
        except KeyboardInterrupt:
            print(f"\n{CR}Upgrade cancelled.{C0}")
            return

        print(f"Using port: {port}")
        print(f"Firmware size: {len(firmware_data)} bytes")

        # Close CLI communication threads before taking over the port for DFU
        if self.device_com.isOpen():
            self.device_com.close()

        # Check if debug mode is enabled
        from pn532_com import DEBUG
        verbose = DEBUG
        
        dfu = pn532_dfu.Pn532KillerDfu(port, verbose=verbose)
        try:
            # Force mode: open directly in DFU mode and wake up bootloader
            print(f"Opening port at 921600 baud...")
            dfu.open(dfu_mode=True)
            
            if dfu.serial:
                # Clear buffers
                dfu.serial.reset_input_buffer()
                dfu.serial.reset_output_buffer()
                
                # Wake up bootloader
                if verbose:
                    print("[DFU] Triggering bootloader wake-up...")
                dfu.serial.rts = True
                dfu.serial.dtr = True
                time.sleep(0.2)
                dfu.serial.rts = False
                time.sleep(0.5)
                
                # Clear buffers again
                dfu.serial.reset_input_buffer()
                dfu.serial.reset_output_buffer()
            
            print("Bootloader wake-up complete")
            time.sleep(0.3)

            # Get device info
            print("Getting device info...")
            init_info = dfu.get_device_init_info()
            
            if init_info is None:
                print(f"{CY}Could not get device info, using default values{C0}")
                init_info = DeviceInitInfo(
                    status=0,
                    zone_addr=0x100,
                    upgrade_len=0,
                    flash_eoffset_size=0x0,
                    erase_unit_size=4096
                )
                print(f"Using defaults: zone=0x{init_info.zone_addr:X}, offset=0x{init_info.flash_eoffset_size:X}, erase={init_info.erase_unit_size}")
            else:
                print(f"Init -> zone=0x{init_info.zone_addr:X}, offset=0x{init_info.flash_eoffset_size:X}, erase={init_info.erase_unit_size}")
                
                check_info = dfu.get_device_check_info()
                if check_info:
                    print(f"Check -> VID=0x{check_info.vid:04X}, PID=0x{check_info.pid:X}, SDK=0x{check_info.sdk_id:X}")

            # Validate firmware
            if len(firmware_data) <= init_info.zone_addr:
                print(f"{CR}Firmware file is smaller than zone address; aborting.{C0}")
                return

            # Calculate blocks
            file_size = len(firmware_data) - init_info.zone_addr
            block_count = (file_size + init_info.erase_unit_size - 1) // init_info.erase_unit_size
            aligned_size = block_count * init_info.erase_unit_size
            
            if aligned_size != file_size:
                print(f"Padding firmware: {file_size} -> {aligned_size} bytes")
                firmware_data += bytes([0xFF]) * (aligned_size - file_size)

            file_buf = firmware_data[init_info.zone_addr : init_info.zone_addr + aligned_size]
            file_crc_list = pn532_dfu.Pn532KillerDfu.get_buffer_crc_list(
                file_buf, block_count, init_info.erase_unit_size
            )

            # Always update all blocks (no CRC comparison)
            upgrade_addr = init_info.flash_eoffset_size
            blocks_updated = 0
            
            def print_progress(current, total, prefix="Progress", suffix="", length=40):
                """Print progress bar with colors"""
                percent = current / total
                filled = int(length * percent)
                bar = '█' * filled + '-' * (length - filled)
                print(f'\r{prefix} {CG}|{bar}|{C0} {percent*100:.1f}% {suffix}', end='', flush=True)
            
            print(f"\nUpdating {block_count} blocks...")
            for idx in range(block_count):
                off = idx * init_info.erase_unit_size
                
                # Erase block
                print_progress(idx * 2, block_count * 2, prefix="Erasing", suffix=f"Block {idx+1}/{block_count}")
                if not dfu.erase_flash(upgrade_addr + off, init_info.erase_unit_size):
                    print(f"\n{CR}Erase failed at block {idx+1}{C0}")
                    return
                
                # Write block
                print_progress(idx * 2 + 1, block_count * 2, prefix="Writing", suffix=f"Block {idx+1}/{block_count}")
                chunk = file_buf[off : off + init_info.erase_unit_size]
                if not dfu.write_flash(chunk, upgrade_addr + off, init_info.erase_unit_size, erase_unit=4096):
                    print(f"\n{CR}Write failed at block {idx+1}{C0}")
                    return
                blocks_updated += 1

            # Complete progress bar
            print_progress(block_count * 2, block_count * 2, prefix="Complete", suffix=f"{blocks_updated}/{block_count} blocks")
            print(f"\n{CG}Updated {blocks_updated}/{block_count} blocks{C0}")

            # Verify
            print("Verifying firmware...")
            new_chip_crc_list = dfu.get_chip_crc_list(
                init_info.flash_eoffset_size, block_count, init_info.erase_unit_size
            )
            
            if new_chip_crc_list == file_crc_list:
                print(f"{CG}✓ Firmware update successful!{C0}")
                print("Rebooting device...")
                dfu.dfu_reboot()
            else:
                print(f"{CR}✗ Firmware verification failed!{C0}")
                print("Device will NOT be rebooted.")
        except KeyboardInterrupt:
            print(f"\n{CR}Upgrade interrupted by user{C0}")
        except Exception as e:
            print(f"{CR}Upgrade failed: {e}{C0}")
        finally:
            dfu.close()
            print("Port closed")


@hw_led.command("on")
class HWLedOn(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Turn on PN532Killer LED"
        return parser

    def on_exec(self, args: argparse.Namespace):
        if self.device_com.get_device_name() != "PN532Killer":
            print("LED control is only supported on PN532Killer.")
            return
        resp = self.cmd.led_on()
        ok = resp.parsed if hasattr(resp, "parsed") else (resp.status == Status.SUCCESS)
        print(f"LED on: {'Success' if ok else 'Fail'}")


@hw_led.command("off")
class HWLedOff(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Turn off PN532Killer LED"
        return parser

    def on_exec(self, args: argparse.Namespace):
        if self.device_com.get_device_name() != "PN532Killer":
            print("LED control is only supported on PN532Killer.")
            return
        resp = self.cmd.led_off()
        ok = resp.parsed if hasattr(resp, "parsed") else (resp.status == Status.SUCCESS)
        print(f"LED off: {'Success' if ok else 'Fail'}")


@hf_mf_sniffer.command("setuid")
class HfSniffSetUid(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Set UID of sniffer slot"
        parser.add_argument(
            "-u",
            type=str,
            required=False,
            help="UID to set (4 bytes)",
            default="11223344",
        )
        # add block0
        parser.add_argument(
            "--blk0",
            metavar="<hex>",
            type=str,
            required=False,
            help="Block 0 (16 bytes)",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        uid = args.u
        if not re.match(r"^[a-fA-F0-9]{8}$", uid) and len(uid) != 8:
            print("UID must be 4 bytes hex")
            return
        if args.blk0 is not None:
            if not re.match(r"^[a-fA-F0-9]{32}$", args.blk0):
                print("Block0 must be 16 bytes hex")
                return
            block0 = bytes.fromhex(args.blk0)
        else:
            block0 = self.get_block0(bytes.fromhex(uid), args)
        if not is_hex(block0, 16):
            print("Invalid block")
            return
        self.cmd.hf_sniff_set_uid(block0)

    def get_block0(self, uid, args):
        sak = 0x08
        atqa = 0x0400
        factory_info = 0xAABBCCDDEEFFFFFF
        block0 = args.blk0
        if block0 == None:
            if len(uid) != 4 and len(uid) != 7:
                print(f"{CR}UID needs to be 4 bytes or 7 bytes{C0}")
                return
            bcc = 0
            if len(uid) == 4:
                bcc = uid[0] ^ uid[1] ^ uid[2] ^ uid[3]
            uid_hex = "".join(format(x, "02x") for x in uid)
            block0 = f"{uid_hex}{format(bcc, '02x')}{format(sak, '02x')}{format(atqa, '04x')}{format(factory_info, '016x')}"
        else:
            if is_hex(block0) == False:
                print(f"{CR}Block0 needs to be hex{C0}")
                return
            if len(block0) != 32:
                print(f"{CR}Block0 needs to be 16 bytes{C0}")
                return

            uid = str_to_bytes(block0[0:8])
            bcc = 0
            bcc = uid[0] ^ uid[1] ^ uid[2] ^ uid[3]
            # check if bcc is valid on the block0
            if block0[8:10] != format(bcc, "02x"):
                print(f"{CR}Invalid BCC{C0}")
                return
        return str_to_bytes(block0)

@hf_mf.command("setuid")
class HfMfSetUid(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.formatter_class = argparse.RawDescriptionHelpFormatter
        parser.description = "Set UID of magic Mifare classic with UID or block0."
        parser.add_argument(
            "-u",
            type=str,
            metavar="<hex>",
            required=False,
            help="UID to set (Default 11223344)",
            default="11223344",
        )
        # add block data, 16 bytes
        parser.add_argument(
            "--blk0",
            metavar="<hex>",
            type=str,
            required=False,
            help="Block 0 (16 bytes)",
        )
        parser.add_argument(
            "-g",
            type=int,
            metavar="<dec>",
            required=False,
            help="Generation: 1 => Gen1A (Default), 2 => cuid, 3 => Gen3, 4 => Gen4",
            default=1,
        )
        parser.add_argument(
            "-k",
            metavar="<hex>",
            type=str,
            required=False,
            default="ffffffffffff",
            help="Mifare Key (6 bytes)",
        )
        parser.add_argument(
            "-b",
            action="store_true",
            default=False,
            help="Set Gen2 use keyB (Default keyA)",
        )
        parser.add_argument(
            "--lock",
            action="store_true",
            help="Lock Gen3 UID forever",
            default=False,
        )
        parser.add_argument(
            "-p",
            type=str,
            metavar="<hex>",
            default="00000000",
            required=False,
            help="Set Gen4 Password (Default 00000000)",
        )
        parser.epilog = (
            parser.epilog
        ) = """
examples:
  hf mf setuid -u 11223344
  hf mf setuid -u 11223344 -g 2
  hf mf setuid -u 11223344556677 -g 3
  hf mf setuid -u 11223344556677 --blk0 11223344556677084400120111003912 -g 3
  hf mf setuid --blk0 1122334444080400aabbccddeeff1122 -g 4 --pwd 00000000
"""
        return parser

    def get_block0(self, uid, args):
        block0 = args.blk0
        if block0 == None:
            if len(uid) != 4 and len(uid) != 7:
                print(f"{CR}UID needs to be 4 bytes or 7 bytes{C0}")
                return
            bcc = 0
            if len(uid) == 4:
                sak = 0x08
                atqa = 0x0400
                factory_info = 0xAABBCCDDEEFFFFFF
                bcc = uid[0] ^ uid[1] ^ uid[2] ^ uid[3]
                uid_hex = "".join(format(x, "02x") for x in uid)
                block0 = f"{uid_hex}{format(bcc, '02x')}{format(sak, '02x')}{format(atqa, '04x')}{format(factory_info, '016x')}"
            elif len(uid) == 7:
                sak = 0x18
                atqa = 0x4200
                factory_info = 0xAABBCCDDEEFF
                uid_hex = "".join(format(x, "02x") for x in uid)
                block0 = f"{uid_hex}{format(sak, '02x')}{format(atqa, '04x')}{format(factory_info, '012x')}"
        else:
            if is_hex(block0) == False:
                print(f"{CR}Block0 needs to be hex{C0}")
                return
            if len(block0) != 32:
                print(f"{CR}Block0 needs to be 16 bytes{C0}")
                return

            if not (block0[16:20].lower() == "4400" or block0[16:20].lower() == "4200"):
                uid = str_to_bytes(block0[0:8])
                bcc = uid[0] ^ uid[1] ^ uid[2] ^ uid[3]
                # check if bcc is valid on the block0
                if int(block0[8:10], 16) != bcc:
                    print(f"{CR}Invalid BCC{C0}")
                    return
        return str_to_bytes(block0)

    def gen1a_set_block0(self, block0: bytes):
        tag_info = {}
        resp = self.cmd.hf_14a_scan()
        self.device_com.halt()
        if resp == None:
            print("No tag found")
            return resp
        # print("Tag found", resp)
        tag_info["uid"] = resp[0]["uid"].hex()
        tag_info["atqa"] = resp[0]["atqa"].hex()
        tag_info["sak"] = resp[0]["sak"].hex()
        tag_info["data"] = []

        if self.cmd.isGen1a():
            print("Found Gen1A:", f"{tag_info['uid'].upper()}")
            options = {
                "activate_rf_field": 0,
                "wait_response": 1,
                "append_crc": 1,
                "auto_select": 0,
                "keep_rf_field": 1,
                "check_response_crc": 0,
            }
            resp = self.cmd.hf14a_raw(
                options=options,
                resp_timeout_ms=1000,
                data=[MifareCommand.MfWriteBlock, 0],
            )
            print(f"Writing block 0: {block0.hex().upper()}")
            options["keep_rf_field"] = 0
            resp = self.cmd.hf14a_raw(
                options=options,
                resp_timeout_ms=1000,
                data=block0,
            )
            print(f" - {CG}Write done.{C0}")
        else:
            print(f"{CR}Tag is not Gen1A{C0}")

    def gen2_set_block0(self, block0: bytes, key: bytes, use_key_b: bool = False):
        tag_info = {}
        resp = self.cmd.hf_14a_scan()
        if resp == None:
            print("No tag found")
            return resp
        # print("Tag found", resp)
        tag_info["uid"] = resp[0]["uid"].hex()
        tag_info["atqa"] = resp[0]["atqa"].hex()
        tag_info["sak"] = resp[0]["sak"].hex()
        tag_info["data"] = []
        print(f"Write block 0: {block0.hex().upper()}")
        resp = self.cmd.mf1_write_one_block(
            resp[0]["uid"], 0, MfcKeyType.B if use_key_b else MfcKeyType.A, key, block0
        )
        if resp:
            print(f" - {CG}Write done.{C0}")
        else:
            print(f" - {CR}Write failed.{C0}")

    def gen3_set_block0(self, uid: bytes, block0: bytes, lock: bool = False):
        isGen3 = self.cmd.isGen3()
        if not isGen3:
            print(f"{CR}Tag is not Gen3{C0}")
            return
        print("Found Gen3 Tag")
        resp1 = self.cmd.setGen3Uid(uid)
        print(
            f"Set UID to {uid.hex().upper()}: {CG}Success{C0}"
            if resp1
            else f"Set UID to {uid.hex().upper()}: {CR}Failed{C0}"
        )
        resp2 = self.cmd.setGen3Block0(block0)
        print(
            f"Set block0 to {block0.hex().upper()}: {CG}Success{C0}"
            if resp2
            else f"Set block0 to {block0.hex().upper()}: {CR}Failed{C0}"
        )
        if lock:
            resp3 = self.cmd.lockGen3Uid()
            print(
                f"Lock UID: {CG}Success{C0}" if resp3 else f"Lock UID: {CR}Failed{C0}"
            )

    def gen4_set_block0(self, uid: bytes, block0: bytes, pwd="00000000"):
        tag_info = {}
        resp = self.cmd.hf_14a_scan()
        if resp == None:
            print("No tag found")
            return resp
        # print("Tag found", resp)
        tag_info["uid"] = resp[0]["uid"].hex()
        tag_info["atqa"] = resp[0]["atqa"].hex()
        tag_info["sak"] = resp[0]["sak"].hex()
        tag_info["data"] = []

        if self.cmd.isGen4():
            print("Found Gen4:", f"{tag_info['uid'].upper()}")
            options = {
                "activate_rf_field": 0,
                "wait_response": 1,
                "append_crc": 1,
                "auto_select": 0,
                "keep_rf_field": 1,
                "check_response_crc": 0,
            }
            uid_length_symbol = "01" if len(uid) == 7 else "00"
            set_uid_length_command = f"CF{pwd}68{uid_length_symbol}"
            resp = self.cmd.hf14a_raw(
                options=options,
                resp_timeout_ms=1000,
                data=bytes.fromhex(set_uid_length_command),
            )
            atqa = "0400" if len(uid) == 4 else "4400"
            sak = "08" if len(uid) == 4 else "18"
            set_atqa_sak_command = f"CF{pwd}35{atqa}{sak}"
            resp = self.cmd.hf14a_raw(
                options=options,
                resp_timeout_ms=1000,
                data=bytes.fromhex(set_atqa_sak_command),
            )
            print(f"Writing block 0: {block0.hex().upper()}")
            options["keep_rf_field"] = 0
            resp = self.cmd.hf14a_raw(
                options=options,
                resp_timeout_ms=1000,
                data=bytes.fromhex(f"CF{pwd}CD00{block0.hex()}"),
            )
            print(f" - {CG}Write done.{C0}")
        else:
            print(f" - {CR}Tag is not Gen4 or wrong pwd.{C0}")

    def on_exec(self, args: argparse.Namespace):
        uid = str_to_bytes(args.u)
        block0 = self.get_block0(uid, args)
        if block0 == None:
            return
        self.device_com.set_normal_mode()
        gen = args.g
        if gen == 1:
            self.gen1a_set_block0(block0)
        elif gen == 2:
            key = str_to_bytes(args.k)
            self.gen2_set_block0(block0, key, args.b)
        elif gen == 3:
            self.gen3_set_block0(uid, block0, args.lock)
        elif gen == 4:
            self.gen4_set_block0(uid, block0, pwd=args.p)


@hf_mf.command("rdbl")
class HfMfRdbl(MF1AuthArgsUnit):
    def on_exec(self, args: argparse.Namespace):
        block = args.blk
        key_type = MfcKeyType.B if args.b else MfcKeyType.A
        key: str = args.key
        if not re.match(r"^[a-fA-F0-9]{12}$", key):
            raise ArgsParserError("key must include 12 HEX symbols")

        scan = self.cmd.hf_14a_scan()
        if _require_mfc_profile(scan) is None:
            return

        resp = self.cmd.mf1_read_one_block(block, key_type, bytes.fromhex(key))

        if resp is not None:
            if resp.parsed is not None:
                print(f"Block {block}: {resp.parsed.hex().upper()}")
            else:
                print(f"Block {block} Failed to read")


@hf_mf.command("wrbl")
class HfMfWrbl(MF1WriteBlockArgsUnit):
    def on_exec(self, args: argparse.Namespace):
        if args.data is None:
            print("usage: hf mf wrbl [-h] -b <dec> -k <hex> -d <hex>")
            print("hf mf wrbl: error: the following arguments are required: -d")
            return
        key_type = MfcKeyType.B if args.b else MfcKeyType.A
        key: str = args.key
        data = args.data
        if not re.match(r"^[a-fA-F0-9]{12}$", key):
            raise ArgsParserError("key must include 12 HEX symbols")
        if not re.match(r"^[a-fA-F0-9]{32}$", data):
            raise ArgsParserError("data must include 32 HEX symbols")
        scan = self.cmd.hf_14a_scan()
        profile = _require_mfc_profile(scan)
        if profile is None:
            return
        uid = profile["uid"]
        resp = self.cmd.mf1_write_one_block(
            uid, args.blk, key_type, bytes.fromhex(key), bytes.fromhex(data)
        )
        print(f" - {CG}Write done.{C0}" if resp else f" - {CR}Write fail.{C0}")


@hf_mf.command("cview")
class HfMfCview(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "View Gen1a dump"
        # add parser arguments f for save to file, bool type
        parser.add_argument("--file", action="store_true", help="Save to json file")
        parser.add_argument("--bin", action="store_true", help="Save to bin file")
        return parser

    def on_exec(self, args: argparse.Namespace):
        start_time = time.perf_counter()
        result = self.cmd.hfmf_cview()
        if result is None:
            return
        uid = result["uid"]
        # check args if file is set
        if args.file:
            # convert dict to json string
            jsonString = json.dumps(result)
            # save to file hf-mf-uid.json
            fileName = f"hf-mf-{uid}-dump"
            # check if file exists, if exists, add -x after dump, x can be 1, 2, 3, ...
            fileIndex = 1
            while os.path.exists(f"{fileName}.json"):
                fileName = f"hf-mf-{uid}-dump-{fileIndex}"
                fileIndex += 1
            with open(f"{fileName}.json", "w") as f:
                f.write(jsonString)
                print(f"Dump saved to {fileName}.json")

        if args.bin:
            if len(result["blocks"]) != 64:
                print("The dump is not complete. It should contain 64 blocks.")
                return
            fileName = f"hf-mf-{uid}-dump"
            fileIndex = 1
            while os.path.exists(f"{fileName}.bin"):
                fileName = f"hf-mf-{uid}-dump-{fileIndex}"
                fileIndex += 1
            with open(f"{fileName}.bin", "wb") as f:
                for block in result["blocks"].values():
                    f.write(bytes.fromhex(block))
                print(f"Dump saved to {fileName}.bin")

        elapsed = time.perf_counter() - start_time
        print(f"Read time: {elapsed:.2f}s")

@hf_mf.command("dump")
class HfMfDump(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Dump Mifare Classic card"
        # add key file
        parser.add_argument(
            "-k",
            metavar="<file>",
            type=argparse.FileType("r"),
            required=False,
            help="Mifare Key file",
        )
        parser.add_argument(
            "--file", action="store_true", help="Save to json file"
        )
        parser.add_argument(
            "--bin", action="store_true", help="Save to bin file"
        )
        return parser
    
    def sak_info(self, data_tag):
        int_sak = data_tag["sak"][0]
        if int_sak in type_id_SAK_dict:
            print(f"Type: {type_id_SAK_dict[int_sak]}")

    def on_exec(self, args: argparse.Namespace):
        valid_keys = []
        if args.k:
            with open(args.k.name, "r") as key_file:
                for line in key_file:
                    mifare_key = line.strip()
                    if re.match(r"^[a-fA-F0-9]{12}$", mifare_key):
                        valid_keys.append(mifare_key)

        print(f"Total keys: {CR}{len(valid_keys)}{C0}")
        resp = self.cmd.hf_14a_scan()
        if resp == None:
            print("No tag found")
            return resp
        uid = resp[0]["uid"]
        print(f"UID: {uid.hex().upper()}")
        print(f"ATQA: {resp[0]['atqa'].hex().upper()}")
        print(f"SAK: {resp[0]['sak'].hex().upper()}")
        self.sak_info(resp[0])
        # print key of block_size_dict
        
        if int.from_bytes(resp[0]['sak'], 'big') in block_size_dict:
            block_size = block_size_dict[int.from_bytes(resp[0]['sak'], 'big')]
            print(f"Block Size: {block_size}")
            time.sleep(0.5)
            dump_map = {}
            for block in range(block_size):
                for key in valid_keys:
                    resp = self.cmd.mf1_read_block(block, bytes.fromhex(key))
                    if resp and resp.parsed:
                        # print line with space * 60
                        print(f"\r{' '*60}", end="\r")
                        dump_map[block] = resp.parsed.hex().upper()
                        if(len(dump_map[block])):
                            block_data = dump_map[block]
                            if block == 0:
                                if len(uid) == 7:
                                    print(
                                        f"{block:02d}: {CY}{block_data[0:14].upper()}{C0}{block_data[14:].upper()}{C0}"
                                    )
                                else:
                                    print(
                                        f"{block:02d}: {CY}{block_data[0:8].upper()}{CR}{block_data[8:10].upper()}{CG}{block_data[10:12].upper()}{CY}{block_data[12:16].upper()}{C0}{block_data[16:].upper()}{C0}"
                                    )
                            elif is_trailer_block(block):
                                print(
                                    f"{block:02d}: {CG}{block_data[0:12].upper()}{CR}{block_data[12:20].upper()}{CG}{block_data[20:].upper()}{C0}"
                                )
                            else:
                                print(f"{block:02d}: {block_data.upper()}")
                            valid_keys.insert(0, valid_keys.pop(valid_keys.index(key)))
                        break
                    else:
                        print(f"\rAuth block {block} with key {key} ({valid_keys.index(key) + 1}/{len(valid_keys)})", end="\r")
            if args.file:
                with open(f"mf_dump_{uid.hex().upper()}.json", "w") as json_file:
                    json.dump({"blocks": dump_map}, json_file)
            if args.bin:
                with open(f"mf_dump_{uid.hex().upper()}.bin", "wb") as bin_file:
                    for block_index, block_data in dump_map.items():
                        bin_file.write(bytes.fromhex(block_data))
        else:
            print(f"{CR}Not MiFare Classic{C0}")

@hf_mf.command("eRead")
class HfMfEread(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Read Mifare Classic emulator dump"
        parser.add_argument(
            "-s", "--slot", default=1, type=int, help="Emulator slot(1-8)"
        )
        parser.add_argument(
            "--json", action="store_true", help="Save to json file"
        )
        parser.add_argument(
            "--bin", action="store_true", help="Save to bin file"
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        slot = args.slot
        
        # Switch to the target slot in emulator mode first
        # Type 1 = MIFARE Classic
        self.device_com.set_work_mode(PN532KillerMode.EMULATOR, 1, slot - 1)
        
        print(f"Reading Mifare Classic 1K emulator from slot {args.slot}...")
        dump_map = self.cmd.hf_mf_eread(slot)
        
        if dump_map is None or len(dump_map) == 0:
            print(f"{CR}Failed to read emulator data{C0}")
            return
        
        # Generate filename based on slot
        filename_base = f"mf_eread_slot{args.slot}"
        
        # Save to JSON if requested
        if args.json:
            json_data = {
                "slot": args.slot,
                "type": "MIFARE Classic 1K",
                "blocks": {}
            }
            for block_idx, block_resp in dump_map.items():
                if hasattr(block_resp, 'parsed'):
                    json_data["blocks"][block_idx] = block_resp.parsed.hex().upper()
                else:
                    json_data["blocks"][block_idx] = block_resp.hex().upper() if isinstance(block_resp, bytes) else str(block_resp)
            
            json_file = f"{filename_base}.json"
            with open(json_file, "w") as f:
                json.dump(json_data, f, indent=2)
            print(f"{CG}Saved to {json_file}{C0}")
        
        # Save to BIN if requested
        if args.bin:
            bin_file = f"{filename_base}.bin"
            with open(bin_file, "wb") as f:
                for block_idx in range(64):
                    if block_idx in dump_map:
                        block_resp = dump_map[block_idx]
                        if hasattr(block_resp, 'parsed'):
                            f.write(block_resp.parsed)
                        elif isinstance(block_resp, bytes):
                            f.write(block_resp)
                        else:
                            f.write(bytes.fromhex(str(block_resp)))
                    else:
                        f.write(b'\x00' * 16)
            print(f"{CG}Saved to {bin_file}{C0}")
        
        # Print summary
        if not args.json and not args.bin:
            print(f"{CG}Read {len(dump_map)} blocks from slot {args.slot}{C0}")

@hf_mf.command("staticnested")
class HfMfStaticnested(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Run a static-nested attack via PN532Killer helpers."
        parser.add_argument(
            "--known-key",
            required=True,
            metavar="<hex>",
            help="Known 6-byte key for the reference block (12 hex characters)",
        )
        parser.add_argument(
            "--known-block",
            type=int,
            required=True,
            metavar="<dec>",
            help="Reference block that uses the known key",
        )
        parser.add_argument(
            "--known-key-type",
            choices=["A", "a", "B", "b"],
            default="A",
            help="Reference key type (default: A)",
        )
        parser.add_argument(
            "--target-block",
            type=int,
            required=True,
            metavar="<dec>",
            help="Target block to recover",
        )
        parser.add_argument(
            "--target-key-type",
            choices=["A", "a", "B", "b"],
            default="B",
            help="Target key type (default: B)",
        )
        parser.add_argument(
            "--show-raw",
            action="store_true",
            help="Print collected nonce/keystream pairs and tool output",
        )
        parser.epilog = "PN532Killer expects an 8-byte datakey field (0x0000||known-key); the CLI fills this automatically."
        return parser

    def on_exec(self, args: argparse.Namespace):
        if not re.fullmatch(r"[0-9a-fA-F]{12}", args.known_key):
            raise ArgsParserError("--known-key must be exactly 12 hex characters")
        key_bytes = bytes.fromhex(args.known_key)
        datakey = b"\x00\x00" + key_bytes
        known_block = args.known_block
        target_block = args.target_block
        if not (0 <= known_block <= 0xFF and 0 <= target_block <= 0xFF):
            raise ArgsParserError("Block numbers must be between 0 and 255")
        known_type = MfcKeyType.B if args.known_key_type.upper() == "B" else MfcKeyType.A
        target_type = MfcKeyType.B if args.target_key_type.upper() == "B" else MfcKeyType.A

        scan = self.cmd.hf_14a_scan()
        if scan is None or len(scan) == 0:
            print("No tag found")
            return

        session = self.cmd.read_userdef_staticnested(
            datakey,
            known_block,
            int(known_type),
            target_block,
            int(target_type),
        )
        if not session:
            print(
                f"{CR}Static-nested helper did not return nonce data. Ensure the card is static and the known key/block are correct.{C0}"
            )
            return

        show_details = args.show_raw or pn532_com.DEBUG
        uid_fmt = _fmt32(session["uid"])
        target_label = _keytype_label(session["key_type"])
        print(f"UID: {uid_fmt}")
        print(f"Target block {target_block} key {target_label}")
        print(
            f"Nonce #0 -> NT={_fmt32(session['nt0'])} KS={_fmt32(session['ks0'])}"
        )
        print(
            f"Nonce #1 -> NT={_fmt32(session['nt1'])} KS={_fmt32(session['ks1'])}"
        )

        args_list = [
            uid_fmt,
            f"{session['key_type']:02X}",
            _fmt32(session["nt0"]),
            _fmt32(session["ks0"]),
            _fmt32(session["nt1"]),
            _fmt32(session["ks1"]),
        ]
        key_hex, output = _run_mfkey("staticnested", args_list, verbose=show_details)
        if key_hex is None and output is None:
            return
        if key_hex:
            print(f"Recovered key: {key_hex}")
        else:
            print(f"{CR}staticnested did not find a key{C0}")
        if show_details and output:
            for line in output.strip().splitlines():
                print(f"    {line}")

@hf_mf.command("mfkey64")
class HfMfMfkey64(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Use PN532Killer sniff data to run mfkey64 (card present sessions)."
        parser.add_argument(
            "--show-raw",
            action="store_true",
            help="Display captured nonce tuples and mfkey logs (auto when debug on)",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        entries = self.cmd.hf_sniff_get_mfkey_entries(with_card=True)
        if not entries:
            print(
                f"{CR}No card-present sniff data found. Put PN532Killer into sniffer mode, capture an auth, then retry.{C0}"
            )
            return
        show_details = args.show_raw or pn532_com.DEBUG
        unique_entries = []
        seen_chunks = set()
        for entry in entries:
            chunk = (entry["uid"], entry["nt"], entry["nr"], entry["ar"], entry["at"])
            if chunk in seen_chunks:
                continue
            seen_chunks.add(chunk)
            unique_entries.append(entry)
        print(f"Found {len(unique_entries)} captured authentication(s).")
        print(f"{'#':<2} {'UID':<8} {'Sec':<3} {'Key':<3} {'Result':<12}")
        for idx, entry in enumerate(unique_entries, start=1):
            args_list = [
                _fmt32(entry["uid"]),
                _fmt32(entry["nt"]),
                _fmt32(entry["nr"]),
                _fmt32(entry["ar"]),
                _fmt32(entry["at"]),
            ]
            key_hex, output = _run_mfkey("mfkey64", args_list, verbose=show_details)
            if key_hex is None and output is None:
                return
            key_display = key_hex or "(not found)"
            print(
                f"{idx:<2} {_fmt32(entry['uid'])} {entry['sector']:02d} {_keytype_label(entry['key_type'])} {key_display}"
            )
            if show_details:
                print(
                    f"    NT={_fmt32(entry['nt'])} NR={_fmt32(entry['nr'])} AR={_fmt32(entry['ar'])} AT={_fmt32(entry['at'])}"
                )
                output_str = (output or "").strip()
                if output_str:
                    for line in output_str.splitlines():
                        print(f"    {line}")


@hf_mf.command("mfkey32v2")
class HfMfMfkey32v2(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Use PN532Killer no-card sniff data to run mfkey32v2 (needs nonce pairs)."
        parser.add_argument(
            "--show-raw",
            action="store_true",
            help="Display captured nonce tuples used for each calculation",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        entries = self.cmd.hf_sniff_get_mfkey_entries(with_card=False)
        if len(entries) < 2:
            print(
                f"{CR}Need at least 2 sniff entries before running mfkey32v2.{C0}"
            )
            return
        groups = {}
        for entry in entries:
            key = (entry["uid"], entry["sector"], entry["key_type"])
            groups.setdefault(key, [])
            # avoid duplicates
            if any(
                existing["nt"] == entry["nt"]
                and existing["nr"] == entry["nr"]
                and existing["ar"] == entry["ar"]
                for existing in groups[key]
            ):
                continue
            groups[key].append(entry)
        print(f"Captured nonce sets for {len(groups)} sector/key slot(s).")
        print(f"{'#':<2} {'UID':<8} {'Sec':<3} {'Key':<3} {'Result':<12}")
        idx = 1
        for (uid, sector, key_type), captures in groups.items():
            if len(captures) < 2:
                print(
                    f"{idx:<2} {_fmt32(uid)} {sector:02d} {_keytype_label(key_type)} (need another nonce)"
                )
                idx += 1
                continue
            key_hex = None
            chosen_pair = None
            for i in range(len(captures)):
                for j in range(i + 1, len(captures)):
                    if captures[i]["nt"] == captures[j]["nt"]:
                        continue
                    args_list = [
                        _fmt32(uid),
                        _fmt32(captures[i]["nt"]),
                        _fmt32(captures[i]["nr"]),
                        _fmt32(captures[i]["ar"]),
                        _fmt32(captures[j]["nt"]),
                        _fmt32(captures[j]["nr"]),
                        _fmt32(captures[j]["ar"]),
                    ]
                    key_hex, output = _run_mfkey(
                        "mfkey32v2",
                        args_list,
                        verbose=(args.show_raw or pn532_com.DEBUG),
                    )
                    if key_hex is None and output is None:
                        return
                    chosen_pair = (captures[i], captures[j])
                    if key_hex:
                        break
                if key_hex:
                    break
            key_display = key_hex or "(not found)"
            print(f"{idx:<2} {_fmt32(uid)} {sector:02d} {_keytype_label(key_type)} {key_display}")
            if args.show_raw and chosen_pair:
                a, b = chosen_pair
                print(
                    f"    Pair A: NT={_fmt32(a['nt'])} NR={_fmt32(a['nr'])} AR={_fmt32(a['ar'])}\n"
                    f"    Pair B: NT={_fmt32(b['nt'])} NR={_fmt32(b['nr'])} AR={_fmt32(b['ar'])}"
                )
            idx += 1


@hf_mf.command("chk")
class HfMfChk(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Check MIFARE Classic sector keys using dictionary candidates."
        parser.add_argument(
            "-k",
            metavar="<file>",
            type=argparse.FileType("r"),
            required=False,
            help="Optional key dictionary file (one 12-hex key per line)",
        )
        parser.add_argument(
            "--key",
            action="append",
            default=[],
            metavar="<hex>",
            help="Add a known key (can be repeated)",
        )
        parser.add_argument(
            "--no-default-keys",
            action="store_true",
            help="Disable built-in default key dictionary",
        )
        parser.add_argument(
            "--start-sector",
            type=int,
            default=0,
            help="Start sector for key checking",
        )
        parser.add_argument(
            "--end-sector",
            type=int,
            default=None,
            help="End sector for key checking (default: card max)",
        )
        parser.add_argument(
            "--dump-keys",
            metavar="<file>",
            help="Save discovered sector keys to a text file",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        _run_chk_workflow(self, args)


def _run_chk_workflow(
    cli_obj: DeviceRequiredUnit,
    args: argparse.Namespace,
    alias_name: Union[str, None] = None,
):
    if alias_name:
        print(
            f"{CY}hf mf {alias_name} is kept for PM3 compatibility and currently maps to hf mf chk.{C0}"
        )

    key_pool = _build_key_pool(args)
    if len(key_pool) == 0:
        raise ArgsParserError("No candidate keys available")

    scan = cli_obj.cmd.hf_14a_scan()
    profile = _card_profile_from_scan(scan)
    if profile is None:
        print("No supported MIFARE Classic tag found")
        return

    sector_count = profile["sector_count"]
    start_sector = max(0, args.start_sector)
    end_sector = sector_count - 1 if args.end_sector is None else min(args.end_sector, sector_count - 1)
    if start_sector > end_sector:
        raise ArgsParserError("Invalid sector range")

    print(f"UID: {profile['uid'].hex().upper()} | sectors: {sector_count}")
    print(f"Candidate keys: {len(key_pool)}")
    sector_keys = _discover_sector_keys(
        cli_obj.cmd,
        key_pool,
        start_sector,
        end_sector,
        uid=profile["uid"],
        print_progress=True,
    )

    missing = []
    print("\nKey check summary:")
    for sector in range(start_sector, end_sector + 1):
        key_a = sector_keys[sector]["A"]
        key_b = sector_keys[sector]["B"]
        ka = key_a.hex().upper() if isinstance(key_a, bytes) else "------------"
        kb = key_b.hex().upper() if isinstance(key_b, bytes) else "------------"
        print(f"  Sector {sector:02d} | A={ka} | B={kb}")
        if not isinstance(key_a, bytes) or not isinstance(key_b, bytes):
            missing.append(sector)

    if args.dump_keys:
        out_path = Path(args.dump_keys).expanduser()
        with open(out_path, "w") as f:
            for sector in range(start_sector, end_sector + 1):
                key_a = sector_keys[sector]["A"]
                key_b = sector_keys[sector]["B"]
                ka = key_a.hex().upper() if isinstance(key_a, bytes) else "------------"
                kb = key_b.hex().upper() if isinstance(key_b, bytes) else "------------"
                f.write(f"{sector:02d} A {ka}\n")
                f.write(f"{sector:02d} B {kb}\n")
        print(f"{CG}Key report saved to {out_path}{C0}")

    if missing:
        print(f"{CY}Sectors with missing key(s): {', '.join(str(s) for s in missing)}{C0}")
    else:
        print(f"{CG}All keys found for selected range.{C0}")


@hf_mf.command("fchk")
class HfMfFchk(HfMfChk):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = super().args_parser()
        parser.description = "PM3-compatible alias of hf mf chk."
        return parser

    def on_exec(self, args: argparse.Namespace):
        _run_chk_workflow(self, args, alias_name="fchk")


@hf_mf.command("autopwn")
class HfMfAutopwn(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Automatic key recovery and dump workflow for MIFARE Classic."
        parser.add_argument(
            "-k",
            metavar="<file>",
            type=argparse.FileType("r"),
            required=False,
            help="Optional key dictionary file (one 12-hex key per line)",
        )
        parser.add_argument(
            "--key",
            action="append",
            default=[],
            metavar="<hex>",
            help="Add a known key (can be repeated)",
        )
        parser.add_argument(
            "--no-default-keys",
            action="store_true",
            help="Disable built-in default key dictionary",
        )
        parser.add_argument(
            "-O",
            "--output",
            dest="output_path",
            metavar="<file>",
            help="Save dump to binary file (.mfd/.bin)",
        )
        parser.add_argument(
            "--show-missing",
            action="store_true",
            help="Print unreadable blocks at the end",
        )
        parser.add_argument(
            "--known-key",
            metavar="<hex>",
            help="Optional seed key for static-nested stage (12 hex)",
        )
        parser.add_argument(
            "--known-block",
            type=int,
            default=0,
            help="Seed block for static-nested stage (default: 0)",
        )
        parser.add_argument(
            "--known-key-type",
            choices=["A", "a", "B", "b"],
            default="A",
            help="Seed key type (default: A)",
        )
        parser.add_argument(
            "--skip-nested",
            action="store_true",
            help="Skip static-nested recovery stage",
        )
        parser.add_argument(
            "--show-raw",
            action="store_true",
            help="Show static-nested helper output",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        key_pool = _build_key_pool(args)
        if len(key_pool) == 0:
            raise ArgsParserError("No candidate keys available")

        scan = self.cmd.hf_14a_scan()
        profile = _card_profile_from_scan(scan)
        if profile is None:
            print("No supported MIFARE Classic tag found")
            return

        uid = profile["uid"]
        sector_count = profile["sector_count"]
        block_count = profile["block_count"]

        print(f"UID: {uid.hex().upper()} | sectors: {sector_count} | blocks: {block_count}")
        print(f"Candidate keys: {len(key_pool)}")

        sector_keys = _discover_sector_keys(
            self.cmd,
            key_pool,
            0,
            sector_count - 1,
            uid=uid,
            print_progress=True,
        )

        missing_key_slots = []
        for sector in range(sector_count):
            if not isinstance(sector_keys[sector]["A"], bytes):
                missing_key_slots.append((sector, "A"))
            if not isinstance(sector_keys[sector]["B"], bytes):
                missing_key_slots.append((sector, "B"))

        if missing_key_slots and (not args.skip_nested):
            if self.device_com.get_device_name() != "PN532Killer":
                print(f"{CY}Static-nested stage skipped: PN532Killer required.{C0}")
            else:
                seed_block = None
                seed_key_type = None
                seed_key = None
                if args.known_key:
                    seed_key = _normalize_key_hex(args.known_key)
                    if seed_key is None:
                        raise ArgsParserError("--known-key must be exactly 12 hex characters")
                    seed_block = args.known_block
                    seed_key_type = args.known_key_type
                else:
                    auto_seed = _pick_seed_from_sector_keys(sector_keys)
                    if auto_seed is not None:
                        seed_block, seed_key_type, seed_key = auto_seed

                if seed_key is None:
                    print(f"{CY}No seed key available for nested stage. Provide --known-key/--known-block.{C0}")
                else:
                    print(
                        f"{CY}Running static-nested stage from block {seed_block} key {seed_key_type}={seed_key.hex().upper()}{C0}"
                    )
                    nested_args = argparse.Namespace(
                        known_key=seed_key.hex().upper(),
                        known_block=seed_block,
                        known_key_type=seed_key_type,
                        target_key_type="both",
                        start_sector=0,
                        end_sector=sector_count - 1,
                        stop_on_fail=False,
                        show_raw=args.show_raw,
                    )
                    known_pairs, _, _ = _run_nestedattack_impl(self, nested_args)
                    for (sector, key_letter), key_bytes in known_pairs.items():
                        if isinstance(key_bytes, bytes):
                            sector_keys[sector][key_letter] = key_bytes
                            _prepend_unique_keys(key_pool, [key_bytes])

        print("\nDumping card blocks:")
        dump_blocks, missing_blocks = _dump_with_sector_keys(
            self.cmd,
            uid,
            block_count,
            sector_keys,
            key_pool,
        )

        if args.output_path:
            out_path = Path(args.output_path).expanduser()
            with open(out_path, "wb") as f:
                for block in range(block_count):
                    data = dump_blocks[block]
                    f.write(data if isinstance(data, bytes) else b"\x00" * 16)
            print(f"{CG}Dump saved to {out_path}{C0}")

        if missing_blocks:
            print(f"{CY}Unreadable blocks: {len(missing_blocks)}/{block_count}{C0}")
            if args.show_missing:
                print("Missing block indexes:", ", ".join(str(i) for i in missing_blocks))
        else:
            print(f"{CG}All blocks read successfully.{C0}")


@hf_mf.command("darkside")
class HfMfDarkside(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Darkside-like automatic recovery entry (uses available sniff/mfkey paths)."
        parser.add_argument(
            "--show-raw",
            action="store_true",
            help="Display captured tuples and helper outputs",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        print(f"{CY}Trying no-card nonce path (mfkey32v2)...{C0}")
        unit32 = HfMfMfkey32v2()
        unit32.device_com = self.device_com
        before = len(self.cmd.hf_sniff_get_mfkey_entries(with_card=False))
        unit32.on_exec(argparse.Namespace(show_raw=args.show_raw))
        after = len(self.cmd.hf_sniff_get_mfkey_entries(with_card=False))
        if before >= 2 or after >= 2:
            return

        print(f"{CY}No sufficient no-card tuples, trying card-present path (mfkey64)...{C0}")
        unit64 = HfMfMfkey64()
        unit64.device_com = self.device_com
        unit64.on_exec(argparse.Namespace(show_raw=args.show_raw))
        print(
            f"{CY}Note: native darkside nonce acquisition is not wired yet; this command currently orchestrates available mfkey pipelines.{C0}"
        )


@hf_mf.command("hardnested")
class HfMfHardnested(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Hardnested fallback entry (currently routes to nestedattack pipeline)."
        parser.add_argument(
            "--known-key",
            required=True,
            metavar="<hex>",
            help="Known 6-byte key for a reference block",
        )
        parser.add_argument(
            "--known-block",
            required=True,
            type=int,
            metavar="<dec>",
            help="Reference block that uses --known-key",
        )
        parser.add_argument(
            "--known-key-type",
            choices=["A", "a", "B", "b"],
            default="A",
            help="Reference key type (default: A)",
        )
        parser.add_argument(
            "--target-key-type",
            choices=["A", "a", "B", "b", "both"],
            default="both",
            help="Key type to recover (default: both)",
        )
        parser.add_argument(
            "--start-sector",
            type=int,
            default=0,
            help="Start sector for attack range",
        )
        parser.add_argument(
            "--end-sector",
            type=int,
            default=None,
            help="End sector for attack range (default: card max)",
        )
        parser.add_argument(
            "--stop-on-fail",
            action="store_true",
            help="Stop immediately when one target key fails",
        )
        parser.add_argument(
            "--show-raw",
            action="store_true",
            help="Print staticnested helper output",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        print(
            f"{CY}hardnested native solver is not integrated yet; running nestedattack fallback pipeline.{C0}"
        )
        _run_nestedattack_impl(self, args)


@hf_mf.command("mfoc")
class HfMfMfoc(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Project-built mfoc-like key recovery + dump (no external mfoc binary)."
        parser.add_argument(
            "-k",
            metavar="<file>",
            type=argparse.FileType("r"),
            required=False,
            help="Optional key dictionary file (one 12-hex key per line)",
        )
        parser.add_argument(
            "--key",
            action="append",
            default=[],
            metavar="<hex>",
            help="Add a known key (can be repeated)",
        )
        parser.add_argument(
            "--no-default-keys",
            action="store_true",
            help="Disable built-in default key dictionary",
        )
        parser.add_argument(
            "-O",
            "--output",
            dest="output_path",
            metavar="<file>",
            help="Save dump to binary file (.mfd/.bin)",
        )
        parser.add_argument(
            "--show-missing",
            action="store_true",
            help="Print unreadable blocks at the end",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        key_pool = _build_key_pool(args)
        if len(key_pool) == 0:
            raise ArgsParserError("No candidate keys available")

        scan = self.cmd.hf_14a_scan()
        if scan is None or len(scan) == 0:
            print("No tag found")
            return

        uid = scan[0]["uid"]
        sak = int.from_bytes(scan[0]["sak"], "big")
        sector_count = _sector_count_from_sak(sak)
        if sector_count == 0:
            print(f"{CR}Not a supported MIFARE Classic card (SAK=0x{sak:02X}).{C0}")
            return
        block_count = _block_count_from_sector_count(sector_count)

        print(f"UID: {uid.hex().upper()} | sectors: {sector_count} | blocks: {block_count}")
        print(f"Candidate keys: {len(key_pool)}")

        sector_keys: dict[int, dict[str, Union[bytes, None]]] = {
            s: {"A": None, "B": None} for s in range(sector_count)
        }

        for sector in range(sector_count):
            trailer = _trailer_block_for_sector(sector)
            trailer_a = None
            found_a = None
            for key in key_pool:
                trailer_a = _try_auth_read_trailer(self.cmd, trailer, key, MfcKeyType.A)
                if trailer_a:
                    found_a = key
                    break
            if found_a:
                sector_keys[sector]["A"] = found_a
                maybe_b = trailer_a[10:16]
                if maybe_b != b"\x00" * 6:
                    sector_keys[sector]["B"] = maybe_b
                    _prepend_unique_keys(key_pool, [found_a, maybe_b])
                else:
                    _prepend_unique_keys(key_pool, [found_a])

            if sector_keys[sector]["B"] is None:
                for key in key_pool:
                    trailer_b = _try_auth_read_trailer(self.cmd, trailer, key, MfcKeyType.B)
                    if trailer_b:
                        sector_keys[sector]["B"] = key
                        maybe_a = trailer_b[0:6]
                        if maybe_a != b"\x00" * 6:
                            sector_keys[sector]["A"] = sector_keys[sector]["A"] or maybe_a
                            _prepend_unique_keys(key_pool, [key, maybe_a])
                        else:
                            _prepend_unique_keys(key_pool, [key])
                        break

            ka = sector_keys[sector]["A"]
            kb = sector_keys[sector]["B"]
            ka_text = ka.hex().upper() if isinstance(ka, bytes) else "------------"
            kb_text = kb.hex().upper() if isinstance(kb, bytes) else "------------"
            print(f"Sector {sector:02d} keys: A={ka_text} B={kb_text}")

        dump_blocks: dict[int, Union[bytes, None]] = {}
        missing_blocks: list[int] = []
        for block in range(block_count):
            sector = _sector_from_block(block)
            candidates = []
            key_a = sector_keys[sector]["A"]
            key_b = sector_keys[sector]["B"]
            if isinstance(key_a, bytes):
                candidates.append((MfcKeyType.A, key_a))
            if isinstance(key_b, bytes):
                candidates.append((MfcKeyType.B, key_b))
            if not candidates:
                candidates.extend([(MfcKeyType.A, key) for key in key_pool])
                candidates.extend([(MfcKeyType.B, key) for key in key_pool])

            block_data = None
            for key_type, key in candidates:
                resp = self.cmd.mf1_read_one_block(block, key_type, key)
                if (
                    resp
                    and hasattr(resp, "parsed")
                    and isinstance(resp.parsed, (bytes, bytearray))
                    and len(resp.parsed) == 16
                ):
                    block_data = bytes(resp.parsed)
                    break

            dump_blocks[block] = block_data
            if block_data is None:
                missing_blocks.append(block)
                print(f"{block:03d}: {CR}<unreadable>{C0}")
                continue

            line = block_data.hex().upper()
            if block == 0:
                if len(uid) == 7:
                    print(f"{block:03d}: {CY}{line[0:14]}{C0}{line[14:]}{C0}")
                else:
                    print(
                        f"{block:03d}: {CY}{line[0:8]}{CR}{line[8:10]}{CG}{line[10:12]}{CY}{line[12:16]}{C0}{line[16:]}{C0}"
                    )
            elif is_trailer_block(block):
                print(f"{block:03d}: {CG}{line[0:12]}{CR}{line[12:20]}{CG}{line[20:]}{C0}")
            else:
                print(f"{block:03d}: {line}")

        if args.output_path:
            out_path = Path(args.output_path).expanduser()
            with open(out_path, "wb") as f:
                for block in range(block_count):
                    data = dump_blocks[block]
                    f.write(data if isinstance(data, bytes) else b"\x00" * 16)
            print(f"{CG}Dump saved to {out_path}{C0}")

        if missing_blocks:
            print(f"{CY}Unreadable blocks: {len(missing_blocks)}/{block_count}{C0}")
            if args.show_missing:
                print("Missing block indexes:", ", ".join(str(i) for i in missing_blocks))
        else:
            print(f"{CG}All blocks read successfully.{C0}")


@hf_mf.command("nestedattack")
class HfMfNestedattack(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Run static-nested attack recursively to recover multiple sector keys."
        parser.add_argument(
            "--known-key",
            required=True,
            metavar="<hex>",
            help="Known 6-byte key for a reference block",
        )
        parser.add_argument(
            "--known-block",
            required=True,
            type=int,
            metavar="<dec>",
            help="Reference block that uses --known-key",
        )
        parser.add_argument(
            "--known-key-type",
            choices=["A", "a", "B", "b"],
            default="A",
            help="Reference key type (default: A)",
        )
        parser.add_argument(
            "--target-key-type",
            choices=["A", "a", "B", "b", "both"],
            default="both",
            help="Key type to recover (default: both)",
        )
        parser.add_argument(
            "--start-sector",
            type=int,
            default=0,
            help="Start sector for attack range",
        )
        parser.add_argument(
            "--end-sector",
            type=int,
            default=None,
            help="End sector for attack range (default: card max)",
        )
        parser.add_argument(
            "--stop-on-fail",
            action="store_true",
            help="Stop immediately when one target key fails",
        )
        parser.add_argument(
            "--show-raw",
            action="store_true",
            help="Print staticnested helper output",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        _run_nestedattack_impl(self, args)


@hf_mf.command("nested")
class HfMfNested(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Compat command: run built-in nestedattack flow (no external mfoc)."
        parser.add_argument("card", type=str, help="Card size flag (0/1/2/4 or 'o' for one-sector mode)")
        parser.add_argument("block", type=str, help="Known block index or '*' for auto search")
        parser.add_argument("key_type", type=str, choices=["A", "a", "B", "b"], help="Known key type")
        parser.add_argument("key", type=str, help="Known 6-byte key (12 hex chars)")
        parser.add_argument(
            "flags",
            nargs="?",
            default="",
            help="Optional flags: d (dump), t (emulator transfer unsupported), s/ss (slow)"
        )
        parser.add_argument(
            "--show-raw",
            action="store_true",
            help="Print staticnested helper output"
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.block in ("*", "auto"):
            raise ArgsParserError("hf mf nested now requires a known block index; use hf mf mfoc for dictionary-based probing")
        try:
            known_block = int(args.block, 10)
        except ValueError as exc:
            raise ArgsParserError("block must be decimal") from exc

        compat_args = argparse.Namespace(
            known_key=args.key,
            known_block=known_block,
            known_key_type=args.key_type,
            target_key_type="both",
            start_sector=0,
            end_sector=None,
            stop_on_fail=("s" in (args.flags or "").lower()),
            show_raw=args.show_raw,
        )
        _run_nestedattack_impl(self, compat_args)

@hf_mf.command("wipe")
class HfMfWipe(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Wipe Mifare Classic card"
        parser.add_argument(
            "-k",
            metavar="<file>",
            type=argparse.FileType("r"),
            required=True,
            help="Mifare Key file",
        )
        return parser

    def sak_info(self, data_tag):
        int_sak = data_tag["sak"][0]
        if int_sak in type_id_SAK_dict:
            print(f"- Guessed type(s) from SAK: {type_id_SAK_dict[int_sak]}")

    def on_exec(self, args: argparse.Namespace):
        valid_keys = []
        with open(args.k.name, "r") as key_file:
            for line in key_file:
                mifare_key = line.strip()
                if re.match(r"^[a-fA-F0-9]{12}$", mifare_key):
                    valid_keys.append(mifare_key)

        if len(valid_keys) == 0:
            print("No valid keys found in the file.")
            return

        print(f"Total keys: {CR}{len(valid_keys)}{C0}")
        print(f"{CR}Warning: Wiping the card will erase all data on the card.{C0}")
        print(f"{CR}Warning: This operation is irreversible.{C0}")
        resp = self.cmd.hf_14a_scan()
        if resp == None:
            print("No tag found")
            return resp

        print(f"UID:  {resp[0]['uid'].hex().upper()}")
        print(f"ATQA: {resp[0]['atqa'].hex().upper()}")
        print(f"SAK:  {resp[0]['sak'].hex().upper()}")

        self.sak_info(resp[0])

        if resp[0]["sak"] in block_size_dict:
            block_size = block_size_dict[resp[0]["sak"]]
            print(f"Block size: {block_size} bytes")
            if self.cmd.isGen1a():
                print(f"{CR}Gen1A detected.{C0}")
                # no key required for Gen1A
                for block in range(64):
                    blockData = ""
                    if(block == 0):
                        if len(resp[0]["uid"]) == 7:
                            blockData = FactoryPreset.mf7bBlock0
                        else:
                            blockData = FactoryPreset.mf4bBlock0
                    elif(is_trailer_block(block)):
                        blockData = FactoryPreset.mfTrailerBlock
                    else:
                        blockData = "00" * 16
                    options = {
                        "activate_rf_field": 0,
                        "wait_response": 1,
                        "append_crc": 1,
                        "auto_select": 0,
                        "keep_rf_field": 1,
                        "check_response_crc": 0,
                    }
                    resp = self.cmd.hf14a_raw(
                        options=options,
                        resp_timeout_ms=1000,
                        data=[MifareCommand.MfWriteBlock, block],
                    )
                    options["keep_rf_field"] = 0
                    resp = self.cmd.hf14a_raw(
                        options=options,
                        resp_timeout_ms=1000,
                        data=blockData,
                    )
                    if resp.length > 0 and resp[0] == 0x00:
                        print(f"Write {blockData} to block {block}: {CG}Success{C0}")
                    else:
                        print(f"Write failed on block {block}")
            elif self.cmd.isGen4():
                print(f"{CR}Gen4 detected.{C0}")
            else:
                print(f"{CR}Try to wipe tag with keys from file{C0}")
                for block in range(block_size):
                    blockData = ""
                    if block == 0:
                        if len(resp[0]["uid"]) == 7:
                            blockData = FactoryPreset.mf7bBlock0
                        else:
                            blockData = FactoryPreset.mf4bBlock0
                    elif is_trailer_block(block):
                        blockData = FactoryPreset.mfTrailerBlock
                    else:
                        blockData = "00" * 16
                    for key in valid_keys:
                        resp = self.cmd.mf1_write_block(
                            resp[0]["uid"],
                            block,
                            bytes.fromhex(key),
                            bytes.fromhex(blockData),
                        )
                        if resp:
                            print(f"Write {blockData} to block {block} with key {key}")
                            valid_keys.insert(0, valid_keys.pop(valid_keys.index(key)))
                            break
                        else:
                            print(f"Auth Failed on block {block} with key {key}")
        else:
            print(f"{CR}Not MiFare Classic{C0}")

@hf_mf.command("restore")
class HfMfRestore(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.formatter_class = argparse.RawDescriptionHelpFormatter
        parser.description = "Restore Mifare Classic card from dump file"
        parser.add_argument(
            "-f",
            metavar="<file>",
            type=str,
            required=False,
            help="Mifare dump file (mfd or bin)",
        )
        parser.add_argument(
            "-g",
            type=int,
            metavar="<dec>",
            required=False,
            default=0,
            help="Generation: 0 => Normal (Default), 1 => Gen1A, 2 => Gen2, 3 => Gen3, 4 => Gen4",
        )
        return parser

    def sak_info(self, data_tag):
        int_sak = data_tag["sak"][0]
        if int_sak in type_id_SAK_dict:
            print(f"- Guessed type(s) from SAK: {type_id_SAK_dict[int_sak]}")

    def on_exec(self, args: argparse.Namespace):
        if not args.f:
            print("usage: hf mf restore [-h] -f <file> [-g <dec>]")
            print("hf mf restore: error: the following arguments are required: -f")
            return
        dump_data = {}
        if args.f.endswith('.mfd'):
            with open(args.f, 'r') as f:
                for line in f:
                    if ':' in line:
                        block_num, data = line.strip().split(':')
                        dump_data[int(block_num)] = data.strip()
        elif args.f.endswith('.bin'):
            with open(args.f, 'rb') as f:
                data = f.read()
                if len(data) != 1024:  # 1KB
                    print(f"{CR}Error: Bin file must be 1KB{C0}")
                    return
                for i in range(64):  # 64 blocks
                    dump_data[i] = data[i*16:(i+1)*16].hex()
        else:
            print(f"{CR}Error: Unsupported file format{C0}")
            return

        # 扫描卡片
        resp = self.cmd.hf_14a_scan()
        if resp is None:
            print("No tag found")
            return

        self.sak_info(resp[0])
        uid = resp[0]["uid"]

        gen = args.g
        if gen == 1:  # Gen1A
            if not self.cmd.isGen1a():
                print(f"{CR}Tag is not Gen1A{C0}")
                return
            print("Found Gen1A:", f"{uid.hex().upper()}")
            for block, block_data in dump_data.items():
                options = {
                    "activate_rf_field": 0,
                    "wait_response": 1,
                    "append_crc": 1,
                    "auto_select": 0,
                    "keep_rf_field": 1,
                    "check_response_crc": 0,
                }
                resp = self.cmd.hf14a_raw(
                    options=options,
                    resp_timeout_ms=1000,
                    data=[MifareCommand.MfWriteBlock, block],
                )
                blk_bytes = bytes.fromhex(block_data)
                print(f"Writing block {block}: {blk_bytes.hex().upper()}")
                options["keep_rf_field"] = 0
                resp = self.cmd.hf14a_raw(
                    options=options,
                    resp_timeout_ms=1000,
                    data=blk_bytes,
                )
                if resp and len(resp) > 0 and resp[0] == 0x00:
                    print(f"Write {block_data} to block {block}: {CG}Success{C0}")
                else:
                    print(f"Write failed on block {block}")
        elif gen == 2:  # Gen2
            for block, block_data in dump_data.items():
                resp = self.cmd.mf1_write_block(
                    uid,
                    block,
                    bytes.fromhex("ffffffffffff"),
                    bytes.fromhex(block_data),
                )
                if resp:
                    print(f"Write block {block}: {CG}Success{C0}")
                else:
                    print(f"Write block {block}: {CR}Failed{C0}")

        elif gen == 3:  # Gen3
            if not self.cmd.isGen3():
                print(f"{CR}Tag is not Gen3{C0}")
                return
            print("Found Gen3 Tag")
            # Set UID
            resp1 = self.cmd.setGen3Uid(uid)
            print(f"Set UID to {uid.hex().upper()}: {CG}Success{C0}" if resp1 else f"Set UID to {uid.hex().upper()}: {CR}Failed{C0}")
            # Set Block0
            resp2 = self.cmd.setGen3Block0(bytes.fromhex(dump_data[0]))
            print(f"Set block0: {CG}Success{C0}" if resp2 else f"Set block0: {CR}Failed{C0}")
            # Write other blocks
            for block, block_data in dump_data.items():
                if block == 0:
                    continue
                resp = self.cmd.mf1_write_block(
                    uid,
                    block,
                    bytes.fromhex("ffffffffffff"),
                    bytes.fromhex(block_data),
                )
                if resp:
                    print(f"Write block {block}: {CG}Success{C0}")
                else:
                    print(f"Write block {block}: {CR}Failed{C0}")

        elif gen == 4:  # Gen4
            if not self.cmd.isGen4("00000000"):
                print(f"{CR}Tag is not Gen4{C0}")
                return
            print("Found Gen4:", f"{uid.hex().upper()}")
            for block, block_data in dump_data.items():
                options = {
                    "activate_rf_field": 0,
                    "wait_response": 1,
                    "append_crc": 1,
                    "auto_select": 0,
                    "keep_rf_field": 1,
                    "check_response_crc": 0,
                }
                resp = self.cmd.hf14a_raw(
                    options=options,
                    resp_timeout_ms=1000,
                    data=bytes.fromhex(f"CF00000000CD{block:02x}{block_data}"),
                )
                if resp and len(resp) > 0 and resp[0] == 0x00:
                    print(f"Write block {block}: {CG}Success{C0}")
                else:
                    print(f"Write block {block}: {CR}Failed{C0}")

        else:  # Normal card
            for block, block_data in dump_data.items():
                if block == 0:
                    print(f"{CR}Skip Block 0.{C0}")
                    continue
                resp = self.cmd.mf1_write_block(
                    uid,
                    block,
                    bytes.fromhex("ffffffffffff"),
                    bytes.fromhex(block_data),
                )
                if resp:
                    print(f"Write block {block}: {CG}Success{C0}")
                else:
                    print(f"Write block {block}: {CR}Failed{C0}")

@hf_mf.command("eSetUid")
class HfMfESetUid(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Set 4 bytes or 7 bytes UID of PN532Killer Mifare 1K emulator"
        parser.add_argument(
            "-s", "--slot", default=1, type=int, help="Emulator slot(1-8)"
        )
        parser.add_argument(
            "-u",
            type=str,
            metavar="<hex>",
            required=False,
            help="UID to set (4 or 7 bytes)",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.u is None:
            print("usage: hf mf eSetUid [-h] -u <hex>")
            print("hf mf eSetUid: error: the following arguments are required: -u")
            return
        uid = bytes.fromhex(args.u)
        if len(uid) not in [4, 7]:
            print("UID length must be 4 or 7 bytes")
            return
        self.cmd.hf_mf_esetuid(args.slot - 1, uid)
        print(f"Set Slot {args.slot} UID to {args.u} {CY}Success{C0}")

@hf_mf.command("eLoad")
class HfMfEload(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.formatter_class = argparse.RawDescriptionHelpFormatter
        parser.description = "Load Mifare Classic Dump to PN532Killer Slot"
        parser.add_argument(
            "-s", "--slot", default=1, type=int, help="Emulator slot(1-8)"
        )
        parser.add_argument(
            "--bin",
            type=str,
            required=False,
            help="MF 1k bin dump file",
        )
        parser.add_argument(
            "--json",
            type=str,
            required=False,
            help="MF 1k json dump file",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        if not args.bin and not args.json:
            print("Please choose either bin file or json file")
            return
        dump_map = {}
        if args.bin:
            #   read bytes from bin, each block 16 bytes, map like "0":"11223344556677889900AABBCCDDEEFF"
            with open(args.bin, "rb") as bin_file:
                block_index = 0
                while True:
                    block = bin_file.read(16)
                    if not block:
                        break
                    dump_map[str(block_index)] = block.hex().upper()
                    block_index += 1
        elif args.json:
            with open(args.json, "r") as json_file:
                file_dump = json.load(json_file)
                if "blocks" in file_dump:
                    dump_map = file_dump["blocks"]

        # if dump_map key count is not 64, return
        if len(dump_map) != 64:
            print("Invalid dump file")
            return
        for block_index, block_data in dump_map.items():
            if not is_hex(block_data, 32):
                print(f"Invalid block {block_index}")
                return
        self.cmd.hf_mf_load(dump_map, args.slot)


@hf_mfu.command("rdbl")
class HfMfuRdbl(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Read Mifare Ultralight block"
        parser.add_argument(
            "-b", "--blk",
            dest="blk",
            type=int,
            metavar="<dec>",
            required=False,
            default=0,
            help="Block to read (default 0)",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        block = args.blk
        resp = self.cmd.hf_14a_scan()
        if resp is None or len(resp) == 0:
            print("No tag found")
            return
        resp = self.cmd.mf0_read_one_block(block)

        if resp is not None:
            if resp.parsed is not None:
                # if length of parsed data is 16, only 4 bytes
                if len(resp.parsed) == 16:
                    first_block_data = resp.parsed[:4]
                    decode_str = ""
                    for j in range(4):
                        byte = int(first_block_data[j:j + 1].hex(), 16)
                        if 32 <= byte <= 126:
                            decode_str += chr(byte)
                        else:
                            decode_str += " "
                    print(f"{block:>2}: {first_block_data.hex().upper()}    |    {decode_str}")
            else:
                print(f"Block {block} Failed to read")

@hf_mfu.command("wrbl")
class HfMfuWrbl(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Write Mifare Ultralight block (blocks 0-2 are blocked to avoid soft-brick)"
        parser.add_argument(
            "-b", "--blk",
            dest="blk",
            type=int,
            metavar="<dec>",
            required=True,
            help="Block to write",
        )
        parser.add_argument(
            "-d",
            type=str,
            metavar="<hex>",
            required=True,
            help="Data to write (4 bytes)",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        block = args.blk
        data = args.d
        if not re.match(r"^[a-fA-F0-9]{8}$", data):
            print("Data must be 4 bytes hex")
            return
        if block in (0, 1, 2):
            print(f"{CR}Blocked single write to reserved page {block} (0/1/2): this would corrupt the BCC and can soft-brick the tag; recovery may require specialized tools.{C0}")
            print(f"{CY}Recommendation: only update the first 3 pages as a whole using the proper procedure/device, and only if you fully understand the process.{C0}")
            return
        resp = self.cmd.hf_14a_scan()
        if resp is None or len(resp) == 0:
            print("No tag found")
            return
        resp = self.cmd.mf0_write_one_block(block, bytes.fromhex(data))
        if resp:
            print(f"Write block {block} with data {data}: {CG}Success{C0}")
        else:
            print(f"Write block {block} with data {data}: {CR}Failed{C0}")

@hf_mfu.command("dump")
class HfMfuDump(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Dump Mifare Ultralight card"
        parser.add_argument(
            "--file", action="store_true", help="Save to json file"
        )
        parser.add_argument(
            "--bin", action="store_true", help="Save to bin file"
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        start_time = time.perf_counter()
        resp = self.cmd.hf_14a_scan()
        if resp is None or len(resp) == 0:
            print("No tag found")
            return

        uid = resp[0]["uid"]
        print(f" UID: {uid.hex().upper()}")
        print(f" ATQA: {resp[0]['atqa'].hex().upper()}")
        print(f" SAK: {resp[0]['sak'].hex().upper()}")

        dump_map = {}
        max_block = 4
        block = 0
        while block < max_block:
            resp = self.cmd.mf0_read_one_block(block)
            if block == 0 and resp and resp.parsed and len(resp.parsed) == 16:
                max_block = resp.parsed[14] * 2 + 9
                print(f" Max block: {max_block}\n")
            if resp and resp.parsed and len(resp.parsed) == 16:
                for i in range(4):
                    block_index = block + i
                    dump_map[block_index] = resp.parsed[i * 4 : i * 4 + 4].hex().upper()
                    if block_index == 0:
                        print(
                            f"{block_index:>2}: {CR}{dump_map[block_index][:6]}{CY}{dump_map[block_index][6:]}{C0}"
                        )
                    elif block_index == 1:
                        print(f"{block_index:>2}: {CR}{dump_map[block_index]}{C0}")
                    elif block_index == 2:
                        print(
                            f"{block_index:>2}: {CY}{dump_map[block_index][:2]}{C0}{dump_map[block_index][2:]}{C0}"
                        )
                    elif block_index == 3:
                        print(
                            f"{block_index:>2}: {C0}{dump_map[block_index][:4]}{CM}{dump_map[block_index][4:6]}{C0}{dump_map[block_index][6:]}{C0}"
                        )
                    elif block_index == max_block + 1 or block_index == max_block + 2:
                        print(
                            f"{block_index:>2}: {CR}{dump_map[block_index]}{C0}"
                        )
                    else:
                        decode_str = ""
                        for j in range(4):
                            byte = int(dump_map[block_index][j * 2 : j * 2 + 2], 16)
                            if 32 <= byte <= 126:
                                decode_str += chr(byte)
                            else:
                                decode_str += " "
                        print(f"{block_index:>2}: {dump_map[block + i]}    |    {decode_str}")                        
            else:
                print(f"Block {block} Failed to read")
            block += 4

        elapsed = time.perf_counter() - start_time
        print(f"Read time: {elapsed:.2f}s")

@hf_14a.command("gen4pwd")
class Hf14aGen4Pwd(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Brute force Gen4 password"
        parser.add_argument(
            "--start",
            type=str,
            metavar="<hex>",
            default="00000000",
            help="Start password (8 bytes)",
        )
        return parser
    
    def on_exec(self, args: argparse.Namespace):
        resp = self.cmd.hf_14a_scan()
        options = {
                "activate_rf_field": 0,
                "wait_response": 1,
                "append_crc": 1,
                "auto_select": 1,
                "keep_rf_field": 1,
                "check_response_crc": 0,
            }
        
        password = bytes.fromhex(args.start)
        start_time = time.time()
        for i in range(16**8):
            resp = self.cmd.hf14a_raw(
            options=options,
            resp_timeout_ms=1000,
            data=bytes.fromhex(f"CF{password.hex()}C6"),
            )
            elapsed_time = time.time() - start_time
            speed = (i + 1) / elapsed_time
            print(f"\rTrying password: {password.hex().upper()} | Speed: {speed:.2f} pwd/s", end="")
            if len(resp) >= 30 and resp[0] == 0x00:
                print(f"\nFound password: {password.hex().upper()}")
                print(f"Elapsed time: {elapsed_time:.2f} seconds")
                break
            
            password = (int.from_bytes(password, 'big') + 1).to_bytes(4, 'big')
        else:
            print("\nPassword not found")
             
@hf_mfu.command("setuid")
class HfMfuSetUid(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Set UID of DirectWrite Mifare Ultralight Tag"
        parser.add_argument(
            "-u",
            type=str,
            metavar="<hex>",
            help="UID to set (7 bytes)",
        )
        # add example
        parser.epilog = (
            parser.epilog
        ) = """
examples:
    hf mfu setuid -u 11223344556677
"""
        return parser

    # UID0 ^ UID1 ^ UID2 ^ 0x88
    def get_bcc0(self, uid):
        bcc0 = uid[0] ^ uid[1] ^ uid[2] ^ 0x88
        return bcc0

    def get_bcc1(self, uid):
        bcc1 = uid[3] ^ uid[4] ^ uid[5] ^ uid[6]
        return bcc1

    def get_first3_pages(self, uid):
        bcc0 = self.get_bcc0(uid)
        bcc1 = self.get_bcc1(uid)
        pages = []
        pages.append(uid[0:3] + bytes([bcc0]))
        pages.append(uid[3:7])
        pages.append(bytes([bcc1]) + bytes([0x00, 0x00, 0x00]))
        return pages

    def on_exec(self, args: argparse.Namespace):
        if args.u is None or not re.match(r"^[a-fA-F0-9]{14}$", args.u):
            print("UID must be 7 bytes hex")
            return
        uid = args.u
        uid = bytes.fromhex(uid)
        pages = self.get_first3_pages(uid)
        resp = self.cmd.hf_14a_scan()
        if resp == None:
            print("No tag found")
        if  resp[0]["sak"] != bytes([0x00]):
            print("Not Ultralight tag")
            return
        print(f"Original UID: {CG}{resp[0]['uid'].hex().upper()}{C0}")
        resp = self.cmd.mf0_read_one_block(0)
        if resp is not None:
            if resp.parsed is not None:
                page2 = bytearray(pages[2])
                page2[1] = resp.parsed[9]
                pages[2] = bytes(page2)

                for i in range(3):
                    self.cmd.mf0_write_one_block(i, pages[i])
                print(f"Updated  UID: {CG}{uid.hex().upper()}{C0}")
            else:
                print("Failed to read original Block0")