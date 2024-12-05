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
from unit.calc import str_to_bytes
from unit.calc import is_hex
from unit.preset import FactoryPreset
from unit.mifare_classic import get_block_size_by_sector, get_block_index_by_sector, is_trailer_block
from multiprocessing import Pool, cpu_count
from typing import Union
from pathlib import Path
from platform import uname
from datetime import datetime
from pn532_enum import MfcKeyType, MifareCommand

from pn532_utils import CLITree

from pn532_utils import ArgumentParserNoExit, ArgsParserError, CG, CR, C0, CY


import pn532_com
import pn532_cmd

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

default_cwd = Path.cwd() / Path(__file__).with_name("bin")


def check_tools():
    tools = ["staticnested", "nested", "darkside", "mfkey32v2"]
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
hw_mode = hw.subgroup("mode", "Mode-related commands")
hf = root.subgroup("hf", "High-frequency commands")
hf_14a = hf.subgroup("14a", "ISO 14443-A commands")
hf_mf = hf.subgroup("mf", "MIFARE Classic commands")
hf_sniff = hf.subgroup("sniff", "Sniffer commands")

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
        if ret:
            if not self.device_com.is_support_cmd(self.__class__.__name__):
                print(
                    f"{CR}{self.__class__.__name__} not support by {self.device_com.get_device_name()}{C0}"
                )
                return False
            return True
        else:
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


@hw_mode.command("r")
class HWModeReader(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Set device to reader mode"
        return parser

    def on_exec(self, args: argparse.Namespace):
        self.device_com.set_work_mode()
        print("Switch to {  Tag Reader  } mode successfully.")


@hw_mode.command("e")
class HWModeEmulator(DeviceRequiredUnit):
    # support -type m14b1k, 15693, em4100 and -slot 1-8
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Set device to emulator mode"
        parser.add_argument(
            "-t",
            "--type",
            default=1,
            type=int,
            required=False,
            help="1 - 4B1K, 3 - 15693, 4 - EM4100",
        )
        parser.add_argument(
            "-s", "--slot", default=1, type=int, help="Emulator slot(1-8)"
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        type = args.type
        slot = args.slot
        self.device_com.set_work_mode(2, type, slot - 1)
        print("Switch to {  Emulator  } mode successfully.")


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
        self.device_com.set_work_mode(3, 1, args.type)
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
        resp = self.cmd.hf14a_scan()
        if resp is not None:
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
            print("ISO14443-A Tag no found")

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


@hf_15.command("esetuid")
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
            print("usage: hf 15 esetuid [-h] -u <hex> [-s SLOT]")
            print("hf 15 esetuid: error: the following arguments are required: -u")
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


@hf_15.command("esetblock")
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
        parser.description = "Connect to pn532 by serial port"
        parser.add_argument("-p", "--port", type=str, required=False)
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
                    return
                # print connecting to device name
            print(f"Connecting to device on port {args.port}")
            self.device_com.open(args.port)
            print("Device:", self.device_com.get_device_name())
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


@hf_sniff.command("setuid")
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


@hf_mf.command("eload")
class HfMfEload(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.formatter_class = argparse.RawDescriptionHelpFormatter
        parser.description = "Load Mifare Dump to PN532Killer Slot"
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


@hf_mf.command("eread")
class HfMfEread(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Get Mifare Classic dump from PN532Killer Slot"
        parser.add_argument(
            "-s", "--slot", default=1, type=int, help="Emulator slot(1-8)"
        )
        parser.add_argument("--file", action="store_true", help="Save to json file")
        parser.add_argument("--bin", action="store_true", help="Save to bin file")
        return parser

    def on_exec(self, args: argparse.Namespace):
        self.device_com.set_work_mode(2, 0x01, args.slot - 1)
        dump_map = self.cmd.hf_mf_eread(args.slot)
        # {"0": "11223344556677889900AABBCCDDEEFF", "1": "11223344556677889900AABBCCDDEEFF", ...}
        if not dump_map:
            print("Get dump failed")
            return
        file_name = "mf_dump_{args.slot}"
        file_index = 0
        if args.file:
            while True:
                if os.path.exists(f"{file_name}_{file_index}.json"):
                    file_index += 1
                else:
                    file_name = f"{file_name}_{file_index}.json"
                    break
            with open(file_name, "w") as json_file:
                json.dump({"blocks": dump_map}, json_file)
        if args.bin:
            while True:
                if os.path.exists(f"{file_name}_{file_index}.bin"):
                    file_index += 1
                else:
                    file_name = f"{file_name}_{file_index}.bin"
                    break
            with open(file_name, "wb") as bin_file:
                for block_index, block_data in dump_map.items():
                    bin_file.write(bytes.fromhex(block_data))


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
  hf mf setuid --blk0 1122334444080400aabbccddeeff1122 -g 3
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

            uid = str_to_bytes(block0[0:8])
            bcc = 0
            bcc = uid[0] ^ uid[1] ^ uid[2] ^ uid[3]
            # check if bcc is valid on the block0
            if block0[8:10] != format(bcc, "02x"):
                print(f"{CR}Invalid BCC{C0}")
                return
        return str_to_bytes(block0)

    def gen1a_set_block0(self, block0: bytes):
        tag_info = {}
        resp = self.cmd.hf14a_scan()
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
        resp = self.cmd.hf14a_scan()
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
        selectTag = self.cmd.selectTag()
        if not selectTag:
            print(f"{CR}Select tag failed{C0}")
            return
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
        resp = self.cmd.hf14a_scan()
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
        resp = self.cmd.hf14a_scan()
        if resp == None:
            print("No tag found")
            return resp
        uid = resp[0]["uid"]
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
        resp = self.cmd.hf14a_scan()
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
        resp = self.cmd.hf14a_scan()
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

@lf.command("scan")
class LfScan(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Scan LF tag, and print basic information"
        return parser

    def on_exec(self, args: argparse.Namespace):
        resp = self.cmd.lf_scan()
        if resp is not None:
            for data_tag in resp:
                if "dec" in data_tag:
                    print(f"- ID  : {data_tag['id'].upper()}")
                    print(f"  DEC : {data_tag['dec']}")
        else:
            print("LF Tag no found")


@lf_em_410x.command("esetid")
class LfEm410xESetId(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Set ID of EM410x Emulation"
        parser.add_argument(
            "-i",
            type=str,
            metavar="<hex>",
            required=False,
            help="ID to set (10 bytes)",
        )
        parser.add_argument(
            "-s", "--slot", default=1, type=int, help="Emulator slot(1-8)"
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.i is None:
            print("usage: lf em410x esetid [-h] -i <hex> [-s SLOT]")
            print("lf em410x esetid: error: the following arguments are required: -i")
            return
        id = args.i
        if not re.match(r"^[a-fA-F0-9]{20}$", id):
            print("ID must be 10 bytes hex")
            return
        resp = self.cmd.lf_em4100_eset_id(args.slot - 1, bytes.fromhex(id))
        print(
            f"Set Slot {args.slot} ID to {id} {CY}{'Success' if resp else 'Fail'}{C0}"
        )


@ntag.command("emulate")
class NtagEmulate(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Start NTAG emulating"
        parser.add_argument(
            "--uri",
            type=str,
            required=False,
            help="URI to emulate",
            default="https://pn532killer.com",
        )
        parser.epilog = (
            parser.epilog
        ) = """
examples:
    ntag emulate --uri https://pn532killer.com
"""

        return parser

    def on_exec(self, args: argparse.Namespace):
        self.device_com.set_normal_mode()
        self.cmd.ntag_emulator(url=args.uri)
