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
from multiprocessing import Pool, cpu_count
from typing import Union
from pathlib import Path
from platform import uname
from datetime import datetime
from pn532_enum import MfcKeyType, MifareClassicPrngType, Command

from pn532_utils import CLITree

from pn532_utils import ArgumentParserNoExit, ArgsParserError, CR, C0, CY


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
hf = root.subgroup("hf", "High-frequency commands")
hf_14a = hf.subgroup("14a", "ISO 14443-A commands")
hf_mf = hf.subgroup("mf", "MIFARE Classic commands")

hf_14b = hf.subgroup("14b", "ISO 14443-B commands")
hf_15 = hf.subgroup("15", "ISO 15693 commands")

lf = root.subgroup("lf", "Low Frequency commands")
lf_em = lf.subgroup("em", "EM commands")
lf_em_410x = lf_em.subgroup("410x", "EM410x commands")


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
        """
            Call a function before exec cmd.

        :return: function references
        """
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
            return True
        else:
            print("Please connect to pn532 device first(use 'hw connect').")
            return False


class ReaderRequiredUnit(DeviceRequiredUnit):
    """
    Make sure of device enter to reader mode.
    """

    def before_exec(self, args: argparse.Namespace):
        if super().before_exec(args):
            ret = self.cmd.is_device_reader_mode()
            if ret:
                return True
            else:
                self.cmd.set_device_reader_mode(True)
                print("Switch to {  Tag Reader  } mode successfully.")
                return True
        return False


class MF1SetUidArgsUnit(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.add_argument("-u", type=str, required=True, help="UID to set")
        return parser

    def get_param(self, args):
        uid = args.uid
        if len(uid) != 14 or len(uid) != 8:
            raise ArgsParserError("UID must be 4 or 7 bytes long")
        return uid

class MF1AuthArgsUnit(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.add_argument(
            "--blk",
            "--block",
            type=int,
            required=True,
            metavar="<dec>",
            help="The block where the key of the card is known",
        )
        type_group = parser.add_mutually_exclusive_group()
        type_group.add_argument(
            "-a", "-A", action="store_true", help="Known key is A key (default)"
        )
        type_group.add_argument(
            "-b", "-B", action="store_true", help="Known key is B key"
        )
        parser.add_argument(
            "-k",
            "--key",
            type=str,
            required=True,
            metavar="<hex>",
            help="tag sector key",
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


@root.command("clear")
class RootClear(BaseCLIUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Clear screen"
        return parser

    def on_exec(self, args: argparse.Namespace):
        os.system("clear" if os.name == "posix" else "cls")


@hf_14a.command("scan")
class HF14AScan(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Scan 14a tag, and print basic information"
        return parser

    def check_mf1_nt(self):
        # detect mf1 support
        if self.cmd.mf1_detect_support():
            # detect prng
            print("- Mifare Classic technology")
            prng_type = self.cmd.mf1_detect_prng()
            print(f"  # Prng: {MifareClassicPrngType(prng_type)}")

    def sak_info(self, data_tag):
        # detect the technology in use based on SAK
        int_sak = data_tag["sak"][0]
        if int_sak in type_id_SAK_dict:
            print(f"- Guessed type(s) from SAK: {type_id_SAK_dict[int_sak]}")

    def scan(self, deep=False):
        resp = self.cmd.hf14a_scan()
        if resp is not None:
            for data_tag in resp:
                print(f"- UID  : {data_tag['uid'].hex().upper()}")
                print(
                    f"- ATQA : {data_tag['atqa'].hex().upper()} "
                    f"(0x{int.from_bytes(data_tag['atqa'], byteorder='little'):04x})"
                )
                print(f"- SAK  : {data_tag['sak'].hex().upper()}")
                if "ats" in data_tag and len(data_tag["ats"]) > 0:
                    print(f"- ATS  : {data_tag['ats'].hex().upper()}")
                if deep:
                    self.sak_info(data_tag)
                    # TODO: following checks cannot be done yet if multiple cards are present
                    if len(resp) == 1:
                        self.check_mf1_nt()
                        # TODO: check for ATS support on 14A3 tags
                    else:
                        print("Multiple tags detected, skipping deep tests...")
        else:
            print("ISO14443-A Tag no found")

    def on_exec(self, args: argparse.Namespace):
        self.scan()


@hf_14a.command("raw")
class HF14ARaw(ReaderRequiredUnit):
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
        parser.add_argument("-d", type=str, metavar="<hex>", help="Hex data to be sent")
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
  hf 14a raw -b 7 -d 40 -k
  hf 14a raw -d 43 -k
  hf 14a raw -d 3000 -c
  hf 14a raw -sc -d 6000
"""
        return parser

    def on_exec(self, args: argparse.Namespace):
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
                # print head
                " - "
                +
                # print data
                " ".join([hex(byte).replace("0x", "").rjust(2, "0") for byte in resp])
            )
        else:
            print(f" [*] {CY}No response{C0}")


@hf_15.command("scan")
class HF15Scan(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Scan ISO15693 tag, and print basic information"
        return parser

    def scan(self, deep=False):
        resp = self.cmd.hf15_scan()
        if resp is not None:
            for data_tag in resp:
                print(f"- UID  : {data_tag['uidHex'].upper()}")
        else:
            print("ISO15693 Tag no found")

    def on_exec(self, args: argparse.Namespace):
        self.scan()


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

        except Exception as e:
            print(f"{CR}PN532 Connect fail: {str(e)}{C0}")
            self.device_com.close()


@hw.command("version")
class HwVersion(ReaderRequiredUnit):
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


@hf_mf.command("setuid")
class HfMfSetUid(ReaderRequiredUnit):
    # def before_exec(self, args: argparse.Namespace):
    #     return True

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.formatter_class = argparse.RawDescriptionHelpFormatter
        parser.description = "Set UID of a Magic Mifare Classic with a specific UID or block0.\nSupports on Gen1A, Gen2, Gen3 and Gen4."
        parser.add_argument(
            "-u",
            type=str,
            metavar="<hex>",
            required=False,
            help="UID to set (Default 11223344)",
            default="11223344",
        )
        # add block data, 16 bytes
        parser.add_argument("-b", metavar="<hex>", type=str, required=False, help="Block 0 (16 bytes)")
        parser.add_argument(
            "-g",
            type=int,
            metavar="<dec>",
            required=False,
            help="Generation: 1 => Gen1A (Default), 2 => cuid, 3 => Gen3, 4 => Gen4",
            default=1,
        )
        parser.add_argument(
            "-p",
            type=str,
            metavar="<hex>",
            required=False,
            help="Gen4 Password (Default 00000000)",
        )
        parser.epilog = (
            parser.epilog
        ) = """
examples:
  hf mf setuid -u 11223344
  hf mf setuid -u 11223344 -g 2
  hf mf setuid -block0 1122334444080400aabbccddeeff1122 -g 3
  hf mf setuid -block0 1122334444080400aabbccddeeff1122 -g 4 --pwd 00000000
"""
        return parser

    def str_to_bytes(self, data):
        try:
            data = data.replace(" ", "")
            return bytes.fromhex(data)
        except ValueError:
            raise ValueError("Not valid hex")

    def is_hex(self, hex_string):
        return all(c in "0123456789abcdefABCDEF" for c in hex_string)

    def get_block0(self, args):
        sak = 0x08
        atqa = 0x0400
        factory_info = 0xaabbccddeeff0011
        uid = self.str_to_bytes(args.u)
        block0 = args.b
        if(block0 == None):
            if len(uid) != 4 and len(uid) != 7:
                print(f"{CR}UID needs to be 4 bytes or 7 bytes{C0}")
                return
            bcc = 0
            if len(uid) == 4:
                bcc = uid[0] ^ uid[1] ^ uid[2] ^ uid[3]
            uid_hex = ''.join(format(x, '02x') for x in uid)
            block0 = f"{uid_hex}{format(bcc, '02x')}{format(sak, '02x')}{format(atqa, '04x')}{format(factory_info, '016x')}"
        else:
            if self.is_hex(block0) == False:
                print(f"{CR}Block0 needs to be hex{C0}")
                return
            if len(block0) != 32:
                print(f"{CR}Block0 needs to be 16 bytes{C0}")
                return

            uid = self.str_to_bytes(block0[0:8])
            bcc = 0
            bcc = uid[0] ^ uid[1] ^ uid[2] ^ uid[3]
            # check if bcc is valid on the block0
            if  block0[8:10] != format(bcc, '02x'):
                print(f"{CR}Invalid BCC{C0}")
                return
        return self.str_to_bytes(block0)

    def gen1a_set_block0(self, block0: bytes):
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
        options = {
            "activate_rf_field": 1,
            "wait_response": 1,
            "append_crc": 0,
            "auto_select": 0,
            "keep_rf_field": 1,
            "check_response_crc": 0,
        }

        if(self.cmd.isGen1a()):
            print("Found Gen1A:", f"{tag_info['uid'].upper()}")
            options = {
                "activate_rf_field": 1,
                "wait_response": 1,
                "append_crc": 1,
                "auto_select": 0,
                "keep_rf_field": 1,
                "check_response_crc": 0,
            }
            resp = self.cmd.hf14a_raw(
                options=options,
                resp_timeout_ms=1000,
                data=[Command.MfWriteBlock, 0],
            )
            print(f"Writing block 0: {block0.hex().upper()}")
            options["keep_rf_field"] = 0
            resp = self.cmd.hf14a_raw(
                options=options,
                resp_timeout_ms=1000,
                data=block0,
            )
            if len(resp) > 0 and resp[0] == 0x0A:
                print("Write done")
            else:
                print("Write fail")
        else:
            print("Not Gen1A")

    def gen2_set_block0(self, block0: bytes):
        pass

    def gen3_set_block0(self, block0: bytes):
        pass

    def gen4_set_block0(self, block0: bytes, pwd: str):
        pass

    def on_exec(self, args: argparse.Namespace):
        block0 = self.get_block0(args)
        if block0 == None:
            return
        gen = args.g
        if gen == 1:
            self.gen1a_set_block0(block0)
        elif gen == 2:
            self.gen2_set_block0(block0)
        elif gen == 3:
            self.gen3_set_block0(block0)
        elif gen == 4:
            self.gen4_set_block0(block0, pwd = args.p)

@hf_mf.command("cview")
class HfMfCview(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "View Gen1a dump"
        # add parser arguments f for save to file, bool type
        parser.add_argument(
            "-f", "--file", action="store_true", help="Save dump to file"
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        result = self.cmd.hfmf_cview()
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
