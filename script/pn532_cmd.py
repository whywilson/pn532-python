import struct
import ctypes
from typing import Union

import pn532_com
from pn532_com import Response, DEBUG
from pn532_utils import expect_response
from pn532_enum import Command, MifareCommand, Status
from pn532_enum import ButtonPressFunction, ButtonType, MifareClassicDarksideStatus
from pn532_enum import MfcKeyType, MfcValueBlockOperator
from time import sleep
from pn532_utils import CC, CB, CG, C0, CY, CR
import os
import subprocess
import argparse
import timeit
from multiprocessing import Pool, cpu_count
from typing import Union
from pathlib import Path
from platform import uname
import serial.tools.list_ports

CURRENT_VERSION_SETTINGS = 5


class Pn532CMD:
    """
    Pn532 cmd function
    """

    def __init__(self, pn532: pn532_com.Pn532Com):
        """
        :param pn532: pn532 instance, @see pn532_device.Pn532
        """
        self.device = pn532

    @expect_response(Status.SUCCESS)
    def get_app_version(self):
        """
        Get firmware version number(application)
        """
        resp = self.device.send_cmd_sync(Command.GET_APP_VERSION)
        if resp.status == Status.SUCCESS:
            resp.parsed = struct.unpack("!BB", resp.data)
        # older protocol, must upgrade!
        if resp.status == 0 and resp.data == b"\x00\x01":
            print("Pn532 does not understand new protocol. Please update firmware")
            return pn532_com.Response(
                cmd=Command.GET_APP_VERSION, status=Status.NOT_IMPLEMENTED
            )
        return resp

    @expect_response(Status.SUCCESS)
    def get_device_chip_id(self):
        """
        Get device chip id
        """
        resp = self.device.send_cmd_sync(Command.GET_DEVICE_CHIP_ID)
        if resp.status == Status.SUCCESS:
            resp.parsed = resp.data.hex()
        return resp

    @expect_response(Status.SUCCESS)
    def get_device_address(self):
        """
        Get device address
        """
        resp = self.device.send_cmd_sync(Command.GET_DEVICE_ADDRESS)
        if resp.status == Status.SUCCESS:
            resp.parsed = resp.data.hex()
        return resp

    @expect_response(Status.SUCCESS)
    def get_git_version(self):
        resp = self.device.send_cmd_sync(Command.GET_GIT_VERSION)
        if resp.status == Status.SUCCESS:
            resp.parsed = resp.data.decode("utf-8")
        return resp

    @expect_response(Status.SUCCESS)
    def get_device_mode(self):
        resp = self.device.send_cmd_sync(Command.GET_DEVICE_MODE)
        if resp.status == Status.SUCCESS:
            (resp.parsed,) = struct.unpack("!?", resp.data)
        return resp

    def is_device_reader_mode(self) -> bool:
        """
            Get device mode, reader, emulator or sniffer.

        :return: True is reader mode, else tag mode
        """
        # return self.get_device_mode()
        return True

    # Note: Will return NOT_IMPLEMENTED if one tries to set reader mode on Lite
    @expect_response(Status.SUCCESS)
    def change_device_mode(self, mode):
        data = struct.pack("!B", mode)
        return self.device.send_cmd_sync(Command.CHANGE_DEVICE_MODE, data)

    def set_device_reader_mode(self, reader_mode: bool = True):
        self.device

    @expect_response(Status.SUCCESS)
    def hf14a_scan(self):
        self.device.set_normal_mode()
        """
        14a tags in the scanning field.

        :return:
        """
        resp = self.device.send_cmd_sync(Command.InListPassiveTarget, b"\x01\x00")
        # print("response status = ", resp.status)
        if resp.status == Status.SUCCESS:
            # tagType[1]tagNum[1]atqa[2]sak[1]uidlen[1]uid[uidlen]
            offset = 0
            data = []
            while offset < len(resp.data):
                tagType = resp.data[offset]
                offset += 1
                tagNum = resp.data[offset]
                offset += 1
                atqa, sak, uidlen = struct.unpack_from("!2s1sB", resp.data, offset)
                offset += struct.calcsize("!2s1sB")
                uid = resp.data[offset : offset + uidlen]
                offset += uidlen
                data.append(
                    {
                        "tagType": tagType,
                        "tagNum": tagNum,
                        "atqa": atqa,
                        "sak": sak,
                        "uid": uid,
                    }
                )
            resp.parsed = data
        return resp

    @expect_response(Status.SUCCESS)
    def hfmf_cview(self):
        """
        View the Gen1A Tag

        :return:
        """
        self.device.set_normal_mode()

        tag_info = {}
        resp = self.hf14a_scan()
        if resp == None:
            print("No tag found")
            return resp
        # print("Tag found", resp)
        tag_info["uid"] = resp[0]["uid"].hex()
        tag_info["atqa"] = resp[0]["atqa"].hex()
        tag_info["sak"] = resp[0]["sak"].hex()
        tag_info["data"] = []
        try:
            if not self.isGen1a():
                print("Not Gen1A tag")
                raise

            options = {
                "activate_rf_field": 0,
                "wait_response": 1,
                "append_crc": 1,
                "auto_select": 0,
                "keep_rf_field": 1,
                "check_response_crc": 1,
            }
            block = 0
            block_data = {}
            while block < 64:
                if block == 63:
                    options["keep_rf_field"] = 0
                resp = self.hf14a_raw(
                    options=options,
                    resp_timeout_ms=1000,
                    data=[MifareCommand.MfReadBlock, block],
                )
                block_data[f"{block}"] = resp.hex()
                # print block index with padding 2 spaces
                # print(f"block {block:02d}: {resp.hex().upper()}")
                if block == 0:
                    print(
                        f"block {block:02d}: {CY}{resp.hex()[0:8].upper()}{CR}{resp.hex()[8:10].upper()}{CG}{resp.hex()[10:14].upper()}{C0}{resp.hex()[14:].upper()}{C0}"
                    )
                elif block % 4 == 3:
                    print(
                        f"block {block:02d}: {CG}{resp.hex()[0:12].upper()}{CR}{resp.hex()[12:20].upper()}{CG}{resp.hex()[20:].upper()}{C0}"
                    )
                else:
                    print(f"block {block:02d}: {resp.hex().upper()}")
                block += 1
            tag_info["blocks"] = block_data
        except Exception as e:
            print("Error:", e)

        resp = Response(Command.InCommunicateThru, Status.SUCCESS)
        resp.parsed = tag_info
        return resp

    @expect_response(Status.HF_TAG_OK)
    def hf14a_raw(self, options, resp_timeout_ms=100, data=[], bitlen=None) -> Response:
        """
        Send raw cmd to 14a tag.

        :param options:
        :param resp_timeout_ms:
        :param data:
        :param bit_owned_by_the_last_byte:
        :return:
        """

        class CStruct(ctypes.BigEndianStructure):
            _fields_ = [
                ("activate_rf_field", ctypes.c_uint8, 1),
                ("wait_response", ctypes.c_uint8, 1),
                ("append_crc", ctypes.c_uint8, 1),
                ("auto_select", ctypes.c_uint8, 1),
                ("keep_rf_field", ctypes.c_uint8, 1),
                ("check_response_crc", ctypes.c_uint8, 1),
                ("reserved", ctypes.c_uint8, 2),
            ]

        cs = CStruct()
        cs.activate_rf_field = options["activate_rf_field"]
        cs.wait_response = options["wait_response"]
        cs.append_crc = options["append_crc"]
        cs.auto_select = options["auto_select"]
        cs.keep_rf_field = options["keep_rf_field"]
        cs.check_response_crc = options["check_response_crc"]

        if cs.activate_rf_field:
            self.device.halt()

        if bitlen is None:
            bitlen = len(data) * 8  # bits = bytes * 8(bit)
        else:
            if len(data) == 0:
                raise ValueError(f"bitlen={bitlen} but missing data")
            if not ((len(data) - 1) * 8 < bitlen <= len(data) * 8):
                raise ValueError(
                    f"bitlen={bitlen} incompatible with provided data ({len(data)} bytes), "
                    f"must be between {((len(data) - 1) * 8 )+1} and {len(data) * 8} included"
                )

        if bitlen == 7:
            self.device.set_register([0x63, 0x3D, 0x07])
            sleep(0.1)

        if cs.append_crc:
            data = bytes(data) + self.crc16A(bytes(data))
        resp = self.device.send_cmd_sync(Command.InCommunicateThru, data, timeout=1)
        resp.parsed = resp.data
        resp.status = resp.data[0:1]
        if cs.keep_rf_field == 0:
            self.device.halt()

        if bitlen == 7:
            self.device.set_register([0x63, 0x3D, 0x00])
            sleep(0.1)

        if DEBUG:
            print(
                f"Send: {bytes(data).hex().upper()} Status: {resp.status.hex().upper()}, Data: {resp.parsed.hex().upper()}"
            )
        return resp

    def crc16A(self, data: bytes) -> bytes:
        crc = 0x6363  # Initial value for CRC-A

        for b in data:
            ch = b ^ (crc & 0xFF)
            ch = (ch ^ (ch << 4)) & 0xFF
            crc = (crc >> 8) ^ (ch << 8) ^ (ch << 3) ^ (ch >> 4)

        crc = crc & 0xFFFF
        return crc.to_bytes(2, byteorder="little")

    def isGen1a(self):
        options = {
            "activate_rf_field": 1,
            "wait_response": 1,
            "append_crc": 0,
            "auto_select": 0,
            "keep_rf_field": 1,
            "check_response_crc": 0,
        }
        # Unlock 1
        resp = self.hf14a_raw(
            options=options, resp_timeout_ms=1000, data=[0x40], bitlen=7
        )
        if DEBUG:
            print("unlock 1:", resp.hex())
        if resp[-1] == 0x0A:
            options["activate_rf_field"] = 0
            # Unlock 2
            resp = self.hf14a_raw(options=options, resp_timeout_ms=1000, data=[0x43])
            if DEBUG:
                print("unlock 2:", resp.hex())
            if resp[-1] == 0x0A:
                return True
        return False

    @expect_response(Status.SUCCESS)
    def hf15_scan(self):
        self.device.set_normal_mode()
        """
        15 tags in the scanning field.

        :return:
        """
        resp = self.device.send_cmd_sync(Command.InListPassiveTarget, b"\x01\x05")
        if resp.status == Status.SUCCESS:
            # 010188888888332211E0
            # tagType[1]tagNum[1]uid[8, reversed]
            offset = 0
            data = []
            while offset < len(resp.data):
                tagType = resp.data[offset]
                offset += 1
                tagNum = resp.data[offset]
                offset += 1
                uid = resp.data[offset : offset + 8]
                offset += 8
                # reversed uid
                uidHex = uid.hex()
                uidHex = (
                    uidHex[12:14]
                    + uidHex[10:12]
                    + uidHex[8:10]
                    + uidHex[6:8]
                    + uidHex[4:6]
                    + uidHex[2:4]
                    + uidHex[0:2]
                )
                data.append({"tagType": tagType, "tagNum": tagNum, "uid": uidHex})
            resp.parsed = data
        return resp

    def mf1_auth_one_key_block(self, block, type_value: MfcKeyType, key, uid) -> bool:
        format_str = f"!BBB6s{len(uid)}s"
        data = struct.pack(format_str, 0x01, type_value, block, key, uid)
        resp = self.device.send_cmd_sync(Command.InDataExchange, data)
        return resp.data[0] == Status.HF_TAG_OK

    def mf1_read_one_block(self, block, type_value: MfcKeyType, key):
        resp = self.hf14a_scan()
        if resp == None:
            print("No tag found")
            return resp

        auth_result = self.mf1_auth_one_key_block(
            block, type_value, key, bytes(resp[0]["uid"])
        )
        if not auth_result:
            return Response(Command.InDataExchange, Status.MF_ERR_AUTH)
        data = struct.pack("!BBB", 0x01, MifareCommand.MfReadBlock, block)
        resp = self.device.send_cmd_sync(Command.InDataExchange, data)
        if len(resp.data) >= 16 and resp.data[0] == Status.HF_TAG_OK:
            resp.parsed = resp.data[1:]
            if self.is_mf_trailler_block(block):
                if type_value == MfcKeyType.A:
                    resp.parsed = key + resp.parsed[6:]
                else:
                    resp.parsed = resp.parsed[0:10] + key
        return resp

    def is_mf_trailler_block(self, block) -> bool:
        return block % 4 == 3

    @expect_response(Status.HF_TAG_OK)
    def mf1_write_one_block(self, block, type_value: MfcKeyType, key, block_data):
        resp = self.hf14a_scan()
        if resp == None:
            print("No tag found")
            return resp

        auth_result = self.mf1_auth_one_key_block(
            block, type_value, key, bytes(resp[0]["uid"])
        )
        if not auth_result:
            return Response(Command.InDataExchange, Status.HF_TAG_NO)
        data = struct.pack(
            "!BBB16s", 0x01, MifareCommand.MfWriteBlock, block, block_data
        )
        resp = self.device.send_cmd_sync(Command.InDataExchange, data)
        resp.parsed = resp.data[0] == Status.HF_TAG_OK
        return resp

    @expect_response([Status.HF_TAG_OK, Status.HF_TAG_NO])
    def mf1_check_keys_of_sectors(self, mask: bytes, keys: list[bytes]):
        """
        Check keys of sectors.
        :return:
        """
        if len(mask) != 10:
            raise ValueError("len(mask) should be 10")
        if len(keys) < 1 or len(keys) > 83:
            raise ValueError("Invalid len(keys)")
        data = struct.pack(f"!10s{6*len(keys)}s", mask, b"".join(keys))

        bitsCnt = 80  # maximum sectorKey_to_be_checked
        for b in mask:
            while b > 0:
                [bitsCnt, b] = [bitsCnt - (b & 0b1), b >> 1]
        if bitsCnt < 1:
            # All sectorKey is masked
            return pn532_com.Response(
                cmd=Command.MF1_CHECK_KEYS_OF_SECTORS,
                status=Status.HF_TAG_OK,
                parsed={"status": Status.HF_TAG_OK},
            )
        # base timeout: 1s
        # auth: len(keys) * sectorKey_to_be_checked * 0.1s
        # read keyB from trailer block: 0.1s
        timeout = 1 + (bitsCnt + 1) * len(keys) * 0.1

        resp = self.device.send_cmd_sync(
            Command.MF1_CHECK_KEYS_OF_SECTORS, data, timeout=timeout
        )
        resp.parsed = {"status": resp.status}
        if len(resp.data) == 490:
            found = "".join([format(i, "08b") for i in resp.data[0:10]])
            # print(f'{found = }')
            resp.parsed.update(
                {
                    "found": resp.data[0:10],
                    "sectorKeys": {
                        k: resp.data[6 * k + 10 : 6 * k + 16]
                        for k, v in enumerate(found)
                        if v == "1"
                    },
                }
            )
        return resp

    @expect_response(Status.SUCCESS)
    def get_firmware_version(self):
        """
        Get firmware version
        """
        resp = self.device.send_cmd_sync(
            Command.GetFirmwareVersion, None, Status.SUCCESS, 1
        )
        resp.parsed = f"Ver.{resp.data.hex()}"
        return resp


def test_fn():
    # connect to pn532
    dev = pn532_com.Pn532Com()
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
                dev.open(_comport.replace("COM", "/dev/ttyS"))
    else:
        # loop through all ports and find pn532
        for port in serial.tools.list_ports.comports():
            if port.vid == 6790:
                dev.open(port.device)
                break
            if "PN532Killer" in port.description:
                dev.open(port.device)
                break
    print(f"Connected to {dev.serial_instance.port}")
    print(f"Device: {dev.device_name}")
    cml = Pn532CMD(dev)

    try:
        block = 3
        key_str = "A0A1A2A3A4A5"
        resp = cml.mf1_read_one_block(block, MfcKeyType.A, bytes.fromhex(key_str))
        if resp is not None:
            print(f"Block {block}: {resp.parsed.hex().upper()}")
    except Exception as e:
        print("Error:", e)
    dev.close()


if __name__ == "__main__":
    test_fn()
