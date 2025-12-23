from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


ENC_KEY = 50205320
ENC_KEY_BYTES_REV = ENC_KEY.to_bytes(4, byteorder="big", signed=False)[::-1]


@dataclass
class DeviceInitInfo:
    status: int
    zone_addr: int
    upgrade_len: int
    flash_eoffset_size: int
    erase_unit_size: int


@dataclass
class DeviceCheckInfo:
    vid: int
    pid: int
    sdk_id: int


@dataclass
class FlashCrcInfo:
    status: int
    value: bytes


def to_positive_int(b: int) -> int:
    return b & 0xFF


def crc16_xmodem(data: bytes) -> bytes:
    crc = 0x0000
    poly = 0x1021
    for byte in data:
        for i in range(8):
            bit = ((byte << i) & 0x80) != 0
            c15 = (crc & 0x8000) != 0
            crc = (crc << 1) & 0xFFFF
            if c15 ^ bit:
                crc ^= poly
    return bytes([crc & 0xFF, (crc >> 8) & 0xFF])


def crc16_xmodem_value(data: bytes) -> int:
    crc = 0x0000
    poly = 0x1021
    for byte in data:
        for i in range(8):
            bit = ((byte << i) & 0x80) != 0
            c15 = (crc & 0x8000) != 0
            crc = (crc << 1) & 0xFFFF
            if c15 ^ bit:
                crc ^= poly
    return crc & 0xFFFF


class Ad15FirmwareUtil:
    JL_SU_CMD_DEVICE_INIT = 0xC0
    JL_SU_CMD_DEVICE_CHECK = 0xC1
    JL_SU_CMD_ERASE = 0xC2
    JL_SU_CMD_WRITE = 0xC3
    JL_SU_CMD_FLASH_CRC = 0xC4
    JL_SU_CMD_EX_KEY = 0xC5
    JL_SU_CMD_REBOOT = 0xCA

    JL_SU_RSP_SUCC = 0x0
    JL_SU_RSP_CRC_ERROR = 0x1
    JL_SU_RSP_SDK_ID_ERROR = 0x2
    JL_SU_RSP_OTHER_ERROR = 0x3

    JL_ERASE_TYPE_PAGE = 1
    JL_ERASE_TYPE_SECTOR = 2
    JL_ERASE_TYPE_BLOCK = 3

    JL_MAX_CRC_LIST_COUNT = 16
    JL_MAX_WRITE_SIZE = 1024

    enc_key = ENC_KEY

    def _make_command(self, opcode: int, bodies: List[bytes]) -> bytes:
        body_len = sum(len(b) for b in bodies)
        total_len = 2 + 2 + 2 + body_len + 2  # header + len + opcode/status + body + crc
        buf = bytearray(total_len)
        buf[0] = 0xAA
        buf[1] = 0x55
        body_and_status_len = body_len + 2
        buf[2] = body_and_status_len & 0xFF
        buf[3] = (body_and_status_len >> 8) & 0xFF
        buf[4] = opcode & 0xFF
        buf[5] = self.JL_SU_RSP_SUCC & 0xFF
        ptr = 6
        for part in bodies:
            end = ptr + len(part)
            buf[ptr:end] = part
            ptr = end
        # encrypt opcode/status/body in-place
        key = ENC_KEY_BYTES_REV
        for idx in range(4, total_len - 2):
            buf[idx] ^= key[idx & 0x03]
        crc = crc16_xmodem(bytes(buf[:-2]))
        buf[-2:] = crc
        return bytes(buf)

    def make_device_init_cmd(self, area: bytes, mode: int) -> bytes:
        padded = bytearray(17)
        area = area[:16]
        padded[: len(area)] = area
        padded[16] = mode & 0xFF
        return self._make_command(self.JL_SU_CMD_DEVICE_INIT, [bytes(padded)])

    def make_device_check_cmd(self, sdk_id: int) -> bytes:
        return self._make_command(self.JL_SU_CMD_DEVICE_CHECK, [sdk_id.to_bytes(4, "big")[::-1]])

    def make_erase_cmd(self, addr: int, erase_type: int) -> bytes:
        return self._make_command(
            self.JL_SU_CMD_ERASE,
            [addr.to_bytes(4, "big")[::-1], erase_type.to_bytes(4, "big")[::-1]],
        )

    def make_write_cmd(self, addr: int, length: int, data: bytes) -> bytes:
        return self._make_command(
            self.JL_SU_CMD_WRITE,
            [addr.to_bytes(4, "big")[::-1], length.to_bytes(4, "big")[::-1], data[:length]],
        )

    def make_flash_crc_cmd(self, addr: int, length: int, block_size: int) -> bytes:
        return self._make_command(
            self.JL_SU_CMD_FLASH_CRC,
            [addr.to_bytes(4, "big")[::-1], length.to_bytes(4, "big")[::-1], block_size.to_bytes(4, "big")[::-1]],
        )

    def make_reboot_cmd(self) -> bytes:
        return self._make_command(self.JL_SU_CMD_REBOOT, [])

    def is_valid_start_cmd(self, data: bytes) -> bool:
        return len(data) >= 2 and (data[0] ^ data[1]) == 0xFF

    def decode_command(self, cmd: bytes) -> bytes:
        buf = bytearray(cmd)
        key = ENC_KEY_BYTES_REV
        for idx in range(4, len(buf) - 2):
            buf[idx] ^= key[idx & 0x03]
        return bytes(buf)

    def is_valid_response(self, data: bytes, opcode: int) -> bool:
        if len(data) < 6:
            return False
        if not self.is_valid_start_cmd(data):
            return False
        return to_positive_int(data[4]) == opcode and to_positive_int(data[5]) == self.JL_SU_RSP_SUCC

    def is_reply_device_init_cmd(self, data: bytes) -> Optional[DeviceInitInfo]:
        payload = data
        if len(data) == 18 + 6:  # strip header/len/crc
            payload = data[4:-2]
        if len(payload) != 18:
            return None
        if to_positive_int(payload[0]) != self.JL_SU_CMD_DEVICE_INIT or to_positive_int(payload[1]) != self.JL_SU_RSP_SUCC:
            return None
        status = payload[1]
        upgrade_addr = int.from_bytes(payload[2:6][::-1], "big")
        upgrade_len = int.from_bytes(payload[6:10][::-1], "big")
        upgrade_eoffset = int.from_bytes(payload[10:14][::-1], "big")
        flash_alignsize = int.from_bytes(payload[14:18][::-1], "big")
        return DeviceInitInfo(status, upgrade_addr, upgrade_len, upgrade_eoffset, flash_alignsize)

    def is_reply_device_check_cmd(self, data: bytes) -> Optional[DeviceCheckInfo]:
        payload = data
        if len(data) == 26 + 6:
            payload = data[4:-2]
        if len(payload) != 26:
            return None
        if to_positive_int(payload[0]) != self.JL_SU_CMD_DEVICE_CHECK or to_positive_int(payload[1]) != self.JL_SU_RSP_SUCC:
            return None
        vid = int.from_bytes(payload[2:6][::-1], "big")
        pid = int.from_bytes(payload[6:22][::-1], "big")
        sdk_id = int.from_bytes(payload[22:26][::-1], "big")
        return DeviceCheckInfo(vid, pid, sdk_id)

    def parse_flash_crc_cmd(self, data: bytes, block_count: int) -> Optional[FlashCrcInfo]:
        if len(data) != 8 + 2 * block_count:
            return None
        if to_positive_int(data[4]) != self.JL_SU_CMD_FLASH_CRC or to_positive_int(data[5]) != self.JL_SU_RSP_SUCC:
            return None
        return FlashCrcInfo(to_positive_int(data[5]), data[6 : 6 + 2 * block_count])
