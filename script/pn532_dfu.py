from __future__ import annotations

import time
from pathlib import Path
from typing import List, Optional

import serial

from unit.ad15_firmware_util import (
    Ad15FirmwareUtil,
    DeviceCheckInfo,
    DeviceInitInfo,
    FlashCrcInfo,
    crc16_xmodem_value,
)


class Pn532KillerDfu:
    def __init__(self, port: str, timeout: float = 2.0, verbose: bool = False):
        self.port = port
        self.timeout = timeout
        self.serial: Optional[serial.Serial] = None
        self.util = Ad15FirmwareUtil()
        self.verbose = verbose

    def open(self, dfu_mode: bool = False) -> None:
        """Open serial port.
        
        Args:
            dfu_mode: If True, open directly at 921600 baud for DFU mode.
                     If False, open at 115200 baud for normal mode.
        """
        baudrate = 921600 if dfu_mode else 115200
        self.serial = serial.Serial(
            self.port, 
            baudrate=baudrate, 
            timeout=self.timeout,
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            rtscts=False,
            dsrdtr=False,
            xonxoff=False
        )
        self.serial.dtr = False
        self.serial.rts = False

    def close(self) -> None:
        if self.serial and self.serial.is_open:
            try:
                self.serial.close()
            except Exception:
                pass
            self.serial = None

    def enter_dfu(self, verbose: bool = False) -> bool:
        if self.serial is None:
            self.open()
        assert self.serial is not None
        
        if verbose:
            print(f"[DFU] Preparing to enter DFU mode...")
        
        # Save port name
        port_name = self.serial.port
        
        # First, ensure device is reset properly
        if verbose:
            print(f"[DFU] Resetting device...")
        self.serial.dtr = False
        self.serial.rts = False
        time.sleep(0.1)
        
        # Close the serial port
        self.serial.close()
        time.sleep(0.5)
        
        if verbose:
            print(f"[DFU] Reopening port at 921600 baud...")
        
        # Reopen with DFU baudrate, initially with control lines LOW
        self.serial = serial.Serial(
            port_name, 
            baudrate=921600, 
            timeout=self.timeout,
            rtscts=False,
            dsrdtr=False
        )
        
        # Ensure lines start LOW
        self.serial.dtr = False
        self.serial.rts = False
        time.sleep(0.1)
        
        # Clear buffers
        self.serial.reset_input_buffer()
        self.serial.reset_output_buffer()
        
        # Toggle control lines to enter bootloader
        # According to Kotlin: RTS=True, DTR=True, wait, then RTS=False
        if verbose:
            print(f"[DFU] Triggering bootloader (RTS=True, DTR=True)...")
        self.serial.rts = True
        self.serial.dtr = True
        time.sleep(0.2)
        
        if verbose:
            print(f"[DFU] Releasing RTS (device should enter bootloader)...")
        self.serial.rts = False
        
        # Give device time to enter DFU mode and initialize bootloader
        time.sleep(0.5)
        
        # Clear any startup messages from bootloader
        self.serial.reset_input_buffer()
        
        if verbose:
            print(f"[DFU] Ready to communicate with bootloader")
        
        return True

    def _dfu_write(self, data: bytes, verbose: bool = False) -> bytes:
        assert self.serial is not None
        # Clear input buffer before writing
        self.serial.reset_input_buffer()
        
        if verbose:
            print(f"[TX] len={len(data)} data={data.hex()}")
        
        self.serial.write(data)
        self.serial.flush()
        
        # Wait for response with timeout
        start_time = time.time()
        timeout = self.timeout
        response = bytearray()
        first_byte_received = False
        
        if verbose:
            print(f"[RX] Waiting for response (timeout={timeout}s)...")
        
        while (time.time() - start_time) < timeout:
            if self.serial.in_waiting > 0:
                chunk = self.serial.read(self.serial.in_waiting)
                response.extend(chunk)
                if not first_byte_received:
                    first_byte_received = True
                    if verbose:
                        print(f"[RX] First byte received after {time.time() - start_time:.3f}s")
                if verbose:
                    print(f"[RX] Received {len(chunk)} bytes")
                # If we got some data, wait longer for any trailing bytes
                time.sleep(0.05)
                if self.serial.in_waiting == 0:
                    # Wait a bit more to ensure all data is received
                    time.sleep(0.05)
                    if self.serial.in_waiting == 0:
                        break
            else:
                time.sleep(0.01)
        
        if verbose:
            if len(response) > 0:
                print(f"[RX] Total: len={len(response)} data={response.hex()}")
                decoded = self.util.decode_command(response)
                print(f"[RX] Decoded: {decoded.hex()}")
            else:
                print(f"[RX] No response received (timeout)")
        
        return bytes(response)

    def dfu_reboot(self) -> None:
        cmd = self.util.make_reboot_cmd()
        try:
            self._dfu_write(cmd)
        except Exception:
            pass

    def get_device_init_info(self) -> Optional[DeviceInitInfo]:
        cmd = self.util.make_device_init_cmd(b"app_dir_head", 0)
        if self.verbose:
            print(f"[DFU] Sending device init command...")
        resp = self._dfu_write(cmd, verbose=self.verbose)
        if self.verbose:
            print(f"[DFU] Response length: {len(resp)} bytes")
        if len(resp) == 0:
            print(f"[WARN] No response from device. Check if device is in DFU mode.")
            return None
        decoded = self.util.decode_command(resp)
        return self.util.is_reply_device_init_cmd(decoded)

    def get_device_check_info(self) -> Optional[DeviceCheckInfo]:
        cmd = self.util.make_device_check_cmd(0x12345678)
        resp = self._dfu_write(cmd, verbose=self.verbose)
        decoded = self.util.decode_command(resp)
        return self.util.is_reply_device_check_cmd(decoded)

    def get_chip_crc_list(self, address: int, block_count: int, block_size: int) -> List[int]:
        crc_list = [0] * block_count
        remaining = block_count
        addr = address
        idx = 0
        while remaining > 0:
            read_count = min(remaining, self.util.JL_MAX_CRC_LIST_COUNT)
            cmd = self.util.make_flash_crc_cmd(addr, read_count * block_size, block_size)
            resp = self._dfu_write(cmd)
            decoded = self.util.decode_command(resp)
            parsed: Optional[FlashCrcInfo] = self.util.parse_flash_crc_cmd(decoded, read_count)
            if parsed is None:
                break
            for i in range(read_count):
                raw = parsed.value[i * 2 : i * 2 + 2]
                crc_list[idx + i] = int.from_bytes(raw[::-1], "big")
            addr += read_count * block_size
            idx += read_count
            remaining -= read_count
        return crc_list

    def erase_flash(self, address: int, length: int) -> bool:
        if length == 256:
            return self._do_erase_flash(address, length)
        left = length
        addr = address
        while left > 0:
            if not self._do_erase_flash(addr, 4096):
                return False
            addr += 4096
            left -= 4096
        return True

    def _do_erase_flash(self, address: int, length: int) -> bool:
        erase_type = self.util.JL_ERASE_TYPE_PAGE
        if length == 4096:
            erase_type = self.util.JL_ERASE_TYPE_SECTOR
        elif length == 64 * 1024:
            erase_type = self.util.JL_ERASE_TYPE_BLOCK
        cmd = self.util.make_erase_cmd(address, erase_type)
        resp = self._dfu_write(cmd)
        decoded = self.util.decode_command(resp)
        return self.util.is_valid_response(decoded, self.util.JL_SU_CMD_ERASE)

    def write_flash(self, buffer: bytes, address: int, length: int, erase_unit: int) -> bool:
        addr = address
        buf = buffer
        left = length
        while left > 0:
            write_len = min(left, erase_unit)
            if not self._do_write_flash(buf[:write_len], addr, write_len):
                return False
            addr += write_len
            buf = buf[write_len:]
            left -= write_len
        return True

    def _do_write_flash(self, data: bytes, address: int, write_length: int) -> bool:
        cmd = self.util.make_write_cmd(address, write_length, data)
        resp = self._dfu_write(cmd)
        decoded = self.util.decode_command(resp)
        return self.util.is_valid_response(decoded, self.util.JL_SU_CMD_WRITE)

    @staticmethod
    def get_buffer_crc_list(buffer: bytes, block_count: int, erase_unit_size: int) -> List[int]:
        result: List[int] = [0] * block_count
        for offset in range(block_count):
            start = offset * erase_unit_size
            end = start + erase_unit_size
            slice_buf = buffer[start:end]
            result[offset] = crc16_xmodem_value(slice_buf)
        return result


def load_firmware(bin_path: str) -> bytes:
    path = Path(bin_path)
    data = path.read_bytes()
    return data
