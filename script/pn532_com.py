import queue
import struct
import threading
import time
from urllib import response
import serial
from typing import Union
from pn532_enum import Command, Pn532KillerCommand, Status, PN532KillerMode, PN532KillerTagType
from pn532_enum import BasicCapabilities, PN532Capabilities, PN532KillerCapabilities
from pn532_utils import CC, CB, CG, C0, CY, CR
from pn532_communication import CommunicationInterface, CommunicationFactory

DEBUG = False 
THREAD_BLOCKING_TIMEOUT = 0.1
class NotOpenException(Exception):
    """
    PN532 err status
    """

class OpenFailException(Exception):
    """
    PN532 open fail(serial port may be error)
    """

class CMDInvalidException(Exception):
    """
    CMD invalid(Unsupported)
    """

class Pn532Com:
    data_preamble = [0x00]
    data_start_code = [0x00, 0xFF]
    data_tfi_send = 0xD4
    data_tfi_receive = 0xD5
    data_postamble = [0x00]

    commands = []

    def __init__(self):
        """
        Create a PN532 device instance
        """
        self.communication: Union[CommunicationInterface, None] = None
        self.send_data_queue = queue.Queue()
        self.wait_response_map = {}
        self.event_closing = threading.Event()

    device_name = "Unknown"
    data_max_length = 0xFF

    def set_device_name(self, device_name):
        self.device_name = device_name

    def get_device_name(self) -> str:
        return self.device_name

    def isOpen(self) -> bool:
        return self.communication is not None and self.communication.is_open()

    def open(self, port) -> "Pn532Com":
        if not self.isOpen():
            error = None
            try:
                # 创建通信接口
                self.communication = CommunicationFactory.create_communication(port)
                protocol_type, actual_address = CommunicationFactory.parse_address(port)
                
                # 打开连接
                if not self.communication.open(actual_address):
                    raise Exception(f"Failed to open {protocol_type} connection to {actual_address}")
                
                print(f"Opened {protocol_type} connection to {actual_address}")
            except Exception as e:
                error = e
            finally:
                if error is not None:
                    raise OpenFailException(error)
            
            assert self.communication is not None
            self.communication.set_timeout(THREAD_BLOCKING_TIMEOUT)
            
            # clear variable
            self.send_data_queue.queue.clear()
            self.wait_response_map.clear()
            # Start a sub thread to process data
            self.event_closing.clear()
            threading.Thread(target=self.thread_data_receive).start()
            threading.Thread(target=self.thread_data_transfer).start()
            threading.Thread(target=self.thread_check_timeout).start()
            
            self.set_normal_mode()
            time.sleep(0.01)
            is_pn532killer = self.is_pn532killer()
            if is_pn532killer:
                self.device_name = "PN532Killer"
            else:
                self.device_name = "PN532"
        return self

    def check_open(self):
        if not self.isOpen():
            raise Exception("Serial port is not open")

    def dcs(self, array: bytearray) -> int:
        return (0x00 - sum(array)) & 0xFF

    def close(self):
        self.event_closing.set()
        try:
            if self.communication is not None:
                self.communication.close()
        except Exception:
            pass
        finally:
            self.communication = None
        self.wait_response_map.clear()
        self.send_data_queue.queue.clear()

    def set_normal_mode(self) -> response:
        self.communication.write(bytes.fromhex("5500000000000000000000000000"))
        time.sleep(0.1)
        response = self.send_cmd_sync(Command.SAMConfiguration, bytes.fromhex("01"))
        return response

    def in_release(self) -> response:
        response = self.send_cmd_sync(Command.InRelease, bytes.fromhex("00"))
        return response

    # PN532Killer
    def set_work_mode(self, mode: PN532KillerMode = PN532KillerMode.READER, type=PN532KillerTagType.MFC, index=0) -> response:
        response = self.send_cmd_sync(
            Pn532KillerCommand.SetWorkMode, [mode.value, type, index]
        )
        return response

    def send_raw(self, data: bytes) -> response:
        cmd = data[0]
        response = self.send_cmd_sync(cmd, data[1:])
        return response.data

    def reset_register(self) -> response:
        response = self.send_cmd_sync(
            Command.WriteRegister, [0x63, 0x02, 0x00, 0x63, 0x03, 0x00]
        )
        return response

    def halt(self) -> response:
        self.reset_register()
        response = self.send_cmd_sync(Command.InCommunicateThru, [0x50, 0x00])
        return response

    def set_register(self, data: bytes) -> response:
        response = self.send_cmd_sync(Command.WriteRegister, data)
        return response

    def is_pn532killer(self):
        response = self.send_cmd_sync(Pn532KillerCommand.checkPn532Killer)
        return response.status == Status.SUCCESS

    def is_support_cmd(self, cmd: int) -> bool:
        if cmd in BasicCapabilities:
            return True
        elif self.device_name == "PN532":
            return cmd in PN532Capabilities
        elif self.device_name == "PN532Killer":
            return cmd in PN532KillerCapabilities or cmd in PN532Capabilities
        return True

    def read_mifare_block(self, block: int) -> str:
        # append 2 bytes crcA to data
        data = bytearray([0x30, block])
        crc16A = self.crc16A(data)
        data.extend(crc16A)
        response = self.send_cmd_sync(Command.InCommunicateThru, data)
        if len(response.data) > 16:
            return response.data[0:16]
        return response.data

    def crc16A(self, data: bytes) -> bytes:
        crc = 0x6363  # Initial value for CRC-A

        for b in data:
            ch = b ^ (crc & 0xFF)
            ch = (ch ^ (ch << 4)) & 0xFF
            crc = (crc >> 8) ^ (ch << 8) ^ (ch << 3) ^ (ch >> 4)

        crc = crc & 0xFFFF
        return crc.to_bytes(2, byteorder="little")

    def thread_data_receive(self):
        data_buffer = bytearray()
        data_position = 0
        data_cmd = 0x0000
        data_status = 0x0000
        data_length = 0x0000
        skip_pattern = bytearray.fromhex("0000ff00ff00")
        skip_pattern_length = len(skip_pattern)

        def reset_frame_parsing():
            nonlocal data_position
            data_position = 0

        def clear_buffer():
            nonlocal data_buffer, data_position, data_length
            data_buffer.clear()
            data_position = 0
            data_length = 0x0000

        def check_for_ack_frame():
            nonlocal data_buffer
            if len(data_buffer) >= skip_pattern_length:
                if data_buffer[:skip_pattern_length] == skip_pattern:
                    data_buffer = data_buffer[skip_pattern_length:]
                    return True
                if data_buffer[-skip_pattern_length:] == skip_pattern:
                    data_buffer = data_buffer[:-skip_pattern_length]
                    return True
            return False

        while self.isOpen():
            try:
                assert self.communication is not None
                data_bytes = self.communication.read(32) 
            except Exception as e:
                if not self.event_closing.is_set():
                    print(f"Communication Error {e}, thread for receiver exit.")
                self.close()
                break

            if len(data_bytes) > 0:
                data_buffer.extend(data_bytes)
                
                while len(data_buffer) > 0:
                    if check_for_ack_frame():
                        reset_frame_parsing()
                        continue

                    if len(data_buffer) > 300: 
                        clear_buffer()
                        break

                    if data_position == 0 and len(data_buffer) < 1:
                        break
                    elif data_position == 1 and len(data_buffer) < 2:
                        break
                    elif data_position == 2 and len(data_buffer) < 3:
                        break
                    elif data_position == 3 and len(data_buffer) < 4:
                        break
                    elif data_position == 4 and len(data_buffer) < 5:
                        break
                    elif data_position >= 5 and len(data_buffer) < 6 + data_length:
                        break

                    if data_position == 0:
                        if data_buffer[0] != self.data_preamble[0]:
                            preamble_pos = -1
                            for i in range(len(data_buffer)):
                                if data_buffer[i] == self.data_preamble[0]:
                                    preamble_pos = i
                                    break
                            if preamble_pos > 0:
                                data_buffer = data_buffer[preamble_pos:]
                                data_position = 0
                                continue
                            else:
                                clear_buffer()
                                break
                    elif data_position == 1:
                        if data_buffer[1] != self.data_start_code[0]:
                            clear_buffer()
                            break
                    elif data_position == 2:
                        if data_buffer[2] != self.data_start_code[1]:
                            if DEBUG:
                                print(f"Data frame start code error at position 2: {data_buffer[2]:02x}")
                            clear_buffer()
                            break
                    elif data_position == 3:
                        data_length = data_buffer[3]  # Get the data length byte
                    elif data_position == 4:
                        # Check length checksum (LCS)
                        length_checksum = data_buffer[4]
                        if (data_length + length_checksum) & 0xFF != 0:
                            if DEBUG:
                                print(f"Data frame LCS error: len={data_length:02x} lcs={length_checksum:02x}")
                            clear_buffer()
                            break
                        # print("length checksum ok")
                    elif data_position == 5 + data_length:
                        # Check DCS (Data Checksum)
                        if data_buffer[5 + data_length] != self.dcs(
                            data_buffer[5 : 5 + data_length]
                        ):
                            if DEBUG:
                                print("Data frame DCS error.")
                            clear_buffer()
                            break
                        # print("data checksum ok")
                    elif data_position == 6 + data_length:
                        # Check POSTAMBLE
                        if data_buffer[6 + data_length] != 0x00:
                            if DEBUG:
                                print("Data frame POSTAMBLE error.")
                            clear_buffer()
                            break
                        # Process complete frame
                        data_response = bytes(data_buffer[5 : 5 + data_length])
                        if len(data_response) == 0:
                            if DEBUG:
                                print("Data frame is empty.")
                            clear_buffer()
                            break
                        if data_response[0] != self.data_tfi_receive:
                            if DEBUG:
                                print("Data frame TFI error.")
                            clear_buffer()
                            break

                        if len(data_response) < 2:
                            if DEBUG:
                                print("Data frame length error.")
                            clear_buffer()
                            break
                        # get cmd
                        data_cmd = data_response[1] - 1
                        if DEBUG:
                            print(f"Parsed command: {data_cmd}, waiting for: {list(self.wait_response_map.keys())}")
                        if data_cmd in self.wait_response_map:
                            if DEBUG:
                                print(f"<=   {CY}{data_buffer[:7+data_length].hex().upper()}{C0}")
                            # update wait_response_map
                            response = Response(data_cmd, Status.SUCCESS, data_response[2:])
                            if (
                                data_cmd == Command.InCommunicateThru or data_cmd == Command.InDataExchange
                                and len(data_response) > 2
                            ):
                                response = Response(
                                    data_cmd, data_response[2], data_response[2:]
                                )
                                if data_response[2] == 0 and len(data_response) > 16:
                                    response = Response(
                                        data_cmd,
                                        data_response[2],
                                        data_response[3: 3 + data_length - 3],  # 修复数据长度计算
                                    )
                            self.wait_response_map[data_cmd]["response"] = response
                            fn_call = self.wait_response_map[data_cmd].get("callback")
                            if callable(fn_call):
                                print("run callback")
                                del self.wait_response_map[data_cmd]
                                fn_call(data_cmd, data_status, data_response)
                        else:
                            if DEBUG:
                                print(f"No task waiting for process: {data_cmd}")
                            pass
                        clear_buffer()
                        break
                    
                    data_position += 1

    def thread_data_transfer(self):
        while self.isOpen():
            # get a task from queue(if exists)
            try:
                task = self.send_data_queue.get(
                    block=True, timeout=THREAD_BLOCKING_TIMEOUT
                )
            except queue.Empty:
                continue
            task_cmd = task["cmd"]
            task_timeout = task["timeout"]
            task_close = task["close"]
            # print("thread_data_transfer", task)
            if "callback" in task and callable(task["callback"]):
                self.wait_response_map[task_cmd] = {
                    "callback": task["callback"]
                }  # The callback for this task
            else:
                self.wait_response_map[task_cmd] = {"response": None}
            # set start time
            start_time = time.time()
            self.wait_response_map[task_cmd]["start_time"] = start_time
            self.wait_response_map[task_cmd]["end_time"] = start_time + task_timeout
            self.wait_response_map[task_cmd]["is_timeout"] = False
            try:
                assert self.communication is not None
                if DEBUG:
                    print(f'=>   {CY}{task["frame"].hex().upper()}{C0}')
                self.communication.write(task["frame"])
            except Exception as e:
                print(f"Communication Error {e}, thread for transfer exit.")
                self.close()
                break

            # update queue status
            self.send_data_queue.task_done()
            # disconnect if DFU command has been sent
            if task_close:
                self.close()

    def thread_check_timeout(self):
        while self.isOpen():
            for task_cmd in self.wait_response_map.keys():
                if time.time() > self.wait_response_map[task_cmd]["end_time"]:
                    if "callback" in self.wait_response_map[task_cmd]:
                        # not sync, call function to notify timeout.
                        self.wait_response_map[task_cmd]["callback"](
                            task_cmd, None, None
                        )
                    else:
                        # sync mode, set timeout flag
                        self.wait_response_map[task_cmd]["is_timeout"] = True
            time.sleep(THREAD_BLOCKING_TIMEOUT)

    def make_data_frame_bytes(
        self, cmd: int, data: Union[bytes, None] = None, status: int = 0
    ) -> bytes:
        if data is None:
            data = b""
        commands = self.data_tfi_send.to_bytes(1, byteorder="big")
        commands += cmd.to_bytes(1, byteorder="big")
        commands = bytearray(commands)
        commands.extend(data)
        frame = bytearray()
        frame.extend(self.data_preamble)
        frame.extend(self.data_start_code)
        length = len(commands)
        length_check_sum = (0x00 - length) & 0xFF
        frame.append(length)
        frame.append(length_check_sum)
        frame.extend(commands)
        dcs = self.dcs(commands)
        frame.append(dcs)
        frame.extend(self.data_postamble)
        return bytes(frame)

    def send_cmd_auto(
        self,
        cmd: int,
        data: Union[bytes, None] = None,
        status: int = 0,
        callback=None,
        timeout: int = 1,
        close: bool = False,
    ):
        """
            Send cmd to device

        :param cmd: cmd
        :param data: bytes data (optional)
        :param status: status (optional)
        :param callback: call on response
        :param timeout: wait response timeout
        :param close: close connection after executing
        :return:
        """
        self.check_open()
        # delete old task
        if cmd in self.wait_response_map:
            del self.wait_response_map[cmd]
        # make data frame
        data_frame = self.make_data_frame_bytes(cmd, data, status)
        task = {"cmd": cmd, "frame": data_frame, "timeout": timeout, "close": close}
        if callable(callback):
            task["callback"] = callback
        self.send_data_queue.put(task)

    def send_cmd_sync(
        self,
        cmd: int,
        data: Union[bytes, None] = None,
        status: int = 0,
        timeout: int = 2,
    ) -> response:
        if len(self.commands):
            # check if PN532 can understand this command
            if cmd not in self.commands:
                raise CMDInvalidException(
                    f"This device doesn't declare that it can support this command: {cmd}.\n"
                    f"Make sure firmware is up to date and matches client"
                )
        # first to send cmd, no callback mode(sync)
        self.send_cmd_auto(cmd, data, status, None, timeout)
        # wait cmd start process
        while cmd not in self.wait_response_map:
            time.sleep(0.01)
        # wait response data set
        while self.wait_response_map[cmd]["response"] is None:
            if (
                "is_timeout" in self.wait_response_map[cmd]
                and self.wait_response_map[cmd]["is_timeout"]
            ):
                # raise TimeoutError(f"CMD {cmd} exec timeout")
                # print(f"CMD {cmd} exec timeout")
                self.wait_response_map[cmd]["is_timeout"] = True
                self.wait_response_map[cmd]["response"] = Response(
                    cmd, Status.TimeoutError
                )
                break
            time.sleep(0.01)
        # ok, data received.
        data_response = self.wait_response_map[cmd]["response"]
        del self.wait_response_map[cmd]
        if data_response.status == Status.INVALID_CMD:
            raise CMDInvalidException(f"Device unsupported cmd: {cmd}")
        return data_response


class Response:
    """
    Pn532 Response Data
    """

    def __init__(self, cmd, status, data=b"", parsed=None):
        self.cmd = cmd
        self.status = status
        self.data: bytes = data
        self.parsed = parsed
