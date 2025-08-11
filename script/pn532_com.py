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
        self.port_string = None  # store original open string
        self.ignore_late_cmd_until = {}  # 记录某命令在这个时间点前的迟到帧直接丢弃

    device_name = "Unknown"
    data_max_length = 0xFF

    def set_device_name(self, device_name):
        self.device_name = device_name

    def get_device_name(self) -> str:
        return self.device_name

    def isOpen(self) -> bool:
        return self.communication is not None and self.communication.is_open()
    
    def get_connection_info(self) -> str:
        """Get connection information"""
        if self.communication is not None:
            return self.communication.get_connection_info()
        return "Not connected"

    def open(self, port) -> "Pn532Com":
        if not self.isOpen():
            error = None
            try:
                self.communication = CommunicationFactory.create_communication(port)
                protocol_type, actual_address = CommunicationFactory.parse_address(port)
                self.connection_type = protocol_type  # 记录连接类型
                if not self.communication.open(actual_address):
                    raise Exception(f"Failed to open {protocol_type} connection to {actual_address}")
                print(f"Opened {protocol_type} connection to {actual_address}")
                self.port_string = port
            except Exception as e:
                error = e
            finally:
                if error is not None:
                    raise OpenFailException(error)
            assert self.communication is not None
            self.communication.set_timeout(0.3 if hasattr(self, 'connection_type') and self.connection_type in ('udp','tcp') else THREAD_BLOCKING_TIMEOUT)
            # clear variable
            self.send_data_queue.queue.clear()
            self.wait_response_map.clear()
            # Start a sub thread to process data
            self.event_closing.clear()
            threading.Thread(target=self.thread_data_receive, daemon=True).start()
            threading.Thread(target=self.thread_data_transfer, daemon=True).start()
            threading.Thread(target=self.thread_check_timeout, daemon=True).start()
            
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

    def send_raw_frame(self, frame: bytes, wait_response: bool = True):
        # Send a full PN532 frame (already contains preamble/startcode/len/LCS/DCS/postamble or any wakeup sequence)
        if not self.isOpen():
            raise NotOpenException("Device not open")
        assert self.communication is not None
        if DEBUG:
            print(f'=>   {CY}{frame.hex().upper()}{C0}')
        self.communication.write(frame)
        
        if not wait_response:
            return None
            
        # For non-command frames (like wakeup), don't wait for structured response
        if not frame.startswith(b'\x00\x00\xFF'):
            return None
            
        # Wait for response with simple timeout
        import time
        start_time = time.time()
        while time.time() - start_time < 2.0:  # 2 second timeout
            time.sleep(0.01)
            # Check if any response came in the normal flow
            # This is a simple implementation - for debugging mostly
        
        return None

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
        """Receiver thread: robust frame extraction with resync & ACK filtering"""
        data_buffer = bytearray()
        ACK = b"\x00\x00\xFF\x00\xFF\x00"
        while self.isOpen():
            # 连接状态检测
            if self.communication is not None and not self.communication.is_open():
                if not self.event_closing.is_set():
                    print("Connection lost, closing device...")
                self.close()
                break
            try:
                assert self.communication is not None
                chunk = self.communication.read(64)
                # UDP 的多包读取已在 communication 层处理，这里去掉额外逻辑
            except Exception as e:
                if not self.event_closing.is_set():
                    print(f"Communication Error {e}, thread for receiver exit.")
                self.close()
                break
            if not chunk:
                continue
            if DEBUG:
                print(f"READ {chunk.hex().upper()}")
            data_buffer.extend(chunk)
            # 过滤所有 ACK
            changed = True
            while changed:
                changed = False
                pos = data_buffer.find(ACK)
                if pos != -1:
                    if DEBUG:
                        print(f"SKIP ACK at {pos}")
                    del data_buffer[pos:pos+len(ACK)]
                    changed = True
            # 尝试解析帧
            i = 0
            while i <= len(data_buffer) - 7:  # 最小帧长度
                # 寻找前导 00 00 FF
                if not (data_buffer[i] == 0x00 and data_buffer[i+1] == 0x00 and data_buffer[i+2] == 0xFF):
                    i += 1
                    continue
                if i + 5 > len(data_buffer):
                    break  # 不足以读取 LEN/LCS
                length = data_buffer[i+3]
                lcs = data_buffer[i+4]
                if ((length + lcs) & 0xFF) != 0:
                    if DEBUG:
                        print(f"LEN/LCS mismatch at {i}: LEN={length:02X} LCS={lcs:02X}")
                    i += 1
                    continue
                frame_end = i + 5 + length + 2  # +DCS +POSTAMBLE
                if frame_end > len(data_buffer):
                    break  # 等待更多数据
                if data_buffer[frame_end-1] != 0x00:
                    if DEBUG:
                        print(f"POSTAMBLE error at {i}")
                    i += 1
                    continue
                data = bytes(data_buffer[i+5:i+5+length])
                dcs = data_buffer[i+5+length]
                if self.dcs(bytearray(data)) != dcs:
                    if DEBUG:
                        print(f"DCS error at {i}: expect {self.dcs(bytearray(data)):02X} got {dcs:02X}")
                    i += 1
                    continue
                if not data:
                    i = frame_end
                    continue
                tfi = data[0]
                if tfi != self.data_tfi_receive:
                    if DEBUG:
                        print(f"Unexpected TFI {tfi:02X} (expect {self.data_tfi_receive:02X}), resync")
                    i += 1
                    continue
                if len(data) < 2:
                    i = frame_end
                    continue
                cmd_resp = data[1] - 1  # 原始命令
                if cmd_resp in getattr(self, 'ignore_late_cmd_until', {}) and time.time() < self.ignore_late_cmd_until[cmd_resp]:
                    if DEBUG:
                        print(f"Discard late frame for CMD=0x{cmd_resp:02X}")
                    i = frame_end
                    continue
                else:
                    if cmd_resp in getattr(self, 'ignore_late_cmd_until', {}) and time.time() >= self.ignore_late_cmd_until[cmd_resp]:
                        del self.ignore_late_cmd_until[cmd_resp]
                if DEBUG:
                    print(f"<=   {CY}{data_buffer[i:frame_end-1].hex().upper()}{C0}")
                if cmd_resp in self.wait_response_map:
                    payload = data[2:]
                    response = Response(cmd_resp, Status.SUCCESS, payload)
                    if (cmd_resp == Command.InCommunicateThru or cmd_resp == Command.InDataExchange) and len(data) > 2:
                        status_byte = data[2]
                        response = Response(cmd_resp, status_byte, data[2:])
                        if status_byte == 0 and len(data) > 3:
                            response = Response(cmd_resp, status_byte, data[3:])
                    self.wait_response_map[cmd_resp]["response"] = response
                    fn_call = self.wait_response_map[cmd_resp].get("callback")
                    if callable(fn_call):
                        del self.wait_response_map[cmd_resp]
                        try:
                            fn_call(cmd_resp, 0, data)
                        except Exception as e:
                            print(f"Callback error: {e}")
                else:
                    if DEBUG:
                        print(f"No waiter for CMD=0x{cmd_resp:02X}, pending keys={[hex(k) for k in self.wait_response_map.keys()]}")
                i = frame_end
            if i > 0:
                del data_buffer[:i]
    def thread_data_transfer(self):
        while self.isOpen():
            try:
                task = self.send_data_queue.get(block=True, timeout=THREAD_BLOCKING_TIMEOUT)
            except queue.Empty:
                continue
            task_cmd = task["cmd"]
            task_timeout = task["timeout"]
            task_close = task["close"]
            # 如果是预注册，占位里补齐时间字段；否则（极少出现）创建新项
            if task_cmd not in self.wait_response_map:
                # 不应发生（预注册保证存在），但兜底
                self.wait_response_map[task_cmd] = {"response": None}
            if '_pre_registered' in self.wait_response_map[task_cmd]:
                del self.wait_response_map[task_cmd]['_pre_registered']
            if 'callback' in task and callable(task['callback']):
                self.wait_response_map[task_cmd]['callback'] = task['callback']
            start_time = time.time()
            self.wait_response_map[task_cmd]["start_time"] = start_time
            self.wait_response_map[task_cmd]["end_time"] = start_time + task_timeout
            self.wait_response_map[task_cmd]["is_timeout"] = False
            try:
                assert self.communication is not None
                if not self.communication.is_open():
                    print("Connection lost during data transfer, closing device...")
                    self.close()
                    break
                if DEBUG:
                    print(f"=>   {CY}{task['frame'].hex().upper()}{C0}")
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
            for task_cmd in list(self.wait_response_map.keys()):  # 使用 list 避免迭代期间修改
                task_data = self.wait_response_map.get(task_cmd, {})
                if "end_time" in task_data and time.time() > task_data["end_time"]:
                    if "callback" in task_data:
                        task_data["callback"](task_cmd, None, None)
                    else:
                        task_data["is_timeout"] = True
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
        if cmd in self.wait_response_map:
            if DEBUG:
                print(f"Replace pending task CMD=0x{cmd:02X}")
            del self.wait_response_map[cmd]
        if hasattr(self, 'connection_type') and self.connection_type in ('tcp', 'udp'):
            if timeout < 2:
                timeout = 2
        data_frame = self.make_data_frame_bytes(cmd, data, status)
        # 预注册占位，防止响应极快到达时无 waiter
        self.wait_response_map[cmd] = self.wait_response_map.get(cmd, {})
        if callable(callback):
            self.wait_response_map[cmd]['callback'] = callback
        if 'response' not in self.wait_response_map[cmd]:
            self.wait_response_map[cmd]['response'] = None
        self.wait_response_map[cmd]['_pre_registered'] = True
        self.wait_response_map[cmd]['_timeout_value'] = timeout
        if DEBUG:
            print(f"PRE-REG CMD=0x{cmd:02X} TIMEOUT={timeout}s DATA={(data.hex().upper() if data else '')}")
        task = {"cmd": cmd, "frame": data_frame, "timeout": timeout, "close": close}
        if callable(callback):
            task["callback"] = callback
        if DEBUG:
            print(f"QUEUE CMD=0x{cmd:02X} TIMEOUT={timeout}s DATA={(data.hex().upper() if data else '')}")
        self.send_data_queue.put(task)

    def send_cmd_sync(
        self,
        cmd: int,
        data: Union[bytes, None] = None,
        status: int = 0,
        timeout: int = 2,
        retries: int = 0,  # 保留参数以兼容，已不再自动重发
    ) -> response:
        """
        发送命令并同步等待响应（不再自动重发）。
        :param cmd: 命令码
        :param data: 数据
        :param status: 状态
        :param timeout: 超时时间（秒）
        :param retries: 已废弃，保留做兼容（不再使用）
        """
        # 校验支持
        if len(self.commands) and cmd not in self.commands:
            raise CMDInvalidException(
                f"This device doesn't declare that it can support this command: {cmd}.\n"
                f"Make sure firmware is up to date and matches client"
            )
        network_mode = hasattr(self, 'connection_type') and self.connection_type in ('udp','tcp')
        # 对扫描类命令直接提升任务自身 timeout (避免 timeout 线程过早置 is_timeout)
        effective_timeout = timeout
        if network_mode and cmd == Command.InListPassiveTarget and effective_timeout < 3:
            effective_timeout = 3  # 给扫描至少 3s
        # 其它命令给少量额外宽限（等待循环内部使用，不影响 timeout 线程判定）
        wait_margin = 0.5 if not network_mode else 0.7
        self.send_cmd_auto(cmd, data, status, None, effective_timeout)
        start_wait = time.time()
        # 等待任务注册
        while cmd not in self.wait_response_map:
            if time.time() - start_wait > effective_timeout + wait_margin:
                self.ignore_late_cmd_until[cmd] = time.time() + 0.3
                return Response(cmd, Status.TimeoutError)
            time.sleep(0.01)
        # 等待响应
        while self.wait_response_map[cmd]["response"] is None:
            if ("is_timeout" in self.wait_response_map[cmd] and self.wait_response_map[cmd]["is_timeout"]):
                self.ignore_late_cmd_until[cmd] = time.time() + 0.3
                self.wait_response_map[cmd]["response"] = Response(cmd, Status.TimeoutError)
                break
            if time.time() - start_wait > effective_timeout + wait_margin:
                self.ignore_late_cmd_until[cmd] = time.time() + 0.3
                self.wait_response_map[cmd]["response"] = Response(cmd, Status.TimeoutError)
                break
            time.sleep(0.01)
        # 对 0x4A (InListPassiveTarget) 若收到空数据，继续等待直到超时或出现非空数据（不重发）
        if cmd == Command.InListPassiveTarget:
            while True:
                resp_tmp = self.wait_response_map[cmd]["response"]
                if resp_tmp is None:
                    # 理论上不会出现，但兜底
                    if time.time() - start_wait > effective_timeout + wait_margin:
                        break
                    time.sleep(0.01)
                    continue
                # 如果已经超时 / 非成功就直接退出
                if resp_tmp.status != Status.SUCCESS:
                    break
                # 数据长度>=2 认为有效
                if len(resp_tmp.data) >= 2:
                    break
                # 还未到时间，等待可能的覆盖（接收线程会覆盖 response）
                if time.time() - start_wait > effective_timeout + wait_margin:
                    break
                time.sleep(0.02)
        resp = self.wait_response_map[cmd]["response"]
        del self.wait_response_map[cmd]
        if resp.status == Status.INVALID_CMD:
            raise CMDInvalidException(f"Device unsupported cmd: {cmd}")
        return resp


class Response:
    """
    Pn532 Response Data
    """

    def __init__(self, cmd, status, data=b"", parsed=None):
        self.cmd = cmd
        self.status = status
        self.data: bytes = data
        self.parsed = parsed
