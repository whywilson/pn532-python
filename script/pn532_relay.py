#!/usr/bin/env python3
"""
PN532 <-> PN532 NFC Relay

用法示例：
  python3 pn532_relay.py --reader /dev/cu.usbmodem1301 --emulator /dev/cu.usbmodem1302
  python3 pn532_relay.py --reader tcp:192.168.0.10:18888 --emulator udp:192.168.0.20:18889

说明：
  - reader 侧：放在被中继的真实卡片旁边，作为“读卡器”，与真实卡进行交互
  - emulator 侧：放在真实读卡器旁边，作为“被动目标/卡”，与真实读卡器交互

流程：
  emulator 使用 TgInitAsTarget 进入被动目标模式，循环 TgGetData 获取来自真实读卡器的数据；
  reader 端先 InListPassiveTarget 选中真实卡，然后将数据通过 InDataExchange 转发给真实卡；
  将真实卡的响应再用 TgSetData 回送给 emulator 侧，完成一次往返。
"""

import argparse
import signal
import sys
import time

import pn532_com
from pn532_enum import Command, Status
from pn532_cmd import Pn532CMD
from typing import Optional


ATR_TARGET_PARAMS = bytes.fromhex(
    # 与仓库中 pn532_cmd.py 的示例保持一致
    "0408001122336001FEA2A3A4A5A6A7C0C1C2C3C4C5C6C7FFFFAA9988776655443322110000"
)


class RelayApp:
    def __init__(self, reader_addr: str, emulator_addr: str, verbose: bool = False):
        self.reader_addr = reader_addr
        self.emulator_addr = emulator_addr
        self.verbose = verbose
        self.dev_reader = None
        self.dev_emulator = None
        self.stop = False

    # -------------- 基础 --------------
    def log(self, msg: str):
        if self.verbose:
            print(msg)

    def open_devices(self):
        self.dev_reader = pn532_com.Pn532Com().open(self.reader_addr)
        print(f"Reader connected: {self.dev_reader.get_connection_info()}, {self.dev_reader.device_name}")

        self.dev_emulator = pn532_com.Pn532Com().open(self.emulator_addr)
        print(f"Emulator connected: {self.dev_emulator.get_connection_info()}, {self.dev_emulator.device_name}")

    def close_devices(self):
        for dev in (self.dev_reader, self.dev_emulator):
            try:
                if dev:
                    dev.close()
            except Exception:
                pass

    # -------------- 读卡侧准备 --------------
    def ensure_tag_selected(self, retry_delay: float = 0.2) -> bool:
        """在 reader 侧扫描并选择一个 14443A 标签，成功返回 True。"""
        assert self.dev_reader is not None
        cmd = Pn532CMD(self.dev_reader)
        # 增强稳定性：循环扫描直到成功
        while not self.stop:
            resp = cmd.hf_14a_scan()
            if resp and resp.status == Status.SUCCESS and resp.parsed:
                self.log(f"Reader side tag selected, UID={resp.parsed[0]['uid'].hex().upper()}")
                return True
            time.sleep(retry_delay)
        return False

    # -------------- 模拟侧准备 --------------
    def init_emulator_target(self) -> bool:
        assert self.dev_emulator is not None
        resp = self.dev_emulator.send_cmd_sync(Command.TgInitAsTarget, ATR_TARGET_PARAMS)
        ok = resp.status == Status.SUCCESS
        if ok:
            self.log(f"TgInitAsTarget OK: {resp.data.hex().upper()}")
        else:
            print("TgInitAsTarget failed")
        return ok

    # -------------- 中继主循环 --------------
    def relay_once(self) -> None:
        """执行一次中继：从 emulator 侧取数据，发到 reader 侧，再把响应回写到 emulator。"""
        assert self.dev_reader is not None and self.dev_emulator is not None
        # 从真实读卡器(经 emulator 侧)获取 APDU / 数据
        resp_get = self.dev_emulator.send_cmd_sync(Command.TgGetData)

        if len(resp_get.data) == 0:
            # 可能是空轮询，轻微等待
            self.dev_emulator.in_release()
            time.sleep(0.01)
            return

        # 有些状态码需要重新进入 target
        first = resp_get.data[0]
        if first in (0x29, 0x25):
            # 发生 RF 去耦/冲突等
            self.log(f"TgGetData event=0x{first:02X}, re-init target")
            self.init_emulator_target()
            return

        if len(resp_get.data) < 2:
            # 数据过短，忽略
            time.sleep(0.005)
            return

        # 去掉第一个状态/标记字节，保留实际 PCD->PICC 的数据
        upstream = resp_get.data[1:]
        if self.verbose:
            print(f"Up -> Card: {upstream.hex().upper()}")

        # 发到真实卡：使用 InDataExchange, 目标号 0x01
        payload = b"\x01" + upstream
        resp_card = self.dev_reader.send_cmd_sync(Command.InDataExchange, payload, timeout=2)

        if resp_card.status != Status.SUCCESS:
            # 读卡侧失败，则尝试重新选择卡
            self.log("InDataExchange failed, reselecting tag...")
            self.ensure_tag_selected()
            return

        downstream = resp_card.data  # 已自动去掉状态字节
        if self.verbose:
            print(f"Down <- Card: {downstream.hex().upper()}")

        # 回写给真实读卡器
        _ = self.dev_emulator.send_cmd_sync(Command.TgSetData, downstream)

    def run(self):
        # 打开设备
        self.open_devices()

        # 读卡侧选中真实卡
        if not self.ensure_tag_selected():
            return

        # 模拟侧进入目标模式
        if not self.init_emulator_target():
            return

        print("Relay started. Press Ctrl+C to stop.")
        while not self.stop:
            try:
                self.relay_once()
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Relay error: {e}")
                time.sleep(0.05)

        self.close_devices()


def main():
    parser = argparse.ArgumentParser(description="PN532 <-> PN532 NFC Relay")
    parser.add_argument("--reader", required=True, help="reader 侧连接串，如 /dev/tty*, tcp:host:port 或 udp:host:port")
    parser.add_argument("--emulator", required=True, help="emulator 侧连接串，如 /dev/tty*, tcp:host:port 或 udp:host:port")
    parser.add_argument("-v", "--verbose", action="store_true", help="输出详细日志")
    args = parser.parse_args()

    app = RelayApp(args.reader, args.emulator, verbose=args.verbose)

    def _sigint(_sig, _frm):
        app.stop = True
    signal.signal(signal.SIGINT, _sigint)

    app.run()


if __name__ == "__main__":
    main()
