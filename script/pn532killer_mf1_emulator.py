import struct
import re
import ctypes
from typing import Union
import threading

import pn532_com
from unit.calc import crc16A, crc16Ccitt
from pn532_com import Response, DEBUG
from pn532_utils import expect_response
from pn532_enum import Command, MifareCommand, ApduCommand, TagFile, NdefCommand, Status
from pn532_enum import Pn532KillerCommand
from pn532_cmd import Pn532CMD

from pn532_enum import ButtonPressFunction, ButtonType, MifareClassicDarksideStatus
from pn532_enum import MfcKeyType, MfcValueBlockOperator
from time import sleep
from pn532_utils import CC, CB, CG, C0, CY, CR
import os
import subprocess
import ndef
from multiprocessing import Pool, cpu_count
from typing import Union
from pathlib import Path
from platform import uname
import sys
import select
import serial.tools.list_ports
# if system is Windows
if os.name == "nt":
    import msvcrt
    
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
        
    if dev.serial_instance is None:
        print("No PN532/PN532Killer found")
        return
    print(f"Connected to {dev.serial_instance.port}, {dev.device_name}")
    cml = Pn532CMD(dev)

    try:
        uid = None
        block0 = None
        if "-u" in sys.argv:
            uid = sys.argv[sys.argv.index("-u") + 1]
            if uid is not None and not re.match(r"^[0-9a-fA-F]{8}$", uid):
                print("UID must be 4 bytes hex string")
                return
        if "-b" in sys.argv:
            block0 = sys.argv[sys.argv.index("-b") + 1]
            if block0 is not None and not re.match(r"^[0-9a-fA-F]{32}$", block0):
                print("Block0 must be 16 bytes hex string")
                return
            block0 = bytes.fromhex(block0)
        if uid is None and block0 is None:
            print("Please provide a uid or block0")
            return
        # check uid length 4 bytes only
        if uid is not None and len(uid) != 8:
            print("UID must be 4 bytes")
            return
        
        # check block0 length 16 bytes only
        if block0 is None:
            bcc = 0
            uidBytes = bytes.fromhex(uid)
            for i in uidBytes:
                bcc ^= i
            sak = 0x08
            atqa = 0x0400
            # generate random factory bytes
            factoryBytes = os.urandom(8)
            # generate block0 with [uid, bcc, sak, atqa and factory bytes]
            block0 = uidBytes + bytes([bcc, sak]) + struct.pack(">H", atqa) + factoryBytes
        print("Block0 set to " + block0.hex() + " on Mifare Classic Emulator Slot 0")
        cml.upload_data_block(type  = 1, slot= 0, index = 0, data = block0)
        cml.upload_data_block_done(slot = 0)
        cml.device.set_work_mode(2, 1, 0)

        delay_time = 10
        if "-d" in sys.argv:
            delay_time = int(sys.argv[sys.argv.index("-d") + 1])
        if "-s" not in sys.argv:
            print(f"Exist Emulation in {delay_time}s, press Enter to skip...")
            rlist, _, _ = select.select([sys.stdin], [], [], delay_time)
            if rlist:
                sys.stdin.readline()
            else:
                print(f"Emulation Existed")
        else:
            print(f"Emulation Existed")
    except Exception as e:
        print("Error:", e)
    dev.close()


if __name__ == "__main__":
    test_fn()