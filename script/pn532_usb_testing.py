import pn532_com
from pn532_cmd import Pn532CMD

import os
import sys

def test_fn():
    dev = pn532_com.Pn532Com()
    try:
        dev.open("/dev/tty.wchusbserial210")
        if not dev.isOpen():
            print("Failed to connect to /dev/tty.wchusbserial210")
            return
        print(f"Connected to /dev/tty.wchusbserial210")
        cml = Pn532CMD(dev)
    except Exception as e:
        print(f"Connection failed: {e}")
        return
    try:
        print("Getting firmware version...")
        fw_version = cml.get_firmware_version()
        print("FW Version:", fw_version)
    except Exception as e:
        print("Error:", e)
        import traceback
        traceback.print_exc()
    dev.close()

if __name__ == "__main__":
    test_fn()
