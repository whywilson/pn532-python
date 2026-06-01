import pn532_com
from pn532_cmd import Pn532CMD

import os
import sys
from platform import uname


def _to_hex_upper(value):
    if isinstance(value, (bytes, bytearray)):
        return value.hex().upper()
    if value is None:
        return ""
    if isinstance(value, str):
        return value.upper()
    try:
        return bytes(value).hex().upper()
    except Exception:
        return str(value).upper()

def test_fn():
    dev = pn532_com.Pn532Com()
    # 1) Allow override via environment variable
    port_name = os.getenv("PN532_PORT")

    # 2) Auto-scan serial ports (macOS/Linux)
    if not port_name:
        try:
            # Common WCH/CH34x USB-Serial VID is 0x1A86 (decimal 6790)
            candidates = []
            try:
                import importlib
                list_ports = importlib.import_module('serial.tools.list_ports')
                ports = list_ports.comports()
            except Exception:
                ports = []
            for port in ports:
                # Prefer known VID or description containing 'PN532Killer'
                if getattr(port, "vid", None) == 6790 or (port.description and "PN532Killer" in port.description):
                    candidates.append(port.device)
                # Otherwise match typical device names
                elif port.device and ("wchusbserial" in port.device or "usbserial" in port.device):
                    candidates.append(port.device)
            if candidates:
                port_name = candidates[0]
        except Exception as e:
            print(f"Enumerate serial ports failed: {e}")

    # 3) WSL/Windows special handling (compatibility fallback)
    if not port_name and "Microsoft" in uname().release:
        try:
            # Try querying Windows COM ports from WSL (if your environment needs it)
            import subprocess
            powershell = r"/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
            if os.path.exists(powershell):
                ps_cmd = (
                    "Get-PnPDevice -Class Ports -PresentOnly |"
                    " where {$_.DeviceID -like '*VID_6868&PID_8686*'} |"
                    " Select-Object -First 1 FriendlyName |"
                    " % FriendlyName |"
                    " select-string COM\\d+ |"
                    " % { $_.matches.value }"
                )
                res = subprocess.run([powershell, ps_cmd], capture_output=True)
                com = res.stdout.decode("utf-8").strip()
                if com:
                    port_name = com.replace("COM", "/dev/ttyS")
        except Exception:
            pass

    try:
        if not port_name:
            print("No available PN532 serial port found. Set PN532_PORT to specify the port.")
            return
        dev.open(port_name)
        if not dev.isOpen():
            print(f"Failed to connect: {port_name}")
            return
        device_name = dev.get_device_name()
        print(f"Connected: {port_name} ({device_name})")
        cml = Pn532CMD(dev)
    except Exception as e:
        print(f"Connection error: {e}")
        return

    try:
        print("Getting firmware version...")
        fw_version = cml.get_firmware_version()
        print("FW Version:", fw_version)
        is_pn532killer = dev.get_device_name() == "PN532Killer"

        # After getting firmware, run hf 14a scan (handle only the first tag)
        print("Running hf 14a scan...")
        resp = cml.hf_14a_scan()  # Decorator returns parsed data (list or None)
        if resp and isinstance(resp, list) and len(resp) > 0:
            t = resp[0]
            uid = t.get("uid", b"")
            uid_hex = _to_hex_upper(uid)
            atqa = t.get("atqa", b"")
            atqa_hex = _to_hex_upper(atqa)
            sak = t.get("sak", b"")
            sak_hex = _to_hex_upper(sak)
            ats = t.get("ats", b"")
            ats_hex = _to_hex_upper(ats)
            # Print each field on a new line
            print(f"UID:  {uid_hex}")
            print(f"ATQA: {atqa_hex}")
            print(f"SAK:  {sak_hex}")
            print(f"ATS:  {ats_hex}")
        else:
            print("No 14a tag found")

        # PN532Killer supports both 14A and 15 scans in reader mode.
        if is_pn532killer:
            print("Running hf 15 scan (ISO15693, PN532Killer only)...")
            resp_15 = cml.hf_15_scan()
            if resp_15 and isinstance(resp_15, list) and len(resp_15) > 0:
                for index, tag in enumerate(resp_15, 1):
                    uid_15 = _to_hex_upper(tag.get("uid", ""))
                    tag_type = tag.get("tagType", "")
                    tag_num = tag.get("tagNum", "")
                    print(f"[{index}] UID: {uid_15}  tagType: {tag_type}  tagNum: {tag_num}")
            else:
                print("No ISO15693 tag found")
    except Exception as e:
        print("Runtime error:", e)
        import traceback
        traceback.print_exc()
    finally:
        dev.close()

if __name__ == "__main__":
    test_fn()
