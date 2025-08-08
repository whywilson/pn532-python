import pn532_com
from pn532_cmd import Pn532CMD

from platform import uname

def test_fn():
    dev = pn532_com.Pn532Com()
    # Connect via TCP to local test server
    try:
        dev.open("tcp:192.168.20.32:18889")
        if not dev.isOpen():
            print("Failed to connect to tcp:192.168.20.32:18889")
            return
        print(f"Connected to tcp:192.168.20.32:18889")
        cml = Pn532CMD(dev)
    except Exception as e:
        print(f"Connection failed: {e}")
        return
    try:
        print("Getting firmware version...")
        fw_version = cml.get_firmware_version()
        print("FW Version:", fw_version)
        hf_14a_scan_result = cml.hf_14a_scan()
        if hf_14a_scan_result is not None:
            for data_tag in hf_14a_scan_result:
                print(f"- UID: {data_tag['uid'].hex().upper()}")
                print(
                    f"- ATQA: {data_tag['atqa'].hex().upper()} "
                    f"(0x{int.from_bytes(data_tag['atqa'], byteorder='little'):04x})"
                )
                print(f"- SAK: {data_tag['sak'].hex().upper()}")
                if "ats" in data_tag and len(data_tag["ats"]) > 0:
                    print(f"- ATS: {data_tag['ats'].hex().upper()}")
        else:
            print("ISO14443-A Tag not found")
    except Exception as e:
        print("Error:", e)
        import traceback
        traceback.print_exc()
    dev.close()

if __name__ == "__main__":
    test_fn()
