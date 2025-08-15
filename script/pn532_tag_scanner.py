import pn532_com
from pn532_cmd import Pn532CMD

import os
import subprocess
from platform import uname
import sys
import select
import serial.tools.list_ports
# if system is Windows
if os.name == "nt":
    import msvcrt
import tkinter as tk

def test_fn():
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

    if not dev.isOpen():
        print("No PN532/PN532Killer found")
        return
    print(f"Connected to {dev.get_connection_info()}, {dev.device_name}")
    cml = Pn532CMD(dev)

    try:
        def update_uid():
            scan_result = cml.hf_14a_scan()
            if scan_result:
                # get UID, ATQA, SAK
                uid = scan_result[0]['uid'].hex().upper()
                atqa = scan_result[0]["atqa"].hex().upper()
                sak = scan_result[0]["sak"].hex().upper()
                uid_label.config(text=f"UID: {uid}\nATS: {atqa}\nSAK: {sak}")
            else:
                uid_label.config(text="No card found")
            root.after(1000, update_uid)

        root = tk.Tk()
        root.title("TAG Scanner")

        uid_label = tk.Label(root, text="Scanning for card...", font=("Helvetica", 18), anchor="w", justify="left")
        uid_label.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        update_uid()
        root.mainloop()
    except Exception as e:
        print("Error:", e)
    dev.close()

if __name__ == "__main__":
    test_fn()
