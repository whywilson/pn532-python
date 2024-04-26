# Example of detecting and reading a block from a MiFare NFC card.
# Author: Manuel Fernando Galindo (mfg90@live.com)
#
# Copyright (c) 2016 Manuel Fernando Galindo
#
# MIT License
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sys
sys.path.append('..')
import PN532
from serial.tools import list_ports


port_name_key = "serial"

# Find the port that the PN532 is connected to.
port_name = None
for port in list_ports.comports():
    if port_name_key in port.device:
        port_name = port.device
        break

# Create an instance of the PN532 class.
pn532 = PN532.PN532(port_name, 115200)

# Call begin to initialize communication with the PN532.  Must be done before
# any other calls to the PN532!
pn532.begin()

# Configure PN532 to communicate with MiFare cards.
# pn532.SAM_configuration()

# Get the firmware version from the chip and print(it out.)
ic, ver, rev, support = pn532.get_firmware_version()
print('Found PN532 with FW: {0}.{1}'.format(ver, rev))


# Main loop to detect cards and read a block.
print('Waiting for MiFare card...')
while True:
    uid = pn532.read_passive_target()
    if uid == "no_card":
        continue
    if uid is None:
        continue
    print('Found tag with UID: 0x{0}'.format(uid.hex().upper()))