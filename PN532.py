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

from functools import reduce
import time
import serial

PN532_PREAMBLE                      = 0x00
PN532_STARTCODE1                    = 0x00
PN532_STARTCODE2                    = 0xFF
PN532_POSTAMBLE                     = 0x00

PN532_HOSTTOPN532                   = 0xD4
PN532_PN532TOHOST                   = 0xD5

# PN532 Commands
PN532_COMMAND_DIAGNOSE              = 0x00
PN532_COMMAND_GETFIRMWAREVERSION    = 0x02
PN532_COMMAND_GETGENERALSTATUS      = 0x04
PN532_COMMAND_READREGISTER          = 0x06
PN532_COMMAND_WRITEREGISTER         = 0x08
PN532_COMMAND_READGPIO              = 0x0C
PN532_COMMAND_WRITEGPIO             = 0x0E
PN532_COMMAND_SETSERIALBAUDRATE     = 0x10
PN532_COMMAND_SETPARAMETERS         = 0x12
PN532_COMMAND_SAMCONFIGURATION      = 0x14
PN532_COMMAND_POWERDOWN             = 0x16
PN532_COMMAND_RFCONFIGURATION       = 0x32
PN532_COMMAND_RFREGULATIONTEST      = 0x58
PN532_COMMAND_INJUMPFORDEP          = 0x56
PN532_COMMAND_INJUMPFORPSL          = 0x46
PN532_COMMAND_INLISTPASSIVETARGET   = 0x4A
PN532_COMMAND_INATR                 = 0x50
PN532_COMMAND_INPSL                 = 0x4E
PN532_COMMAND_INDATAEXCHANGE        = 0x40
PN532_COMMAND_INCOMMUNICATETHRU     = 0x42
PN532_COMMAND_INDESELECT            = 0x44
PN532_COMMAND_INRELEASE             = 0x52
PN532_COMMAND_INSELECT              = 0x54
PN532_COMMAND_INAUTOPOLL            = 0x60
PN532_COMMAND_TGINITASTARGET        = 0x8C
PN532_COMMAND_TGSETGENERALBYTES     = 0x92
PN532_COMMAND_TGGETDATA             = 0x86
PN532_COMMAND_TGSETDATA             = 0x8E
PN532_COMMAND_TGSETMETADATA         = 0x94
PN532_COMMAND_TGGETINITIATORCOMMAND = 0x88
PN532_COMMAND_TGRESPONSETOINITIATOR = 0x90
PN532_COMMAND_TGGETTARGETSTATUS     = 0x8A

PN532_RESPONSE_INDATAEXCHANGE       = 0x41
PN532_RESPONSE_INLISTPASSIVETARGET  = 0x4B

PN532_WAKEUP                        = 0x55

PN532_SPI_STATREAD                  = 0x02
PN532_SPI_DATAWRITE                 = 0x01
PN532_SPI_DATAREAD                  = 0x03
PN532_SPI_READY                     = 0x01

PN532_MIFARE_ISO14443A              = 0x00

# Mifare Commands
MIFARE_CMD_AUTH_A                   = 0x60
MIFARE_CMD_AUTH_B                   = 0x61
MIFARE_CMD_READ                     = 0x30
MIFARE_CMD_WRITE                    = 0xA0
MIFARE_CMD_TRANSFER                 = 0xB0
MIFARE_CMD_DECREMENT                = 0xC0
MIFARE_CMD_INCREMENT                = 0xC1
MIFARE_CMD_STORE                    = 0xC2
MIFARE_ULTRALIGHT_CMD_WRITE         = 0xA2

# Prefixes for NDEF Records (to identify record type)
NDEF_URIPREFIX_NONE                 = 0x00
NDEF_URIPREFIX_HTTP_WWWDOT          = 0x01
NDEF_URIPREFIX_HTTPS_WWWDOT         = 0x02
NDEF_URIPREFIX_HTTP                 = 0x03
NDEF_URIPREFIX_HTTPS                = 0x04
NDEF_URIPREFIX_TEL                  = 0x05
NDEF_URIPREFIX_MAILTO               = 0x06
NDEF_URIPREFIX_FTP_ANONAT           = 0x07
NDEF_URIPREFIX_FTP_FTPDOT           = 0x08
NDEF_URIPREFIX_FTPS                 = 0x09
NDEF_URIPREFIX_SFTP                 = 0x0A
NDEF_URIPREFIX_SMB                  = 0x0B
NDEF_URIPREFIX_NFS                  = 0x0C
NDEF_URIPREFIX_FTP                  = 0x0D
NDEF_URIPREFIX_DAV                  = 0x0E
NDEF_URIPREFIX_NEWS                 = 0x0F
NDEF_URIPREFIX_TELNET               = 0x10
NDEF_URIPREFIX_IMAP                 = 0x11
NDEF_URIPREFIX_RTSP                 = 0x12
NDEF_URIPREFIX_URN                  = 0x13
NDEF_URIPREFIX_POP                  = 0x14
NDEF_URIPREFIX_SIP                  = 0x15
NDEF_URIPREFIX_SIPS                 = 0x16
NDEF_URIPREFIX_TFTP                 = 0x17
NDEF_URIPREFIX_BTSPP                = 0x18
NDEF_URIPREFIX_BTL2CAP              = 0x19
NDEF_URIPREFIX_BTGOEP               = 0x1A
NDEF_URIPREFIX_TCPOBEX              = 0x1B
NDEF_URIPREFIX_IRDAOBEX             = 0x1C
NDEF_URIPREFIX_FILE                 = 0x1D
NDEF_URIPREFIX_URN_EPC_ID           = 0x1E
NDEF_URIPREFIX_URN_EPC_TAG          = 0x1F
NDEF_URIPREFIX_URN_EPC_PAT          = 0x20
NDEF_URIPREFIX_URN_EPC_RAW          = 0x21
NDEF_URIPREFIX_URN_EPC              = 0x22
NDEF_URIPREFIX_URN_NFC              = 0x23

PN532_GPIO_VALIDATIONBIT            = 0x80
PN532_GPIO_P30                      = 0
PN532_GPIO_P31                      = 1
PN532_GPIO_P32                      = 2
PN532_GPIO_P33                      = 3
PN532_GPIO_P34                      = 4
PN532_GPIO_P35                      = 5

PN532_ACK_STRING                    = "0000ff00ff00"
PN532_ACK_FRAME                     = "\x00\x00\xFF\x00\xFF\x00"


def millis():
    return int(round(time.time() * 1000))

class PN532(object):

    def __init__(self, uart_port = "COM5", uart_baudrate = 115200):
        self.status = False
        self.message = ""

        print("Port:"+uart_port)
        try:
            self.ser = serial.Serial(uart_port, uart_baudrate)
            self.ser.timeout=2;
            self.status = True
        except serial.SerialException:
            print("Opening port error.")
            self.status = False

    def _uint8_add(self, a, b):
        """Add add two values as unsigned 8-bit values."""
        return ((a & 0xFF) + (b & 0xFF)) & 0xFF

    def _busy_wait_ms(self, ms):
        """Busy wait for the specified number of milliseconds."""
        start = time.time()
        delta = ms/1000.0
        while (time.time() - start) <= delta:
            pass

    def _write_frame(self, data):
        ack = False
        """Write a frame to the PN532 with the specified data bytearray."""
        assert data is not None and 0 < len(data) < 255, 'Data must be array of 1 to 255 bytes.'
        # Build frame to send as:
        # - Preamble (0x00)
        # - Start code  (0x00, 0xFF)
        # - Command length (1 byte)
        # - Command length checksum
        # - Command bytes
        # - Checksum
        # - Postamble (0x00)
        length = len(data)
        frame = bytearray(length+7)
        frame[0] = PN532_PREAMBLE
        frame[1] = PN532_STARTCODE1
        frame[2] = PN532_STARTCODE2
        frame[3] = length & 0xFF
        frame[4] = self._uint8_add(~length, 1)
        frame[5:-2] = data
        checksum = reduce(self._uint8_add, data, 0xFF)
        frame[-2] = ~checksum & 0xFF
        frame[-1] = PN532_POSTAMBLE
        # Send frame.
        # print("sendData: ", frame.hex())
        self.ser.flushInput()
        while(not ack):
            self.ser.write(frame)
            ack = self._ack_wait(1000)
            time.sleep(0.3)
        return ack


    def _ack_wait(self, timeout):
        ack=False
        rx_info=b""
        start_time = millis()
        current_time = start_time
        while((current_time - start_time) < timeout and not ack):
            time.sleep(0.12)
            rx_info += self.ser.read(self.ser.inWaiting())
            current_time = millis()
            # print("rx_info: ", rx_info.hex())
            if (PN532_ACK_STRING in rx_info.hex()):
                ack = True
        if(ack):
            if(len(rx_info)>6):
                # found index of pn322_ack_frame in rx_info and return the remaining bytes
                index = rx_info.hex().index(PN532_ACK_STRING)
                self.message = rx_info[index+6:]
            else:
                self.message = rx_info
            self.ser.flush()
            return ack
        else:
            self.message = ""
            return ack

    def _read_data(self, count):
        timeout = 1000
        rx_info=""
        if(self.message == ""):
            self._ack_wait(timeout)
        else:
            rx_info = self.message
        # print("_read_data rx_info: ", rx_info)
        return rx_info

    def _read_frame(self, length):
        """Read a response frame from the PN532 of at most length bytes in size.
        Returns the data inside the frame if found, otherwise raises an exception
        if there is an error parsing the frame.  Note that less than length bytes
        might be returned!
        """
        # Read frame with expected length of data.
        response = self._read_data(length+8)
        # Check frame starts with 0x01 and then has 0x00FF (preceeded by optional
        # zeros).
        # print("_read_frame response: ", response.hex())
        if not (PN532_ACK_STRING == response.hex()):
            if response[0] != 0x00:
                raise RuntimeError('Response frame does not start with 0x01!')
            # Swallow all the 0x00 values that preceed 0xFF.
            offset = 1
            while response[offset] == 0x00:
                offset += 1
                if offset >= len(response):
                    raise RuntimeError('Response frame preamble does not contain 0x00FF!')
            if response[offset] != 0xFF:
                raise RuntimeError('Response frame preamble does not contain 0x00FF!')
            offset += 1
            if offset >= len(response):
                    raise RuntimeError('Response contains no data!')
            # Check length & length checksum match.
            frame_len = response[offset]
            if (frame_len + response[offset+1]) & 0xFF != 0:
                raise RuntimeError('Response length checksum did not match length!')
            # Check frame checksum value matches bytes.
            checksum = reduce(self._uint8_add, response[offset+2:offset+2+frame_len+1], 0)
            if checksum != 0:
                raise RuntimeError('Response checksum did not match expected value!')
            # Return frame data.
            return response[offset+2:offset+2+frame_len]
        else:
            return "no_card"

    def wakeup(self):
        # write 555500000000000000000000000000000000FF03FDD414011700
        msg = bytearray([0x55, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x03, 0xFD, 0xD4, 0x14, 0x01, 0x17, 0x00])
        self.ser.write(msg)
        buff = self.ser.readline()
        # print(buff.hex())

    def call_function(self, command, response_length=0, params=[], timeout_sec=1):
        """Send specified command to the PN532 and expect up to response_length
        bytes back in a response.  Note that less than the expected bytes might
        be returned!  Params can optionally specify an array of bytes to send as
        parameters to the function call.  Will wait up to timeout_secs seconds
        for a response and return a bytearray of response bytes, or None if no
        response is available within the timeout.
        """
        # Build frame data with command and parameters.
        data = bytearray(2+len(params))
        data[0]  = PN532_HOSTTOPN532
        data[1]  = command & 0xFF
        data[2:] = params
        # Send frame and wait for response.
        if not self._write_frame(data):
            return None
        # Read response bytes.
        response = self._read_frame(response_length+2)
        # Check that response is for the called function.
        # print("call_function response", response)
        if not (response == "no_card"):
            if not (response[0] == PN532_PN532TOHOST and response[1] == (command+1)):
                raise RuntimeError('Received unexpected command response!')
            # Return response data.
            return response[2:]
        else:
            return response

    def begin(self):
        """Initialize communication with the PN532.  Must be called before any
        other calls are made against the PN532.
        """
        self.wakeup()

    def get_firmware_version(self):
        """Call PN532 GetFirmwareVersion function and return a tuple with the IC,
        Ver, Rev, and Support values.
        """
        response = self.call_function(PN532_COMMAND_GETFIRMWAREVERSION, 4)
        # print(response.hex())
        if response is None:
            raise RuntimeError('Failed to detect the PN532!  Make sure there is sufficient power (use a 1 amp or greater power supply), the PN532 is wired correctly to the device, and the solder joints on the PN532 headers are solidly connected.')
        return (response[0], response[1], response[2], response[3])

    def SAM_configuration(self):
        """Configure the PN532 to read MiFare cards."""
        # Send SAM configuration command with configuration for:
        # - 0x01, normal mode
        # - 0x14, timeout 50ms * 20 = 1 second
        # - 0x01, use IRQ pin
        # Note that no other verification is necessary as call_function will
        # check the command was executed as expected.
        self.call_function(PN532_COMMAND_SAMCONFIGURATION, params=[0x01, 0x14, 0x01])

    def read_passive_target(self, card_baud=PN532_MIFARE_ISO14443A, timeout_sec=1):
        """Wait for a MiFare card to be available and return its UID when found.
        Will wait up to timeout_sec seconds and return None if no card is found,
        otherwise a bytearray with the UID of the found card is returned.
        """
        # Send passive read command for 1 card.  Expect at most a 7 byte UUID.
        response = self.call_function(PN532_COMMAND_INLISTPASSIVETARGET,
                                      params=[0x01, card_baud],
                                      response_length=17)
        # print("read_passive_target response", response)
        # If no response is available return None to indicate no card is present.
        if response is None:
            return None
        if not (response == "no_card"):
            # Check only 1 card with up to a 7 byte UID is present.
            
            if response[0] == 0x00:
                return None
            if response[0] != 0x01:
                raise RuntimeError('More than one card detected!')
            if response[5] > 7:
                raise RuntimeError('Found card with unexpectedly long UID!')
            # Return UID of card.
            return response[6:6+response[5]]
        else:
            return response


    def mifare_classic_authenticate_block(self, uid, block_number, key_number, key):
        """Authenticate specified block number for a MiFare classic card.  Uid
        should be a byte array with the UID of the card, block number should be
        the block to authenticate, key number should be the key type (like
        MIFARE_CMD_AUTH_A or MIFARE_CMD_AUTH_B), and key should be a byte array
        with the key data.  Returns True if the block was authenticated, or False
        if not authenticated.
        """
        # Build parameters for InDataExchange command to authenticate MiFare card.
        uidlen = len(uid)
        keylen = len(key)
        params = bytearray(3+uidlen+keylen)
        params[0] = 0x01  # Max card numbers
        params[1] = key_number & 0xFF
        params[2] = block_number & 0xFF
        params[3:3+keylen] = key
        params[3+keylen:]  = uid
        # Send InDataExchange request and verify response is 0x00.
        response = self.call_function(PN532_COMMAND_INDATAEXCHANGE,
                                      params=params,
                                      response_length=1)
        return response[0] == 0x00

    def mifare_classic_read_block(self, block_number):
        """Read a block of data from the card.  Block number should be the block
        to read.  If the block is successfully read a bytearray of length 16 with
        data starting at the specified block will be returned.  If the block is
        not read then None will be returned.
        """
        # Send InDataExchange request to read block of MiFare data.
        response = self.call_function(PN532_COMMAND_INDATAEXCHANGE,
                                      params=[0x01, MIFARE_CMD_READ, block_number & 0xFF],
                                      response_length=17)
        # Check first response is 0x00 to show success.
        if response[0] != 0x00:
            return None
        # Return first 4 bytes since 16 bytes are always returned.
        return response[1:]

    def mifare_classic_write_block(self, block_number, data):
        """Write a block of data to the card.  Block number should be the block
        to write and data should be a byte array of length 16 with the data to
        write.  If the data is successfully written then True is returned,
        otherwise False is returned.
        """
        assert data is not None and len(data) == 16, 'Data must be an array of 16 bytes!'
        # Build parameters for InDataExchange command to do MiFare classic write.
        params = bytearray(19)
        params[0] = 0x01  # Max card numbers
        params[1] = MIFARE_CMD_WRITE
        params[2] = block_number & 0xFF
        params[3:] = data
        # Send InDataExchange request.
        response = self.call_function(PN532_COMMAND_INDATAEXCHANGE,
                                      params=params,
                                      response_length=1)
        return response[0] == 0x00
