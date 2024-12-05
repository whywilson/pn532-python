import enum


@enum.unique
class Command(enum.IntEnum):
    Diagnose = 0x00
    GetFirmwareVersion = 0x02
    GetGeneralStatus = 0x04
    ReadRegister = 0x06
    WriteRegister = 0x08
    ReadGPIO = 0x0C
    WriteGPIO = 0x0E
    SetSerialBaudRate = 0x10
    SetParameters = 0x12
    SAMConfiguration = 0x14
    PowerDown = 0x16
    RFConfiguration = 0x32
    RFRegulationTest = 0x58
    InJumpForDEP = 0x56
    InJumpForPSL = 0x46
    InListPassiveTarget = 0x4A
    InATR = 0x50
    InPSL = 0x4E
    InDataExchange = 0x40
    InCommunicateThru = 0x42
    InDeselect = 0x44
    InRelease = 0x52
    InSelect = 0x54
    InAutoPoll = 0x60
    TgInitAsTarget = 0x8C
    TgGetData = 0x86
    TgSetData = 0x8E


@enum.unique
class Pn532KillerCommand(enum.IntEnum):
    getEmulatorData = 0x1C
    setEmulatorData = 0x1E
    checkPn532Killer = 0xAA
    SetWorkMode = 0xAC
    GetSnifferLog = 0x20
    ClearSnifferLog = 0x22

BasicCapabilities = [
    "RootExit",
]

PN532Capabilities = [
    "HWConnect",
    "HWVersion",
    "HWWakeUp",
    "HWRaw",
    "HF14AScan",
    "HF14ARaw",
    "HfMfSetUid",
    "HfMfRdbl",
    "HfMfWrbl",
    "HfMfCview",
    "HfMfDump",
    "HfMfWipe",
    "NtagEmulate",
]
PN532KillerCapabilities = [
    "HWModeReader",
    "HWModeSniffer",
    "HWModeEmulator",
    "HF15Scan",
    "HF15Info",
    "HF15Rdbl",
    "HF15Wrbl",
    "HF15Raw",
    "HfSniffSetUid",
    "HF15Gen1Uid",
    "HF15Gen2Uid",
    "HF15Gen2Config",
    "HF15ESetUid",
    "HF15ESetBlock",
    "HF15ESetWriteProtect",
    "HF15ESetResvEasAfiDsfid",
    "HfMfEload",
    "HfMfEread",
    "LfScan",
    "LfEm410xESetId",
]

@enum.unique
class MifareCommand(enum.IntEnum):
    MfReadBlock = 0x30
    MfWriteBlock = 0xA0

class ApduCommand:
    C_APDU_CLA = 0
    C_APDU_INS = 1
    C_APDU_P1 = 2
    C_APDU_P2 = 3
    C_APDU_LC = 4
    C_APDU_DATA = 5
    C_APDU_P1_SELECT_BY_ID = 0x00
    C_APDU_P1_SELECT_BY_NAME = 0x04

    R_APDU_SW1_COMMAND_COMPLETE = 0x90
    R_APDU_SW2_COMMAND_COMPLETE = 0x00
    R_APDU_SW1_NDEF_TAG_NOT_FOUND = 0x6A
    R_APDU_SW2_NDEF_TAG_NOT_FOUND = 0x82
    R_APDU_SW1_FUNCTION_NOT_SUPPORTED = 0x6A
    R_APDU_SW2_FUNCTION_NOT_SUPPORTED = 0x81
    R_APDU_SW1_MEMORY_FAILURE = 0x65
    R_APDU_SW2_MEMORY_FAILURE = 0x81
    R_APDU_SW1_END_OF_FILE_BEFORE_REACHED_LE_BYTES = 0x62
    R_APDU_SW2_END_OF_FILE_BEFORE_REACHED_LE_BYTES = 0x82

    ISO7816_SELECT_FILE = 0xA4
    ISO7816_READ_BINARY = 0xB0
    ISO7816_UPDATE_BINARY = 0xD6


class NdefCommand:
    APPLICATION_NAME_V2 = [0, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01]
    NDEF_MAX_LENGTH = 0x64


@enum.unique
class TagFile(enum.IntEnum):
    NONE = 0
    CC = 1
    NDEF = 2


@enum.unique
class Status(enum.IntEnum):
    TimeoutError = -1
    HF_TAG_OK = 0x00  # IC card operation is successful
    HF_TAG_NO = 0x01  # IC card not found
    HF_ERR_STAT = 0x02  # Abnormal IC card communication
    HF_ERR_CRC = 0x03  # IC card communication verification abnormal
    HF_COLLISION = 0x04  # IC card conflict
    HF_ERR_BCC = 0x05  # IC card BCC error
    MF_ERR_AUTH = 0x06  # MF card verification failed
    HF_ERR_PARITY = 0x07  # IC card parity error
    HF_ERR_ATS = 0x08  # ATS should be present but card NAKed, or ATS too large

    # Some operations with low frequency cards succeeded!
    LF_TAG_OK = 0x40
    # Unable to search for a valid EM410X label
    EM410X_TAG_NO_FOUND = 0x41

    # The parameters passed by the BLE instruction are wrong, or the parameters passed
    # by calling some functions are wrong
    PAR_ERR = 0x60
    # The mode of the current device is wrong, and the corresponding API cannot be called
    DEVICE_MODE_ERROR = 0x66
    INVALID_CMD = 0x67
    SUCCESS = 0x68
    NOT_IMPLEMENTED = 0x69
    FLASH_WRITE_FAIL = 0x70
    FLASH_READ_FAIL = 0x71
    INVALID_SLOT_TYPE = 0x72

    def __str__(self):
        if self == Status.HF_TAG_OK:
            return "HF tag operation succeeded"
        elif self == Status.HF_TAG_NO:
            return "HF tag no found or lost"
        elif self == Status.HF_ERR_STAT:
            return "HF tag status error"
        elif self == Status.HF_ERR_CRC:
            return "HF tag data crc error"
        elif self == Status.HF_COLLISION:
            return "HF tag collision"
        elif self == Status.HF_ERR_BCC:
            return "HF tag uid bcc error"
        elif self == Status.MF_ERR_AUTH:
            return "HF tag auth fail"
        elif self == Status.HF_ERR_PARITY:
            return "HF tag data parity error"
        elif self == Status.HF_ERR_ATS:
            return "HF tag was supposed to send ATS but didn't"
        elif self == Status.LF_TAG_OK:
            return "LF tag operation succeeded"
        elif self == Status.EM410X_TAG_NO_FOUND:
            return "EM410x tag no found"
        elif self == Status.PAR_ERR:
            return "API request fail, param error"
        elif self == Status.DEVICE_MODE_ERROR:
            return "API request fail, device mode error"
        elif self == Status.INVALID_CMD:
            return "API request fail, cmd invalid"
        elif self == Status.SUCCESS:
            return "Device operation succeeded"
        elif self == Status.NOT_IMPLEMENTED:
            return "Some api not implemented"
        elif self == Status.FLASH_WRITE_FAIL:
            return "Flash write failed"
        elif self == Status.FLASH_READ_FAIL:
            return "Flash read failed"
        elif self == Status.INVALID_SLOT_TYPE:
            return "Invalid card type in slot"
        return "Invalid status"


@enum.unique
class SlotNumber(enum.IntEnum):
    SLOT_1 = 1
    SLOT_2 = 2
    SLOT_3 = 3
    SLOT_4 = 4
    SLOT_5 = 5
    SLOT_6 = 6
    SLOT_7 = 7
    SLOT_8 = 8

    @staticmethod
    def to_fw(index: int):  # can be int or SlotNumber
        # SlotNumber() will raise error for us if index not in slot range
        return SlotNumber(index).value - 1

    @staticmethod
    def from_fw(index: int):
        # SlotNumber() will raise error for us if index not in fw range
        return SlotNumber(index + 1)


@enum.unique
class TagSenseType(enum.IntEnum):
    # Unknown
    UNDEFINED = 0
    # 125 kHz
    LF = 1
    # 13.56 MHz
    HF = 2


@enum.unique
class MfcKeyType(enum.IntEnum):
    A = 0x60
    B = 0x61


@enum.unique
class TagSpecificType(enum.IntEnum):
    UNDEFINED = 0

    # old HL/LF common types, slots using these ones need to be migrated first
    OLD_EM410X = 1
    OLD_MIFARE_Mini = 2
    OLD_MIFARE_1024 = 3
    OLD_MIFARE_2048 = 4
    OLD_MIFARE_4096 = 5
    OLD_NTAG_213 = 6
    OLD_NTAG_215 = 7
    OLD_NTAG_216 = 8
    OLD_TAG_TYPES_END = 9

    # LF

    # ASK Tag-Talk-First      100
    # EM410x
    EM410X = 100
    # FDX-B
    # securakey
    # gallagher
    # PAC/Stanley
    # Presco
    # Visa2000
    # Viking
    # Noralsy
    # Jablotron

    # FSK Tag-Talk-First      200
    # HID Prox
    # ioProx
    # AWID
    # Paradox

    # PSK Tag-Talk-First      300
    # Indala
    # Keri
    # NexWatch

    # Reader-Talk-First       400
    # T5577
    # EM4x05/4x69
    # EM4x50/4x70
    # Hitag series

    TAG_TYPES_LF_END = 999

    # HF

    # MIFARE Classic series  1000
    MIFARE_Mini = 1000
    MIFARE_1024 = 1001
    MIFARE_2048 = 1002
    MIFARE_4096 = 1003
    # MFUL / NTAG series     1100
    NTAG_213 = 1100
    NTAG_215 = 1101
    NTAG_216 = 1102
    MF0ICU1 = 1103
    MF0ICU2 = 1104
    MF0UL11 = 1105
    MF0UL21 = 1106
    NTAG_210 = 1107
    NTAG_212 = 1108
    # MIFARE Plus series     1200
    # DESFire series         1300

    # ST25TA series          2000

    # HF14A-4 series         3000

    @staticmethod
    def list(exclude_meta=True):
        return [
            t
            for t in TagSpecificType
            if (
                t > TagSpecificType.OLD_TAG_TYPES_END
                and t != TagSpecificType.TAG_TYPES_LF_END
            )
            or not exclude_meta
        ]

    @staticmethod
    def list_hf():
        return [
            t for t in TagSpecificType.list() if (t > TagSpecificType.TAG_TYPES_LF_END)
        ]

    @staticmethod
    def list_lf():
        return [
            t
            for t in TagSpecificType.list()
            if (TagSpecificType.UNDEFINED < t < TagSpecificType.TAG_TYPES_LF_END)
        ]

    def __str__(self):
        if self == TagSpecificType.UNDEFINED:
            return "Undefined"
        elif self == TagSpecificType.EM410X:
            return "EM410X"
        elif self == TagSpecificType.MIFARE_Mini:
            return "Mifare Mini"
        elif self == TagSpecificType.MIFARE_1024:
            return "Mifare Classic 1k"
        elif self == TagSpecificType.MIFARE_2048:
            return "Mifare Classic 2k"
        elif self == TagSpecificType.MIFARE_4096:
            return "Mifare Classic 4k"
        elif self == TagSpecificType.NTAG_213:
            return "NTAG 213"
        elif self == TagSpecificType.NTAG_215:
            return "NTAG 215"
        elif self == TagSpecificType.NTAG_216:
            return "NTAG 216"
        elif self == TagSpecificType.MF0ICU1:
            return "Mifare Ultralight"
        elif self == TagSpecificType.MF0ICU2:
            return "Mifare Ultralight C"
        elif self == TagSpecificType.MF0UL11:
            return "Mifare Ultralight EV1 (640 bit)"
        elif self == TagSpecificType.MF0UL21:
            return "Mifare Ultralight EV1 (1312 bit)"
        elif self == TagSpecificType.NTAG_210:
            return "NTAG 210"
        elif self == TagSpecificType.NTAG_212:
            return "NTAG 212"
        elif self < TagSpecificType.OLD_TAG_TYPES_END:
            return "Old tag type, must be migrated! Upgrade fw!"
        return "Invalid"


@enum.unique
class MifareClassicWriteMode(enum.IntEnum):
    # Normal write
    NORMAL = 0
    # Send NACK to write attempts
    DENIED = 1
    # Acknowledge writes, but don't remember contents
    DECEIVE = 2
    # Store data to RAM, but not to ROM
    SHADOW = 3
    # Shadow requested, will be changed to SHADOW and stored to ROM
    SHADOW_REQ = 4

    @staticmethod
    def list(exclude_meta=True):
        return [
            m
            for m in MifareClassicWriteMode
            if m != MifareClassicWriteMode.SHADOW_REQ or not exclude_meta
        ]

    def __str__(self):
        if self == MifareClassicWriteMode.NORMAL:
            return "Normal"
        elif self == MifareClassicWriteMode.DENIED:
            return "Denied"
        elif self == MifareClassicWriteMode.DECEIVE:
            return "Deceive"
        elif self == MifareClassicWriteMode.SHADOW:
            return "Shadow"
        elif self == MifareClassicWriteMode.SHADOW_REQ:
            return "Shadow requested"
        return "None"


@enum.unique
class MifareClassicPrngType(enum.IntEnum):
    # the random number of the card response is fixed
    STATIC = 0
    # the random number of the card response is weak
    WEAK = 1
    # the random number of the card response is unpredictable
    HARD = 2

    def __str__(self):
        if self == MifareClassicPrngType.STATIC:
            return "Static"
        elif self == MifareClassicPrngType.WEAK:
            return "Weak"
        elif self == MifareClassicPrngType.HARD:
            return "Hard"
        return "None"


@enum.unique
class MifareClassicDarksideStatus(enum.IntEnum):
    OK = 0
    # Darkside can't fix NT (PRNG is unpredictable)
    CANT_FIX_NT = 1
    # Darkside try to recover a default key
    LUCKY_AUTH_OK = 2
    # Darkside can't get tag response enc(nak)
    NO_NAK_SENT = 3
    # Darkside running, can't change tag
    TAG_CHANGED = 4

    def __str__(self):
        if self == MifareClassicDarksideStatus.OK:
            return "Success"
        elif self == MifareClassicDarksideStatus.CANT_FIX_NT:
            return "Cannot fix NT (unpredictable PRNG)"
        elif self == MifareClassicDarksideStatus.LUCKY_AUTH_OK:
            return "Try to recover a default key"
        elif self == MifareClassicDarksideStatus.NO_NAK_SENT:
            return "Cannot get tag response enc(nak)"
        elif self == MifareClassicDarksideStatus.TAG_CHANGED:
            return "Tag changed during attack"
        return "None"


@enum.unique
class AnimationMode(enum.IntEnum):
    FULL = 0
    MINIMAL = 1
    NONE = 2

    def __str__(self):
        if self == AnimationMode.FULL:
            return "Full animation"
        elif self == AnimationMode.MINIMAL:
            return "Minimal animation"
        elif self == AnimationMode.NONE:
            return "No animation"


@enum.unique
class ButtonType(enum.IntEnum):
    A = ord("A")
    B = ord("B")


@enum.unique
class MfcKeyType(enum.IntEnum):
    A = 0x60
    B = 0x61


@enum.unique
class ButtonPressFunction(enum.IntEnum):
    NONE = 0
    NEXTSLOT = 1
    PREVSLOT = 2
    CLONE = 3
    BATTERY = 4

    def __str__(self):
        if self == ButtonPressFunction.NONE:
            return "No Function"
        elif self == ButtonPressFunction.NEXTSLOT:
            return "Select next slot"
        elif self == ButtonPressFunction.PREVSLOT:
            return "Select previous slot"
        elif self == ButtonPressFunction.CLONE:
            return "Read then simulate the ID/UID card number"
        elif self == ButtonPressFunction.BATTERY:
            return "Show Battery Level"
        return "None"


@enum.unique
class MfcValueBlockOperator(enum.IntEnum):
    DECREMENT = 0xC0
    INCREMENT = 0xC1
    RESTORE = 0xC2
