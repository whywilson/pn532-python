def str_to_bytes(data):
    try:
        data = data.replace(" ", "")
        if len(data) % 2 != 0:
            data = "0" + data
        return bytes.fromhex(data)
    except ValueError:
        raise ValueError("Not valid hex")


def is_hex(data, length=None):
    if isinstance(data, bytes):
        return length is None or len(data) == length

    if length is not None and len(data) != length:
        return False

    return all(c in "0123456789abcdefABCDEF" for c in data)


def crc16A(data: bytes) -> bytes:
    crc = 0x6363  # Initial value for CRC-A

    for b in data:
        ch = b ^ (crc & 0xFF)
        ch = (ch ^ (ch << 4)) & 0xFF
        crc = (crc >> 8) ^ (ch << 8) ^ (ch << 3) ^ (ch >> 4)

    crc = crc & 0xFFFF
    return crc.to_bytes(2, byteorder="little")

def crc16Ccitt(data: bytes) -> bytes:
    crc_preset = 0xFFFF
    crc_poly = 0x8408
    
    crc = crc_preset 
    for b in data:
        crc = crc ^ b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ crc_poly
            else:
                crc >>= 1
    return (crc ^ crc_preset).to_bytes(2, byteorder="little")