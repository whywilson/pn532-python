def str_to_bytes(data):
    try:
        data = data.replace(" ", "")
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
