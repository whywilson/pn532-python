"""
ntag_ndef.py  –  NDEF message encoder for pn532-python
Place in:  pn532-python/script/ntag_ndef.py
"""

import struct

# NFC Forum URI prefix table
_URI_PREFIXES = [
    "",                          # 0x00
    "http://www.",               # 0x01
    "https://www.",              # 0x02
    "http://",                   # 0x03
    "https://",                  # 0x04
    "tel:",                      # 0x05
    "mailto:",                   # 0x06
    "ftp://anonymous:anonymous@",# 0x07
    "ftp://ftp.",                # 0x08
    "ftps://",                   # 0x09
    "sftp://",                   # 0x0A
    "smb://",                    # 0x0B
    "nfs://",                    # 0x0C
    "ftp://",                    # 0x0D
    "dav://",                    # 0x0E
    "news:",                     # 0x0F
    "telnet://",                 # 0x10
    "imap:",                     # 0x11
    "rtsp://",                   # 0x12
    "urn:",                      # 0x13
    "pop:",                      # 0x14
    "sip:",                      # 0x15
    "sips:",                     # 0x16
    "tftp:",                     # 0x17
    "btspp://",                  # 0x18
    "btl2cap://",                # 0x19
    "btgoep://",                 # 0x1A
    "tcpobex://",                # 0x1B
    "irdaobex://",               # 0x1C
    "file://",                   # 0x1D
    "urn:epc:id:",               # 0x1E
    "urn:epc:tag:",              # 0x1F
    "urn:epc:pat:",              # 0x20
    "urn:epc:raw:",              # 0x21
    "urn:epc:",                  # 0x22
    "urn:nfc:",                  # 0x23
]


def _ndef_record(tnf: int, type_bytes: bytes, payload: bytes,
                 is_first: bool = True, is_last: bool = True) -> bytes:
    """Build a single NDEF record."""
    flags = tnf & 0x07
    if is_first:
        flags |= 0x80  # MB
    if is_last:
        flags |= 0x40  # ME
    payload_len = len(payload)
    type_len = len(type_bytes)
    if payload_len <= 255:
        flags |= 0x10  # SR
        return bytes([flags, type_len, payload_len]) + type_bytes + payload
    else:
        return bytes([flags, type_len]) + struct.pack(">I", payload_len) + type_bytes + payload


def tlv_wrap(ndef_message: bytes) -> bytes:
    """Wrap NDEF message in Type 3 TLV with terminator."""
    length = len(ndef_message)
    if length <= 254:
        return bytes([0x03, length]) + ndef_message + bytes([0xFE])
    else:
        return bytes([0x03, 0xFF]) + struct.pack(">H", length) + ndef_message + bytes([0xFE])


def pad_pages(data: bytes) -> bytes:
    """Pad to multiple of 4 bytes (one NTAG page)."""
    r = len(data) % 4
    return data + bytes(4 - r) if r else data


def encode_url(uri: str) -> bytes:
    """RTD_URI (TNF=1, type='U'). Strips longest matching URI prefix."""
    best_id, best_len = 0, 0
    for i, prefix in enumerate(_URI_PREFIXES[1:], start=1):
        if uri.lower().startswith(prefix.lower()) and len(prefix) > best_len:
            best_id, best_len = i, len(prefix)
    payload = bytes([best_id]) + uri[best_len:].encode("utf-8")
    return _ndef_record(0x01, b"U", payload)


def encode_text(text: str, lang: str = "en") -> bytes:
    """RTD_TEXT (TNF=1, type='T'). UTF-8 encoding."""
    lang_bytes = lang.encode("ascii")
    status = len(lang_bytes) & 0x3F  # UTF-8 flag=0
    payload = bytes([status]) + lang_bytes + text.encode("utf-8")
    return _ndef_record(0x01, b"T", payload)


def encode_vcard(name: str, tel: str = "", email: str = "",
                 org: str = "", url: str = "") -> bytes:
    """vCard 3.0 as MIME record (TNF=2, type='text/vcard')."""
    lines = ["BEGIN:VCARD", "VERSION:3.0", f"FN:{name}"]
    if org:
        lines.append(f"ORG:{org}")
    if tel:
        lines.append(f"TEL:{tel}")
    if email:
        lines.append(f"EMAIL:{email}")
    if url:
        lines.append(f"URL:{url}")
    lines.append("END:VCARD")
    payload = "\r\n".join(lines).encode("utf-8")
    return _ndef_record(0x02, b"text/vcard", payload)


def encode_wifi(ssid: str, password: str,
                auth: str = "WPA2", enc: str = "AES") -> bytes:
    """Wi-Fi credential as WFA WSC MIME record (TNF=2)."""
    AUTH_TYPES = {"OPEN": 0x0001, "WPA": 0x0002,
                  "WPA2": 0x0020, "WPAWPA2": 0x0022}
    ENC_TYPES  = {"NONE": 0x0001, "WEP": 0x0002, "TKIP": 0x0004,
                  "AES":  0x0008, "AESTKIP": 0x000C}

    def tlv(attr_id, value):
        return struct.pack(">HH", attr_id, len(value)) + value

    inner  = tlv(0x1045, ssid.encode("utf-8"))
    inner += tlv(0x1003, struct.pack(">H", AUTH_TYPES.get(auth.upper(), 0x0020)))
    inner += tlv(0x100F, struct.pack(">H", ENC_TYPES.get(enc.upper(),  0x0008)))
    inner += tlv(0x1027, password.encode("utf-8"))
    inner += tlv(0x1020, bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]))
    credential = tlv(0x100E, inner)
    return _ndef_record(0x02, b"application/vnd.wfa.wsc", credential)


def encode_raw(hex_str: str) -> bytes:
    """Pass-through: user supplies complete NDEF message as hex."""
    return bytes.fromhex(hex_str.replace(" ", "").replace(":", ""))


# ── NDEF decoder (for ntag read) ─────────────────────────────────────────────

_URI_PREFIXES_DECODE = _URI_PREFIXES  # same table

def _extract_ndef_from_tlv(data: bytes) -> bytes:
    """Strip NTAG page header (pages 0-3 = 16 bytes) and parse TLV to get NDEF message."""
    # Skip the first 4 pages (UID, lock, CC)
    i = 16
    while i < len(data):
        t = data[i]
        if t == 0xFE:  # terminator
            break
        if t == 0x00:  # null TLV
            i += 1
            continue
        if i + 1 >= len(data):
            break
        # length
        if data[i + 1] == 0xFF:
            if i + 4 > len(data):
                break
            length = (data[i + 2] << 8) | data[i + 3]
            value_start = i + 4
        else:
            length = data[i + 1]
            value_start = i + 2
        value_end = value_start + length
        if t == 0x03:  # NDEF message TLV
            return data[value_start:value_end]
        i = value_end
    return b''


def _decode_record(flags, rec_type, payload):
    """Decode a single NDEF record into a human-readable dict."""
    tnf = flags & 0x07

    # RTD Well-Known (TNF=1)
    if tnf == 0x01:
        if rec_type == b'U':
            prefix_id = payload[0] if payload else 0
            prefix = _URI_PREFIXES_DECODE[prefix_id] if prefix_id < len(_URI_PREFIXES_DECODE) else ""
            uri = prefix + payload[1:].decode('utf-8', errors='replace')
            return {'type': 'URI', 'value': uri}

        if rec_type == b'T':
            if not payload:
                return {'type': 'Text', 'value': ''}
            status = payload[0]
            lang_len = status & 0x3F
            lang = payload[1:1 + lang_len].decode('ascii', errors='replace')
            text = payload[1 + lang_len:].decode('utf-8', errors='replace')
            return {'type': 'Text', 'lang': lang, 'value': text}

        if rec_type == b'Sp':  # Smart Poster
            return {'type': 'SmartPoster', 'value': payload.hex().upper()}

    # MIME (TNF=2)
    if tnf == 0x02:
        mime = rec_type.decode('ascii', errors='replace')

        if mime.lower() == 'text/vcard':
            return {'type': 'vCard', 'value': payload.decode('utf-8', errors='replace')}

        if mime.lower() == 'application/vnd.wfa.wsc':
            fields = _decode_wsc(payload)
            return {'type': 'WiFi', 'value': fields}

        return {'type': f'MIME:{mime}', 'value': payload.decode('utf-8', errors='replace')}

    # Absolute URI (TNF=3)
    if tnf == 0x03:
        return {'type': 'AbsURI', 'value': payload.decode('utf-8', errors='replace')}

    # Unknown
    return {'type': f'TNF{tnf}:{rec_type.hex()}', 'value': payload.hex().upper()}


def _decode_wsc(data: bytes) -> dict:
    """Decode WFA WSC TLV into a readable dict."""
    NAMES = {
        0x1045: 'SSID', 0x1003: 'Auth', 0x100F: 'Enc',
        0x1027: 'Password', 0x1020: 'MAC', 0x100E: 'Credential',
    }
    AUTH = {0x0001:'OPEN', 0x0002:'WPA', 0x0020:'WPA2', 0x0022:'WPA/WPA2'}
    ENC  = {0x0001:'NONE', 0x0002:'WEP', 0x0004:'TKIP', 0x0008:'AES', 0x000C:'AES+TKIP'}
    result = {}
    i = 0
    while i + 4 <= len(data):
        attr = (data[i] << 8) | data[i+1]
        length = (data[i+2] << 8) | data[i+3]
        value = data[i+4:i+4+length]
        name = NAMES.get(attr)
        if name == 'Credential':
            result.update(_decode_wsc(value))
        elif name == 'SSID':
            result['SSID'] = value.decode('utf-8', errors='replace')
        elif name == 'Auth':
            v = (value[0] << 8 | value[1]) if len(value) >= 2 else 0
            result['Auth'] = AUTH.get(v, hex(v))
        elif name == 'Enc':
            v = (value[0] << 8 | value[1]) if len(value) >= 2 else 0
            result['Enc'] = ENC.get(v, hex(v))
        elif name == 'Password':
            result['Password'] = value.decode('utf-8', errors='replace')
        i += 4 + length
    return result


def parse_ndef_dump(raw_pages: bytes) -> list:
    """
    Parse a full NTAG page dump (starting from page 0) into a list of
    decoded record dicts.  Returns [] if no valid NDEF found.
    """
    ndef_msg = _extract_ndef_from_tlv(raw_pages)
    if not ndef_msg:
        return []

    records = []
    i = 0
    while i < len(ndef_msg):
        if i + 2 > len(ndef_msg):
            break
        flags = ndef_msg[i]
        type_len = ndef_msg[i + 1]
        sr = bool(flags & 0x10)

        if sr:
            if i + 3 > len(ndef_msg):
                break
            payload_len = ndef_msg[i + 2]
            header_size = 3
        else:
            if i + 6 > len(ndef_msg):
                break
            payload_len = int.from_bytes(ndef_msg[i+2:i+6], 'big')
            header_size = 6

        # id_len present?
        il = bool(flags & 0x08)
        id_len = ndef_msg[i + header_size] if il else 0
        header_size += (1 + id_len) if il else 0

        type_start   = i + header_size
        payload_start = type_start + type_len
        payload_end   = payload_start + payload_len

        if payload_end > len(ndef_msg):
            break

        rec_type = ndef_msg[type_start:type_start + type_len]
        payload  = ndef_msg[payload_start:payload_end]

        records.append(_decode_record(flags, rec_type, payload))
        i = payload_end

        if flags & 0x40:  # ME – Message End
            break

    return records
