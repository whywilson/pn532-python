from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from pn532_cmd import Pn532CMD
from unit.calc import crc16A


class MfuRecoverTest(unittest.TestCase):
    def test_rebuilds_uid_pages_and_preserves_page2_tail(self):
        pages = Pn532CMD._mfu_uid_pages(
            bytes.fromhex("04112233445566"), bytes.fromhex("480000")
        )

        self.assertEqual(
            pages,
            [
                bytes.fromhex("041122BF"),
                bytes.fromhex("33445566"),
                bytes.fromhex("44480000"),
            ],
        )

    def test_rejects_non_7_byte_uid(self):
        with self.assertRaisesRegex(ValueError, "7 bytes"):
            Pn532CMD._mfu_uid_pages(bytes.fromhex("04112233"), b"\x00\x00\x00")

    def test_validates_iso14443a_response_crc(self):
        payload = bytes.fromhex("041122BF3344556644480000E1101200")

        self.assertEqual(
            Pn532CMD._require_iso14443a_crc(
                payload + crc16A(payload), len(payload), "READ page 0"
            ),
            payload,
        )
        with self.assertRaisesRegex(RuntimeError, "invalid CRC"):
            Pn532CMD._require_iso14443a_crc(
                payload + b"\x00\x00", len(payload), "READ page 0"
            )


if __name__ == "__main__":
    unittest.main()
