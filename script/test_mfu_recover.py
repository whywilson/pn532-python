from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

from pn532_cmd import Pn532CMD
from pn532_com import Pn532Com, Response
from pn532_enum import Command, Pn532KillerCommand, Status
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

    def test_reader_mode_uses_killer_protocol_type_zero(self):
        device = Pn532Com()
        device.send_cmd_sync = Mock(return_value=Response(0xAC, Status.SUCCESS))

        device.set_work_mode()

        device.send_cmd_sync.assert_called_once_with(
            Pn532KillerCommand.SetWorkMode, [1, 0, 0]
        )

    @patch("pn532_cmd.time.sleep")
    def test_killer_select_skips_passive_scan_and_accepts_wupa_metadata(self, _sleep):
        device = Mock()
        device.get_device_name.return_value = "PN532Killer"
        device.set_work_mode.return_value = Response(0xAC, Status.SUCCESS, b"\x00")
        device.isOpen.return_value = True
        device.set_normal_mode.return_value = Response(
            Command.SAMConfiguration, Status.SUCCESS
        )
        cmd = Pn532CMD(device)
        cmd.hf14a_raw = Mock(
            side_effect=[
                bytes.fromhex("440102"),
                bytes.fromhex("88041122BF"),
                bytes.fromhex("04") + crc16A(b"\x04"),
                bytes.fromhex("33445566AA"),
                bytes.fromhex("00") + crc16A(b"\x00"),
            ]
        )

        tag = cmd._mfu_select_7b_uid_ignoring_bcc()

        self.assertEqual(tag["uid"], bytes.fromhex("04112233445566"))
        self.assertFalse(tag["bcc1_valid"])
        device.set_work_mode.assert_called_once_with()
        device.send_cmd_sync.assert_not_called()
        device.halt.assert_not_called()

    @patch("pn532_cmd.time.sleep")
    def test_killer_accepts_framing_status_only_after_readback(self, _sleep):
        uid = bytes.fromhex("04112233445566")
        before = bytes.fromhex("041122BF33445566AA480000E1101200")
        after = bytes.fromhex("041122BF3344556644480000E1101200")
        device = Mock()
        device.get_device_name.return_value = "PN532Killer"
        device.set_work_mode.return_value = Response(0xAC, Status.SUCCESS, b"\x00")
        device.isOpen.return_value = True
        device.set_normal_mode.return_value = Response(
            Command.SAMConfiguration, Status.SUCCESS
        )
        cmd = Pn532CMD(device)
        cmd._mfu_select_7b_uid_ignoring_bcc = Mock(
            return_value={
                "atqa": bytes.fromhex("4400"),
                "sak": b"\x00",
                "uid": uid,
                "cl1": bytes.fromhex("88041122BF"),
                "cl2": bytes.fromhex("33445566AA"),
                "bcc0_valid": True,
                "bcc1_valid": False,
            }
        )
        cmd.hf14a_raw = Mock(
            side_effect=[
                before + crc16A(before),
                b"\x05",
                b"\x05",
                b"\x05",
                after + crc16A(after),
            ]
        )
        cmd.hf_14a_scan = Mock(return_value=[{"uid": uid}])

        result = cmd.hf_mfu_recover_uid()

        self.assertTrue(result["written"])
        self.assertTrue(result["verified"])
        self.assertEqual(result["write_responses"], [b"\x05"] * 3)

    @patch("pn532_cmd.time.sleep")
    def test_killer_reader_mode_reconnects_after_transient_timeout(self, _sleep):
        device = Mock()
        device.port_string = "/dev/cu.pn532killer"
        device.set_work_mode.side_effect = [
            Response(0xAC, Status.TimeoutError),
            Response(0xAC, Status.SUCCESS, b"\x00"),
        ]
        device.isOpen.return_value = True
        device.set_normal_mode.return_value = Response(
            Command.SAMConfiguration, Status.SUCCESS
        )
        cmd = Pn532CMD(device)

        cmd._prepare_pn532killer_reader()

        device.close.assert_called_once_with()
        device.open.assert_called_once_with("/dev/cu.pn532killer")
        self.assertEqual(device.set_work_mode.call_count, 2)


if __name__ == "__main__":
    unittest.main()
