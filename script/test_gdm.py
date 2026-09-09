from argparse import Namespace
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, call, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

from pn532_cmd import Pn532CMD
from pn532_cli_unit import HfMfGdmSetBlk, HfMfGdmSetCfg, HfMfGdmSetUid
from pn532_com import Response
from pn532_enum import Command, Status
from pn532_enum import PN532Capabilities
from pn532_utils import ArgsParserError
from unit.calc import crc16A


class GdmCommandTest(unittest.TestCase):
    def make_cmd(self):
        device = Mock()
        device.get_device_name.return_value = "PN532"
        return Pn532CMD(device), device

    def test_set_uid_is_exposed_by_pn532_capabilities(self):
        self.assertIn("HfMfGdmSetUid", PN532Capabilities)
        self.assertIn("HfMfInfo", PN532Capabilities)

    def test_info_prioritizes_gdm_magic_auth(self):
        cmd, device = self.make_cmd()
        device.get_device_name.return_value = "PN532Killer"
        tag = {
            "uid": bytes.fromhex("11223344556677"),
            "atqa": bytes.fromhex("0044"),
            "sak": b"\x08",
            "ats": b"",
        }
        nonce = bytes.fromhex("A06A0956")
        cmd.hf_14a_scan = Mock(return_value=[tag])
        cmd.hf_mf_gdm_probe_magic_auth = Mock(return_value=nonce)
        cmd._probe_gdm_wakeup_config = Mock(return_value=None)

        result = cmd.hf_mf_info()

        self.assertEqual(result["type"], "GDM / USCUID (Gen 4 GDM)")
        self.assertIn("nonce A06A0956", result["capabilities"][0])
        self.assertIn("cannot complete", result["limitations"][0])

    def test_pn532_info_reads_config_after_gdm_nonce_detection(self):
        cmd, _device = self.make_cmd()
        tag = {
            "uid": bytes.fromhex("11223344556677"),
            "atqa": bytes.fromhex("0044"),
            "sak": b"\x08",
            "ats": b"",
        }
        config = bytes.fromhex("8500000000005A00005A005A005A0008")
        cmd.hf_14a_scan = Mock(return_value=[tag])
        cmd._probe_gdm_wakeup_config = Mock(return_value=None)
        cmd.hf_mf_gdm_read = Mock(return_value=config)

        result = cmd.hf_mf_info()

        self.assertEqual(result["type"], "GDM / USCUID (Gen 4 GDM)")
        self.assertEqual(result["config"], config)
        cmd.hf_mf_gdm_read.assert_called_once_with(0xE0, mode="wupa")

    def test_info_distinguishes_gdm_gen1a_wakeup_from_gen1a(self):
        cmd, _device = self.make_cmd()
        tag = {
            "uid": bytes.fromhex("11223344"),
            "atqa": bytes.fromhex("0004"),
            "sak": b"\x08",
            "ats": b"",
        }
        config = bytes.fromhex("7AFF000000005A000000005A005A0008")
        cmd.hf_14a_scan = Mock(return_value=[tag])
        cmd.hf_mf_gdm_probe_magic_auth = Mock(return_value=None)
        cmd._probe_gdm_wakeup_config = Mock(side_effect=[None, config])

        result = cmd.hf_mf_info()

        self.assertEqual(result["type"], "GDM / USCUID (Gen 4 GDM)")
        self.assertEqual(result["config"], config)
        self.assertIn("40(7)/43", result["capabilities"][0])

    def test_gen3_probe_requires_valid_block_crc(self):
        cmd, _device = self.make_cmd()
        block = bytes.fromhex("11223344440804000011223344556677")
        cmd.hf_14a_scan = Mock(return_value=[{"uid": block[:4]}])
        cmd._select_iso14443a_raw = Mock(return_value=True)
        cmd.hf14a_raw = Mock(return_value=block + crc16A(block))
        cmd._restart_iso14443a_field = Mock()

        self.assertTrue(cmd._probe_gen3_direct_read())

        cmd.hf14a_raw = Mock(return_value=block + b"\x00\x00")
        self.assertFalse(cmd._probe_gen3_direct_read())

    def test_raw_select_validates_seven_byte_uid_cascades(self):
        cmd, _device = self.make_cmd()
        uid = bytes.fromhex("041219C3CC9802")
        cl1 = bytes.fromhex("8804121987")
        cl2 = bytes.fromhex("C3CC980295")
        cmd.hf14a_raw = Mock(
            side_effect=[
                bytes.fromhex("4400"),
                cl1,
                b"\x0C" + crc16A(b"\x0C"),
                cl2,
                b"\x08" + crc16A(b"\x08"),
            ]
        )

        self.assertTrue(cmd._select_iso14443a_raw(uid))

        sent = [entry.args[2] for entry in cmd.hf14a_raw.call_args_list]
        self.assertEqual(
            sent,
            [
                b"\x52",
                b"\x93\x20",
                b"\x93\x70" + cl1,
                b"\x95\x20",
                b"\x95\x70" + cl2,
            ],
        )

    def test_raw_select_accepts_killer_seven_bit_wupa_metadata(self):
        cmd, device = self.make_cmd()
        device.get_device_name.return_value = "PN532Killer"
        uid = bytes.fromhex("041219C3CC9802")
        cl1 = bytes.fromhex("8804121987")
        cl2 = bytes.fromhex("C3CC980295")
        cmd.hf14a_raw = Mock(
            side_effect=[
                bytes.fromhex("440102"),
                cl1,
                b"\x0C" + crc16A(b"\x0C"),
                cl2,
                b"\x08" + crc16A(b"\x08"),
            ]
        )

        self.assertTrue(cmd._select_iso14443a_raw(uid))

    def test_info_checks_gen3_before_gen1a(self):
        cmd, device = self.make_cmd()
        tag = {
            "uid": bytes.fromhex("11223344"),
            "atqa": bytes.fromhex("0004"),
            "sak": b"\x08",
            "ats": b"",
        }
        cmd.hf_14a_scan = Mock(return_value=[tag])
        cmd.hf_mf_gdm_read = Mock(side_effect=RuntimeError("not GDM"))
        cmd._probe_gdm_wakeup_config = Mock(return_value=None)
        cmd._probe_gen4_gtu = Mock(return_value=False)
        cmd._probe_gen3_direct_read = Mock(return_value=True)
        cmd._gdm_wakeup = Mock()

        result = cmd.hf_mf_info()

        self.assertEqual(result["type"], "Magic Gen3")
        cmd._gdm_wakeup.assert_not_called()
        device.halt.assert_not_called()

    def test_parses_factory_gdm_configuration(self):
        config = bytes.fromhex("850000000000000000005A5A00000008")

        parsed = Pn532CMD.parse_gdm_config(config)

        self.assertFalse(parsed["magic_wakeup_enabled"])
        self.assertEqual(parsed["wakeup_style"], "gen1a")
        self.assertTrue(parsed["shadow"])
        self.assertTrue(parsed["magic_auth"])
        self.assertEqual(parsed["sak"], 0x08)

    @patch("pn532_cmd.time.sleep")
    def test_restart_iso14443a_field_cycles_rf_without_selecting(self, _sleep):
        cmd, device = self.make_cmd()

        cmd._restart_iso14443a_field()

        self.assertEqual(
            device.send_cmd_sync.call_args_list,
            [
                call(Command.RFConfiguration, b"\x01\x00", timeout=0.5),
                call(Command.RFConfiguration, b"\x01\x01", timeout=0.5),
            ],
        )
        device.reset_register.assert_called_once_with()

    def test_magic_auth_uses_ciu_mfauthent_with_uid_tail(self):
        cmd, device = self.make_cmd()
        uid = bytes.fromhex("04CDE50002F4A9")
        cmd.hf_14a_scan = Mock(return_value=[{"uid": uid}])
        device.send_cmd_sync.side_effect = [
            Response(Command.WriteRegister, Status.SUCCESS),
            Response(Command.ReadRegister, Status.SUCCESS, b"\x14\x00\x08"),
        ]

        result = cmd._gdm_magic_auth()

        self.assertEqual(result, uid)
        write = device.send_cmd_sync.call_args_list[0]
        self.assertEqual(write.args[0], Command.WriteRegister)
        triples = [write.args[1][i : i + 3] for i in range(0, len(write.args[1]), 3)]
        fifo = bytes(triple[2] for triple in triples if triple[:2] == b"\x63\x39")
        self.assertEqual(fifo, b"\x80\x00" + bytes(6) + uid[-4:])

    def test_killer_magic_auth_reports_firmware_limitation_after_nonce(self):
        cmd, device = self.make_cmd()
        device.get_device_name.return_value = "PN532Killer"
        uid = bytes.fromhex("11223344556677")
        cmd.hf_14a_scan = Mock(return_value=[{"uid": uid}])
        cmd._gdm_magic_auth_nonce_active = Mock(
            return_value=bytes.fromhex("A06A0956")
        )

        with self.assertRaisesRegex(RuntimeError, "firmware does not expose"):
            cmd._gdm_magic_auth()

        cmd._gdm_magic_auth_nonce_active.assert_called_once_with()

    def test_gdm_nonce_probe_sends_8000_with_crc(self):
        cmd, device = self.make_cmd()
        nonce = bytes.fromhex("A06A0956")
        device.send_cmd_sync.return_value = Response(
            Command.InCommunicateThru, Status.HF_TAG_OK, nonce
        )

        result = cmd._gdm_magic_auth_nonce_active()

        self.assertEqual(result, nonce)
        device.send_cmd_sync.assert_called_once_with(
            Command.InCommunicateThru,
            b"\x80\x00" + crc16A(b"\x80\x00"),
            timeout=0.5,
        )

    def test_magic_auth_read_uses_hardware_crc_and_crypto(self):
        cmd, device = self.make_cmd()
        config = bytes.fromhex("8500000000005A00005A005A005A0008")
        cmd._gdm_magic_auth = Mock()
        cmd._restart_iso14443a_field = Mock()
        device.send_cmd_sync.return_value = Response(
            Command.InCommunicateThru, Status.HF_TAG_OK, config
        )

        result = cmd.hf_mf_gdm_read(0xE0, mode="wupa")

        self.assertEqual(result, config)
        device.send_cmd_sync.assert_called_once_with(
            Command.InCommunicateThru, b"\xE0\x00", timeout=1.0
        )
        cmd._restart_iso14443a_field.assert_called_once_with()

    def test_magic_auth_config_write_disables_rx_crc_for_four_bit_acks(self):
        cmd, device = self.make_cmd()
        config = bytes.fromhex("7AFF000000005A00005A005A005A0008")
        cmd._gdm_magic_auth = Mock()
        cmd._restart_iso14443a_field = Mock()
        cmd.hf_mf_gdm_read = Mock(return_value=config)
        device.send_cmd_sync.side_effect = [
            Response(Command.ReadRegister, Status.SUCCESS, b"\x80"),
            Response(Command.WriteRegister, Status.SUCCESS),
            Response(Command.InCommunicateThru, Status.HF_TAG_OK, b"\x0A"),
            Response(Command.InCommunicateThru, Status.HF_TAG_OK, b"\x0A"),
            Response(Command.WriteRegister, Status.SUCCESS),
        ]

        result = cmd._gdm_write_config_magic(config)

        self.assertEqual(result, config)
        self.assertEqual(
            device.send_cmd_sync.call_args_list[1],
            call(Command.WriteRegister, b"\x63\x03\x00", timeout=0.5),
        )
        self.assertEqual(
            device.send_cmd_sync.call_args_list[2],
            call(Command.InCommunicateThru, b"\xE1\x00", timeout=1.0),
        )
        self.assertEqual(
            device.send_cmd_sync.call_args_list[3],
            call(Command.InCommunicateThru, config, timeout=1.0),
        )
        self.assertEqual(
            device.send_cmd_sync.call_args_list[4],
            call(Command.WriteRegister, b"\x63\x03\x80", timeout=0.5),
        )

    def test_set_uid_bridges_magic_auth_only_card_through_gen1a(self):
        cmd, _device = self.make_cmd()
        old_uid = bytes.fromhex("04CDE50002F4A9")
        uid = bytes.fromhex("11223344556677")
        original_config = bytes.fromhex("8500000000005A00005A005A005A0008")
        temporary_config = bytes.fromhex("7AFF000000005A00005A005A005A0008")
        public = bytes.fromhex("11223344556677884400000000000000")
        hidden = bytes.fromhex("88112233880444556677000800000000")
        cmd.hf_mf_gdm_read = Mock(
            side_effect=[original_config, original_config, public]
        )
        cmd._gdm_write_config_magic = Mock(return_value=temporary_config)
        cmd.hf_mf_gdm_write = Mock(side_effect=[hidden, public, original_config])
        cmd._restart_iso14443a_field = Mock()
        cmd.hf_14a_scan = Mock(
            side_effect=[
                [{"uid": old_uid}],
                [{"uid": uid}],
                [{"uid": uid}],
                [{"uid": uid}],
            ]
        )

        result = cmd.hf_mf_gdm_set_uid(uid)

        self.assertEqual(result["uid"], uid)
        self.assertEqual(result["hidden_block"], hidden)
        self.assertEqual(result["public_block"], public)
        cmd._gdm_write_config_magic.assert_called_once_with(
            temporary_config, bytes(6)
        )
        self.assertEqual(
            cmd.hf_mf_gdm_write.call_args_list,
            [
                call(0xA8, 0, hidden, "gen1a"),
                call(0xA0, 0, public, "gen1a"),
                call(0xE1, 0, original_config, "gen1a"),
            ],
        )

    def test_set_uid_switches_from_seven_to_four_byte_mode(self):
        cmd, _device = self.make_cmd()
        old_uid = bytes.fromhex("11223344556677")
        uid = bytes.fromhex("11223344")
        original_config = bytes.fromhex("8500000000005A00005A005A005A0008")
        temporary_config = bytes.fromhex("7AFF000000005A00005A005A005A0008")
        final_config = bytes.fromhex("8500000000005A000000005A005A0008")
        public = bytes.fromhex("11223344440804000000000000000000")
        cmd.hf_mf_gdm_read = Mock(
            side_effect=[original_config, final_config, public]
        )
        cmd._gdm_write_config_magic = Mock(return_value=temporary_config)
        cmd.hf_mf_gdm_write = Mock(side_effect=[public, final_config])
        cmd._restart_iso14443a_field = Mock()
        cmd.hf_14a_scan = Mock(
            side_effect=[[{"uid": old_uid}], [{"uid": uid}]]
        )

        result = cmd.hf_mf_gdm_set_uid(uid)

        self.assertEqual(result["uid"], uid)
        self.assertIsNone(result["hidden_block"])
        self.assertEqual(result["public_block"], public)
        cmd._gdm_write_config_magic.assert_called_once_with(
            temporary_config, bytes(6)
        )
        self.assertEqual(
            cmd.hf_mf_gdm_write.call_args_list,
            [
                call(0xA0, 0, public, "gen1a"),
                call(0xE1, 0, final_config, "gen1a"),
            ],
        )

    def test_public_magic_write_bridges_and_restores_config(self):
        cmd, _device = self.make_cmd()
        data = bytes.fromhex("11223344556677884400112233445566")
        original_config = bytes.fromhex("8500000000005A00005A005A005A0008")
        temporary_config = bytes.fromhex("7AFF000000005A00005A005A005A0008")
        cmd.hf_mf_gdm_read = Mock(
            side_effect=[original_config, data, original_config]
        )
        cmd._gdm_write_config_magic = Mock(return_value=temporary_config)
        cmd.hf_mf_gdm_write = Mock(side_effect=[data, original_config])
        cmd._restart_iso14443a_field = Mock()
        cmd.hf_14a_scan = Mock(return_value=[{"uid": bytes.fromhex("11223344556677")}])

        result = cmd.hf_mf_gdm_write_public_magic(0, data)

        self.assertEqual(result, data)
        cmd._gdm_write_config_magic.assert_called_once_with(
            temporary_config, bytes(6)
        )
        self.assertEqual(
            cmd.hf_mf_gdm_write.call_args_list,
            [
                call(0xA0, 0, data, "gen1a"),
                call(0xE1, 0, original_config, "gen1a"),
            ],
        )

    @patch("pn532_cmd.time.sleep")
    def test_reads_config_after_gdm_wakeup(self, _sleep):
        cmd, device = self.make_cmd()
        config = bytes.fromhex("7AFF850102015A00005A005A005A0008")
        cmd.hf14a_raw = Mock(
            side_effect=[b"\x0A", b"\x0A", config + crc16A(config)]
        )

        result = cmd.hf_mf_gdm_read(0xE0, 0, "gdm")

        self.assertEqual(result, config)
        self.assertEqual(cmd.hf14a_raw.call_args_list[0].args[2], b"\x20")
        self.assertEqual(cmd.hf14a_raw.call_args_list[0].kwargs["bitlen"], 7)
        self.assertEqual(
            cmd.hf14a_raw.call_args_list[0].args[0]["activate_rf_field"], 1
        )
        self.assertEqual(cmd.hf14a_raw.call_args_list[1].args[2], b"\x23")
        self.assertEqual(cmd.hf14a_raw.call_args_list[2].args[2], b"\xE0\x00")
        device.halt.assert_called_once_with()

    @patch("pn532_cmd.time.sleep")
    def test_gen1a_wakeup_uses_40_and_43(self, _sleep):
        cmd, _device = self.make_cmd()
        data = bytes(range(16))
        cmd.hf14a_raw = Mock(
            side_effect=[b"\x0A", b"\x0A", data + crc16A(data)]
        )

        cmd.hf_mf_gdm_read(0x38, 7, "gen1a")

        self.assertEqual(cmd.hf14a_raw.call_args_list[0].args[2], b"\x40")
        self.assertEqual(cmd.hf14a_raw.call_args_list[1].args[2], b"\x43")
        self.assertEqual(cmd.hf14a_raw.call_args_list[2].args[2], b"\x38\x07")

    @patch("pn532_cmd.time.sleep")
    def test_failed_wakeup_still_halts_the_field(self, _sleep):
        cmd, device = self.make_cmd()
        cmd.hf14a_raw = Mock(return_value=b"")

        with self.assertRaisesRegex(RuntimeError, "wakeup step 1"):
            cmd.hf_mf_gdm_read(0xE0)

        device.halt.assert_called_once_with()

    @patch("pn532_cmd.time.sleep")
    def test_write_requires_exact_readback(self, _sleep):
        cmd, device = self.make_cmd()
        data = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
        cmd.hf14a_raw = Mock(
            side_effect=[
                b"\x0A",
                b"\x0A",
                b"\x0A",
                b"\x0A",
                data + crc16A(data),
            ]
        )

        result = cmd.hf_mf_gdm_write(0xA8, 3, data)

        self.assertEqual(result, data)
        sent = [entry.args[2] for entry in cmd.hf14a_raw.call_args_list]
        self.assertEqual(sent, [b"\x20", b"\x23", b"\xA8\x03", data, b"\x38\x03"])
        device.halt.assert_called_once_with()

    @patch("pn532_cmd.time.sleep")
    def test_write_rejects_mismatched_readback(self, _sleep):
        cmd, _device = self.make_cmd()
        data = bytes(16)
        other = bytes([1]) + bytes(15)
        cmd.hf14a_raw = Mock(
            side_effect=[
                b"\x0A",
                b"\x0A",
                b"\x0A",
                b"\x0A",
                other + crc16A(other),
            ]
        )

        with self.assertRaisesRegex(RuntimeError, "did not match"):
            cmd.hf_mf_gdm_write(0xA0, 1, data)

    def test_public_block_zero_write_requires_force(self):
        unit = HfMfGdmSetBlk()
        unit._device_cmd = Mock()

        with self.assertRaisesRegex(ArgsParserError, "require --force"):
            unit.on_exec(
                Namespace(
                    blk=0,
                    data="00" * 16,
                    force=False,
                    gen1a=False,
                    gdm=False,
                )
            )
        unit._device_cmd.hf_mf_gdm_write.assert_not_called()

    def test_public_block_wupa_uses_magic_bridge(self):
        unit = HfMfGdmSetBlk()
        unit._device_cmd = Mock()
        data = "11223344556677884400112233445566"

        unit.on_exec(
            Namespace(
                blk=0,
                data=data,
                force=True,
                gen1a=False,
                gdm=False,
                wupa=True,
                key="000000000000",
            )
        )

        unit._device_cmd.hf_mf_gdm_write_public_magic.assert_called_once_with(
            0, bytes.fromhex(data), key=bytes(6)
        )

    def test_config_write_requires_force(self):
        unit = HfMfGdmSetCfg()
        unit._device_cmd = Mock()

        with self.assertRaisesRegex(ArgsParserError, "require --force"):
            unit.on_exec(
                Namespace(
                    data="00" * 16,
                    force=False,
                    gen1a=False,
                    gdm=False,
                )
            )
        unit._device_cmd.hf_mf_gdm_write.assert_not_called()

    def test_uid_write_requires_force(self):
        unit = HfMfGdmSetUid()
        unit._device_cmd = Mock()

        with self.assertRaisesRegex(ArgsParserError, "require --force"):
            unit.on_exec(
                Namespace(
                    uid="11223344556677",
                    key="000000000000",
                    wupa=True,
                    force=False,
                )
            )
        unit._device_cmd.hf_mf_gdm_set_uid.assert_not_called()

    def test_uid_write_accepts_four_byte_uid(self):
        unit = HfMfGdmSetUid()
        unit._device_cmd = Mock()
        unit._device_cmd.hf_mf_gdm_set_uid.return_value = {
            "uid": bytes.fromhex("11223344"),
            "public_block": bytes.fromhex("1122334444080400" + "00" * 8),
            "config": bytes.fromhex("8500000000005A000000005A005A0008"),
        }

        unit.on_exec(
            Namespace(
                uid="11223344",
                key="000000000000",
                wupa=True,
                force=True,
            )
        )

        unit._device_cmd.hf_mf_gdm_set_uid.assert_called_once_with(
            bytes.fromhex("11223344"), key=bytes(6)
        )


if __name__ == "__main__":
    unittest.main()
