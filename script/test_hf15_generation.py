import unittest
from unittest.mock import Mock
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from pn532_cmd import Pn532CMD


class HF15GenerationTests(unittest.TestCase):
    def setUp(self):
        self.cmd = object.__new__(Pn532CMD)
        self.info = {
            "uid": bytes.fromhex("E004112233445566"),
            "block_size": 32,
            "ic_reference": 0x01,
        }

    def test_detects_gen3_before_hidden_uid_probe(self):
        self.cmd.hf_15_check_gen3 = Mock(return_value=(True, None))
        self.cmd.hf_15_read_block = Mock()

        self.assertEqual(self.cmd.hf_15_get_generation(self.info), "Gen3")
        self.cmd.hf_15_check_gen3.assert_called_once_with(self.info)
        self.cmd.hf_15_read_block.assert_not_called()

    def test_detects_gen1_from_hidden_uid_blocks(self):
        self.cmd.hf_15_check_gen3 = Mock(return_value=(False, "not Gen3"))
        self.cmd.hf_15_read_block = Mock(
            side_effect=[
                self.info["uid"][4:][::-1],
                self.info["uid"][:4][::-1],
            ]
        )

        self.assertEqual(self.cmd.hf_15_get_generation(self.info), "Gen1")
        self.assertEqual(
            self.cmd.hf_15_read_block.call_args_list,
            [unittest.mock.call(32), unittest.mock.call(33)],
        )

    def test_detects_28_block_gen1_with_write_only_uid_blocks(self):
        self.info.update(
            uid=bytes.fromhex("E004015000000061"),
            block_size=28,
            ic_reference=0x01,
        )
        self.cmd.hf_15_check_gen3 = Mock(return_value=(False, "not Gen3"))
        self.cmd.hf_15_read_block = Mock()

        self.assertEqual(self.cmd.hf_15_get_generation(self.info), "Gen1")
        self.cmd.hf_15_read_block.assert_not_called()

    def test_falls_back_to_gen2_without_destructive_probe(self):
        self.cmd.hf_15_check_gen3 = Mock(return_value=(False, "not Gen3"))
        self.cmd.hf_15_read_block = Mock(side_effect=[None, None])

        self.assertEqual(self.cmd.hf_15_get_generation(self.info), "Gen2")

    def test_gen1_uid_write_restarts_field_and_verifies_uid(self):
        uid = bytes.fromhex("E011223344556671")
        self.cmd.hf_15_write_block = Mock(side_effect=[True, True])
        self.cmd._restart_iso14443a_field = Mock()
        self.cmd.hf_15_scan = Mock(return_value=[{"uid": uid.hex()}])

        self.assertTrue(self.cmd.hf_15_set_gen1_uid(uid, 28))
        self.assertEqual(
            self.cmd.hf_15_write_block.call_args_list,
            [
                unittest.mock.call(28, uid[4:][::-1]),
                unittest.mock.call(29, uid[:4][::-1]),
            ],
        )
        self.cmd._restart_iso14443a_field.assert_called_once_with()

    def test_gen1_uid_write_does_not_report_unverified_success(self):
        uid = bytes.fromhex("E011223344556671")
        self.cmd.hf_15_write_block = Mock(side_effect=[True, True])
        self.cmd._restart_iso14443a_field = Mock()
        self.cmd.hf_15_scan = Mock(
            return_value=[{"uid": "E004015000000061"}]
        )

        self.assertFalse(self.cmd.hf_15_set_gen1_uid(uid, 28))


if __name__ == "__main__":
    unittest.main()
