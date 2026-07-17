import contextlib
import io
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from pn532_utils import ArgumentParserNoExit, ParserExitIntercept


class ArgumentParserHelpTest(unittest.TestCase):
    def test_help_stops_before_required_argument_validation(self):
        parser = ArgumentParserNoExit(prog="hf 15 gen2config")
        parser.description = "Set block size"
        parser.add_argument("-s", "--size", required=True)

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            with self.assertRaises(ParserExitIntercept):
                parser.parse_args(["-h"])

        self.assertTrue(parser.help_requested)
        self.assertEqual(output.getvalue().count("hf 15 gen2config"), 2)
        self.assertNotIn("required", output.getvalue())


if __name__ == "__main__":
    unittest.main()
