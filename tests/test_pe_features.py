import unittest

import pefile

from pe_features import extract_pe_features


class TestPEFeatures(unittest.TestCase):
    def test_invalid_pe_raises(self):
        with self.assertRaises(pefile.PEFormatError):
            extract_pe_features(b"not-a-pe-file")


if __name__ == "__main__":
    unittest.main()
