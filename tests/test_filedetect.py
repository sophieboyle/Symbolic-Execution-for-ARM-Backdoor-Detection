import unittest
from src.main import *


class TestFileDetectionOpen(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        analyser = Analyser("code-samples/file-access/file-open",
                                      {"string": [],
                                       "file_operation": {"fread": [],
                                                          "fwrite": [],
                                                          "fopen": []},
                                       },
                            None
                            )
        cls.results = analyser.run_symbolic_execution()
        cls.file_access_table = cls.results["file_access_table"]
        cls.files = ["/etc/passwd"]
        cls.operations = ["fopen"]

    def test_correct_file(self):
        if len(self.file_access_table) != len(self.files):
            self.fail("Files not detected correctly")
        else:
            for f in self.files:
                b = False
                if f in [k for k in self.file_access_table.keys()]:
                    b = True
                self.assertTrue(b)

    def test_correct_operation(self):
        for f in self.files:
            for op, b in self.file_access_table[f].items():
                if op in self.operations:
                    self.assertEqual(b, True)
                else:
                    self.assertEqual(b, False)


if __name__ == '__main__':
    unittest.main()
