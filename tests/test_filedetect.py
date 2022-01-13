import unittest
from src.main import *
from parameterized import parameterized_class


@parameterized_class([
    {"code_sample": "file-open", "operations": {"/etc/passwd": ["fopen"]}},
    {"code_sample": "multiple-file-open", "operations": {"/etc/passwd": ["fopen"], "/etc/shadow": ["fopen"]}},
#    {"code_sample": "file-read", "operations": {"/etc/passwd": ["fopen", "fread"]}},
])
class TestFileDetection(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        analyser = Analyser(f"code-samples/file-access/{cls.code_sample}",
                            {"string": []},
                            None
                            )
        cls.results = analyser.run_symbolic_execution()
        cls.file_access_table = cls.results["file_access_table"]

    def test_correct_file(self):
        for f in self.operations.keys():
            b = False
            if f in [k for k in self.file_access_table.keys()]:
                b = True
            self.assertTrue(b)

    def test_correct_operation(self):
        # TODO: Refactor filedetect module to get rid of this nested loop
        for f, detected_ops in self.operations.items():
            for op, b in self.file_access_table[f].items():
                if op in detected_ops:
                    self.assertEqual(b, True)
                else:
                    self.assertEqual(b, False)


if __name__ == '__main__':
    unittest.main()
