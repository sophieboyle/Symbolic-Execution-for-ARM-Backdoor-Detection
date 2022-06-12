import unittest
from src.main import *
from parameterized import parameterized_class


@parameterized_class([
    {"code_sample": "hidden-shell", "shell_strings_expected": ["/bin/sh"]},
    {"code_sample": "two-shell", "shell_strings_expected": ["/bin/sh", "/bin/ksh"]},
    {"code_sample": "shell", "shell_strings_expected": ["/bin/sh"]},
    {"code_sample": "no-shell", "shell_strings_expected": []},
])
class TestShellDetection(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        analyser = Analyser(f"tests/code-samples/shell-strings/{cls.code_sample}",
                            {"string": []},
                            None
                            )
        cls.results = analyser.run_symbolic_execution()
        cls.shell_strings = cls.results["shell_strings"]

    def test_shell_strings_found(self):
        if len(self.shell_strings_expected) != len(self.shell_strings):
            self.fail("Shell strings detected incorrectly")
        else:
            self.assertEqual(self.shell_strings_expected.sort(),
                             self.shell_strings.sort())


if __name__ == '__main__':
    unittest.main()
