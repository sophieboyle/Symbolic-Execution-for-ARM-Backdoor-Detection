import re

class ShellCommandDetection:
    def __init__(self, binary):
        self.binary = binary
        self.strings = None
        self.out_string = ""

    def find_strings(self):
        with open(self.binary, errors="ignore") as f:
            content = f.read()
        self.strings = re.findall("[ -~]{4,}", content)
        return self.strings

    def check_for_shell_cmds(self):
        shell_cmds = ["/bin/sh", "/bin/ksh", "/bin/csh"]
        l = [s in self.strings for s in shell_cmds]
        result = []
        for i, e in enumerate(l):
            if e:
                result.append(shell_cmds[i])
        return result

    def get_output_string(self):
        return self.out_string

    def output_shell_cmds_information(self):
        print(self.out_string)
        return self.out_string

    def find(self):
        self.find_strings()
        result = self.check_for_shell_cmds()
        self.out_string += '-'*30+'\n'
        if result:
            self.out_string += f"Shell commands in binary: {len(result)}\nShell commands: {result}"
        else:
            self.out_string += f"No shell commands found in binary"
        return result