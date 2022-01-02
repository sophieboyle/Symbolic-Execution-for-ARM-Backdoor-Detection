from logging import raiseExceptions
import angr
import argparse
import socket
import struct
import re
from modules.netdetect import *


class FileIODetector:
    """
    This object takes a simulator, a function address, and a filename
    It will check if there's a state that reaches a function which operates
    on a specific file given by filename.
    """

    def __init__(self, sim, func_addr, filename):
        self.sim = sim
        self.func_addr = func_addr
        self.filename = filename

    def file_io_func_state(self, state):
        """
        Function which represents the state at which the instruction pointer points
        at the object's function address, and operates on the file defined by the object's
        filename
        """
        if state.ip.args[0] == self.func_addr:
            if state.mem[state.solver.eval(state.regs.r0)].string.concrete.decode("utf-8") \
                    == self.filename:
                return True
        return False

    def step_until_func_addr_in_rip(self, sim, addr):
        try:
            while sim.active[0].solver.eval(sim.active[0].regs.r15) != addr:
                sim.step()
                print(f"R15: {sim.active[0].regs.r15}, \
                        evaluated: {sim.active[0].solver.eval(sim.active[0].regs.r15)}")
            if sim.active[0].solver.eval(sim.active[0].regs.r15) == addr:
                print("Successfully stepped until r15 = function addr")
            else:
                print("Failed to step to function")
        except:
            print(f"Failed with sim.active {sim.active}")

    def find(self):
        self.sim.explore(find=self.file_io_func_state)
        print(f"Sim found {self.sim.found}")
        return self.sim.found[0].posix.dumps(0)


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


class Analyser:
    def __init__(self, filename, authentication_identifiers, output_file):
        """
        string filename : The name of the binary to be analysed
        dict authentication_identifiers : dictionary with each key stating the type of\
                                        data which is considered an 'authentication\
                                        identifier'. Each key can be mapped to a list\
                                        of possible identifiers
        """
        self.filename = filename
        self.output_file = output_file
        self.authentication_identifiers = authentication_identifiers
        self.output_string = ""
        self.project = angr.Project(filename, load_options={'auto_load_libs': False})
        self.entry_state = self.project.factory.entry_state()
        self.cfg = self.project.analyses.CFGEmulated(fail_fast=True)

    def find_func_addr(self, func_name):
        """
        io_funct_name : string name of function to identify
        file_accessed : the filename of the file that the function operates on
        Function that finds the address of IO to a given file. This will only work
        for binaries that haven't been stripped. Stripped binaries will require
        something like IDA's Fast Library Identification and Recognition Technology
        """
        nodes = [n for n in self.cfg.nodes() if n.name == func_name]
        call_addresses = [n.predecessors[0].predecessors[0].addr for n in
                          nodes]  # The addresses in main which call the given function
        return call_addresses

    def find_paths_to_auth_strings(self, sim, auth_strings):
        for auth_str in auth_strings:
            sim.explore(find=lambda s: bytes(auth_str, 'utf-8') in s.posix.dumps(1),
                        avoid=lambda s: b'Access denied' in s.posix.dumps(1))
            if sim.found:
                access_state = sim.found[0]
                print(f"Stdin resulting in printing of authentication string {auth_str}:\
                        {self.parse_solution_dump(access_state.posix.dumps(0))}")
            else:
                print("No solution")

    def write_results_to_file(self):
        with open(self.output_file, "w") as f:
            f.write(self.output_string)

    def run_symbolic_execution(self):
        sim = self.project.factory.simgr(self.entry_state)
        if self.authentication_identifiers["file_operation"]:

            for f_op in self.authentication_identifiers["file_operation"]:
                if self.authentication_identifiers["file_operation"][f_op]:

                    for f_string in self.authentication_identifiers["file_operation"][f_op]:
                        func_addrs = self.find_func_addr(f_op)

                        for func_addr in func_addrs:
                            # Insansiate File IO object
                            file_io_detector = FileIODetector(sim, func_addrs[0], f_string)
                            sol = file_io_detector.find()
                            print(f"Stdin resulting in {f_op} with file {f_string}: \
                                {self.parse_solution_dump(sol)}")

        if self.authentication_identifiers["string"]:
            for auth_str in self.authentication_identifiers["string"]:
                self.find_paths_to_auth_strings(sim, self.authentication_identifiers["string"])

        # Run network detection
        net_addresses = {"socket": self.find_func_addr('socket'),
                         "accept": self.find_func_addr('accept'),
                         "bind": self.find_func_addr('bind'),
                         "connect": self.find_func_addr("connect"),
                         "send": self.find_func_addr("send"),
                         "sendto": self.find_func_addr("sendto"),
                         "recvfrom": self.find_func_addr("recvfrom"),
                         "recv": self.find_func_addr("recv")}
        net_driver = NetworkDriver(self.project, self.entry_state, net_addresses,
                                   (self.authentication_identifiers["allowed_listening_ports"],
                                    self.authentication_identifiers["allowed_outbound_ports"]))
        net_driver.run_network_detection()
        net_driver.prune_non_malicious_comms()
        self.output_string += net_driver.output_network_information()

        # Detect shell commands
        shellcmd_detect = ShellCommandDetection(self.filename)
        shellcmd_detect.find()
        self.output_string += shellcmd_detect.output_shell_cmds_information()

        if self.output_file:
            self.write_results_to_file()

    def parse_solution_dump(self, bytestring):
        """
        A solution must be parsed since angr cannot work with fgets or scanf.
        This is because it cannot handle the dynamic number of values readable
        from scanf or fgets. It applies constraints based on the full size of 
        the buffer instead.

        This means that the normal results returned by access_state.posix.dumps(0))
        may be filled with garbage bytes after the null character. This function
        is simply a way of formatting the output such that the garbage bytes
        are not printed.

        This could result in an extra output being emitted as an error, since a
        garbage byte may by chance be an alphanumeric character.

        Run tool at least twice to identify undefined behaviour.

        TODO: Fix this by hooking fgets() functionality in angr?
        """
        results = []
        tmp = ''
        print(bytestring)
        iterbytes = [bytestring[i:i + 1] for i in range(len(bytestring))]
        for b in iterbytes:
            if b == b'\x00':
                results.append(tmp)
                tmp = ''
                continue
            try:
                tmp += b.decode('utf-8')
            except:
                pass
        return results


def arg_parsing():
    parser = argparse.ArgumentParser()
    parser.add_argument('filename', nargs=1,
                        help='Filename of firmware to analyse')
    parser.add_argument('--strings', nargs="+")
    parser.add_argument('--fread', nargs="+")
    parser.add_argument('--fwrite', nargs="+")
    parser.add_argument('--fopen', nargs="+")
    parser.add_argument('--allowed-inbound-ports', nargs="+")
    parser.add_argument('--allowed-outbound-ips', nargs="+")
    parser.add_argument('--allowed-outbound-ports', nargs="+")
    parser.add_argument('--output-file', nargs="?", default=None)
    args = parser.parse_args()
    get_listen_ports = lambda ports: [int(p) for p in ports] if ports != None else []
    get_outbound_ports = lambda ips, ports: zip(ips, ports) if ips != None and ports != None else []

    return (args.filename,
            {"string": args.strings,
             "file_operation": {"fread": args.fread,
                                "fwrite": args.fwrite,
                                "fopen": args.fopen},
             "allowed_listening_ports": get_listen_ports(args.allowed_inbound_ports),
             "allowed_outbound_ports": get_outbound_ports(args.allowed_outbound_ips,
                                                          args.allowed_outbound_ports),
             },
            args.output_file)


def read_bytes(filename):
    with open(filename, "rb") as f:
        bytes_str = f.read()
    return bytes_str


def main():
    filename, auth_ids, output_file = arg_parsing()
    analyser = Analyser(filename[0], auth_ids, output_file)
    analyser.run_symbolic_execution()


if __name__ == '__main__':
    main()
