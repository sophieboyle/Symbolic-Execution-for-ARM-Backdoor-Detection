import argparse
from src.modules.netdetect_v2 import *
from src.modules.shelldetect import *
from src.modules.filedetect import *


class Analyser:
    def __init__(self, filename, authentication_identifiers, output_file):
        """
        Initialises the analyser which runs all simulations
        :param string filename : The name of the binary to be analysed
        :param dict authentication_identifiers : dictionary with each key stating the type of\
                                        data which is considered an 'authentication\
                                        identifier'. Each key can be mapped to a list\
                                        of possible identifiers
        :param output_file : Name of the file to output results to
        """
        self.filename = filename
        self.output_file = output_file
        self.authentication_identifiers = authentication_identifiers
        self.project = angr.Project(filename, load_options={'auto_load_libs': False})
        self.project.hook_symbol('inet_addr', InetAddr())
        self.project.hook_symbol('inet_aton', InetAton())
        self.project.hook_symbol('inet_ntoa', InetNtoa())
        self.entry_state = self.project.factory.entry_state()
        self.cfg = self.project.analyses.CFGEmulated(fail_fast=True)
        self.output_string = ""
        self.results = {}

    def find_func_addr(self, func_name):
        # TODO: Double check that returning predeccors[0] isn't going to cause problems...
        """
        Function that finds the address of IO to a given file. This will only work
        for binaries that haven't been stripped. Stripped binaries will require
        something like IDA's Fast Library Identification and Recognition Technology
        :param io_funct_name : string name of function to identify
        :param file_accessed : the filename of the file that the function operates on
        :return: a list of addresses at which a function is called
        :return: a list of predecessor blocks which occur before the calling block of
        the given function
        """
        nodes = [n for n in self.cfg.nodes() if n.name == func_name]
        call_addresses = [n.predecessors[0].predecessors[0].addr for n in
                          nodes]  # The addresses in main which call the given function
        func_prelude_block_nodes = [n.predecessors[0].block for n in nodes]
        return call_addresses, func_prelude_block_nodes

    def find_post_blocks(self, func_name):
        """
        Finds the block after a given function. This block is important to ensure that
        it's possible to jump to the beginning of a block *after* a return value has been
        loaded into a register
        :param func_name: The function of which is the predecessor to the post block
        :return: The list of post blocks which follow the blocks which call the given
        function
        """
        # TODO: Double check that returning predeccors[0] isn't going to cause problems...
        # TODO: Find the block after a function (e.g. socket) is executed, so that we can get the return arg
        nodes = [n for n in self.cfg.nodes() if n.name == func_name]
        return [n.successors[0].block for n in nodes]

    def find_paths_to_auth_strings(self, sim, auth_strings):
        """
        Unused function
        :param sim:
        :param auth_strings:
        :return:
        """
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
        """
        Write output of analysis to file
        :return: None
        """
        with open(self.output_file, "w") as f:
            f.write(self.output_string)

    def get_addresses_and_blocks_for_func_names(self, func_names):
        """
        Gets the addresses, prelude blocks, and post blocks for all given function
        names
        :param func_names: List of strings (function names)
        :return: Dictionary of addresses formatted {function: [addresses]}
        :return: Dictionary of prelude blocks formatted {function: [blocks]}
        """
        addresses = {}
        prelude_blocks = {}
        for func in func_names:
            addrs, func_prelude_blocks = self.find_func_addr(func)
            addresses[func] = addrs
            prelude_blocks[func] = func_prelude_blocks
        return addresses, prelude_blocks

    def run_symbolic_execution(self):
        """
        Run the symbolic execution analysis for the given binary
        :return: A dictionary of the results in the format {detection_type: detecton_results}
        """
        sim = self.project.factory.simgr(self.entry_state)

        # Run file detection
        file_io_addresses, file_io_prelude_blocks = self.get_addresses_and_blocks_for_func_names(
                                                        ["fopen", "fwrite", "fread", "__isoc99_fscanf"])
        file_access_driver = FileAccessDriver(self.project, self.entry_state, file_io_addresses, file_io_prelude_blocks)
        self.results["file_access_table"] = file_access_driver.run_file_detection()
        self.output_string += file_access_driver.get_output_string()

        # Run network detection
        socket_post_blocks = self.find_post_blocks("socket")
        net_addresses, net_prelude_blocks = self.get_addresses_and_blocks_for_func_names(
                                                        ["socket", "accept", "bind",
                                                         "connect", "send", "sendto",
                                                         "recvfrom", "recv"])
        # net_driver = NetworkDriver(self.project, self.entry_state, net_addresses, net_prelude_blocks, socket_post_blocks)
        #self.results["network_table"] = net_driver.run_network_detection()
        #self.output_string += net_driver.get_output_string()

        net_driver = NetworkAnalysis(self.project, self.entry_state, self.cfg)
        self.results["network_table"] = net_driver.analyse()
        self.output_string += net_driver.build_output_string(self.results["network_table"])

        # Detect shell commands
        shellcmd_detect = ShellCommandDetection(self.filename)
        self.results["shell_strings"] = shellcmd_detect.find()
        self.output_string += shellcmd_detect.get_output_string()

        # Handle output
        if self.output_file:
            self.write_results_to_file()
        print(self.output_string)

        return self.results

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
    parser.add_argument('--output-file', nargs="?", default=None)
    args = parser.parse_args()

    return (args.filename,
            {"string": args.strings
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
