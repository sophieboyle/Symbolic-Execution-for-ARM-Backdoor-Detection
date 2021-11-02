import angr
import argparse


class Analyser:
    def __init__(self, filename, authentication_identifiers):
        """
        string filename : The name of the binary to be analysed
        dict authentication_identifiers : dictionary with each key stating the type of\
                                        data which is considered an 'authentication\
                                        identifier'. Each key can be mapped to a list\
                                        of possible identifiers
        """
        self.filename = filename
        self.authentication_identifiers = authentication_identifiers
        self.project = project = angr.Project(filename)
        self.entry_state = project.factory.entry_state()
        self.cfg = project.analyses.CFG(fail_fast=True)
        print(self.authentication_identifiers["string"][0])

    def find_file_io(self, io_func_name, file_accessed):
        """
        io_funct_name : string name of function to identify
        file_accessed : the filename of the file that the function operates on
        Function that finds the address of IO to a given file. This will only work
        for binaries that haven't been stripped. Stripped binaries will require
        something like IDA's Fast Library Identification and Recognition Technology
        """
        function_addresses = []
        for a, f in self.cfg.kb.functions.items():
            print(f.__dir__)
            if (f.name == io_func_name):
                function_addresses.append(a)
        print(f'Function addresses are: {function_addresses}')

    def find_paths_to_auth_strings(self, sim, auth_strings):
        for auth_str in auth_strings:
            sim.explore(find=lambda s: bytes(auth_str, 'utf-8') in s.posix.dumps(1),
                    avoid=lambda s: b'Access denied' in s.posix.dumps(1))
            if sim.found:
                access_state = sim.found[0]
                print(f"Credentials for access string {auth_str}:\
                        {self.parse_solution_dump(access_state.posix.dumps(0))}")
            else:
                print("No solution")

    def run_symbolic_execution(self):
        sim = self.project.factory.simgr(self.entry_state)
        self.find_paths_to_auth_strings(sim, self.authentication_identifiers["string"])
        self.find_file_io("fopen", "help.txt")

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
        iterbytes = [bytestring[i:i+1] for i in range(len(bytestring))]
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
    args = parser.parse_args()
    return args.filename[0]


def read_bytes(filename):
    with open(filename, "rb") as f:
        bytes_str = f.read()
    return bytes_str


def main():
    filename = arg_parsing()
    analyser = Analyser(filename, {"string": ["Access granted"]})
    analyser.run_symbolic_execution()


if __name__ == '__main__':
    main()
