import angr


class FileAccessDetector:
    """
    This object takes a simulator, a function address, and a filename
    It will check if there's a state that reaches a function which operates
    on a specific file given by filename.
    """

    def __init__(self, project, entry_state, fileio_addresses, filename):
        self.sim = project.factory.simgr(entry_state)
        self.fileio_addresses = fileio_addresses
        self.filename = filename
        self.result = {}
        self.currently_finding_func_name = None
        for func_name in fileio_addresses.keys():
            self.result[func_name] = False
        limiter = angr.exploration_techniques.lengthlimiter.LengthLimiter(max_length=100, drop=True)
        self.sim.use_technique(limiter)

    def file_io_func_state(self, state):
        """
        Function which represents the state at which the instruction pointer points
        at the object's function address, and operates on the file defined by the object's
        filename
        """
        if state.ip.args[0] in self.fileio_addresses[self.currently_finding_func_name]:
            self.sim.step()
            state = self.sim.active[0]
            try:
                # try to extract the string argument
                filename_arg = state.mem[state.solver.eval(state.regs.r0)].string.concrete.decode("utf-8")
            except:
                return False

            if filename_arg == self.filename:
                self.result[self.currently_finding_func_name] = True
                return True
        return False

    def find(self):
        for func_name in self.fileio_addresses.keys():
            if self.fileio_addresses[func_name]:
                self.currently_finding_func_name = func_name
                self.sim.explore(find=self.file_io_func_state)
        return self.result


class FileAccessDriver:
    """
            fileio_addresses should be a dictionary of {func_name: [addresses]}

    """
    def __init__(self, project, entry_state, fileio_func_addresses):
        self.project = project
        self.entry_state = entry_state
        self.fileio_func_addresses = fileio_func_addresses
        self.sensitive_files = self.get_sensitive_files('../resources/sensitive-files.csv')
        self.file_table = {}
        self.output_string = '-'*30+'\n'

    def get_sensitive_files(self, path):
        with open(path, 'r') as f:
            f.readline()
            file_list = f.read().splitlines()
        return file_list

    def run_file_detection(self):
        if self.fileio_func_addresses and self.sensitive_files:
            for filename in self.sensitive_files:
                filedetector = FileAccessDetector(self.project, self.entry_state,
                                                  self.fileio_func_addresses, filename)
                file_accesses = filedetector.find()
                self.file_table[filename] = file_accesses
        self.construct_output_string()
        return self.file_table

    def construct_output_string(self):
        for filename, accesses in self.file_table.items():
            if all(v == False for v in self.file_table[filename].values()):
                continue
            self.output_string += f"{filename} is accessed: {[a for a, b in accesses.items() if b == True]}\n"
        if self.output_string == '-'*30+'\n':
            self.output_string += "No sensitive files were accessed\n"

    def output_file_information(self):
        print(self.output_string)

    def get_output_string(self):
        return self.output_string
