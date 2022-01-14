import angr


class FileAccessDetector:
    """
    This object takes a simulator, a function address, and a filename
    It will check if there's a state that reaches a function which operates
    on a specific file given by filename.
    """

    def __init__(self, project, entry_state, addr_to_func_map, filename):
        self.sim = project.factory.simgr(entry_state)
        self.addr_to_func_map = addr_to_func_map
        self.filename = filename
        self.result = {}
        self.currently_finding_func_name = None
        limiter = angr.exploration_techniques.lengthlimiter.LengthLimiter(max_length=100, drop=True)
        self.sim.use_technique(limiter)
        self.updated_file_pointer = None
        self.result = {"fopen": False, "fread": False, "fwrite": False}
        self.file_pointer = None

    def fopen_state(self, state):
        try:
            # try to extract the string argument
            filename_arg = state.mem[state.solver.eval(state.regs.r0)].string.concrete.decode("utf-8")
        except:
            return False
        if filename_arg == self.filename:
            self.result["fopen"] = True
            self.sim.step()
            self.sim.step()
            state = self.sim.active[0]
            self.file_pointer = state.solver.eval(state.regs.r0)
            return True
        else:
            return False

    def fread_state(self, state):
        # Check if the fourth argument is a recorded file pointer (access stack)
        f_ptr = state.solver.eval(state.regs.r3)
        if f_ptr == self.file_pointer:
            self.result["fread"] = True
            return True
        else:
            return False

    def fwrite_state(self, state):
        f_ptr = state.solver.eval(state.regs.r3)
        if f_ptr == self.file_pointer:
            self.result["fwrite"] = True
            return True
        else:
            return False

    def file_io_func_state(self, state):
        """
        Function which represents the state at which the instruction pointer points
        at the object's function address, and operates on the file defined by the object's
        filename
        """
        call_addr = state.ip.args[0]
        if call_addr in [k for k in self.addr_to_func_map]:
            self.sim.step()
            state = self.sim.active[0]
            if self.addr_to_func_map[call_addr] == 'fopen':
                self.fopen_state(state)
            elif self.addr_to_func_map[call_addr] == 'fread':
                self.fread_state(state)
            elif self.addr_to_func_map[call_addr] == 'fwrite':
                self.fwrite_state(state)
        # Hacky fix because for some reason, num_find for sim.explore doesn't work
        return False

    def find(self):
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
        self.addr_to_func_map = self.reformat_fileio_func_addresses()
        self.sensitive_files = self.get_sensitive_files('../resources/sensitive-files.csv')
        self.file_table = {}
        self.file_pointer_tracker = {}
        self.output_string = '-'*30+'\n'

    def get_sensitive_files(self, path):
        with open(path, 'r') as f:
            f.readline()
            file_list = f.read().splitlines()
        return file_list

    def reformat_fileio_func_addresses(self):
        addr_to_func_map = {}
        for f, address_list in self.fileio_func_addresses.items():
            for addr in address_list:
                addr_to_func_map[addr] = f
        return addr_to_func_map

    def run_file_detection(self):
        if self.fileio_func_addresses and self.sensitive_files:
            for filename in self.sensitive_files:
                filedetector = FileAccessDetector(self.project, self.entry_state,
                                                  self.addr_to_func_map, filename)
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
