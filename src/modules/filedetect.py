import angr

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
