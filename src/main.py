import angr
import argparse
import socket
import struct


class FileIODetector():
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
        if (state.ip.args[0] == self.func_addr):
            if (state.mem[state.solver.eval(state.regs.r0)].string.concrete).decode("utf-8")\
                == self.filename:
                return True
        return False

    def step_until_func_addr_in_rip(self, sim, addr):
        try:
            while (sim.active[0].solver.eval(sim.active[0].regs.r15) != addr):
                sim.step()
                print(f"R15: {sim.active[0].regs.r15}, \
                        evaluated: {sim.active[0].solver.eval(sim.active[0].regs.r15)}")
            if (sim.active[0].solver.eval(sim.active[0].regs.r15) == addr):
                print("Successfully stepped until r15 = function addr")
            else:
                print("Failed to step to function")
        except:
            print(f"Failed with sim.active {sim.active}")

    def find(self):
        self.sim.explore(find=self.file_io_func_state)
        print(f"Sim found {self.sim.found}")
        return self.sim.found[0].posix.dumps(0)


class NetworkDetection():
    """
    Object will take a function address representative of
    the bind function. It will dump the sockaddr_in struct
    and check if the sin_port is in the allowed_ports list
    
    Mode option can choose between finding IP and ports to which outbound
    traffic is sent (sending), or finding ports on which the
    binary is listening (listening)

    If the mode is sending, the allowed_ports is a list of tuples (IP, port)
    If mode is listening, the allowed_ports is a list of ports
    """
    def __init__(self, sim, mode, func_addr, allowed_ports):
        self.sim = sim
        self.mode = mode
        self.func_addr = func_addr
        self.allowed_ports = allowed_ports
        self.found_undocumented_ports = []

        if mode != "sending" and mode != "listening":
            raise ValueError("NetworkDetection mode needs to be either sending or listening")
        
        limiter = angr.exploration_techniques.lengthlimiter.LengthLimiter(max_length=1000, drop=True)
        self.sim.use_technique(limiter)
        angr.types.register_types(angr.types.parse_type('struct in_addr{ uint32_t s_addr; }'))
        angr.types.register_types(angr.types.parse_type('struct sockaddr_in{ unsigned short sin_family; uint16_t sin_port; struct in_addr sin_addr; }'))
    
    def bind_func_state(self, state):
        if (state.ip.args[0] == self.func_addr):
            sockaddr_param = state.mem[state.solver.eval(state.regs.r1)].struct.sockaddr_in.concrete
            host_port = socket.ntohs(sockaddr_param.sin_port)
            if host_port not in self.allowed_ports:
                self.found_undocumented_ports.append(host_port)
                return True
        return False
    
    def connect_func_state(self, state):
        if (state.ip.args[0] == self.func_addr):
            print("Found connect function state")
            sockaddr_param = state.mem[state.solver.eval(state.regs.r1)].struct.sockaddr_in.concrete
            # The ip address in sin_addr.s_addr needs to be packed in little endian format
            # despite the fact that inet_ntoa converts from network byte order (big endian)
            # to a formatted IPv4 string. The register must store s_addr in little endian format
            # Otherwise, setting struct.pack to pack in big endian format results in the IP address
            # being printed backwards
            server_ip = socket.inet_ntoa(struct.pack('<I', sockaddr_param.sin_addr.s_addr))
            server_port = socket.ntohs(sockaddr_param.sin_port)
            print(f"{server_ip}: {server_port}")
            if (server_ip, server_port) not in self.allowed_ports:
                self.found_undocumented_ports.append((server_ip, server_port))
                return True
            return True
        return False

    def find(self):
        if (self.mode == "listening"):
            self.sim.explore(find=self.bind_func_state)
        elif (self.mode == "sending"):
            self.sim.explore(find=self.connect_func_state)
        return self.found_undocumented_ports


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
        self.project = angr.Project(filename)
        self.entry_state = self.project.factory.entry_state()
        self.cfg = self.project.analyses.CFG(fail_fast=True)

    def find_func_addr(self, func_name):
        """
        io_funct_name : string name of function to identify
        file_accessed : the filename of the file that the function operates on
        Function that finds the address of IO to a given file. This will only work
        for binaries that haven't been stripped. Stripped binaries will require
        something like IDA's Fast Library Identification and Recognition Technology
        """
        function_addresses = []
        for a, f in self.cfg.kb.functions.items():
            if (f.name == func_name):
                function_addresses.append(a)
        return function_addresses

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

        # Passing the simulation manager to netdetectin first seems to prevent the sim manager from finding
        # states correctly when passed in again to netdetectout
        # Must find a way to copy sim manager
        """
        bind_addr = self.find_func_addr("bind")
        if bind_addr:
            netdetectin = NetworkDetection(sim, "listening", bind_addr[0], self.authentication_identifiers["allowed_listening_ports"])
            undocumented_ports = netdetectin.find()
            print(f"Undocumented network ports listening: {undocumented_ports}")
        """

        connect_addr = self.find_func_addr("connect")
        if connect_addr:
            for addr in connect_addr:
                netdetectout = NetworkDetection(sim, "sending", connect_addr[0], self.authentication_identifiers["allowed_outbound_ports"])
                undocumented_ports_out = netdetectout.find()
                if len(undocumented_ports_out) > 0:
                    print(f"Undocumented network traffic outbound: {undocumented_ports_out}")

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
    parser.add_argument('--strings', nargs="+")
    parser.add_argument('--fread', nargs="+")
    parser.add_argument('--fwrite', nargs="+")
    parser.add_argument('--fopen', nargs="+")
    parser.add_argument('--allowed-inbound-ports', nargs="+")
    parser.add_argument('--allowed-outbound-ips', nargs="+")
    parser.add_argument('--allowed-outbound-ports', nargs="+")
    args = parser.parse_args()
    get_listen_ports = lambda ports : [int(p) for p in ports] if ports!=None else []
    get_outbound_ports = lambda ips, ports : zip(ips, ports) if ips != None and ports !=None else []

    return (args.filename,
            {"string": args.strings,
                "file_operation": {"fread": args.fread,
                                    "fwrite": args.fwrite,
                                    "fopen": args.fopen},
                "allowed_listening_ports": get_listen_ports(args.allowed_inbound_ports),
                "allowed_outbound_ports": get_outbound_ports(args.allowed_outbound_ips,
                                                        args.allowed_outbound_ports),
            })


def read_bytes(filename):
    with open(filename, "rb") as f:
        bytes_str = f.read()
    return bytes_str


def main():
    filename, auth_ids = arg_parsing()
    print(auth_ids)

    analyser = Analyser(filename[0], auth_ids)
    analyser.run_symbolic_execution()


if __name__ == '__main__':
    main()
