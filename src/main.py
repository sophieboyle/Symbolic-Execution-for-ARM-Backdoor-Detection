from logging import raiseExceptions
import angr
import argparse
import socket
import struct

socket_type_reference = {1: "TCP (SOCK_STREAM)",
                    2: "UDP (SOCK_DGRAM)",
                    3: "SOCK_RAW",
                    4: "SOCK_RDM",
                    5: "SOCK_SEQPACKET",
                    6: "SOCK_DCCP",
                    10: "SOCK_PACKET"}

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
    def __init__(self, project, entry_state, func_name, func_addr, allowed_ports, socket_table):
        self.sim = project.factory.simgr(entry_state)
        self.func_name = func_name
        self.func_addr = func_addr
        self.allowed_ports = allowed_ports
        self.socket_table = socket_table
        self.found_undocumented_ports = []
        self.socket = None

        if func_name in ["bind", "connect"]:
            self.arg_register = 1
        elif func_name in ["send", "sendto"]:
            # Note: if IP dereferenced from sendto call is 0.0.0.0 on port 0, sockaddr for sendto is unknown
            # Most likely dependent on recieving some external information of where to sendto
            self.arg_register = 4
        else:
            raise ValueError("Unimplemented function name passed")

        limiter = angr.exploration_techniques.lengthlimiter.LengthLimiter(max_length=1000, drop=True)
        self.sim.use_technique(limiter)
        angr.types.register_types(angr.types.parse_type('struct in_addr{ uint32_t s_addr; }'))
        angr.types.register_types(angr.types.parse_type('struct sockaddr_in{ unsigned short sin_family; uint16_t sin_port; struct in_addr sin_addr; }'))

    def net_func_state(self, state):
        if (state.ip.args[0] == self.func_addr):
            self.sim.step()
            state = self.sim.active[0]

            self.socket = state.solver.eval(state.regs.r0)

            if self.arg_register == 1:
                sockaddr_param = state.mem[state.solver.eval(state.regs.r1)].struct.sockaddr_in.concrete
            elif self.arg_register == 4:
                sockaddr_param = state.mem[state.solver.eval(state.regs.r4)].struct.sockaddr_in.concrete
            else:
                raise ValueError("Unimplemented argument register")
            # The ip address in sin_addr.s_addr needs to be packed in little endian format
            # despite the fact that inet_ntoa converts from network byte order (big endian)
            # to a formatted IPv4 string. The register must store s_addr in little endian format
            # Otherwise, setting struct.pack to pack in big endian format results in the IP address
            # being printed backwards
            server_ip = socket.inet_ntoa(struct.pack('<I', sockaddr_param.sin_addr.s_addr))
            server_port = socket.ntohs(sockaddr_param.sin_port)

            if (server_ip, server_port) not in self.allowed_ports:
                self.found_undocumented_ports.append((server_ip, server_port))
                return True
            return True
        return False

    def find(self):
        self.sim.explore(find=self.net_func_state, num_find=3)
        # Using the socket table, identify which data stream is being used
        data_stream = socket_type_reference[self.socket_table[self.socket]]
        return self.found_undocumented_ports, data_stream


class SocketDetection():
    def __init__(self, project, entry_state, sock_addr):
        self.socket_fd = None
        self.socket_type = None
        self.project = project
        self.sim = project.factory.simgr(entry_state)
        self.sock_addr = sock_addr
        
    def socket_state(self, state):
        if (state.ip.args[0] == self.sock_addr):
            self.sim.step()
            state = self.sim.active[0]
            self.socket_type = state.solver.eval(state.regs.r1)
            # Step until end of function to find return value
            self.sim.step()
            self.sim.step()
            state = self.sim.active[0]
            self.socket_fd = state.solver.eval(state.regs.r0)
            return True
        return False

    def find_socket(self):
        self.sim.explore(find=self.socket_state)
        return (self.socket_fd, self.socket_type)


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
        call_addresses = [n.predecessors[0].predecessors[0].addr for n in nodes]  # The addresses in main which call the given function
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

    def run_network_detection(self):
        output_log = ""
        # Check for instances of bind
        bind_addrs = self.find_func_addr("bind")
        if bind_addrs:
            bind_info = self.investigate_network_functions("bind", bind_addrs, self.authentication_identifiers["allowed_listening_ports"])
            output_log += f"Found {len(bind_addrs)} instances of bind()\nListening on ports {bind_info}\n"
        else:
            output_log += "No instances of bind()\nNo listening ports detected\n"
        
        output_log += "-" * 30 + "\n"

        # Find connected sockets
        connect_addrs = self.find_func_addr("connect")
        if connect_addrs:
            connect_info = self.investigate_network_functions("connect", connect_addrs, self.authentication_identifiers["allowed_outbound_ports"])
            output_log += f"Found {len(connect_addrs)} instances of connect() \
                            \nConnecting to the following addresses and ports {connect_info}\n"
        else:
            output_log += "No instances of connect()\nNo connected sockets detected. However, UDP packets may still be being sent.\n"

        output_log += "-" * 30 + "\n"
            
        # Check if TCP: outbound TCP connections will have instances of send
        output_log += "Outbound TCP Information:\n"
        send_addrs = self.find_func_addr("send")
        if send_addrs:
            send_info = self.investigate_network_functions("send", send_addrs, self.authentication_identifiers["allowed_outbound_ports"])
            output_log += f"Found {len(send_addrs)} instances of send() \
                            \nSending TCP packets to the following addresses {send_info}\n"
        else:
            output_log+= "Found no instances of send()\n"

        output_log += "-" * 30 + "\n"

        # Check if UDP: outbound UDP packets will be sent via sendto()
        output_log += "Outbound UDP Information\n"
        sendto_addrs = self.find_func_addr("sendto")
        if sendto_addrs:
            sendto_info = self.investigate_network_functions("sendto", sendto_addrs, self.authentication_identifiers["allowed_outbound_ports"])
            output_log += f"Found {len(sendto_addrs)} instances of sendto\nSending UDP packets to the following addresses {sendto_info}\n"
        else:
            output_log += "Found n instances of sendto()\n"

        output_log += "-" * 30 + "\n"
        
        # Check for inbound UDP indications
        output_log += "Inbound UDP Information - Indications of the binary expecting inbound UDP traffic\n"
        recvfrom_addrs = self.find_func_addr("recvfrom")
        if recvfrom_addrs:
            output_log += f"Found {len(recvfrom_addrs)} instances of recvfrom. Expect inbound UDP traffic.\n"
        else:
            output_log += "No instances of recvfrom() found\n"

        return output_log

    def investigate_network_functions(self, net_func, func_addrs, allowed_list):
        undocumented_net = []
        if func_addrs:
            for addr in func_addrs:
                netdetect = NetworkDetection(self.project, self.entry_state, net_func, addr, allowed_list, self.socket_table)
                undocumented_ports, data_stream = netdetect.find()
                for result in undocumented_ports:
                    # if result not in undocumented_net:
                    undocumented_net.append((undocumented_ports, data_stream))
        return undocumented_net

    def find_sockets(self):
        # Check for sockets
        sock_addrs = self.find_func_addr("socket")
        print(f"sockaddrs: {sock_addrs}")
        socket_table = {}
        if sock_addrs:
            for addr in sock_addrs:
                sock_detector = SocketDetection(self.project, self.entry_state, addr)
                socket_info = sock_detector.find_socket()
                print(f"socket_info: {socket_info}")
                socket_table[socket_info[0]] = socket_info[1]
        return socket_table

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

        # Generate the socket table prior to running network detection
        self.socket_table = self.find_sockets()
        print(self.socket_table)
        print(self.run_network_detection())

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
