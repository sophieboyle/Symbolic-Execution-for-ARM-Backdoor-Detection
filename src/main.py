from logging import raiseExceptions
import angr
import argparse
import socket
import struct
import re

socket_type_reference = {1: "TCP (SOCK_STREAM)",
                         2: "UDP (SOCK_DGRAM)",
                         3: "SOCK_RAW",
                         4: "SOCK_RDM",
                         5: "SOCK_SEQPACKET",
                         6: "SOCK_DCCP",
                         10: "SOCK_PACKET"}


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


class InetAddr(angr.SimProcedure):
    def run(self, addr):
        ip_string = self.state.mem[self.state.solver.eval(addr.to_claripy())].string.concrete.decode('utf-8')
        ip_int = struct.unpack("<I", socket.inet_aton(ip_string))[0]
        return ip_int


class NetworkDetection:
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
        self.socket = None
        self.ip = None
        self.port = None
        self.size = None

        if func_name in ["bind", "connect"]:
            self.arg_register = 1
        elif func_name in ["send", "sendto"]:
            # Note: if IP dereferenced from sendto call is 0.0.0.0 on port 0, sockaddr for sendto is unknown
            # Most likely dependent on recieving some external information of where to sendto
            self.arg_register = 4
        elif func_name in ["recvfrom", "recv"]:
            self.arg_register = None
        else:
            raise ValueError("Unimplemented function name passed")

        limiter = angr.exploration_techniques.lengthlimiter.LengthLimiter(max_length=1000, drop=True)
        self.sim.use_technique(limiter)
        angr.types.register_types(angr.types.parse_type('struct in_addr{ uint32_t s_addr; }'))
        angr.types.register_types(angr.types.parse_type(
            'struct sockaddr_in{ unsigned short sin_family; uint16_t sin_port; struct in_addr sin_addr; }'))

    def net_func_state(self, state):
        if state.ip.args[0] == self.func_addr:
            self.sim.step()
            state = self.sim.active[0]

            self.socket = state.solver.eval(state.regs.r0)

            if self.func_name in ["bind", "connect"]:
                # Get IP and port from r1
                sockaddr_param = state.mem[state.solver.eval(state.regs.r1)].struct.sockaddr_in.concrete
            elif self.func_name in ["send"]:
                # Get the size of the transmission
                self.size = state.solver.eval(state.regs.r2)
                # IP and port is associated with the socket
                self.ip = self.socket_table[self.socket]["ip"]
                self.port = self.socket_table[self.socket]["port"]
                return True
            elif self.func_name in ["sendto"]:
                # Get the size of the transmission
                self.size = state.solver.eval(state.regs.r2)
                # Determine if sendto() is in connection or connectionless mode
                # If in connection mode, get IP and port from socket's connect call
                # If in connectionless mode, get IP and port from r4
                if self.socket_table[self.socket]["type"] in [socket_type_reference[1], socket_type_reference[5]]:
                    # Connection mode
                    self.ip = self.socket_table[self.socket]["ip"]
                    self.port = self.socket_table[self.socket]["port"]
                    return True
                else:
                    sockaddr_param = state.mem[state.mem[state.solver.eval(state.regs.sp)].int.concrete].struct.sockaddr_in.concrete
            elif self.func_name in ["recvfrom", "recv"]:
                # Also get the size of the transmission
                self.size = state.solver.eval(state.regs.r2)
                # Get ip and port information from socket
                self.ip = self.socket_table[self.socket]["ip"]
                self.port = self.socket_table[self.socket]["port"]
                return True
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
                self.ip = server_ip
                self.port = server_port
                return True
            return True
        return False

    def find(self):
        self.sim.explore(find=self.net_func_state)
        return {"ip": self.ip,
                "port": self.port,
                "socket": self.socket,
                "size": self.size}


class SocketDetection:
    def __init__(self, project, entry_state, sock_addr):
        self.socket_fd = None
        self.socket_type = None
        self.project = project
        self.sim = project.factory.simgr(entry_state)
        self.sock_addr = sock_addr

    def socket_state(self, state):
        if state.ip.args[0] == self.sock_addr:
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
        return self.socket_fd, self.socket_type


class AcceptDetection:
    def __init__(self, project, entry_state, sock_addr, socket_table):
        self.socket_table = socket_table
        self.socket_fd = None
        self.socket_type = None
        self.project = project
        self.sim = project.factory.simgr(entry_state)
        self.sock_addr = sock_addr

    def socket_state(self, state):
        if state.ip.args[0] == self.sock_addr:
            self.sim.step()
            state = self.sim.active[0]
            # Can automatically assign the socket type as SOCK_STREAM
            self.socket_type = 1
            # Step until end of function to find return value
            self.sim.step()
            self.sim.step()
            state = self.sim.active[0]
            self.socket_fd = state.solver.eval(state.regs.r0)
            return True
        return False

    def find_socket(self):
        self.sim.explore(find=self.socket_state)
        return self.socket_fd, self.socket_type


class NetworkDriver:
    """
        Produces a network table of the format
        { (ip, port):
            {'bind': [SOCKET_TYPE],
            'connect': [SOCKET_TYPE],
            'send':, [SOCKET_TYPE],
            'sendto': [SOCKET_TYPE],
            'recvfrom': [SOCKET_TYPE]
        }
    """

    def __init__(self, project, entry_state, addresses, allowed_ports):
        self.project = project
        self.project.hook_symbol('inet_addr', InetAddr())
        self.entry_state = entry_state
        self.addresses = addresses
        self.allowed_inbound, self.allowed_outbound = allowed_ports
        self.socket_table = self.find_sockets()
        self.network_table = {}
        self.malicious_ips = self.get_malicious_net('../resources/bad-ips.csv')
        self.malicious_ports = self.get_malicious_net('../resources/bad-ports.csv')

    def get_malicious_net(self, filename):
        with open(filename, 'r') as f:
            f.readline()
            netlist = f.read().splitlines()
        return netlist

    def update_socket_info(self, func_call, info):
        self.socket_table[info["socket"]]["function_calls"][func_call] += 1
        # Only update IP and port information if connect or bind
        if func_call in ["connect", "bind"]:
            if info["ip"] is not None:
                self.socket_table[info["socket"]]["ip"] = info["ip"]
            if info["port"] != 0 and info["port"] is not None:
                self.socket_table[info["socket"]]["port"] = info["port"]

    def update_network_table(self, func_call, info):
        addr = (info["ip"], info["port"])
        if addr not in self.network_table.keys():
            self.network_table[addr] = {'bind': [],
                                        'connect': [],
                                        'send': [],
                                        'sendto': [],
                                        'recvfrom': [],
                                        'recv': []}
        if func_call in ["bind", "connect"]:
            self.network_table[addr][func_call].append(self.socket_table[info["socket"]]["type"])
        elif func_call in ["send", "sendto", "recvfrom", "recv"]:
            self.network_table[addr][func_call].append((self.socket_table[info["socket"]]["type"],
                                                        info["size"]))

    def run_network_detection(self):
        # Check for instances of bind
        bind_addrs = self.addresses["bind"]
        if bind_addrs:
            self.investigate_network_functions("bind", bind_addrs, self.allowed_inbound)

        # Find connected sockets
        connect_addrs = self.addresses["connect"]
        if connect_addrs:
            self.investigate_network_functions("connect", connect_addrs, self.allowed_outbound)

        # Check if TCP: outbound TCP connections will have instances of send
        send_addrs = self.addresses["send"]
        if send_addrs:
            self.investigate_network_functions("send", send_addrs, self.allowed_outbound)

        recv_addrs = self.addresses["recv"]
        if recv_addrs:
            self.investigate_network_functions("recv", recv_addrs, self.allowed_inbound)

        # Check if UDP: outbound UDP packets will be sent via sendto()
        sendto_addrs = self.addresses["sendto"]
        if sendto_addrs:
            self.investigate_network_functions("sendto", sendto_addrs, self.allowed_outbound)

        # Check for inbound UDP indications
        recvfrom_addrs = self.addresses["recvfrom"]
        if recvfrom_addrs:
            self.investigate_network_functions("recvfrom", recvfrom_addrs, self.allowed_inbound)

    def investigate_network_functions(self, net_func, func_addrs, allowed_list):
        if func_addrs:
            for addr in func_addrs:
                netdetect = NetworkDetection(self.project, self.entry_state, net_func, addr,
                                             allowed_list, self.socket_table)
                result = netdetect.find()
                self.update_socket_info(net_func, result)
                self.update_network_table(net_func, result)

    def prune_non_malicious_comms(self):
        for addr in self.network_table.copy().keys():
            # If the communication is outbound, check the IP
            if (len(self.network_table[addr]['connect']) > 0) and (addr[0] not in self.malicious_ips):
                del self.network_table[addr]
                continue
            # If the communication is inbound, check the port it is listening on
            if (len(self.network_table[addr]['bind']) > 0) and (str(addr[1]) not in self.malicious_ports):
                del self.network_table[addr]
                continue
        return

    def output_network_information(self):
        output_string = ""
        for addr in self.network_table.keys():
            output_string += '-' * 30 + '\n'
            net_info = self.network_table[addr]
            output_string += f"IP: {addr[0]}\nPort: {addr[1]}\n"
            if addr[0] is None and addr[1] is None:
                output_string += f"No IP and Port information was found. The IP and Port is likely resolved dynamically.\n"
            if len(net_info["bind"]) > 0 and len(net_info["connect"]) == 0:
                output_string += f"Type: {net_info['bind'][0]}\nListening for inbound traffic.\n"
            elif len(net_info["connect"]) > 0 and len(net_info["bind"]) == 0:
                output_string += f"Type: {net_info['connect'][0]}\nConnecting to send outbound traffic.\n"
            elif len(net_info["bind"]) > 0 and len(net_info["connect"]) > 0:
                output_string += f"Type: {net_info['bind'][0]}\nSocket is both bound and connecting. Unconfirmed behaviour\n"
            else:
                output_string += "Socket does not knowingly bind or connect. Check for usages of sendto or recvfrom.\n"
            output_string += "\nDetailed network function information:\n"
            for func in net_info.keys():
                if func in ["bind", "connect"]:
                    output_string += f"Instances of {func}: {len(net_info[func])}, TYPES: {net_info[func]}\n"
                if func in ["send", "sendto", "recvfrom", "recv"]:
                    output_string += (f"Instances of {func}: {len(net_info[func])}, "
                                      f"TYPES: {[i[0] for i in net_info[func]]}, "
                                      f"MESSAGE SIZES: {[i[1] for i in net_info[func]]}\n")
        print(output_string)
        return output_string

    def find_sockets(self):
        # Check for sockets
        sock_addrs = self.addresses["socket"]
        socket_table = {}
        if sock_addrs:
            for addr in sock_addrs:
                sock_detector = SocketDetection(self.project, self.entry_state, addr)
                socket_info = sock_detector.find_socket()
                socket_table[socket_info[0]] = {"type": socket_type_reference[socket_info[1]],
                                                "ip": None,
                                                "port": None,
                                                "function_calls": {"bind": 0,
                                                                   "connect": 0,
                                                                   "send": 0,
                                                                   "sendto": 0,
                                                                   "recvfrom": 0,
                                                                   "recv": 0}}

        accept_addrs = self.addresses["accept"]
        if accept_addrs:
            for addr in accept_addrs:
                accept_detector = AcceptDetection(self.project, self.entry_state, addr, socket_table)
                socket_info = accept_detector.find_socket()
                print(f"socket_info: {socket_info}")
                socket_table[socket_info[0]] = {"type": socket_type_reference[socket_info[1]],
                                                "ip": None,
                                                "port": None,
                                                "function_calls": {"bind": 0,
                                                                   "connect": 0,
                                                                   "send": 0,
                                                                   "sendto": 0,
                                                                   "recvfrom": 0,
                                                                   "recv": 0}}
        return socket_table


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
