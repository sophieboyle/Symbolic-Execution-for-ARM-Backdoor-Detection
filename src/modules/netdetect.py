import angr
import socket
import struct
import archinfo

socket_type_reference = {1: "TCP (SOCK_STREAM)",
                         2: "UDP (SOCK_DGRAM)",
                         3: "SOCK_RAW",
                         4: "SOCK_RDM",
                         5: "SOCK_SEQPACKET",
                         6: "SOCK_DCCP",
                         10: "SOCK_PACKET"}


# ------------- BEGIN SIMPROCEDURES -------------

class InetAddr(angr.SimProcedure):
    def run(self, addr):
        ip_string = self.state.mem[self.state.solver.eval(addr.to_claripy())].string.concrete.decode('utf-8')
        ip_int = struct.unpack("<I", socket.inet_aton(ip_string))[0]
        return ip_int


class InetAton(angr.SimProcedure):
    def run(self, addr, in_addr_struct_ptr):
        ip_string = self.state.mem[self.state.solver.eval(addr.to_claripy())].string.concrete.decode('utf-8')
        ip_int = struct.unpack("<I", socket.inet_aton(ip_string))[0]
        self.state.memory.store(in_addr_struct_ptr, ip_int, endness=archinfo.Endness.LE)
        return 1


class InetNtoa(angr.SimProcedure):
    def run(self, in_addr_struct):
        self.state.register_plugin("heap", angr.state_plugins.heap.heap_ptmalloc.SimHeapPTMalloc())
        # Since in_addr is only 4 bytes in size and only holds an int, arg can be resolved as an int
        try:
            i = self.state.solver.eval(in_addr_struct.to_claripy())
            ip_string = socket.inet_ntoa(struct.pack('<L', i))

        except Exception as e:
            exception = e
            ip_string = "0.0.0.0"

        # Must return a string pointer, therefore memory must be allocated
        ip_string_ptr = self.state.heap.malloc(len(ip_string))
        self.state.memory.store(ip_string_ptr, self.state.solver.BVV(ip_string.encode('utf-8'), len(ip_string)*8))
        return ip_string_ptr

# ------------- END SIMPROCEDURES -------------


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

        # TODO: Remove redundant arg_register attribute and its usage
        if func_name in ["bind", "connect"]:
            self.arg_register = 1
        elif func_name in ["send", "sendto", "recvfrom"]:
            # Note: if IP dereferenced from sendto call is 0.0.0.0 on port 0, sockaddr for sendto is unknown
            # Most likely dependent on recieving some external information of where to sendto
            self.arg_register = 4
        elif func_name in ["recv"]:
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
                    sockaddr_param = state.mem[
                        state.mem[state.solver.eval(state.regs.sp)].int.concrete].struct.sockaddr_in.concrete
            elif self.func_name in ["recv"]:
                # Also get the size of the transmission
                self.size = state.solver.eval(state.regs.r2)
                # Get ip and port information from socket
                self.ip = self.socket_table[self.socket]["ip"]
                self.port = self.socket_table[self.socket]["port"]
                return True
            elif self.func_name in ["recvfrom"]:
                # Also get the size of the transmission
                self.size = state.solver.eval(state.regs.r2)
                # Similar to sendto(), can be used in connection or connectionless mode
                if self.socket_table[self.socket]["type"] in [socket_type_reference[1], socket_type_reference[5]]:
                    # Connection mode
                    self.ip = self.socket_table[self.socket]["ip"]
                    self.port = self.socket_table[self.socket]["port"]
                    return True
                else:
                    sockaddr_param = state.mem[
                        state.mem[state.solver.eval(state.regs.sp)].int.concrete].struct.sockaddr_in.concrete
            else:
                raise ValueError("Unimplemented argument register")

            # The ip address in sin_addr.s_addr needs to be packed in little endian format
            # despite the fact that inet_ntoa converts from network byte order (big endian)
            # to a formatted IPv4 string. The register must store s_addr in little endian format
            # Otherwise, setting struct.pack to pack in big endian format results in the IP address
            # being printed backwards
            server_ip = socket.inet_ntoa(struct.pack('<I', sockaddr_param.sin_addr.s_addr))
            server_port = socket.ntohs(sockaddr_param.sin_port)

            self.ip = server_ip
            self.port = server_port

            if self.func_name != "bind":
                if self.ip == '0.0.0.0':
                    self.ip = None
                if self.port == 0:
                    self.port = None

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
        self.project.hook_symbol('inet_aton', InetAton())
        self.project.hook_symbol('inet_ntoa', InetNtoa())
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
        return output_string, self.network_table

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
