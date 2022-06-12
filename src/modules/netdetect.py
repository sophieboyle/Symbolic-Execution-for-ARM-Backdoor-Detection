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
    def __init__(self, project, entry_state, func_name, func_addr, socket_table, prelude_blocks):
        """
        Initialises the detector which will run the symbolic execution for finding network
        functions. Here, the C types for network address information are registered with the
        angr project. A limiter for the angr project is also set, to avoid long computation
        times at the cost of limited depth.
        :param project: The angr project
        :param entry_state: The entry state where simulation begins
        :param func_name: The name of the function for the simulation to find
        :param func_addr: The address of the function for the simulation to find
        :param socket_table: A dictionary of socket file descriptors matched to their protocol
        :param prelude_blocks: A list of prelude blocks which may exist before the function
        block
        """
        self.project = project
        self.sim = project.factory.simgr(entry_state)
        self.main = project.loader.main_object.get_symbol("main")
        self.main_state = project.factory.blank_state(addr=self.main.rebased_addr)
        self.entry_state = entry_state
        self.func_prelude_blocks = prelude_blocks

        self.func_name = func_name
        self.func_addr = func_addr
        self.socket_table = socket_table

        self.socket = None
        self.ip = None
        self.port = None
        self.size = None

        if func_name not in ["bind", "connect", "send", "sendto", "recv", "recvfrom"]:
            raise ValueError("Unimplemented function name passed")

        limiter = angr.exploration_techniques.lengthlimiter.LengthLimiter(max_length=1000, drop=True)
        self.sim.use_technique(limiter)
        angr.types.register_types(angr.types.parse_type('struct in_addr{ uint32_t s_addr; }'))
        angr.types.register_types(angr.types.parse_type(
            'struct sockaddr_in{ unsigned short sin_family; uint16_t sin_port; struct in_addr sin_addr; }'))

    def correct_addresses_if_none(self):
        """
        If the IP address detected for an activity has been resolved to 0.0.0.0 or port 0,
        set the address to None for the sake of consistency.
        :return:
        """
        if self.ip == '0.0.0.0':
            self.ip = None
        if self.port == 0:
            self.port = None

    def bind_state(self, state):
        """
        Obtains the sockaddr struct which is passed as a parameter to bind(). From the
        sockaddr struct, extracts the IP and port bound to.
        :param state: The state where the bind() function has been reached
        :return:
        """
        sockaddr_param = state.mem[state.solver.eval(state.regs.r1)].struct.sockaddr_in.concrete
        self.ip = socket.inet_ntoa(struct.pack('<I', sockaddr_param.sin_addr.s_addr))
        self.port = socket.ntohs(sockaddr_param.sin_port)

    def connect_state(self, state):
        """
        Obtains the sockaddr struct passed as a parameter to connect(), and extracts the IP
        and port used from it. Also corrects the address from 0.0.0.0 or port from 0 to None.
        :param state: The state where the connect() function has been reached
        :return:
        """
        sockaddr_param = state.mem[state.solver.eval(state.regs.r1)].struct.sockaddr_in.concrete
        self.ip = socket.inet_ntoa(struct.pack('<I', sockaddr_param.sin_addr.s_addr))
        self.port = socket.ntohs(sockaddr_param.sin_port)
        self.correct_addresses_if_none()

    def send_state(self, state):
        """
        Gets the size of the message being sent via the send() call. Also cross-references
        with the socket table to determine the IP and port used for sending.
        :param state: The state where the send() function has been reached
        :return:
        """
        self.size = state.solver.eval(state.regs.r2)
        # IP and port is associated with the socket
        self.ip = self.socket_table[self.socket]["ip"]
        self.port = self.socket_table[self.socket]["port"]

    def sendto_state(self, state):
        """
        Gets the size of the message being sent via the sendto() call. Must check whether or not
        the sendto() function was used in connection or connectionless mode, by cross-referencing
        with the socket table to check the protocol used. If in connection mode, it retrieves
        the IP and port from the socket table. If in connectionless mode, retrieves the
        sockaddr struct from the function's parameters and obtains the IP and port. Also makes
        corrections if necessary.
        :param state: State where the sendto() function has been reached
        :return:
        """
        self.size = state.solver.eval(state.regs.r2)
        if self.socket_table[self.socket]["type"] in [socket_type_reference[1], socket_type_reference[5]]:
            # Connection mode: get IP and port from socket's connect call
            self.ip = self.socket_table[self.socket]["ip"]
            self.port = self.socket_table[self.socket]["port"]
        else:
            # Connectionless mode: get IP and port from stack
            sockaddr_param = state.mem[
                state.mem[state.solver.eval(state.regs.sp)].int.concrete].struct.sockaddr_in.concrete
            self.ip = socket.inet_ntoa(struct.pack('<I', sockaddr_param.sin_addr.s_addr))
            self.port = socket.ntohs(sockaddr_param.sin_port)
            self.correct_addresses_if_none()

    def recv_state(self, state):
        """
        Retrieves the size of the buffer allocated for the received message. Also checks the
        socket table for the IP and port information
        :param state: State where the recv() function has been reached
        :return:
        """
        self.size = state.solver.eval(state.regs.r2)
        # Get ip and port information from socket
        self.ip = self.socket_table[self.socket]["ip"]
        self.port = self.socket_table[self.socket]["port"]

    def recvfrom_state(self, state):
        """
        Gets the size of the message being sent via the recvfrom() call. Must check whether or not
        the recvfrom() function was used in connection or connectionless mode, by cross-referencing
        with the socket table to check the protocol used. If in connection mode, it retrieves
        the IP and port from the socket table. If in connectionless mode, retrieves the
        sockaddr struct from the function's parameters and obtains the IP and port. Also makes
        corrections if necessary.
        :param state: State where the recvfrom() function has been reached
        :return:
        """
        self.size = state.solver.eval(state.regs.r2)
        # Similar to sendto(), can be used in connection or connectionless mode
        if self.socket_table[self.socket]["type"] in [socket_type_reference[1], socket_type_reference[5]]:
            self.ip = self.socket_table[self.socket]["ip"]
            self.port = self.socket_table[self.socket]["port"]
        else:
            sockaddr_param = state.mem[
                state.mem[state.solver.eval(state.regs.sp)].int.concrete].struct.sockaddr_in.concrete
            self.ip = socket.inet_ntoa(struct.pack('<I', sockaddr_param.sin_addr.s_addr))
            self.port = socket.ntohs(sockaddr_param.sin_port)
            self.correct_addresses_if_none()

    def net_func_state(self, state):
        if state.ip.args[0] == self.func_addr:
            # block1 = self.project.factory.block(state.solver.eval(state.ip))
            # num_instr = block1.instructions

            # self.sim.step(num_inst=num_instr-1)
            self.sim.step()
            # Is it taking the first element from the active list that's the problem?
            # It looks like it, since there are two states active at this point

            # state = self.sim.active[0]

            for active_state in self.sim.active:
                # active_state_blocks.append(self.project.factory.block(state.solver.eval(active_state.ip)))
                active_block = self.project.factory.block(active_state.solver.eval(active_state.ip))
                if active_block not in self.func_prelude_blocks:
                    continue

                # block2 = self.project.factory.block(state.solver.eval(state.ip))

                # self.socket_symb = state.regs.r0
                self.socket = active_state.solver.eval(active_state.regs.r0)

                # const = state.history.constraints_since(self.main_state.history)
                # sao_const = const[0].to_claripy()
                # print(type(sao_const))

                if self.func_name == 'bind':
                    self.bind_state(active_state)
                elif self.func_name == 'connect':
                    self.connect_state(active_state)
                elif self.func_name == 'send':
                    self.send_state(active_state)
                elif self.func_name == 'sendto':
                    self.sendto_state(active_state)
                elif self.func_name == 'recv':
                    self.recv_state(active_state)
                elif self.func_name == 'recvfrom':
                    self.recvfrom_state(active_state)
                else:
                    raise ValueError("Unimplemented function name")

                return True
        return False

    def find(self):
        self.sim.explore(find=self.net_func_state)
        return {"ip": self.ip,
                "port": self.port,
                "socket": self.socket,
                "size": self.size}


class SocketDetection:
    def __init__(self, project, entry_state, sock_addr, prelude_blocks, post_blocks):
        """
        Initialises the detector which will run symbolic execution to find the given
        address of a socket() call.
        :param project: The angr project
        :param entry_state: The entry state to the symbolic execution
        :param sock_addr: The address of the socket to find
        :param prelude_blocks: List of possible prelude blocks which may exist before
        the block at which the socket() function is called
        :param post_blocks: List of possible post blocks which may exist after the
        block at which the socket() function is called
        """
        self.socket_fd = None
        self.socket_type = None
        self.project = project
        self.sim = project.factory.simgr(entry_state)
        self.sock_addr = sock_addr
        self.prelude_blocks = prelude_blocks
        self.post_blocks = post_blocks

    def socket_state(self, state):
        """
        Retrieves the file descriptor returned by the socket call. Also retrieves the
        protocol information passed as a parameter.
        :param state: The state at which the socket function is called
        :return:
        """
        if state.ip.args[0] == self.sock_addr:
            self.sim.step()

            for active_state in self.sim.active:
                active_block = self.project.factory.block(active_state.solver.eval(active_state.ip))
                if active_block not in self.prelude_blocks:
                    continue
                self.socket_type = active_state.solver.eval(active_state.regs.r1)

            # Step until end of function to find return value
            self.sim.step()
            self.sim.step()

            for active_state in self.sim.active:
                active_block = self.project.factory.block(active_state.solver.eval(active_state.ip))
                if active_block not in self.post_blocks:
                    continue
                self.socket_fd = active_state.solver.eval(active_state.regs.r0)
                return True
        return False

    def find_socket(self):
        """
        Run the symbolic execution to find the given address of the socket call
        :return: Integer, file descriptor returned by the socket
        :return: Integer, the numerical representation of the protocol
        """
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

    def __init__(self, project, entry_state, addresses, prelude_blocks, socket_post_blocks):
        """
        Initialises the object which will run all symbolic executions for each network function
        :param project: The angr project
        :param entry_state: The entry point to the angr project
        :param addresses: Dictionary of addresses for each network function
        :param prelude_blocks: Dictionary of the prelude blocks for each network function
        :param socket_post_blocks: Dictionary of post blocks, specifically for socket functions
        """
        self.project = project
        self.entry_state = entry_state
        self.addresses = addresses
        self.prelude_blocks = prelude_blocks
        self.socket_post_blocks = socket_post_blocks

        self.socket_table = self.find_sockets()
        self.network_table = {}
        self.malicious_ips = self.get_malicious_net('resources/bad-ips.csv')
        self.malicious_ports = self.get_malicious_net('resources/bad-ports.csv')
        self.output_string = ""

    def get_malicious_net(self, filename):
        """
        Retrieve the disallow list of malicious network addresses/ports
        :param filename: File to read malicious network addresses/ports from
        :return: A list of strings representing disallowed addresses/ports
        """
        with open(filename, 'r') as f:
            f.readline()
            netlist = f.read().splitlines()
        return netlist

    def update_socket_info(self, func_call, info):
        """
        Updates the socket table with information about the function calls being made for a
        given socket file descriptor
        :param func_call: The function call which was made
        :param info: The information gathered from the function call, such as IP/port info
        :return:
        """
        if info["socket"] in self.socket_table.keys():
            self.socket_table[info["socket"]]["function_calls"][func_call] += 1
            # Only update IP and port information if connect or bind
            if func_call in ["connect", "bind"]:
                if info["ip"] is not None:
                    self.socket_table[info["socket"]]["ip"] = info["ip"]
                if info["port"] != 0 and info["port"] is not None:
                    self.socket_table[info["socket"]]["port"] = info["port"]

    def update_network_table(self, func_call, info):
        """
        Updates the network table with information gathered from analysis.
        :param func_call: The function call which is to be updated
        :param info: The information gathered from the function call to be updated
        :return:
        """
        addr = (info["ip"], info["port"])
        if addr not in self.network_table.keys():
            self.network_table[addr] = {'bind': [],
                                        'connect': [],
                                        'send': [],
                                        'sendto': [],
                                        'recvfrom': [],
                                        'recv': []}
        if func_call in ["bind", "connect"] and info["socket"] in self.socket_table.keys():
            self.network_table[addr][func_call].append(self.socket_table[info["socket"]]["type"])
        elif func_call in ["send", "sendto", "recvfrom", "recv"] and info["socket"] in self.socket_table.keys():
            self.network_table[addr][func_call].append((self.socket_table[info["socket"]]["type"],
                                                        info["size"]))

    def run_network_detection(self):
        """
        Investigates each network function, removes networking which isn't seen as malicious,
        and builds the output
        :return: A dictionary representing all malicious networking
        """
        self.investigate_network_functions("bind", self.addresses["bind"])
        self.investigate_network_functions("connect", self.addresses["connect"])
        self.investigate_network_functions("send", self.addresses["send"])
        self.investigate_network_functions("recv", self.addresses["recv"])
        self.investigate_network_functions("sendto", self.addresses["sendto"])
        self.investigate_network_functions("recvfrom", self.addresses["recvfrom"])
        self.prune_non_malicious_comms()
        self.construct_output_string()
        return self.network_table

    def investigate_network_functions(self, net_func, func_addrs):
        if func_addrs:
            for addr in func_addrs:
                netdetect = NetworkDetection(self.project, self.entry_state, net_func, addr,
                                             self.socket_table, self.prelude_blocks[net_func])
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

    def construct_output_string(self):
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
        self.output_string = output_string

    def output_network_information(self):
        print(self.output_string)

    def get_output_string(self):
        return self.output_string

    def get_network_table(self):
        return self.network_table

    def find_sockets(self):
        # Check for sockets
        sock_addrs = self.addresses["socket"]
        socket_table = {}
        if sock_addrs:
            for addr in sock_addrs:
                sock_detector = SocketDetection(self.project, self.entry_state, addr, self.prelude_blocks["socket"], self.socket_post_blocks)
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
