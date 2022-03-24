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


def get_malicious_net(filename):
    """
    Retrieve the disallow list of malicious network addresses/ports
    :param filename: File to read malicious network addresses/ports from
    :return: A list of strings representing disallowed addresses/ports
    """
    with open(filename, 'r') as f:
        f.readline()
        netlist = f.read().splitlines()
    return netlist


class NetFuncTree:
    def __init__(self, socket_fd, protocol, ip, port):
        """
        Initialises the root of a network function tree
        :param socket_fd: Integer socket file descriptor number
        :param protocol: Integer protocol being used
        :param ip: String IP address
        :param port: Integer port number
        """
        self.socket_fd = socket_fd
        self.protocol = protocol
        self.ip = ip
        self.port = port
        self.successors = []

    def add_successor(self, net_func_node):
        """
        Add a successor network function node to the root node
        :param net_func_node: A NetFuncNode representing a successor node
        :return:
        """
        self.successors.append(net_func_node)


class NetFuncNode:
    def __init__(self, func_name):
        """
        Creates a node of the network function tree
        :param func_name: String name of the function stored by the node
        """
        self.func_name = func_name
        self.successors = []

    def add_successor(self, net_func_node):
        """
        Adds a new network function node to the list of successors to this node
        :param net_func_node: A NetFuncNode representing a successor node
        :return:
        """
        self.successors.append(net_func_node)


class PathSearch:
    def __init__(self):
        self.g_paths = []

    def DFS(self, n, visited, path):
        """
        Recursive depth first search to find all paths from node n to a destination node.
        Note that this appends completed paths to the GLOBAL VARIABLE g_paths
        :param n: The node from which to find a path
        :param destination: The final node in the path to be reached
        :param visited: The set of nodes which have already been visited
        :param path: The current path
        :return: A list representing a path of nodes
        """
        visited.add(n)
        path.append(n)
        if n.name == "PathTerminator":
            self.g_paths.append(path.copy())
        else:
            for successor in n.successors:
                if successor not in visited:
                    self.DFS(successor, visited, path)
        path.pop()
        visited.remove(n)

    def get_paths_from_CFG(self, cfg):
        """
        Works up from the deadended nodes of the CFG, iterating over all of the predecessors
        and building a data structure of all possible paths
        :param cfg: The control flow graph of the angr project
        :return: List of lists of blocks for each path, keyed by an arbitrary path ID
        """
        main = [n for n in cfg.nodes() if n.name == "main"]
        # Assumes that only one main node was found
        if len(main) != 1:
            raise Exception("Error, multiple main nodes")
        self.DFS(main[0], set(), [])
        return self.g_paths


def correct_addresses_if_none(ip, port):
    """
    If the IP address detected for an activity has been resolved to 0.0.0.0 or port 0,
    set the address to None for the sake of consistency.
    :return:
    """
    if ip == '0.0.0.0':
        ip = None
    if port == 0:
        port = None
    return ip, port


def bind_state(state):
    """
    Obtains the sockaddr struct which is passed as a parameter to bind(). From the
    sockaddr struct, extracts the IP and port bound to
    :param state: The state where the bind() function has been reached
    :return:
    """
    sockaddr_param = state.mem[state.solver.eval(state.regs.r1)].struct.sockaddr_in.concrete
    ip = socket.inet_ntoa(struct.pack('<I', sockaddr_param.sin_addr.s_addr))
    port = socket.ntohs(sockaddr_param.sin_port)
    return ip, port


def connect_state(state):
    """
    Obtains the sockaddr struct passed as a parameter to connect(), and extracts the IP
    and port used from it. Also corrects the address from 0.0.0.0 or port from 0 to None
    :param state: The state where the connect() function has been reached
    :return:
    """
    sockaddr_param = state.mem[state.solver.eval(state.regs.r1)].struct.sockaddr_in.concrete
    ip = socket.inet_ntoa(struct.pack('<I', sockaddr_param.sin_addr.s_addr))
    port = socket.ntohs(sockaddr_param.sin_port)
    return correct_addresses_if_none(ip, port)


def send_state(state, socket_table, socket):
    """
    Gets the size of the message being sent via the send() call. Also cross-references
    with the socket table to determine the IP and port used for sending.
    :param state: The state where the send() function has been reached
    :return:
    """
    size = state.solver.eval(state.regs.r2)
    # IP and port is associated with the socket
    ip = socket_table[socket]["ip"]
    port = socket_table[socket]["port"]
    return ip, port, size


def sendto_state(state, socket_table, socket):
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
    size = state.solver.eval(state.regs.r2)
    if socket_table[socket]["type"] in [socket_type_reference[1], socket_type_reference[5]]:
        # Connection mode: get IP and port from socket's connect call
        ip = socket_table[socket]["ip"]
        port = socket_table[socket]["port"]
        return ip, port, size
    else:
        # Connectionless mode: get IP and port from stack
        sockaddr_param = state.mem[
            state.mem[state.solver.eval(state.regs.sp)].int.concrete].struct.sockaddr_in.concrete
        ip = socket.inet_ntoa(struct.pack('<I', sockaddr_param.sin_addr.s_addr))
        port = socket.ntohs(sockaddr_param.sin_port)
        return correct_addresses_if_none(ip, port), size


def recv_state(state, socket_table, socket):
    """
    Retrieves the size of the buffer allocated for the received message. Also checks the
    socket table for the IP and port information
    :param state: State where the recv() function has been reached
    :return:
    """
    size = state.solver.eval(state.regs.r2)
    # Get ip and port information from socket
    ip = socket_table[socket]["ip"]
    port = socket_table[socket]["port"]
    return ip, port, size


def recvfrom_state(state, socket_table, socket):
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
    size = state.solver.eval(state.regs.r2)
    # Similar to sendto(), can be used in connection or connectionless mode
    if socket_table[socket]["type"] in [socket_type_reference[1], socket_type_reference[5]]:
        ip = socket_table[socket]["ip"]
        port = socket_table[socket]["port"]
    else:
        sockaddr_param = state.mem[
            state.mem[state.solver.eval(state.regs.sp)].int.concrete].struct.sockaddr_in.concrete
        ip = socket.inet_ntoa(struct.pack('<I', sockaddr_param.sin_addr.s_addr))
        port = socket.ntohs(sockaddr_param.sin_port)
        ip, port = correct_addresses_if_none(ip, port)
    return ip, port, size


class NetworkAnalysis:
    def __init__(self, project, entry_state, cfg):
        self.project = project
        self.entry_state = entry_state
        self.sim = project.factory.simgr(entry_state)
        self.cfg = cfg

        self.network_table = {}
        self.malicious_ips = get_malicious_net('../resources/bad-ips.csv')
        self.malicious_ports = get_malicious_net('../resources/bad-ports.csv')
        self.output_string = ""

        limiter = angr.exploration_techniques.lengthlimiter.LengthLimiter(max_length=1000, drop=True)
        self.sim.use_technique(limiter)

        angr.types.register_types(angr.types.parse_type('struct in_addr{ uint32_t s_addr; }'))
        angr.types.register_types(angr.types.parse_type(
            'struct sockaddr_in{ unsigned short sin_family; uint16_t sin_port; struct in_addr sin_addr; }'))

    def run(self):
        PathSearcher = PathSearch()
        paths = PathSearcher.get_paths_from_CFG(self.cfg)
        path_dict = {}
        i = 0
        for path in paths:
            path_dict[i] = path
            self.network_table[i] = path
            i += 1

        while self.sim.active:
            self.sim.step()

        return
