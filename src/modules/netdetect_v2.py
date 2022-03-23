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


g_paths = []


def DFS(n, visited, path):
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
        g_paths.append(path.copy())
    else:
        for successor in n.successors:
            if successor not in visited:
                DFS(successor, visited, path)
    path.pop()
    visited.remove(n)


def get_paths_from_CFG(cfg):
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
    DFS(main[0], set(), [])
    return g_paths


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
        # TODO: Explore through all possible paths using depth first traversal
        paths = get_paths_from_CFG(self.cfg)
        return
