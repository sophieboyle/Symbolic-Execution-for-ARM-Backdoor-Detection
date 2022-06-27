import copy

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
    def __init__(self, protocol, block, socket_fd=None, ip=None, port=None):
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
        self.block = block
        self.successors = []
        self.func_dict = {"connect":0, "bind":0, "send":0, "recvfrom":0, "recv":0,
                          "sendto":0}

        # udp_type is set to "established" or "unconnected" for UDP sockets
        if protocol == 2:
            self.udp_type = "unconnected"
        else:
            self.udp_type = None

    def add_successor(self, net_func_node):
        """
        Add a successor network function node to the root node
        :param net_func_node: A NetFuncNode representing a successor node
        :return:
        """
        self.successors.append(net_func_node)
        self.func_dict[net_func_node.func_name] += 1
        if net_func_node.func_name == "bind" and self.protocol == 2:
            self.udp_type = "established_bound"
        elif net_func_node.func_name == "connect" and self.protocol == 2:
            self.udp_type = "established_connected"


class NetFuncNode:
    def __init__(self, func_name, msg_size=None):
        """
        Creates a node of the network function tree
        :param func_name: String name of the function stored by the node
        """
        self.func_name = func_name
        self.msg_size = msg_size
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
        if n.name == "PathTerminator" or n.name == "exit":
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
    Obtains the sockaddr sgtruct passed as a parameter to connect(), and extracts the IP
    and port used from it. Also corrects the address from 0.0.0.0 or port from 0 to None
    :param state: The state where the connect() function has been reached
    :return:
    """
    sockaddr_param = state.mem[state.solver.eval(state.regs.r1)].struct.sockaddr_in.concrete
    ip = socket.inet_ntoa(struct.pack('<I', sockaddr_param.sin_addr.s_addr))
    port = socket.ntohs(sockaddr_param.sin_port)
    return correct_addresses_if_none(ip, port)


def send_state(state):
    """
    Gets the size of the message being sent via the send() call
    :param state: The state where the send() function has been reached
    :return:
    """
    size = state.solver.eval(state.regs.r2)
    return size


def sendto_state(state):
    """
    Gets the size of the message being sent via the sendto() call. Must check whether or not
    the sendto() function was used in connection or connectionless mode, by cross-referencing
    with the socket table to check the protocol used. If in connection mode, it retrieves
    the IP and port from the socket table. If in connectionless mode, retrieves the
    sockaddr struct from the function's parameters and obtains the IP and port. Also makes
    corrections if necess ary.
    :param state: State where the sendto() function has been reached
    :return:
    """
    size = state.solver.eval(state.regs.r2)
    # Try get IP and port from stack regardless of connection/connectionless mode
    # Whether the socket is connection/connectionless is determined by the caller
    # Therefore note that the return for ip:port may be garbage
    sockaddr_param = state.mem[
        state.mem[state.solver.eval(state.regs.sp)].int.concrete].struct.sockaddr_in.concrete
    ip = socket.inet_ntoa(struct.pack('<I', sockaddr_param.sin_addr.s_addr))
    port = socket.ntohs(sockaddr_param.sin_port)
    corrected_addr_info = correct_addresses_if_none(ip, port)
    return corrected_addr_info[0], corrected_addr_info[1], size


def recv_state(state):
    """
    Retrieves the size of the buffer allocated for the received message
    :param state: State where the recv() function has been reached
    :return:
    """
    size = state.solver.eval(state.regs.r2)
    return size


def recvfrom_state(state):
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
    # Try get IP and port from stack regardless of connection/connectionless mode
    # Whether the socket is connection/connectionless is determined by the caller
    # Therefore note that the return for ip:port may be garbage
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
        self.main = project.loader.main_object.get_symbol("main")
        self.main_state = project.factory.blank_state(addr=self.main.rebased_addr)
        self.sim = project.factory.simgr(self.main_state)
        self.cfg = cfg

        self.network_table = {}
        self.malicious_ips = get_malicious_net('resources/bad-ips.csv')
        self.malicious_ports = get_malicious_net('resources/bad-ports.csv')
        self.output_string = ""

        limiter = angr.exploration_techniques.lengthlimiter.LengthLimiter(max_length=100, drop=True)
        self.sim.use_technique(limiter)

        loopseer = angr.exploration_techniques.LoopSeer(cfg=self.cfg, bound=1)
        self.sim.use_technique(loopseer)

        angr.types.register_types(angr.types.parse_type('struct in_addr{ uint32_t s_addr; }'))
        angr.types.register_types(angr.types.parse_type(
            'struct sockaddr_in{ unsigned short sin_family; uint16_t sin_port; struct in_addr sin_addr; }'))

    def add_node_to_network_table(self, func_name, socket, path_indexes, path_dict, size=None):
        """
        Adds a node representing a network function to the network table by reading its file descriptor
        :param func_name: The name of the network function
        :param path_indexes: The indexes (list) to the valid paths to which the change might apply
        :param size: The optional integer size of the message recieved/transmitted
        :return:
        """
        for i in path_indexes:
            for tree in self.network_table[i]:
                if tree.socket_fd == socket:
                    net_func_node = NetFuncNode(func_name, size)
                    # If the node is unique and the number of nodes for the given function in the path
                    # have not been added to the tree yet
                    if not [n for n in tree.successors if n.func_name == func_name and n.msg_size == size] and\
                            len(list(filter(lambda cfg_n: cfg_n.name == func_name, path_dict[i]))) != tree.func_dict[func_name]:
                        tree.add_successor(net_func_node)
                    break

    def case_bind(self, net_func_node, path_indexes, socket, ip, port):
        for i in path_indexes:
            for tree in self.network_table[i]:
                if tree.socket_fd == socket:
                    # Socket ip, port assigned for the first time
                    if tree.ip is None and tree.port is None:
                        tree.ip = ip
                        tree.port = port
                        tree.add_successor(
                            copy.deepcopy(net_func_node)) if net_func_node not in tree.successors else None
                    # If the socket has been rebound, create new socket
                    # and re-assign the file descriptor
                    else:
                        new_net_func_tree = NetFuncTree(tree.protocol, tree.block, tree.socket_fd, ip, port)
                        new_net_func_tree.add_successor(copy.deepcopy(net_func_node))
                        self.network_table[i].append(new_net_func_tree)
                        tree.socket_fd = None
                    break

    def case_connect(self, net_func_node, path_indexes, socket, ip, port):
        for i in path_indexes:
            for tree in self.network_table[i]:
                if tree.socket_fd == socket:
                    if tree.protocol == 2:
                        # If UDP connection, must create new netfunctree with the same socket
                        # file descriptor in case of a bind() followed by connect().
                        # Should also remove file descriptor from the bound socket
                        new_net_func_tree = NetFuncTree(tree.protocol, tree.block, tree.socket_fd, ip, port)
                        new_net_func_tree.ip = ip
                        new_net_func_tree.port = port
                        new_net_func_tree.add_successor(copy.deepcopy(
                            net_func_node)) if net_func_node not in new_net_func_tree.successors else None
                        self.network_table[i].append(new_net_func_tree)
                        tree.socket_fd = None
                    else:
                        # Regular TCP communication
                        tree.ip = ip
                        tree.port = port
                        tree.add_successor(
                            copy.deepcopy(net_func_node)) if net_func_node not in tree.successors else None
                    break

    def case_sendto(self, net_func_node, path_indexes, state_block, socket, ip, port, size=None):
        for i in path_indexes:
            sendto_node_added = False
            for tree in self.network_table[i]:
                if tree.socket_fd == socket:
                    # If TCP or established_connected UDP Just use the socket's ip:port
                    if tree.protocol in [1, 5] or \
                            (tree.protocol == 2 and tree.udp_type == "established_connected"):
                        tree.add_successor(
                            copy.deepcopy(net_func_node)) if net_func_node not in tree.successors else None
                        sendto_node_added = True
                        break
                    # If unestablished UDP: Assign the socket with the ip:port specified?
                    elif not tree.udp_type == "established_bound" and tree.ip is None and tree.port is None\
                            and len(tree.successors) == 0:
                        tree.ip = ip
                        tree.port = port
                        tree.add_successor(
                            copy.deepcopy(net_func_node)) if net_func_node not in tree.successors else None
                        sendto_node_added = True
                        break
            if not sendto_node_added:
                new_net_func_tree = NetFuncTree(2, state_block, socket)
                new_net_func_tree.ip = ip
                new_net_func_tree.port = port
                new_net_func_tree.add_successor(copy.deepcopy(
                    net_func_node)) if net_func_node not in new_net_func_tree.successors else None
                self.network_table[i].append(new_net_func_tree)

    def case_recvfrom(self, net_func_node, path_indexes, state_block, socket, size=None):
        for i in path_indexes:
            recvfrom_node_added = False
            for tree in self.network_table[i]:
                if tree.socket_fd == socket:
                    # If TCP or established_connected UDP: use the socket's IP and port
                    if tree.protocol in [1, 5] or \
                            (tree.protocol == 2 and tree.udp_type == "established_connected"):
                        tree.add_successor(
                            copy.deepcopy(net_func_node)) if net_func_node not in tree.successors else None
                        recvfrom_node_added = True
                        break
                    elif tree.protocol == 2 and tree.ip is None and tree.port is None:
                        tree.add_successor(copy.deepcopy(
                            net_func_node)) if net_func_node not in tree.successors else None
                        recvfrom_node_added = True
                        break
            if not recvfrom_node_added:
                # Create new None:None connection
                new_net_func_tree = NetFuncTree(2, state_block, socket)
                new_net_func_tree.add_successor(copy.deepcopy(
                    net_func_node)) if net_func_node not in new_net_func_tree.successors else None
                self.network_table[i].append(new_net_func_tree)

    def run(self):
        PathSearcher = PathSearch()
        paths = PathSearcher.get_paths_from_CFG(self.cfg)
        path_dict = {}
        i = 0
        for path in paths:
            path_dict[i] = path
            self.network_table[i] = []
            i += 1

        # This is necessary since it seems impossible to get a CFG node from a block
        block_to_cfg = {}
        for n in list(self.cfg.nodes()):
            block_to_cfg[n.block] = n

        # Find stack check fail blocks -> these loop infinitely
        stck_chk_fail_blocks = [n for n in self.cfg.nodes() if n.name == "__stack_chk_fail"]

        while self.sim.active:
            for state in self.sim.active:
                state_block = self.project.factory.block(state.solver.eval(state.ip))
                state_cfg_node = next(filter(lambda node: node.addr == state_block.addr, list(self.cfg.nodes())), None)

                # If current block is the successor to a block which called socket or accept
                # get the file descriptor from this current block and update each network tree node
                for path_num, func_trees in self.network_table.items():
                    for func_tree in func_trees:
                        if func_tree.block.addr in [predecessor.addr for predecessor in state_cfg_node.predecessors]:
                            # Get the socket's file descriptor
                            func_tree.socket_fd = state.solver.eval(state.regs.r0)

                # Check what path this block applies to
                path_indexes = []
                for path_num, path in path_dict.items():
                    # TODO: Add conditional to ensure that the predecessor to the block must be in the path?
                    # not set([s.addr for s in state_cfg_node.predecessors[0].predecessors]).isdisjoint([b.addr for b in path]):
                    test = state.history.bbl_addrs
                    if state_block.addr in [b.addr for b in path]:
                        if len(state.history.bbl_addrs) > 2:
                            if list(state.history.bbl_addrs)[-2] in [b.addr for b in path]:
                                path_indexes.append(path_num)
                        else:
                            path_indexes.append(path_num)

                if state_cfg_node:
                    # If the block is initialising a socket, then create a NetFuncTree node
                    if state_cfg_node.name == "socket" or state_cfg_node.name == "accept":
                        if state_cfg_node.name == "socket":
                            socket_type = state.solver.eval(state.regs.r1)
                        elif state_cfg_node.name == "accept":
                            socket_type = 1
                        net_root_node = NetFuncTree(socket_type, state_block)
                        for path_index in path_indexes:
                            self.network_table[path_index].append(copy.deepcopy(net_root_node))
                        continue

                    socket = state.solver.eval(state.regs.r0)
                    if state_cfg_node.name == "bind":
                        ip, port = bind_state(state)
                        net_func_node = NetFuncNode("bind")
                        print(f"Bind {port}")
                        self.case_bind(net_func_node, path_indexes, socket, ip, port)
                    elif state_cfg_node.name == "connect":
                        ip, port = connect_state(state)
                        net_func_node = NetFuncNode("connect")
                        self.case_connect(net_func_node, path_indexes, socket, ip, port)
                    elif state_cfg_node.name == "send":
                        size = send_state(state)
                        self.add_node_to_network_table("send", socket, path_indexes, path_dict, size)
                    elif state_cfg_node.name == "sendto":
                        ip, port, size = sendto_state(state)
                        net_func_node = NetFuncNode("sendto", size)
                        self.case_sendto(net_func_node, path_indexes, state_block, socket, ip, port, size)
                    elif state_cfg_node.name == "recvfrom":
                        ip, port, size = recvfrom_state(state)
                        net_func_node = NetFuncNode("recvfrom", size)
                        self.case_recvfrom(net_func_node, path_indexes, state_block, socket, size)
                    elif state_cfg_node.name == "recv":
                        size = recv_state(state)
                        self.add_node_to_network_table("recv", socket, path_indexes, path_dict, size)
                else:
                    pass
            self.sim.step()

        return

    def analyse(self, disallowed_ips, disallowed_ports):
        self.run()
        unique_comms = self.get_unique_communications()
        final_comms = self.remove_null_comms(unique_comms)
        malicious_comms = self.remove_non_malicious_comms(final_comms, disallowed_ips, disallowed_ports)
        return malicious_comms

    def remove_non_malicious_comms(self, final_comms, disallowed_ips, disallowed_ports):
        malicious_comms = {}
        for addr_info, netfunctree in final_comms.items():
            # If IP and port is None, then keep info anyway
            if addr_info == (None, None):
                malicious_comms[addr_info] = netfunctree
            # If bound, then check that the port is a disallowed port
            if addr_info[0] == '0.0.0.0':
                if str(addr_info[1]) in disallowed_ports:
                    malicious_comms[addr_info] = netfunctree
            # If sending outbound, then check the IP
            else:
                if addr_info[0] in disallowed_ips:
                    malicious_comms[addr_info] = netfunctree
        return malicious_comms

    def get_unique_communications(self):
        unique_comms = {}
        for path, trees in self.network_table.items():
            for tree in trees:
                if (tree.ip, tree.port) not in unique_comms.keys():
                    unique_comms[(tree.ip, tree.port)] = copy.deepcopy(tree)
                # if (tree.ip, tree.port) in unique_comms.keys():
                else:
                    for successor in tree.successors:
                        unique_comms[(tree.ip, tree.port)].add_successor(copy.deepcopy(successor)) \
                            if not [n for n in unique_comms[(tree.ip, tree.port)].successors
                                    if n.func_name == successor.func_name
                                    and n.msg_size == successor.msg_size] else None
        return unique_comms

    def remove_null_comms(self, comms_table):
        """
        This function exists to remove null communication detections from a dictionary. These null communications appear
        when a socket in a path is only initialised, but never used.

        :param comms_table: a dictionary of (ip:port) keys bound to a NetFuncTree object
        :returns: a dictionary of (ip:port) keys bound to a NetFuncTree object, with no connections
        """
        new_comms = {}
        for k, netfunctree in comms_table.items():
            if not (k == (None, None) and len(netfunctree.successors) == 0):
                new_comms[k] = netfunctree
        return new_comms

    def build_output_string(self, net_info):
        out_str = ""
        for addr, tree in net_info.items():
            out_str += '-' * 30 + '\n'
            out_str += f"IP: {addr[0]}\nPort: {addr[1]}\n"
            out_str += f"Type: {socket_type_reference[tree.protocol]}\n"
            if tree.func_dict["bind"] > 0 and tree.func_dict["connect"] == 0:
                out_str += f"Listening for inbound traffic.\n"
            elif tree.func_dict["connect"] > 0 and tree.func_dict["bind"] == 0:
                out_str += f"Connecting to send outbound traffic.\n"
            elif tree.func_dict["bind"] and tree.func_dict["connect"]:
                out_str += f"Socket is both bound and connecting. Unconfirmed behaviour\n"
            else:
                out_str += "Socket does not knowingly bind or connect. " \
                           "Check for usages of sendto or recvfrom.\n"
            out_str += "\nDetailed network function information:\n"
            for func, count in tree.func_dict.items():
                out_str += f"Instances of {func}: {count}"
                msg_sizes = []
                for netfuncnode in tree.successors:
                    if func == netfuncnode.func_name:
                        msg_sizes.append(netfuncnode.msg_size)
                # For the sake of better formatting
                if func == "recvfrom":
                    out_str += f"\t\tMessage sizes: {msg_sizes}\n"
                elif func in ["send", "sendto", "recv"]:
                    out_str += f"\t\t\tMessage sizes: {msg_sizes}\n"
                else:
                    out_str += "\n"
        return out_str
