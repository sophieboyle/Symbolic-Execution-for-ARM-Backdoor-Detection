import unittest
from src.main import *


class TestNetworkDetectionTcpClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        analyser = Analyser("code-samples/networking/tcp-client-sample",
                                      {"string": [],
                                       "file_operation": {"fread": [],
                                                          "fwrite": [],
                                                          "fopen": []},
                                       "allowed_listening_ports": [],
                                       "allowed_outbound_ports": []
                                       },
                            None
                            )
        cls.results = analyser.run_symbolic_execution()
        cls.network_table = cls.results["network_table"]
        cls.addr = ('127.0.0.1', 8888)
        cls.protocol = 'TCP (SOCK_STREAM)'

    def test_address_is_detected(self):
        if len(self.network_table) != 1:
            self.fail("Address not detected correctly")
        else:
            self.assertEqual([k for k, v in self.network_table.items()][0], self.addr)

    def test_correct_call_numbers(self):
        self.assertEqual(len(self.network_table[self.addr]['bind']), 0)
        self.assertEqual(len(self.network_table[self.addr]['connect']), 1)
        self.assertEqual(len(self.network_table[self.addr]['send']), 1)
        self.assertEqual(len(self.network_table[self.addr]['recv']), 1)
        self.assertEqual(len(self.network_table[self.addr]['sendto']), 0)
        self.assertEqual(len(self.network_table[self.addr]['recvfrom']), 0)

    def test_protocol(self):
        self.assertEqual(self.network_table[self.addr]['connect'][0], self.protocol)
        self.assertEqual(self.network_table[self.addr]['send'][0][0], self.protocol)
        self.assertEqual(self.network_table[self.addr]['recv'][0][0], self.protocol)


class TestNetworkDetectionTcpServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        analyser = Analyser("code-samples/networking/tcp-server-sample",
                                      {"string": [],
                                       "file_operation": {"fread": [],
                                                          "fwrite": [],
                                                          "fopen": []},
                                       "allowed_listening_ports": [],
                                       "allowed_outbound_ports": []
                                       },
                            None
                            )
        cls.results = analyser.run_symbolic_execution()
        cls.network_table = cls.results["network_table"]
        cls.addr = ('0.0.0.0', 8888)
        cls.protocol = 'TCP (SOCK_STREAM)'

    def test_address_is_detected(self):
        if len(self.network_table) != 2:
            self.fail("Addresses detected incorrectly")
        else:
            self.assertEqual([k for k, v in self.network_table.items()][0], self.addr)
            self.assertEqual([k for k, v in self.network_table.items()][1], (None, None))

    def test_correct_call_numbers(self):
        self.assertEqual(len(self.network_table[self.addr]['bind']), 1)
        self.assertEqual(len(self.network_table[self.addr]['connect']), 0)
        self.assertEqual(len(self.network_table[self.addr]['send']), 0)
        self.assertEqual(len(self.network_table[self.addr]['recv']), 0)
        self.assertEqual(len(self.network_table[self.addr]['sendto']), 0)
        self.assertEqual(len(self.network_table[self.addr]['recvfrom']), 0)

        self.assertEqual(len(self.network_table[(None, None)]['bind']), 0)
        self.assertEqual(len(self.network_table[(None, None)]['connect']), 0)
        self.assertEqual(len(self.network_table[(None, None)]['send']), 0)
        self.assertEqual(len(self.network_table[(None, None)]['recv']), 1)
        self.assertEqual(len(self.network_table[(None, None)]['sendto']), 0)
        self.assertEqual(len(self.network_table[(None, None)]['recvfrom']), 0)

    def test_protocol(self):
        self.assertEqual(self.network_table[self.addr]['bind'][0], self.protocol)
        self.assertEqual(self.network_table[(None, None)]['recv'][0][0], self.protocol)


class TestNetworkDetectionUdpClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        analyser = Analyser("code-samples/networking/udp-client-sample",
                                      {"string": [],
                                       "file_operation": {"fread": [],
                                                          "fwrite": [],
                                                          "fopen": []},
                                       "allowed_listening_ports": [],
                                       "allowed_outbound_ports": []
                                       },
                            None
                            )
        cls.results = analyser.run_symbolic_execution()
        cls.network_table = cls.results["network_table"]
        cls.addr = ('127.0.0.1', 8888)
        cls.protocol = 'UDP (SOCK_DGRAM)'

    def test_address_is_detected(self):
        if len(self.network_table) != 1:
            self.fail("Addresses detected incorrectly")
        else:
            self.assertEqual([k for k, v in self.network_table.items()][0], self.addr)

    def test_correct_call_numbers(self):
        self.assertEqual(len(self.network_table[self.addr]['bind']), 0)
        self.assertEqual(len(self.network_table[self.addr]['connect']), 0)
        self.assertEqual(len(self.network_table[self.addr]['send']), 0)
        self.assertEqual(len(self.network_table[self.addr]['recv']), 0)
        self.assertEqual(len(self.network_table[self.addr]['sendto']), 1)
        self.assertEqual(len(self.network_table[self.addr]['recvfrom']), 1)

    def test_protocol(self):
        self.assertEqual(self.network_table[self.addr]['sendto'][0][0], self.protocol)
        self.assertEqual(self.network_table[self.addr]['recvfrom'][0][0], self.protocol)


class TestNetworkDetectionUdpServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        analyser = Analyser("code-samples/networking/udp-server-sample",
                                      {"string": [],
                                       "file_operation": {"fread": [],
                                                          "fwrite": [],
                                                          "fopen": []},
                                       "allowed_listening_ports": [],
                                       "allowed_outbound_ports": []
                                       },
                            None
                            )
        cls.results = analyser.run_symbolic_execution()
        cls.network_table = cls.results["network_table"]
        cls.addr = ('0.0.0.0', 8888)
        cls.addr2 = (None, None)
        cls.protocol = 'UDP (SOCK_DGRAM)'

    def test_address_is_detected(self):
        if len(self.network_table.keys()) != 2:
            self.fail("Addresses detected incorrectly")
        else:
            self.assertEqual([k for k, v in self.network_table.items()][0], self.addr)
            self.assertEqual([k for k, v in self.network_table.items()][1], self.addr2)

    def test_correct_call_numbers(self):
        self.assertEqual(len(self.network_table[self.addr]['bind']), 1)
        self.assertEqual(len(self.network_table[self.addr]['connect']), 0)
        self.assertEqual(len(self.network_table[self.addr]['send']), 0)
        self.assertEqual(len(self.network_table[self.addr]['recv']), 0)
        self.assertEqual(len(self.network_table[self.addr]['sendto']), 0)
        self.assertEqual(len(self.network_table[self.addr]['recvfrom']), 0)

        self.assertEqual(len(self.network_table[self.addr2]['bind']), 0)
        self.assertEqual(len(self.network_table[self.addr2]['connect']), 0)
        self.assertEqual(len(self.network_table[self.addr2]['send']), 0)
        self.assertEqual(len(self.network_table[self.addr2]['recv']), 0)
        self.assertEqual(len(self.network_table[self.addr2]['sendto']), 1)
        self.assertEqual(len(self.network_table[self.addr2]['recvfrom']), 1)

    def test_protocol(self):
        self.assertEqual(self.network_table[self.addr2]['sendto'][0][0], self.protocol)
        self.assertEqual(self.network_table[self.addr2]['recvfrom'][0][0], self.protocol)


if __name__ == '__main__':
    unittest.main()