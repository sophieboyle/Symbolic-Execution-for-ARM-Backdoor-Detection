import unittest
from src.main import *
from parameterized import parameterized_class


# TODO: Add information about message sizes
@parameterized_class([
    {"code_sample": "tcp-client-sample",
        "comms": {('127.0.0.1', 8888): {"protocol": 1,
                                        "functions": {
                                             "connect": {"number": 1},
                                             "send": {"number": 1, "size": None},
                                             "recv": {"number": 1, "size": None},
                                            }
                                        }
                }
     },
    {"code_sample": "tcp-server-sample",
        "comms": {('0.0.0.0', 8888): {"protocol": 1,
                                      "functions": {
                                          "bind": {"number": 1}
                                          }
                                      },
                  (None, None): {"protocol": 1,
                                 "functions": {
                                         "recv": {"number": 1}
                                     }
                                 }
                  }
    },
    {"code_sample": "udp-client-sample",
        "comms": {('127.0.0.1', 8888): {"protocol": 2,
                                        "functions": {
                                            "sendto": {"number": 1, "size": None},
                                            }
                                        },
                  (None, None): {"protocol": 2,
                                 "functions": {
                                        "recvfrom": {"number": 1, "size": None}
                                        }
                                 },
                  }
    },
    {"code_sample": "connected_udpclient",
        "comms": {('127.0.0.1', 5000): {"protocol": 2,
                                        "functions": {
                                            "connect": {"number": 1},
                                            "sendto": {"number": 1, "size": None},
                                            "recvfrom": {"number": 1, "size": None}
                                            }
                                        }
                  }
    },
    {"code_sample": "udp-server-sample",
        "comms": {('0.0.0.0', 8888): {"protocol": 2,
                                      "functions": {
                                          "bind": {"number": 1}
                                      }},
                  (None, None): {"protocol": 2,
                                 "functions": {
                                     "sendto": {"number": 1},
                                     "recvfrom": {"number": 1}
                                 }}}
     },
    {"code_sample": "sequential_udp",
        "comms": {('127.0.0.1', 8888): {"protocol": 2,
                                      "functions": {
                                          "sendto": {"number": 1}
                                      }},
                  ('127.0.0.1', 8889): {"protocol": 2,
                                      "functions": {
                                        "sendto": {"number": 1}
                                      }},
                  (None, None): {"protocol": 2,
                                 "functions": {
                                        "recvfrom": {"number": 2}
                                      }}
                  },
     },
    {"code_sample": "conditional-connect-sample",
        "comms": {('127.0.0.1', 8888): {"protocol": 1,
                                        "functions": {
                                            "connect": {"number": 1}
                                        }}
                  },
     },
    {"code_sample": "conditional-socket",
        "comms": {('127.0.0.1', 8888): {"protocol": 1,
                                        "functions": {
                                            "connect": {"number": 1}
                                        }}
                  },
     },
    {"code_sample": "conditional-net-malicious-and-non-malicious",
        "comms": {('0.0.0.0', 1337): {"protocol": 1,
                                      "functions": {
                                           "bind": {"number": 1}
                                       }}
                  },
     },
])
class TestNetworkDetection(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        analyser = Analyser(f"tests/code-samples/networking/{cls.code_sample}", {"string": []}, None)
        cls.results = analyser.run_symbolic_execution()
        cls.network_table = cls.results["network_table"]

    def test_correct_number_of_detections(self):
        self.assertEqual(len(self.comms), len(self.network_table))

    def test_correct_detections(self):
        for addr, netfunctree in self.network_table.items():
            # Check address occurs in the network table
            self.assertIn(addr, self.comms.keys())
            if addr in self.comms.keys():
                # Check if the protocol is correct
                self.assertEqual(netfunctree.protocol, self.comms[addr]["protocol"])
                # Check detected network functions are correct
                for net_function, number_of_calls in netfunctree.func_dict.items():
                    if number_of_calls != 0:
                        self.assertEqual(self.comms[addr]["functions"][net_function]["number"], number_of_calls)


if __name__ == '__main__':
    unittest.main()
