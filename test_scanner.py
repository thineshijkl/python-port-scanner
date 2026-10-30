import socket
import unittest

from scanner import parse_ports, scan_port


class TestParsePorts(unittest.TestCase):
    def test_single_port(self):
        self.assertEqual(parse_ports("80"), [80])

    def test_range(self):
        self.assertEqual(parse_ports("20-23"), [20, 21, 22, 23])

    def test_mixed_list_and_range(self):
        self.assertEqual(parse_ports("22,80,100-102"), [22, 80, 100, 101, 102])

    def test_duplicates_are_removed(self):
        self.assertEqual(parse_ports("80,80,79-80"), [79, 80])

    def test_port_zero_is_invalid(self):
        with self.assertRaises(ValueError):
            parse_ports("0")

    def test_port_above_65535_is_invalid(self):
        with self.assertRaises(ValueError):
            parse_ports("65536")

    def test_reversed_range_is_invalid(self):
        with self.assertRaises(ValueError):
            parse_ports("200-100")

    def test_non_numeric_is_invalid(self):
        with self.assertRaises(ValueError):
            parse_ports("http")


class TestScanPort(unittest.TestCase):
    def test_detects_open_port(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        try:
            result = scan_port("127.0.0.1", port, 1.0, False)
            self.assertIsNotNone(result)
            self.assertEqual(result["port"], port)
            self.assertEqual(result["state"], "open")
        finally:
            server.close()

    def test_closed_port_returns_none(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
        server.close()  # nothing is listening on this port any more
        self.assertIsNone(scan_port("127.0.0.1", port, 1.0, False))


if __name__ == "__main__":
    unittest.main()