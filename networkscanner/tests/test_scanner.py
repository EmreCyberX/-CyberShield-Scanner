"""Unit tests for the advanced network scanner."""

import unittest
from unittest.mock import patch, MagicMock
import socket
import ssl
from pathlib import Path
import sys
import os
import json
import tempfile

# Add src directory to Python path
src_path = Path(__file__).parent.parent / "src"
sys.path.append(str(src_path))

from core.scanner import AdvancedPortScanner, ScanResult


class TestAdvancedPortScanner(unittest.TestCase):
    """Test cases for AdvancedPortScanner class."""

    def setUp(self):
        """Set up test fixtures."""
        self.target = "10.0.0.1"
        self.scanner = AdvancedPortScanner(
            target=self.target,
            start_port=1,
            end_port=100,
            workers=10,
            timeout=0.1,
            verbose=True,
            deep_scan=True,
            ssl_check=True,
        )

    @patch("socket.socket")
    def test_basic_port_scan(self, mock_socket):
        """Test basic port scanning functionality."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket.return_value = mock_sock

        result = self.scanner.scan_port(80)

        self.assertIsNotNone(result)
        self.assertEqual(result.port, 80)
        self.assertEqual(result.status, "open")
        self.assertEqual(result.service, "HTTP")

    @patch("socket.socket")
    def test_banner_grabbing(self, mock_socket):
        """Test banner grabbing functionality."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.2p1"
        mock_socket.return_value = mock_sock

        result = self.scanner.scan_port(22)

        self.assertEqual(result.status, "open")
        self.assertEqual(result.service, "SSH")
        self.assertIn("SSH-2.0", result.banner)

    @patch("socket.socket")
    @patch("ssl.create_default_context")
    def test_ssl_checking(self, mock_ssl_context, mock_socket):
        """Test SSL certificate checking."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket.return_value = mock_sock

        mock_context = MagicMock()
        mock_ssl_sock = MagicMock()
        mock_cert = {
            "issuer": [("commonName", "Test CA")],
            "subject": [("commonName", "test-server.local")],
            "version": 3,
            "serialNumber": "1234",
            "notBefore": "20230101000000Z",
            "notAfter": "20240101000000Z",
        }
        mock_ssl_sock.getpeercert.return_value = mock_cert
        mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssl_sock
        mock_ssl_context.return_value = mock_context

        result = self.scanner.scan_port(443)

        self.assertEqual(result.status, "open")
        self.assertEqual(result.service, "HTTPS")
        self.assertIsNotNone(result.ssl_info)
        self.assertEqual(result.ssl_info["issuer"]["commonName"], "Test CA")

    def test_invalid_port_range(self):
        """Test invalid port range handling."""
        with self.assertRaises(ValueError):
            AdvancedPortScanner(target=self.target, start_port=65536, end_port=100)

        with self.assertRaises(ValueError):
            AdvancedPortScanner(target=self.target, start_port=100, end_port=50)

    def test_invalid_target(self):
        """Test invalid target handling."""
        with self.assertRaises(socket.gaierror):
            AdvancedPortScanner(
                target="nonexistent-test-domain.local", start_port=1, end_port=100
            )

    def test_save_results_json(self):
        """Test saving results in JSON format."""
        self.scanner.results = [
            ScanResult(port=80, status="open", service="HTTP", latency=0.1),
            ScanResult(
                port=443,
                status="open",
                service="HTTPS",
                latency=0.1,
                ssl_info={"issuer": {"commonName": "Test CA"}},
            ),
        ]

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            self.scanner.save_results(tf.name, format="json")

            with open(tf.name, "r") as f:
                data = json.load(f)
                self.assertEqual(len(data["open_ports"]), 2)
                self.assertEqual(data["open_ports"][0]["port"], 80)
                self.assertEqual(data["open_ports"][1]["port"], 443)
                self.assertIn("ssl", data["open_ports"][1])

        os.unlink(tf.name)

    def test_save_results_html(self):
        """Test saving results in HTML format."""
        self.scanner.results = [
            ScanResult(port=80, status="open", service="HTTP", latency=0.1),
            ScanResult(
                port=443,
                status="open",
                service="HTTPS",
                latency=0.1,
                ssl_info={"issuer": {"commonName": "Test CA"}},
            ),
        ]

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tf:
            self.scanner.save_results(tf.name, format="html")

            with open(tf.name, "r") as f:
                content = f.read()
                self.assertIn("<!DOCTYPE html>", content)
                self.assertIn("Port Scan Report", content)
                self.assertIn("80", content)
                self.assertIn("443", content)
                self.assertIn("Test CA", content)

        os.unlink(tf.name)

    def test_vulnerability_check(self):
        """Test basic vulnerability checking."""
        with patch.object(self.scanner, "check_vulnerabilities") as mock_check:
            mock_check.return_value = [
                {
                    "port": 21,
                    "service": "ftp",
                    "type": "default_credentials",
                    "details": "Default credentials check: anonymous:anonymous",
                }
            ]

            result = self.scanner.scan_port(21)

            self.assertEqual(result.status, "open")
            self.assertEqual(result.service, "FTP")
            self.assertIsNotNone(getattr(result, "vulnerabilities", None))

    def test_concurrent_scanning(self):
        """Test concurrent port scanning."""
        # Mock multiple ports as open
        with patch("socket.socket") as mock_socket:
            mock_sock = MagicMock()
            mock_sock.connect_ex.return_value = 0
            mock_socket.return_value = mock_sock

            results = self.scanner.run()

            self.assertGreater(len(results), 0)
            self.assertEqual(results["target"], self.target)
            self.assertIn("duration", results)
            self.assertIn("open_ports", results)


if __name__ == "__main__":
    unittest.main()
