"""Core scanner functionality with advanced features."""

import socket
import ssl
import sys
import threading
from queue import Queue
from datetime import datetime
from typing import Dict, List, Optional, Union, Tuple
import logging
import json
from pathlib import Path
import requests
import nmap
import pyOpenSSL
from ..utils.logger import setup_logger
from ..utils.config import load_config

logger = setup_logger(__name__)


class AdvancedPortScanner:
    """Enhanced port scanner with advanced security features."""

    def __init__(
        self,
        target: str,
        start_port: int,
        end_port: int,
        workers: int = 100,
        timeout: float = 1.0,
        verbose: bool = False,
        deep_scan: bool = False,
        ssl_check: bool = False,
    ):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.workers = workers
        self.timeout = timeout
        self.verbose = verbose
        self.deep_scan = deep_scan
        self.ssl_check = ssl_check

        self.open_ports: List[Dict[str, Union[int, str, float, dict]]] = []
        self.scan_start_time: Optional[datetime] = None
        self.scan_end_time: Optional[datetime] = None
        self._print_lock = threading.Lock()
        self._ports_queue = Queue()
        self._vulnerabilities: List[Dict] = []

        try:
            self.target_ip = socket.gethostbyname(target)
        except socket.gaierror as e:
            logger.error(f"Host resolution failed: {str(e)}")
            raise

    def check_ssl(self, port: int) -> Optional[Dict]:
        """SSL/TLS sertifika kontrolü."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection(
                (self.target_ip, port), timeout=self.timeout
            ) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        "issuer": dict(x[0] for x in cert["issuer"]),
                        "expires": cert["notAfter"],
                        "subject": dict(x[0] for x in cert["subject"]),
                        "version": cert["version"],
                    }
        except Exception as e:
            logger.debug(f"SSL check failed for port {port}: {str(e)}")
            return None

    def grab_banner(self, port: int) -> Optional[str]:
        """Service banner bilgisi alma."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((self.target_ip, port))
                banner = sock.recv(1024).decode().strip()
                return banner
        except Exception:
            return None

    def check_vulnerabilities(self, port: int, service: str) -> List[Dict]:
        """Basit zafiyet kontrolü."""
        vulns = []

        # Default credentials kontrolü
        default_creds = {
            "ftp": [("anonymous", "anonymous")],
            "ssh": [("root", "root"), ("admin", "admin")],
            "telnet": [("admin", "admin")],
        }

        if service in default_creds:
            for username, password in default_creds[service]:
                try:
                    # Burada gerçek credential check yapılabilir
                    vulns.append(
                        {
                            "port": port,
                            "service": service,
                            "type": "default_credentials",
                            "details": f"Default credentials check: {username}:{password}",
                        }
                    )
                except Exception:
                    pass

        return vulns

    def detect_service_version(
        self, port: int, banner: Optional[str] = None
    ) -> Dict[str, str]:
        """Servis ve versiyon tespiti."""
        try:
            service = socket.getservbyport(port)
        except (socket.error, OSError):
            service = "unknown"

        version_info = {"service": service, "version": "unknown"}

        if banner:
            # Version extraction from banner
            if "SSH" in banner:
                version_info["version"] = banner.split("-")[1].split()[0]
            elif "FTP" in banner:
                version_info["version"] = banner.split()[1]

        return version_info

    def scan_port(self, port: int) -> Optional[Dict]:
        """Enhanced port scanning with service detection."""
        start_time = datetime.now()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            result = sock.connect_ex((self.target_ip, port))
            scan_duration = (datetime.now() - start_time).total_seconds()

            if result == 0:
                banner = self.grab_banner(port) if self.deep_scan else None
                service_info = self.detect_service_version(port, banner)
                ssl_info = self.check_ssl(port) if self.ssl_check else None

                port_info = {
                    "port": port,
                    "state": "open",
                    "service": service_info["service"],
                    "version": service_info["version"],
                    "banner": banner,
                    "ssl": ssl_info,
                    "response_time": round(scan_duration, 3),
                }

                if self.deep_scan:
                    vulns = self.check_vulnerabilities(port, service_info["service"])
                    if vulns:
                        port_info["vulnerabilities"] = vulns

                with self._print_lock:
                    logger.info(f"Port {port} open - {service_info['service']}")
                    if banner:
                        logger.info(f"Banner: {banner}")
                    if ssl_info:
                        logger.info(f"SSL Info: {ssl_info}")

                return port_info

            elif self.verbose:
                with self._print_lock:
                    logger.debug(f"Port {port} closed ({scan_duration:.3f}s)")

            return None

        except Exception as e:
            logger.debug(f"Error scanning port {port}: {str(e)}")
            return None
        finally:
            sock.close()

    def worker(self) -> None:
        """Worker thread for parallel scanning."""
        while True:
            try:
                port = self._ports_queue.get_nowait()
            except Queue.Empty:
                break

            result = self.scan_port(port)
            if result:
                self.open_ports.append(result)
            self._ports_queue.task_done()

    def run(self) -> Dict:
        """Execute the scan with all enabled features."""
        self.scan_start_time = datetime.now()
        logger.info(f"Starting enhanced scan of {self.target} ({self.target_ip})")
        logger.info(f"Port range: {self.start_port}-{self.end_port}")

        if self.deep_scan:
            logger.info(
                "Deep scan enabled: Service detection and vulnerability checks active"
            )
        if self.ssl_check:
            logger.info("SSL/TLS checking enabled")

        for port in range(self.start_port, self.end_port + 1):
            self._ports_queue.put(port)

        threads = []
        thread_count = min(self.workers, self.end_port - self.start_port + 1)

        for _ in range(thread_count):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        self.scan_end_time = datetime.now()
        duration = (self.scan_end_time - self.scan_start_time).total_seconds()

        results = {
            "target": self.target,
            "target_ip": self.target_ip,
            "scan_start": self.scan_start_time.isoformat(),
            "scan_end": self.scan_end_time.isoformat(),
            "duration": duration,
            "open_ports": sorted(self.open_ports, key=lambda x: x["port"]),
            "scan_type": "deep" if self.deep_scan else "basic",
        }

        logger.info(f"\nScan completed in {duration:.2f} seconds")
        logger.info(f"Found {len(self.open_ports)} open ports")

        return results

    def save_results(self, filename: str, format: str = "json") -> None:
        """Save scan results in various formats."""
        if not self.scan_end_time:
            raise RuntimeError("Scan must be completed before saving results")

        results = {
            "target": self.target,
            "target_ip": self.target_ip,
            "scan_start": self.scan_start_time.isoformat(),
            "scan_end": self.scan_end_time.isoformat(),
            "duration": (self.scan_end_time - self.scan_start_time).total_seconds(),
            "open_ports": self.open_ports,
            "scan_type": "deep" if self.deep_scan else "basic",
        }

        if format == "json":
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=4, ensure_ascii=False)
        elif format == "html":
            # HTML rapor oluşturma
            html_content = self._generate_html_report(results)
            with open(filename, "w", encoding="utf-8") as f:
                f.write(html_content)

        logger.info(f"Results saved to {filename}")

    def _generate_html_report(self, results: Dict) -> str:
        """Generate HTML report from scan results."""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Port Scan Report - {target}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background: #f4f4f4; padding: 20px; border-radius: 5px; }}
                .port-table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                .port-table th, .port-table td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                .port-table tr:nth-child(even) {{ background-color: #f9f9f9; }}
                .vulnerability {{ color: red; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Port Scan Report</h1>
                <p>Target: {target} ({target_ip})</p>
                <p>Scan Duration: {duration:.2f} seconds</p>
                <p>Scan Type: {scan_type}</p>
                <p>Start Time: {scan_start}</p>
                <p>End Time: {scan_end}</p>
            </div>
            
            <h2>Open Ports ({port_count})</h2>
            <table class="port-table">
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Version</th>
                    <th>Response Time</th>
                    <th>Banner</th>
                    <th>SSL Info</th>
                </tr>
                {port_rows}
            </table>
        </body>
        </html>
        """

        port_row_template = """
        <tr>
            <td>{port}</td>
            <td>{service}</td>
            <td>{version}</td>
            <td>{response_time}s</td>
            <td>{banner}</td>
            <td>{ssl_info}</td>
        </tr>
        """

        port_rows = []
        for port_info in sorted(results["open_ports"], key=lambda x: x["port"]):
            ssl_info = "Yes" if port_info.get("ssl") else "No"
            port_rows.append(
                port_row_template.format(
                    port=port_info["port"],
                    service=port_info["service"],
                    version=port_info.get("version", "unknown"),
                    response_time=port_info["response_time"],
                    banner=port_info.get("banner", "N/A"),
                    ssl_info=ssl_info,
                )
            )

        return html_template.format(
            target=results["target"],
            target_ip=results["target_ip"],
            duration=results["duration"],
            scan_type=results["scan_type"],
            scan_start=results["scan_start"],
            scan_end=results["scan_end"],
            port_count=len(results["open_ports"]),
            port_rows="\n".join(port_rows),
        )
