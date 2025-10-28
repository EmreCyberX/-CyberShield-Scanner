"""
Network Scanner: Gelişmiş Port Tarama Aracı
"""

import socket
import sys
import argparse
from datetime import datetime
import threading
from queue import Queue
import logging
import json
from pathlib import Path
from typing import List, Dict, Optional, Union
import concurrent.futures
import time

# Logging yapılandırması
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("scanner.log")],
)

logger = logging.getLogger(__name__)


class PortScanner:
    """Port tarama işlemlerini yöneten ana sınıf."""

    def __init__(
        self,
        target: str,
        start_port: int,
        end_port: int,
        workers: int = 100,
        timeout: float = 1.0,
        verbose: bool = False,
    ):
        """
        Args:
            target: Hedef IP adresi veya domain adı
            start_port: Başlangıç port numarası
            end_port: Bitiş port numarası
            workers: Eşzamanlı thread sayısı
            timeout: Her port denemesi için timeout süresi
            verbose: Detaylı çıktı modunu aktifleştir
        """
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.workers = workers
        self.timeout = timeout
        self.verbose = verbose
        self.open_ports: List[Dict[str, Union[int, str, float]]] = []
        self.scan_start_time: Optional[datetime] = None
        self.scan_end_time: Optional[datetime] = None

        # Thread güvenliği için lock
        self._print_lock = threading.Lock()
        self._ports_queue = Queue()

        try:
            self.target_ip = socket.gethostbyname(target)
        except socket.gaierror as e:
            logger.error(f"Hedef adı çözümlenemedi: {str(e)}")
            raise

    def scan_port(self, port: int) -> Optional[Dict[str, Union[int, str, float]]]:
        """Tek bir portu tara ve durumunu döndür."""
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            result = sock.connect_ex((self.target_ip, port))
            end_time = time.time()
            duration = round(end_time - start_time, 3)

            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except (socket.error, OSError):
                    service = "unknown"

                port_info = {
                    "port": port,
                    "state": "open",
                    "service": service,
                    "response_time": duration,
                }

                with self._print_lock:
                    logger.info(f"Port {port} açık - Servis: {service} ({duration}s)")
                return port_info

            elif self.verbose:
                with self._print_lock:
                    logger.debug(f"Port {port} kapalı ({duration}s)")
            return None

        except Exception as e:
            logger.debug(f"Port {port} hatası: {str(e)}")
            return None
        finally:
            sock.close()

    def worker(self) -> None:
        """Worker thread fonksiyonu."""
        while True:
            try:
                port = self._ports_queue.get_nowait()
            except Queue.Empty:
                break

            result = self.scan_port(port)
            if result:
                self.open_ports.append(result)
            self._ports_queue.task_done()

    def run(
        self,
    ) -> Dict[str, Union[str, List[Dict[str, Union[int, str, float]]], float]]:
        """Tarama işlemini başlat ve sonuçları döndür."""
        self.scan_start_time = datetime.now()
        logger.info(f"Tarama başlatılıyor: {self.target} ({self.target_ip})")
        logger.info(f"Port aralığı: {self.start_port}-{self.end_port}")

        # Port kuyruğunu doldur
        for port in range(self.start_port, self.end_port + 1):
            self._ports_queue.put(port)

        # Thread havuzu oluştur ve çalıştır
        threads = []
        thread_count = min(self.workers, self.end_port - self.start_port + 1)

        for _ in range(thread_count):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            threads.append(t)
            t.start()

        # Thread'lerin bitmesini bekle
        for t in threads:
            t.join()

        self.scan_end_time = datetime.now()
        duration = (self.scan_end_time - self.scan_start_time).total_seconds()

        # Sonuçları hazırla
        results = {
            "target": self.target,
            "target_ip": self.target_ip,
            "scan_start": self.scan_start_time.isoformat(),
            "scan_end": self.scan_end_time.isoformat(),
            "duration": duration,
            "open_ports": sorted(self.open_ports, key=lambda x: x["port"]),
        }

        # Özet rapor
        logger.info("\nTarama tamamlandı!")
        logger.info(f"Süre: {duration:.2f} saniye")
        logger.info(f"Açık port sayısı: {len(self.open_ports)}")

        return results

    def save_results(self, filename: str) -> None:
        """Tarama sonuçlarını JSON formatında kaydet."""
        if not self.scan_end_time:
            raise RuntimeError("Önce tarama yapmalısınız!")

        results = {
            "target": self.target,
            "target_ip": self.target_ip,
            "scan_start": self.scan_start_time.isoformat(),
            "scan_end": self.scan_end_time.isoformat(),
            "duration": (self.scan_end_time - self.scan_start_time).total_seconds(),
            "open_ports": self.open_ports,
        }

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4, ensure_ascii=False)
        logger.info(f"Sonuçlar kaydedildi: {filename}")


def main():
    """Ana program."""
    parser = argparse.ArgumentParser(
        description="Gelişmiş Ağ Port Tarayıcı",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "--target", "-t", required=True, help="Hedef IP adresi veya domain adı"
    )
    parser.add_argument(
        "--start", "-s", type=int, default=1, help="Başlangıç port numarası (1-65535)"
    )
    parser.add_argument(
        "--end", "-e", type=int, default=1024, help="Bitiş port numarası (1-65535)"
    )
    parser.add_argument(
        "--workers", "-w", type=int, default=100, help="Eşzamanlı thread sayısı"
    )
    parser.add_argument(
        "--timeout",
        "-T",
        type=float,
        default=1.0,
        help="Her port denemesi için timeout süresi (saniye)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Detaylı çıktı modunu aktifleştir"
    )
    parser.add_argument("--output", "-o", help="Sonuçları JSON dosyasına kaydet")
    parser.add_argument(
        "--quiet", "-q", action="store_true", help="Sadece hataları göster"
    )

    args = parser.parse_args()

    # Quiet mod için log seviyesini ayarla
    if args.quiet:
        logging.getLogger().setLevel(logging.WARNING)

    try:
        # Port aralığını kontrol et
        if not (1 <= args.start <= 65535 and 1 <= args.end <= 65535):
            raise ValueError("Port numaraları 1-65535 arasında olmalı!")
        if args.start > args.end:
            raise ValueError("Başlangıç portu bitiş portundan büyük olamaz!")

        # Scanner'ı oluştur ve çalıştır
        scanner = PortScanner(
            target=args.target,
            start_port=args.start,
            end_port=args.end,
            workers=args.workers,
            timeout=args.timeout,
            verbose=args.verbose,
        )

        results = scanner.run()

        # Sonuçları kaydet
        if args.output:
            scanner.save_results(args.output)

    except KeyboardInterrupt:
        logger.warning("\nKullanıcı tarafından durduruldu!")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Hata: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
