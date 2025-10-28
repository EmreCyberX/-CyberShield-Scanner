#!/usr/bin/env python3
"""Gelişmiş Ağ Tarayıcı - Command Line Interface"""

import sys
import argparse
import logging
from datetime import datetime
from pathlib import Path

# Add src directory to Python path for imports
src_path = Path(__file__).parent / 'src'
sys.path.append(str(src_path))

from src.core.scanner import AdvancedPortScanner
from src.gui.main_window import PortScannerGUI
from src.utils.logger import setup_logger
from src.utils.config import load_config

def main():
    """Ana program."""
    parser = argparse.ArgumentParser(
        description="Gelişmiş Ağ Port Tarayıcı",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument("--target", "-t",
                     help="Hedef IP adresi veya domain adı")
    parser.add_argument("--start", "-s", type=int, default=1,
                     help="Başlangıç port numarası (1-65535)")
    parser.add_argument("--end", "-e", type=int, default=1024,
                     help="Bitiş port numarası (1-65535)")
    parser.add_argument("--workers", "-w", type=int, default=100,
                     help="Eşzamanlı thread sayısı")
    parser.add_argument("--timeout", "-T", type=float, default=1.0,
                     help="Her port denemesi için timeout süresi (saniye)")
    parser.add_argument("--verbose", "-v", action="store_true",
                     help="Detaylı çıktı modunu aktifleştir")
    parser.add_argument("--output", "-o",
                     help="Sonuçları dosyaya kaydet (uzantıya göre format)")
    parser.add_argument("--deep-scan", "-d", action="store_true",
                     help="Derin tarama (servis tespiti, banner)")
    parser.add_argument("--ssl-check", "-s", action="store_true",
                     help="SSL/TLS sertifikalarını kontrol et")
    parser.add_argument("--gui", "-g", action="store_true",
                     help="Grafiksel arayüzü başlat")
    parser.add_argument("--config", "-c",
                     help="Özel yapılandırma dosyası kullan")
    parser.add_argument("--quiet", "-q", action="store_true",
                     help="Sadece hataları göster")
    
    args = parser.parse_args()
    
    # Yapılandırma yükle
    config = load_config(args.config if args.config else None)
    
    # Log seviyesini ayarla
    log_level = logging.ERROR if args.quiet else logging.INFO
    logger = setup_logger(__name__, level=log_level)
    
    if args.gui:
        try:
            app = PortScannerGUI()
            app.run()
            return
        except ImportError as e:
            logger.error(f"GUI bağımlılıkları bulunamadı: {e}")
            logger.error("GUI için tkinter kurulu olmalı")
            sys.exit(1)
    
    try:
        # Interactive mod veya CLI mod kontrolü
        if not args.target:
            args.target = input("Hedef IP adresi veya domain adı girin: ")
            args.start = int(input("Başlangıç port numarası (1-65535): "))
            args.end = int(input("Bitiş port numarası (1-65535): "))
        
        # Port aralığı kontrolü
        if not (1 <= args.start <= 65535 and 1 <= args.end <= 65535):
            raise ValueError("Port numaraları 1-65535 arasında olmalı!")
        if args.start > args.end:
            raise ValueError("Başlangıç portu bitiş portundan büyük olamaz!")
        
        # Scanner'ı oluştur ve çalıştır
        scanner = AdvancedPortScanner(
            target=args.target,
            start_port=args.start,
            end_port=args.end,
            workers=args.workers,
            timeout=args.timeout,
            verbose=args.verbose,
            deep_scan=args.deep_scan,
            ssl_check=args.ssl_check
        )
        
        logger.info("\nTarama başlatılıyor...")
        logger.info(f"Hedef: {args.target}")
        logger.info(f"Port aralığı: {args.start}-{args.end}")
        if args.deep_scan:
            logger.info("Derin tarama aktif: Servis tespiti ve banner alınacak")
        if args.ssl_check:
            logger.info("SSL/TLS kontrolleri aktif")
        
        scan_start = datetime.now()
        results = scanner.run()
        scan_duration = (datetime.now() - scan_start).total_seconds()
        
        # Sonuçları yazdır
        logger.info(f"\nTarama tamamlandı! ({scan_duration:.2f}s)")
        logger.info(f"Hedef: {results['target']} ({results['target_ip']})")
        logger.info(f"Açık port sayısı: {len(results['open_ports'])}")
        
        for port_info in results["open_ports"]:
            port_str = f"\nPort {port_info['port']} ({port_info['service']})"
            if port_info.get('version'):
                port_str += f" - Version: {port_info['version']}"
            if port_info.get('banner'):
                port_str += f"\n  Banner: {port_info['banner']}"
            if port_info.get('ssl'):
                port_str += f"\n  SSL: {port_info['ssl']}"
            if port_info.get('vulnerabilities'):
                port_str += "\n  Vulnerabilities:"
                for vuln in port_info['vulnerabilities']:
                    port_str += f"\n    - {vuln['type']}: {vuln['description']}"
            logger.info(port_str)
        
        # Sonuçları kaydet
        if args.output:
            format = "html" if args.output.endswith(".html") else "json"
            scanner.save_results(args.output, format=format)
            logger.info(f"\nSonuçlar kaydedildi: {args.output}")
        
    except KeyboardInterrupt:
        logger.warning("\nKullanıcı tarafından durduruldu!")
        sys.exit(1)
    except ValueError as e:
        logger.error(f"\nHata: {str(e)}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"\nBeklenmeyen hata: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()