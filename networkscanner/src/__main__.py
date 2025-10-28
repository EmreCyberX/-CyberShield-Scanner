"""Main entry point for the network scanner."""

import argparse
import sys
from pathlib import Path
import logging

# Add src directory to Python path
src_path = Path(__file__).parent
sys.path.append(str(src_path))

from core.scanner import AdvancedPortScanner
from utils.logger import setup_logger
from utils.config import load_config


def main():
    """Main function for CLI interface."""
    parser = argparse.ArgumentParser(
        description="Advanced Network Port Scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "--target", "-t", required=True, help="Target IP address or domain name"
    )
    parser.add_argument(
        "--start", "-s", type=int, default=1, help="Start port (1-65535)"
    )
    parser.add_argument(
        "--end", "-e", type=int, default=1024, help="End port (1-65535)"
    )
    parser.add_argument(
        "--workers", "-w", type=int, default=100, help="Number of concurrent workers"
    )
    parser.add_argument(
        "--timeout",
        "-T",
        type=float,
        default=1.0,
        help="Timeout for each port in seconds",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )
    parser.add_argument(
        "--output", "-o", help="Save results to file (format determined by extension)"
    )
    parser.add_argument(
        "--deep-scan",
        "-d",
        action="store_true",
        help="Enable deep scanning (service detection, banner grabbing)",
    )
    parser.add_argument(
        "--ssl-check",
        "-s",
        action="store_true",
        help="Check SSL/TLS certificates on open ports",
    )
    parser.add_argument("--gui", "-g", action="store_true", help="Launch GUI interface")
    parser.add_argument("--quiet", "-q", action="store_true", help="Show only errors")

    args = parser.parse_args()

    # Set up logging
    log_level = logging.ERROR if args.quiet else logging.INFO
    logger = setup_logger(__name__, level=log_level)

    if args.gui:
        try:
            from gui.main_window import PortScannerGUI

            app = PortScannerGUI()
            app.run()
            return
        except ImportError as e:
            logger.error(f"GUI dependencies not available: {e}")
            logger.error("Install tkinter to use GUI mode")
            sys.exit(1)

    try:
        # Validate ports
        if not (1 <= args.start <= 65535 and 1 <= args.end <= 65535):
            raise ValueError("Ports must be between 1 and 65535")
        if args.start > args.end:
            raise ValueError("Start port must be less than end port")

        # Create and run scanner
        scanner = AdvancedPortScanner(
            target=args.target,
            start_port=args.start,
            end_port=args.end,
            workers=args.workers,
            timeout=args.timeout,
            verbose=args.verbose,
            deep_scan=args.deep_scan,
            ssl_check=args.ssl_check,
        )

        results = scanner.run()

        # Save results if output file specified
        if args.output:
            format = "html" if args.output.endswith(".html") else "json"
            scanner.save_results(args.output, format=format)
            logger.info(f"Results saved to {args.output}")

    except KeyboardInterrupt:
        logger.warning("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
