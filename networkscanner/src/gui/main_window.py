"""GUI implementation for the port scanner."""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
from typing import Optional
import json
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from core.scanner import AdvancedPortScanner
from utils.logger import setup_logger

logger = setup_logger(__name__)


class PortScannerGUI:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Advanced Port Scanner")
        self.window.geometry("800x600")

        self.scanner: Optional[AdvancedPortScanner] = None
        self.scan_thread: Optional[threading.Thread] = None

        self._create_widgets()
        self._create_layout()

    def _create_widgets(self):
        """Create all GUI widgets."""
        # Target input
        self.target_frame = ttk.LabelFrame(self.window, text="Target")
        self.target_entry = ttk.Entry(self.target_frame, width=40)
        self.target_entry.insert(0, "10.0.0.1")

        # Port range
        self.ports_frame = ttk.LabelFrame(self.window, text="Port Range")
        self.start_port = ttk.Entry(self.ports_frame, width=10)
        self.start_port.insert(0, "1")
        self.end_port = ttk.Entry(self.ports_frame, width=10)
        self.end_port.insert(0, "1024")

        # Options
        self.options_frame = ttk.LabelFrame(self.window, text="Scan Options")
        self.deep_scan_var = tk.BooleanVar(value=False)
        self.deep_scan_check = ttk.Checkbutton(
            self.options_frame, text="Deep Scan", variable=self.deep_scan_var
        )

        self.ssl_check_var = tk.BooleanVar(value=False)
        self.ssl_check = ttk.Checkbutton(
            self.options_frame, text="SSL Check", variable=self.ssl_check_var
        )

        # Control buttons
        self.button_frame = ttk.Frame(self.window)
        self.start_button = ttk.Button(
            self.button_frame, text="Start Scan", command=self.start_scan
        )
        self.stop_button = ttk.Button(
            self.button_frame, text="Stop", command=self.stop_scan, state=tk.DISABLED
        )
        self.save_button = ttk.Button(
            self.button_frame,
            text="Save Results",
            command=self.save_results,
            state=tk.DISABLED,
        )

        # Results area
        self.results_frame = ttk.LabelFrame(self.window, text="Scan Results")
        self.results_text = tk.Text(
            self.results_frame, height=20, width=80, wrap=tk.WORD
        )
        self.scrollbar = ttk.Scrollbar(
            self.results_frame, orient=tk.VERTICAL, command=self.results_text.yview
        )
        self.results_text.configure(yscrollcommand=self.scrollbar.set)

        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            self.window, variable=self.progress_var, maximum=100
        )

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        self.status_bar = ttk.Label(
            self.window, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W
        )

    def _create_layout(self):
        """Arrange widgets in the window."""
        # Target
        self.target_frame.pack(fill=tk.X, padx=5, pady=5)
        self.target_entry.pack(fill=tk.X, padx=5, pady=5)

        # Ports
        self.ports_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(self.ports_frame, text="Start:").pack(side=tk.LEFT, padx=5)
        self.start_port.pack(side=tk.LEFT, padx=5)
        ttk.Label(self.ports_frame, text="End:").pack(side=tk.LEFT, padx=5)
        self.end_port.pack(side=tk.LEFT, padx=5)

        # Options
        self.options_frame.pack(fill=tk.X, padx=5, pady=5)
        self.deep_scan_check.pack(side=tk.LEFT, padx=5)
        self.ssl_check.pack(side=tk.LEFT, padx=5)

        # Buttons
        self.button_frame.pack(fill=tk.X, padx=5, pady=5)
        self.start_button.pack(side=tk.LEFT, padx=5)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        self.save_button.pack(side=tk.LEFT, padx=5)

        # Results
        self.results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.results_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Progress and status
        self.progress_bar.pack(fill=tk.X, padx=5, pady=5)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM, padx=5, pady=5)

    def update_status(self, message: str):
        """Update status bar message."""
        self.status_var.set(message)
        self.window.update_idletasks()

    def update_progress(self, value: float):
        """Update progress bar value."""
        self.progress_var.set(value)
        self.window.update_idletasks()

    def append_result(self, message: str):
        """Add message to results area."""
        self.results_text.insert(tk.END, message + "\n")
        self.results_text.see(tk.END)
        self.window.update_idletasks()

    def clear_results(self):
        """Clear results area."""
        self.results_text.delete(1.0, tk.END)
        self.window.update_idletasks()

    def start_scan(self):
        """Start port scanning in a separate thread."""
        try:
            target = self.target_entry.get().strip()
            start_port = int(self.start_port.get())
            end_port = int(self.end_port.get())

            if not target:
                messagebox.showerror("Error", "Please enter a target")
                return

            if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
                messagebox.showerror("Error", "Ports must be between 1 and 65535")
                return

            if start_port > end_port:
                messagebox.showerror("Error", "Start port must be less than end port")
                return

            # Update UI state
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.save_button.config(state=tk.DISABLED)
            self.clear_results()

            # Create and start scanner
            self.scanner = AdvancedPortScanner(
                target=target,
                start_port=start_port,
                end_port=end_port,
                deep_scan=self.deep_scan_var.get(),
                ssl_check=self.ssl_check_var.get(),
            )

            self.scan_thread = threading.Thread(target=self._run_scan)
            self.scan_thread.start()

        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def _run_scan(self):
        """Execute scan in background thread."""
        try:
            self.update_status("Scanning...")
            total_ports = self.scanner.end_port - self.scanner.start_port + 1

            results = self.scanner.run()

            self.append_result("\nScan Results:")
            self.append_result(f"Target: {results['target']} ({results['target_ip']})")
            self.append_result(f"Duration: {results['duration']:.2f} seconds")
            self.append_result(f"\nOpen Ports ({len(results['open_ports'])}):")

            for port_info in sorted(results["open_ports"], key=lambda x: x["port"]):
                port_str = f"\nPort {port_info['port']} ({port_info['service']})"
                if port_info.get("version"):
                    port_str += f" - Version: {port_info['version']}"
                if port_info.get("banner"):
                    port_str += f"\n  Banner: {port_info['banner']}"
                if port_info.get("ssl"):
                    port_str += f"\n  SSL: {port_info['ssl']}"
                self.append_result(port_str)

            self.update_status("Scan completed")
            self.save_button.config(state=tk.NORMAL)

        except Exception as e:
            self.update_status(f"Error: {str(e)}")
            messagebox.showerror("Error", str(e))
        finally:
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)

    def stop_scan(self):
        """Stop ongoing scan."""
        if self.scanner:
            # Implement stop mechanism
            self.update_status("Stopping scan...")
            self.stop_button.config(state=tk.DISABLED)

    def save_results(self):
        """Save scan results to file."""
        if not self.scanner or not self.scanner.open_ports:
            messagebox.showwarning("Warning", "No results to save")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[
                ("HTML files", "*.html"),
                ("JSON files", "*.json"),
                ("All files", "*.*"),
            ],
        )

        if filename:
            try:
                format = "html" if filename.endswith(".html") else "json"
                self.scanner.save_results(filename, format=format)
                messagebox.showinfo("Success", f"Results saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save results: {str(e)}")

    def run(self):
        """Start the GUI application."""
        self.window.mainloop()


if __name__ == "__main__":
    app = PortScannerGUI()
    app.run()
