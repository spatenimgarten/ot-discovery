"""Tkinter GUI for OT Discovery."""

import asyncio
import logging
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from typing import Optional
from datetime import datetime

try:
    import netifaces
    HAVE_NETIFACES = True
except ImportError:
    netifaces = None
    HAVE_NETIFACES = False

from ..core import OTScanner, ScanConfig, ScanMode
from ..models.device import Device
from ..logging_config import setup_logging
from ..netutil import parse_network
from ..npcap_util import is_npcap_installed, NPCAP_DOWNLOAD_URL
from ..paths import LOG_DIR
from ..version import get_version


# Setup logging for GUI
setup_logging(log_file=LOG_DIR / "ot_discovery_gui.log", level=logging.DEBUG, console_level=logging.INFO)


class OTDiscoveryGUI:
    """Main GUI application."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"OT Discovery - Asset Management ({get_version()})")
        self.root.geometry("1200x700")
        self.root.minsize(900, 600)
        # Start maximized/fullscreen
        self.root.state('zoomed')  # Windows/Linux
        # For macOS: self.root.attributes('-zoomed', True)

        self.scanner: Optional[OTScanner] = None
        self.scan_thread: Optional[threading.Thread] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.devices: list[Device] = []
        self.is_scanning = False

        self._setup_ui()
        self._setup_styles()
        self.root.after(200, self._check_npcap)

    def _setup_styles(self) -> None:
        style = ttk.Style()
        style.configure("Treeview", rowheight=25)
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

    def _setup_ui(self) -> None:
        # Main paned window
        main_paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main_paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Left panel - Configuration
        left_frame = ttk.Frame(main_paned, width=350)
        main_paned.add(left_frame, weight=1)
        self._build_config_panel(left_frame)

        # Right panel - Results
        right_frame = ttk.Frame(main_paned)
        main_paned.add(right_frame, weight=3)
        self._build_results_panel(right_frame)

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM, padx=5, pady=5)

    def _check_npcap(self) -> None:
        """Point the user at the Npcap download if it's missing (needed for the fast ARP sweep and DCP scan)."""
        if is_npcap_installed():
            return
        if messagebox.askyesno(
            "Npcap not found",
            "Npcap is not installed. Without it, ARP scans fall back to a slower "
            "per-host method and Profinet/DCP device detection is skipped.\n\n"
            "Open the Npcap download page now?",
        ):
            import webbrowser
            webbrowser.open(NPCAP_DOWNLOAD_URL)

    def _get_available_interfaces(self) -> list[str]:
        """Get list of available network interfaces with IPv4 addresses."""
        interfaces = []
        if HAVE_NETIFACES:
            try:
                for iface in netifaces.interfaces():
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        for addr in addrs[netifaces.AF_INET]:
                            if 'addr' in addr and not addr['addr'].startswith('127.'):
                                interfaces.append(f"{iface} ({addr['addr']})")
            except Exception:
                pass
        if not interfaces:
            interfaces = ["auto-detect"]
        return interfaces

    def _build_config_panel(self, parent: ttk.Frame) -> None:
        # Network section
        net_frame = ttk.LabelFrame(parent, text="Network", padding=10)
        net_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(net_frame, text="Network (CIDR):").grid(row=0, column=0, sticky=tk.W)
        self.network_var = tk.StringVar(value="192.168.1.0/24")
        ttk.Entry(net_frame, textvariable=self.network_var, width=28).grid(
            row=0, column=1, columnspan=2, sticky=tk.EW, pady=2)

        # Interface selection (only show if multiple interfaces available)
        interfaces = self._get_available_interfaces()
        self.interface_var = tk.StringVar()
        if len(interfaces) > 1 or (len(interfaces) == 1 and interfaces[0] != "auto-detect"):
            ttk.Label(net_frame, text="Interface:").grid(row=1, column=0, sticky=tk.W)
            self.interface_combo = ttk.Combobox(net_frame, textvariable=self.interface_var, state="readonly", width=28)
            self.interface_combo['values'] = interfaces
            if self.interface_combo['values']:
                self.interface_combo.current(0)
            self.interface_combo.grid(row=1, column=1, sticky=tk.EW, pady=2)
            ttk.Button(net_frame, text="↻", width=2, command=self._refresh_interfaces).grid(
                row=1, column=2, padx=(2, 0))
        else:
            # Auto-detect only - no UI needed
            self.interface_combo = None

        net_frame.columnconfigure(1, weight=1)

        # Scan Steps section
        steps_frame = ttk.LabelFrame(parent, text="Scan Steps", padding=10)
        steps_frame.pack(fill=tk.X, pady=(0, 10))

        self.step_vars = {}
        steps = [
            ("do_arp", "ARP Scan (Layer 2)"),
            ("do_dcp", "DCP Scan (Profinet)"),
            ("do_tcp", "TCP Port Scan"),
            ("do_udp", "UDP Port Scan"),
            ("do_plugins", "Plugin Identification"),
        ]
        for i, (key, label) in enumerate(steps):
            var = tk.BooleanVar(value=True if key != "do_udp" else False)
            self.step_vars[key] = var
            ttk.Checkbutton(steps_frame, text=label, variable=var).grid(row=i, column=0, sticky=tk.W, pady=1)

        # Advanced options
        adv_frame = ttk.LabelFrame(parent, text="Advanced", padding=10)
        adv_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(adv_frame, text="TCP Ports:").grid(row=0, column=0, sticky=tk.W)
        self.tcp_ports_var = tk.StringVar()
        ttk.Entry(adv_frame, textvariable=self.tcp_ports_var).grid(row=0, column=1, sticky=tk.EW, pady=2)

        ttk.Label(adv_frame, text="UDP Ports:").grid(row=1, column=0, sticky=tk.W)
        self.udp_ports_var = tk.StringVar()
        ttk.Entry(adv_frame, textvariable=self.udp_ports_var).grid(row=1, column=1, sticky=tk.EW, pady=2)

        adv_frame.columnconfigure(1, weight=1)

        # Export section
        export_frame = ttk.LabelFrame(parent, text="Export", padding=10)
        export_frame.pack(fill=tk.X, pady=(0, 10))

        self.export_csv_var = tk.BooleanVar()
        ttk.Checkbutton(export_frame, text="Export CSV", variable=self.export_csv_var,
                        command=self._toggle_csv).grid(row=0, column=0, sticky=tk.W)
        self.csv_path_var = tk.StringVar()
        self.csv_entry = ttk.Entry(export_frame, textvariable=self.csv_path_var, state=tk.DISABLED)
        self.csv_entry.grid(row=0, column=1, sticky=tk.EW, padx=2)
        self.csv_btn = ttk.Button(export_frame, text="...", command=self._browse_csv, state=tk.DISABLED)
        self.csv_btn.grid(row=0, column=2, padx=2)

        self.export_json_var = tk.BooleanVar()
        ttk.Checkbutton(export_frame, text="Export JSON", variable=self.export_json_var,
                        command=self._toggle_json).grid(row=1, column=0, sticky=tk.W)
        self.json_path_var = tk.StringVar()
        self.json_entry = ttk.Entry(export_frame, textvariable=self.json_path_var, state=tk.DISABLED)
        self.json_entry.grid(row=1, column=1, sticky=tk.EW, padx=2)
        self.json_btn = ttk.Button(export_frame, text="...", command=self._browse_json, state=tk.DISABLED)
        self.json_btn.grid(row=1, column=2, padx=2)

        export_frame.columnconfigure(1, weight=1)

        # Action buttons
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, pady=(10, 0))

        self.start_btn = ttk.Button(btn_frame, text="Start Scan", command=self._start_scan, style="Accent.TButton")
        self.start_btn.pack(fill=tk.X, pady=2)

        self.stop_btn = ttk.Button(btn_frame, text="Stop Scan", command=self._stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(fill=tk.X, pady=2)

        ttk.Button(btn_frame, text="Clear Results", command=self._clear_results).pack(fill=tk.X, pady=2)

        # Progress
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(parent, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=(10, 0))

        self.progress_label_var = tk.StringVar(value="")
        ttk.Label(parent, textvariable=self.progress_label_var).pack(fill=tk.X)

    def _build_results_panel(self, parent: ttk.Frame) -> None:
        # Toolbar
        toolbar = ttk.Frame(parent)
        toolbar.pack(fill=tk.X, pady=(0, 5))

        ttk.Label(toolbar, text="Results:").pack(side=tk.LEFT)
        self.count_var = tk.StringVar(value="0 devices")
        ttk.Label(toolbar, textvariable=self.count_var).pack(side=tk.LEFT, padx=5)

        ttk.Button(toolbar, text="Export CSV", command=self._export_csv).pack(side=tk.RIGHT, padx=2)
        ttk.Button(toolbar, text="Export JSON", command=self._export_json).pack(side=tk.RIGHT, padx=2)

        # Treeview container
        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        columns = [
            "IP", "Hostname", "DCP Name", "Hersteller", "Gerätetyp",
            "Firmware", "Seriennummer", "Bestellnummer", "MAC",
            "TCP Ports", "UDP Ports", "Protokolle", "Risiko", "CVEs"
        ]
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="extended")
        self.tree.tag_configure("duplicate_mac", background="#ffc2c2")

        col_widths = {
            "IP": 100, "Hostname": 120, "DCP Name": 120, "Hersteller": 100,
            "Gerätetyp": 80, "Firmware": 80, "Seriennummer": 100,
            "Bestellnummer": 100, "MAC": 120, "TCP Ports": 150,
            "UDP Ports": 150, "Protokolle": 150, "Risiko": 60, "CVEs": 150
        }

        for col in columns:
            self.tree.heading(col, text=col, command=lambda c=col: self._sort_tree(c))
            self.tree.column(col, width=col_widths.get(col, 100), minwidth=50)

        # Scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky=tk.NSEW)
        vsb.grid(row=0, column=1, sticky=tk.NS)
        hsb.grid(row=1, column=0, sticky=tk.EW)

        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        # Context menu
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Copy IP", command=self._copy_ip)
        self.context_menu.add_command(label="Copy Row", command=self._copy_row)
        self.tree.bind("<Button-3>", self._show_context_menu)

    def _refresh_interfaces(self) -> None:
        """Refresh the interface combobox with current available interfaces."""
        if self.interface_combo is None:
            return
        interfaces = self._get_available_interfaces()
        self.interface_combo['values'] = interfaces
        if interfaces:
            self.interface_combo.current(0)

    def _parse_interface(self, value: str) -> Optional[str]:
        """Extract interface name from combobox value (format: 'name (IP)')."""
        if not value:
            return None
        # Format: "interface_name (IP)"
        if ' (' in value:
            return value.split(' (')[0]
        return value

    def _toggle_csv(self) -> None:
        state = tk.NORMAL if self.export_csv_var.get() else tk.DISABLED
        self.csv_entry.config(state=state)
        self.csv_btn.config(state=state)

    def _toggle_json(self) -> None:
        state = tk.NORMAL if self.export_json_var.get() else tk.DISABLED
        self.json_entry.config(state=state)
        self.json_btn.config(state=state)

    def _browse_csv(self) -> None:
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if path:
            self.csv_path_var.set(path)

    def _browse_json(self) -> None:
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if path:
            self.json_path_var.set(path)

    def _start_scan(self) -> None:
        if self.is_scanning:
            return

        try:
            network = parse_network(self.network_var.get())
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid network: {e}")
            return

        config = ScanConfig(
            network=network,
            mode=ScanMode.CUSTOM,
            interface=self._parse_interface(self.interface_var.get()) or None,
            do_arp=self.step_vars["do_arp"].get(),
            do_dcp=self.step_vars["do_dcp"].get(),
            do_tcp=self.step_vars["do_tcp"].get(),
            do_udp=self.step_vars["do_udp"].get(),
            do_plugins=self.step_vars["do_plugins"].get(),
            export_csv=Path(self.csv_path_var.get()) if self.export_csv_var.get() and self.csv_path_var.get() else None,
            export_json=Path(self.json_path_var.get()) if self.export_json_var.get() and self.json_path_var.get() else None,
            progress_callback=self._gui_progress_callback,
            device_callback=self._gui_device_callback,
        )

        if self.tcp_ports_var.get():
            config.tcp_ports = [int(p.strip()) for p in self.tcp_ports_var.get().split(",")]
        if self.udp_ports_var.get():
            config.udp_ports = [int(p.strip()) for p in self.udp_ports_var.get().split(",")]

        self.is_scanning = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress_var.set(0)
        self.progress_label_var.set("Starting...")
        self._clear_tree()

        self.scanner = OTScanner(config)
        self.scan_thread = threading.Thread(target=self._run_scan_thread, daemon=True)
        self.scan_thread.start()

    def _run_scan_thread(self) -> None:
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        try:
            devices = self.loop.run_until_complete(self.scanner.run())
            self.root.after(0, self._scan_complete, devices)
        except Exception as e:
            self.root.after(0, self._scan_error, str(e))
        finally:
            self.loop.close()

    def _scan_complete(self, devices: list[Device]) -> None:
        self.devices = devices
        self._populate_tree(devices)
        self.count_var.set(f"{len(devices)} devices")
        self.status_var.set(f"Scan complete - {len(devices)} devices found")
        self.progress_var.set(100)
        self.progress_label_var.set("Done")
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.is_scanning = False

    def _scan_error(self, error: str) -> None:
        messagebox.showerror("Scan Error", error)
        self.status_var.set(f"Error: {error}")
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.is_scanning = False

    def _stop_scan(self) -> None:
        if self.scanner and self.loop:
            # Cancel all tasks
            for task in asyncio.all_tasks(self.loop):
                task.cancel()
        self.status_var.set("Stopping...")
        self.progress_label_var.set("Stopping...")

    async def _gui_progress_callback(self, current: int, total: int, step: str) -> None:
        def update():
            if total > 0:
                self.progress_var.set((current / total) * 100)
            self.progress_label_var.set(f"{step}: {current}/{total}")
        self.root.after(0, update)

    async def _gui_device_callback(self, device: Device) -> None:
        def update():
            self._add_device_to_tree(device)
            self.count_var.set(f"{len(self.devices)} devices")
        self.root.after(0, update)

    def _clear_results(self) -> None:
        self._clear_tree()
        self.devices = []
        self.count_var.set("0 devices")
        self.progress_var.set(0)
        self.progress_label_var.set("")

    def _clear_tree(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)

    def _populate_tree(self, devices: list[Device]) -> None:
        self._clear_tree()
        for device in devices:
            self._add_device_to_tree(device)

    def _add_device_to_tree(self, device: Device) -> None:
        values = [
            str(device.ip),
            device.hostname or "",
            device.dcp_name or "",
            device.manufacturer or "",
            device.device_type.value if device.device_type else "",
            device.firmware or "",
            device.serial_number or "",
            device.order_number or "",
            device.mac or "",
            ", ".join(map(str, sorted(device.tcp_ports))),
            ", ".join(map(str, sorted(device.udp_ports))),
            ", ".join(p.value for p in sorted(device.protocols, key=lambda x: x.value)),
            f"{device.risk_score:.1f}",
            ", ".join(device.vulnerabilities),
        ]
        tags = [str(device.ip)]
        if device.duplicate_mac:
            tags.append("duplicate_mac")
        self.tree.insert("", tk.END, values=values, tags=tuple(tags))

    def _sort_tree(self, col: str) -> None:
        # Simple sort toggle
        pass

    def _show_context_menu(self, event) -> None:
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def _copy_ip(self) -> None:
        selection = self.tree.selection()
        if selection:
            ip = self.tree.item(selection[0])['values'][0]
            self.root.clipboard_clear()
            self.root.clipboard_append(ip)

    def _copy_row(self) -> None:
        selection = self.tree.selection()
        if selection:
            values = self.tree.item(selection[0])['values']
            self.root.clipboard_clear()
            self.root.clipboard_append("\t".join(str(v) for v in values))

    def _export_csv(self) -> None:
        if not self.devices:
            messagebox.showwarning("Warning", "No devices to export")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if path:
            from ..export import CSVExporter
            CSVExporter(Path(path)).export(self.devices)
            messagebox.showinfo("Success", f"Exported to {path}")

    def _export_json(self) -> None:
        if not self.devices:
            messagebox.showwarning("Warning", "No devices to export")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if path:
            from ..export import JSONExporter
            JSONExporter(Path(path)).export(self.devices)
            messagebox.showinfo("Success", f"Exported to {path}")


def main() -> None:
    root = tk.Tk()
    app = OTDiscoveryGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()