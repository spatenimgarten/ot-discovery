# OT Discovery

Asset Management Tool for Automation Networks (OT/ICS).

## Features

- **Multi-protocol Discovery**: ARP, DCP (Profinet), TCP, UDP
- **Manufacturer Identification**: Plugin-based architecture for Siemens, IFM, Festo, Phoenix Contact, Wago, Beckhoff, Moxa, Hirschmann
- **Device Details**: Firmware, serial number, order number, hardware revision
- **Export**: CSV, JSON
- **GUI**: Tkinter-based desktop application
- **CLI**: Command-line interface for automation
- **Executable**: PyInstaller build for standalone .exe

## Installation

```bash
pip install -e .
```

Or with development dependencies:

```bash
pip install -e ".[dev]"
```

## Usage

### GUI Application

```bash
ot-discovery-gui
```

Or run directly:

```bash
python -m ot_discovery.gui.main
```

### CLI

```bash
# Basic scan
ot-discovery 192.168.1.0/24

# With options
ot-discovery 192.168.1.0/24 -i eth0 --mode deep --csv results.csv --json results.json

# Custom ports
ot-discovery 192.168.1.0/24 --tcp-ports "80,443,502,102,4840" --udp
```

### Build Executable

```bash
pip install pyinstaller
pyinstaller ot_discovery.spec
```

Output: `dist/OTDiscovery.exe`

## Architecture

```
ot_discovery/
├── models/          # Data models (Device, ScanResult)
├── plugins/         # Plugin system
│   ├── base.py      # Abstract base classes
│   ├── manager.py   # Plugin registry
│   └── manufacturers.py  # Vendor plugins
├── scanners/        # Network scanners
│   ├── arp.py       # ARP scanner (raw sockets)
│   ├── dcp.py       # DCP scanner (Profinet)
│   ├── tcp.py       # TCP port scanner
│   ├── udp.py       # UDP port scanner
│   └── hostname.py  # Reverse DNS
├── core/            # Orchestration
│   └── scanner.py   # Main scan pipeline
├── export/          # Export formats
│   ├── csv_exporter.py
│   └── json_exporter.py
├── gui/             # Tkinter GUI
│   └── main.py
└── cli.py           # Command-line interface
```

## Scan Pipeline

1. **ARP Scan** - Layer 2 discovery, MAC addresses
2. **DCP Scan** - Profinet device identification (names, vendor/device IDs)
3. **Merge** - Combine results by IP address
4. **TCP Scan** - Port scan on discovered devices
5. **UDP Scan** (optional) - UDP port scan
6. **Hostname Resolution** - Reverse DNS
7. **Plugin Identification** - Manufacturer-specific detection
8. **Export** - CSV/JSON output

## Plugin System

Each manufacturer plugin implements:

- `match(device)` - Fast check (vendor ID, OUI, ports)
- `identify(device)` - Determine device type
- `details(device)` - Extract firmware, serial, order number

## Supported Devices

- Siemens: S7-1200, S7-1500, ET200SP, LOGO!, Panels, SCALANCE
- IFM: IO-Link masters, sensors
- Festo: Valve terminals, controllers
- Phoenix Contact: I/O, switches
- Wago: Controllers, I/O
- Beckhoff: PLCs, I/O
- Moxa: Switches, gateways
- Hirschmann: Switches
- Generic: Modbus TCP, OPC UA, SNMP devices

## Requirements

- Python 3.10+
- Administrator/root privileges (for raw sockets)
- Windows/Linux/macOS

## License

MIT