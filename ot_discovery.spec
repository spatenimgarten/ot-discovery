# -*- mode: python ; coding: utf-8 -*-

import sys
from pathlib import Path

block_cipher = None

# Collect data files. ieee_oui.csv lives in data/ next to the exe and is
# downloaded on first run if missing, so it does not need to be bundled here.
datas = []

# Hidden imports for asyncio and network modules
hiddenimports = [
    'asyncio',
    'asyncio.selector_events',
    'asyncio.proactor_events',
    'ipaddress',
    'netifaces',
    'socket',
    'struct',
    'fcntl',
    'csv',
    'json',
    'tkinter',
    'tkinter.ttk',
    'tkinter.filedialog',
    'tkinter.messagebox',
    'ot_discovery',
    'ot_discovery.models',
    'ot_discovery.models.device',
    'ot_discovery.models.scan_result',
    'ot_discovery.plugins',
    'ot_discovery.plugins.base',
    'ot_discovery.plugins.manager',
    'ot_discovery.plugins.manufacturers',
    'ot_discovery.scanners',
    'ot_discovery.scanners.arp',
    'ot_discovery.scanners.dcp',
    'ot_discovery.scanners.tcp',
    'ot_discovery.scanners.udp',
    'ot_discovery.scanners.hostname',
    'ot_discovery.core',
    'ot_discovery.core.scanner',
    'ot_discovery.export',
    'ot_discovery.export.csv_exporter',
    'ot_discovery.export.json_exporter',
    'ot_discovery.gui',
    'ot_discovery.gui.main',
]

# Exclude unnecessary modules
excludes = [
    'matplotlib',
    'numpy',
    'pandas',
    'scipy',
    'PIL',
    'cv2',
    'pytest',
    'black',
    'ruff',
    'mypy',
]

a = Analysis(
    ['ot_discovery/gui/main.py'],
    pathex=[str(Path(__file__).parent)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='OTDiscovery',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # GUI mode - no console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,  # Add .ico file path here if you have one
)