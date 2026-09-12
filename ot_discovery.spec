# -*- mode: python ; coding: utf-8 -*-

import subprocess
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

block_cipher = None

# Collect data files. ieee_oui.csv lives in data/ next to the exe and is
# downloaded on first run if missing, so it does not need to be bundled here.
# Npcap itself (the kernel driver scapy/DCP need) is not bundled either - it
# can't be baked into the exe, and the free edition's license disallows
# redistribution anyway. The app points users at npcap.com if it's missing
# (see ot_discovery/npcap_util.py), keeping this build small.
datas = []

# Stamp the exe with the git commit it was built from (see
# ot_discovery/version.py, which reads this back at runtime since the
# frozen exe can't call git itself).
try:
    _git_hash = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=SPECPATH, capture_output=True, text=True, check=True,
    ).stdout.strip()
except (OSError, subprocess.SubprocessError):
    _git_hash = "unknown"
_version_file = Path(SPECPATH) / "_version.txt"
_version_file.write_text(_git_hash, encoding="utf-8")
datas.append((str(_version_file), "."))

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
    'ot_discovery.npcap_util',
    'winreg',
] + collect_submodules('scapy')

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
    ['run_gui.py'],
    pathex=[SPECPATH],
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