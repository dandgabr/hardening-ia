# -*- mode: python ; coding: utf-8 -*-
import sys
from pathlib import Path

block_cipher = None

# Bundle declarative YAML policies and native helper scripts
datas = [
    ('configs', 'configs'),
    ('scripts', 'scripts')
]

hiddenimports = [
    'rich',
    'rich.markup',
    'rich.console',
    'rich.table',
    'rich.panel',
    'rich.text',
    'rich.logging',
    'rich.markdown',
    'textual',
    'textual.app',
    'textual.containers',
    'textual.widgets',
    'textual.screen',
    'textual.reactive',
    'textual.events',
    'textual.binding',
    'textual.timer',
    'yaml',
    'jinja2',
    'psutil',
    'unittest',
    'unittest.mock'
]

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
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
    name='hardening-ia',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
