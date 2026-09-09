from PyInstaller.utils.hooks import collect_all
from pathlib import Path

root = Path(SPECPATH).parent
scapy_data, scapy_binaries, scapy_imports = collect_all('scapy')
a = Analysis(
    [str(root / 'backend/portable.py')], pathex=[str(root / 'backend')],
    binaries=scapy_binaries,
    datas=[(str(root / 'dist'), 'dist'), (str(root / 'skills/ibmc'), 'skills/ibmc')] + scapy_data,
    hiddenimports=scapy_imports,
    hookspath=[], hooksconfig={}, runtime_hooks=[], excludes=[], noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name='Pangea',
          debug=False, bootloader_ignore_signals=False, strip=False, upx=False, console=True)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name='Pangea')
