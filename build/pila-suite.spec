# PILA Suite — Community (Host) build spec.
# Build (run from repo root on Windows):  pyinstaller build/pila-suite.spec
# Output: dist/pila-suite-<version>.exe  — one file, no third-party runtime deps.
import os
import freescore

VER = freescore.__version__
_parts = (VER.split("+")[0].split("-")[0].split(".") + ["0", "0", "0", "0"])[:4]
VTUPLE = tuple(int(x) if x.isdigit() else 0 for x in _parts)

# Windows version resource, generated from __version__ so releases need no manual edit.
_VERSION_RC = f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={VTUPLE}, prodvers={VTUPLE}, mask=0x3f, flags=0x0,
                    OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'ByTE X Bit Technologies LLC'),
      StringStruct('FileDescription', 'PILA Suite - Community (Host)'),
      StringStruct('FileVersion', '{VER}'),
      StringStruct('InternalName', 'pila-suite'),
      StringStruct('LegalCopyright', 'Copyright ByTE X Bit Technologies LLC'),
      StringStruct('OriginalFilename', 'pila-suite-{VER}.exe'),
      StringStruct('ProductName', 'PILA Suite - Community'),
      StringStruct('ProductVersion', '{VER}')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""
_rc_path = os.path.join('build', 'version_info.generated.txt')
with open(_rc_path, 'w', encoding='utf-8') as _fh:
    _fh.write(_VERSION_RC)

a = Analysis(
    ['build/pila_suite_app.py'],
    pathex=['.'],
    binaries=[],
    datas=[('freescore/templates/index.html', 'freescore/templates')],
    hiddenimports=[],
    hookspath=[], hooksconfig={}, runtime_hooks=[], excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name=f'pila-suite-{VER}',
    debug=False, bootloader_ignore_signals=False, strip=False,
    upx=False,                 # no UPX: avoids AV false positives on a security tool
    runtime_tmpdir=None,
    console=True,              # shows "Serving on ..."; closing the window stops it
    version=_rc_path,
)
