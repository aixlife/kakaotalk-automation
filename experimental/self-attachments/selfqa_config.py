"""Separate shipped code, shipped reader, and private per-user QA state."""
import os
from pathlib import Path
import struct
import sys

if not __debug__:
    raise RuntimeError('OPTIMIZED_PYTHON_UNSUPPORTED')
SOURCE_ROOT=Path(__file__).resolve().parent
READER_ROOT=SOURCE_ROOT.parents[1]/'skills/kakaotalk-mac/scripts/windows'
PYTHON=sys.executable
_local=os.environ.get('LOCALAPPDATA')
ROOT=(Path(_local).absolute()/'KakaoReader'/'self-attachment-qa') if _local else None
if str(READER_ROOT) not in sys.path:
    sys.path.insert(0,str(READER_ROOT))

def require_windows():
    if os.name!='nt' or struct.calcsize('P')!=8 or sys.version_info<(3,11):
        raise RuntimeError('WINDOWS_X64_PYTHON_3_11_REQUIRED')
    if ROOT is None or not ROOT.is_absolute() or not READER_ROOT.is_dir():
        raise RuntimeError('PRIVATE_STATE_OR_READER_PACKAGE_UNAVAILABLE')
    # Never accept a state directory redirected into this checkout.
    resolved=ROOT.resolve()
    if SOURCE_ROOT.parents[1] in resolved.parents or resolved==SOURCE_ROOT.parents[1]:
        raise RuntimeError('PRIVATE_STATE_LOCATION_UNSAFE')
    def reject_redirects():
        for path in (ROOT,*ROOT.parents):
            if path.is_symlink():raise RuntimeError('PRIVATE_STATE_PARENT_SYMLINK')
            try:attributes=getattr(path.lstat(),'st_file_attributes',0)
            except FileNotFoundError:continue
            if attributes & 0x400:raise RuntimeError('PRIVATE_STATE_REPARSE_POINT')
    reject_redirects()
    ROOT.mkdir(parents=True,exist_ok=True)
    reject_redirects()
