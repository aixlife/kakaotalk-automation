"""Local paths and fixed resource bounds; no user or account configuration."""
import os
import hashlib
from pathlib import Path
import struct
import sys

if not __debug__:
    raise RuntimeError('OPTIMIZED_PYTHON_UNSUPPORTED')

ROOT=Path(__file__).resolve().parent
SOURCE_NAMES=frozenset(('reader_config.py','kakao_read_win.py','reader_rpc.py','reader_job.py',
    'room_reader.py','reader_queries.py','reader_envelope.py','v2_key_derivation.py','vendor_appstate.py'))
MEMORY_LIMIT=256*1024*1024

def installation_matches(path,expected,maximum_bytes=256*1024*1024):
    """Reject oversized artifacts before hashing; never buffer an executable."""
    if not path.is_file() or not 0<path.stat().st_size<=maximum_bytes:
        return False
    with path.open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()==expected

def state_root():
    if os.name!='nt' or struct.calcsize('P')!=8 or sys.version_info<(3,11):
        raise RuntimeError('WINDOWS_X64_PYTHON_REQUIRED')
    local=os.environ.get('LOCALAPPDATA')
    if not local:
        raise RuntimeError('LOCALAPPDATA_REQUIRED')
    root=Path(local)/'KakaoReader'/'receipts'
    root.mkdir(parents=True,exist_ok=True)
    return root
