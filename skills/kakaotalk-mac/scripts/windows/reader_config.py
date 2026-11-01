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

def installation_digest(path,maximum_bytes=256*1024*1024):
    """Reject oversized artifacts before hashing; never buffer an executable."""
    if not path.is_file() or not 0<path.stat().st_size<=maximum_bytes:
        return None
    with path.open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()

def pe_architecture(path,maximum_bytes=256*1024*1024):
    """Read bounded PE headers without loading or executing the application."""
    if not path.is_file() or not 64<=path.stat().st_size<=maximum_bytes:
        return None
    with path.open('rb') as stream:
        header=stream.read(64)
        if len(header)!=64 or header[:2]!=b'MZ':
            return None
        offset=struct.unpack_from('<I',header,0x3c)[0]
        if not 64<=offset<=min(1024*1024,path.stat().st_size-26):
            return None
        stream.seek(offset)
        header=stream.read(26)
        if len(header)!=26 or header[:4]!=b'PE\0\0':
            return None
        machine=struct.unpack_from('<H',header,4)[0]
        optional_size,magic=struct.unpack_from('<H',header,20)[0],struct.unpack_from('<H',header,24)[0]
        if optional_size<2 or offset+24+optional_size>path.stat().st_size:
            return None
        if machine==0x14c and magic==0x10b:return 'x86'
        if machine==0x8664 and magic==0x20b:return 'x64'
        if machine==0xaa64 and magic==0x20b:return 'arm64'
        return 'unsupported'

def matched_installation(path,expected,maximum_bytes=256*1024*1024,architecture=None):
    allowed=(expected,) if isinstance(expected,str) else expected
    digest=installation_digest(path,maximum_bytes)
    if digest not in allowed:
        return None
    if architecture is not None and pe_architecture(path,maximum_bytes)!=architecture:
        return None
    return digest

def installation_matches(path,expected,maximum_bytes=256*1024*1024):
    """Keep the original boolean contract used by existing integrations."""
    return matched_installation(path,expected,maximum_bytes) is not None

def file_version(path):
    """Read Windows file-version metadata only; it never grants compatibility."""
    if os.name!='nt' or not path.is_file():return None
    import ctypes as C
    import ctypes.wintypes as W
    version=C.WinDLL('version',use_last_error=True)
    version.GetFileVersionInfoSizeW.argtypes=[W.LPCWSTR,C.POINTER(W.DWORD)]
    version.GetFileVersionInfoSizeW.restype=W.DWORD
    version.GetFileVersionInfoW.argtypes=[W.LPCWSTR,W.DWORD,W.DWORD,C.c_void_p]
    version.GetFileVersionInfoW.restype=W.BOOL
    version.VerQueryValueW.argtypes=[C.c_void_p,W.LPCWSTR,C.POINTER(C.c_void_p),C.POINTER(W.UINT)]
    version.VerQueryValueW.restype=W.BOOL
    size=version.GetFileVersionInfoSizeW(str(path),None)
    if not 52<=size<=1024*1024:return None
    data=C.create_string_buffer(size)
    if not version.GetFileVersionInfoW(str(path),0,size,data):return None
    value=C.c_void_p();length=W.UINT()
    if not version.VerQueryValueW(data,'\\',C.byref(value),C.byref(length)) or length.value<52:return None
    start=C.addressof(data)
    if not value.value or not start<=value.value<=start+size-52:return None
    fields=struct.unpack('<13I',C.string_at(value.value,52))
    if fields[0]!=0xfeef04bd:return None
    return '.'.join(str(v) for v in (fields[2]>>16,fields[2]&65535,fields[3]>>16,fields[3]&65535))

def installation_report(primary,reader_supported,legacy_expected,fallback=None):
    """Describe file compatibility, without opening a process or account data."""
    path=primary
    if not path.is_file() and fallback is not None and fallback.is_file():path=fallback
    digest=installation_digest(path)
    architecture=pe_architecture(path)
    version=file_version(path) if digest is not None else None
    if not path.is_file():reason='APP_NOT_FOUND'
    elif digest is None:reason='APP_FILE_SIZE_LIMIT'
    elif architecture is None:reason='INVALID_APP_EXECUTABLE'
    elif architecture=='x86':reason='APP_X86_UNSUPPORTED'
    elif architecture!='x64':reason='APP_ARCHITECTURE_UNSUPPORTED'
    elif path!=primary:reason='APP_INSTALLATION_PATH_UNSUPPORTED'
    elif digest not in reader_supported:reason='INSTALLATION_NOT_REVIEWED'
    else:reason=None
    supported=reason is None
    actions={
        'APP_NOT_FOUND':'Install a reviewed x64 KakaoTalk build in its standard Program Files location.',
        'APP_FILE_SIZE_LIMIT':'Keep the file-size limit; use a reviewed installation.',
        'INVALID_APP_EXECUTABLE':'Use an intact official x64 installation; do not edit the hash guard.',
        'APP_X86_UNSUPPORTED':'This reader requires the x64 KakaoTalk app, even on 64-bit Windows. Do not replace the expected hash.',
        'APP_ARCHITECTURE_UNSUPPORTED':'Use a reviewed x64 KakaoTalk installation.',
        'APP_INSTALLATION_PATH_UNSUPPORTED':'The reader uses the standard Program Files installation; do not redirect it to another build.',
        'INSTALLATION_NOT_REVIEWED':'Check for a reviewed reader release for this exact build. Do not replace the expected hash.',
    }
    return {'supported_installation':supported,'reader_supported':supported,
        'room_open_supported':supported and digest==legacy_expected,
        'self_attachment_supported':supported and digest==legacy_expected,
        'capability_scope':'installation_eligibility_only','read_verification':'NOT_RUN',
        'app_path':str(path),'app_architecture':architecture,'app_version':version,
        'matched_app_version':reader_supported.get(digest) if supported else None,
        'installation_sha256':digest,'supported_reader_versions':list(reader_supported.values()),
        'reason':reason,'next_action':actions.get(reason,'Run one explicitly selected room read to verify the logged-in session.')}

def state_root():
    if os.name!='nt' or struct.calcsize('P')!=8 or sys.version_info<(3,11):
        raise RuntimeError('WINDOWS_X64_PYTHON_REQUIRED')
    local=os.environ.get('LOCALAPPDATA')
    if not local:
        raise RuntimeError('LOCALAPPDATA_REQUIRED')
    root=Path(local)/'KakaoReader'/'receipts'
    root.mkdir(parents=True,exist_ok=True)
    return root
