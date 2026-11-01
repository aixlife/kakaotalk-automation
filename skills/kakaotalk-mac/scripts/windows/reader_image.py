"""Compare the running main module's bounded PE headers with its disk image.

This is a stale-image/architecture guard, not a hash of all mapped code. It
never executes the target, changes protection, or reads account data.
API/layout references:
https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-moduleentry32w
https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
"""
import ctypes as C
import hashlib
import json
import ntpath
import os
from pathlib import Path
import stat
import struct

MAX_DISK_HEADER=8192
MAX_MAPPED_HEADER=32768
MAX_PROCESS_READ=384*1024*1024
MAX_IMAGE_FILE=256*1024*1024


class MODULEENTRY32W(C.Structure):
    # Native host pointers remain native width even for a WOW64 target.
    # Fixed Windows scalar widths also make non-Windows fixture tests valid.
    _fields_=[('dwSize',C.c_uint32),('th32ModuleID',C.c_uint32),
        ('th32ProcessID',C.c_uint32),('GlblcntUsage',C.c_uint32),
        ('ProccntUsage',C.c_uint32),('modBaseAddr',C.c_void_p),
        ('modBaseSize',C.c_uint32),('hModule',C.c_void_p),
        ('szModule',C.c_uint16*256),('szExePath',C.c_uint16*260)]


def _require(condition,reason):
    if not condition:raise RuntimeError(reason)


def _stat_identity(info):
    # Windows path-stat and fstat can disagree on deprecated st_ctime_ns.
    # Birth time, when present, has consistent creation-time semantics.
    return (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,
            getattr(info,'st_birthtime_ns',info.st_ctime_ns))


def image_file_identity(path):
    """Return a private stat token, rejecting link/reparse path components."""
    path=Path(path)
    _require(path.is_absolute() and '..' not in path.parts,'DISK_IMAGE_PATH_UNSAFE')
    try:
        for part in (path,*path.parents):
            info=part.lstat()
            _require(not stat.S_ISLNK(info.st_mode) and
                not getattr(info,'st_file_attributes',0)&0x400,'DISK_IMAGE_LINK_OR_REPARSE')
            _require(stat.S_ISREG(info.st_mode) if part==path else stat.S_ISDIR(info.st_mode),
                'DISK_IMAGE_PATH_UNSAFE')
        info=path.lstat()
    except OSError:
        raise RuntimeError('DISK_IMAGE_UNAVAILABLE') from None
    _require(64<=info.st_size<=MAX_IMAGE_FILE,'DISK_IMAGE_SIZE_LIMIT')
    return _stat_identity(info)


def _pe_offset(data):
    _require(len(data)>=64 and data[:2]==b'MZ','IMAGE_HEADERS_INVALID')
    offset=struct.unpack_from('<I',data,0x3c)[0]
    _require(64<=offset<=MAX_DISK_HEADER-24,'IMAGE_HEADER_LIMIT')
    return offset


def _extent(offset,coff):
    _require(len(coff)==24 and coff[:4]==b'PE\0\0','IMAGE_HEADERS_INVALID')
    sections=struct.unpack_from('<H',coff,6)[0]
    optional_size=struct.unpack_from('<H',coff,20)[0]
    _require(1<=sections<=96 and 64<=optional_size<=4096,'IMAGE_HEADERS_INVALID')
    end=offset+24+optional_size+sections*40
    _require(end<=MAX_DISK_HEADER,'IMAGE_HEADER_LIMIT')
    return end,sections,optional_size


def _parse_headers(data,file_size):
    offset=_pe_offset(data)
    end,count,optional_size=_extent(offset,data[offset:offset+24])
    _require(len(data)>=end,'IMAGE_HEADERS_INVALID')
    machine=struct.unpack_from('<H',data,offset+4)[0]
    optional=offset+24
    magic=struct.unpack_from('<H',data,optional)[0]
    architecture={(0x14c,0x10b):'x86',(0x8664,0x20b):'x64'}.get((machine,magic))
    _require(architecture is not None,'IMAGE_ARCHITECTURE_UNSUPPORTED')
    _require(optional_size>=(96 if architecture=='x86' else 112),'IMAGE_HEADERS_INVALID')
    image_size,header_size=struct.unpack_from('<II',data,optional+56)
    entrypoint=struct.unpack_from('<I',data,optional+16)[0]
    _require(end<=header_size<=min(file_size,image_size) and
        0<entrypoint<image_size,'IMAGE_HEADERS_INVALID')
    sections=[]
    for index in range(count):
        base=optional+optional_size+index*40
        virtual_size,virtual_address,raw_size,raw_offset=struct.unpack_from('<IIII',data,base+8)
        _require(virtual_address+max(virtual_size,raw_size)<=image_size and
            (not raw_size or raw_offset+raw_size<=file_size),'IMAGE_HEADERS_INVALID')
        # An empty on-disk extent has no file pointer. A reviewed packed image
        # can carry a nonzero pointer on disk which is zeroed when mapped.
        # Keep every nonempty extent and all virtual layout fields exact.
        sections.append((data[base:base+8].hex(),virtual_size,virtual_address,
            raw_size,raw_offset if raw_size else 0,struct.unpack_from('<I',data,base+36)[0]))
    # ImageBase is intentionally omitted: ASLR can relocate the loaded image.
    fields={'machine':machine,'timestamp':struct.unpack_from('<I',data,offset+8)[0],
        'optional_magic':magic,'optional_size':optional_size,'image_size':image_size,
        'header_size':header_size,'entrypoint':entrypoint,
        'section_alignment':struct.unpack_from('<I',data,optional+32)[0],
        'file_alignment':struct.unpack_from('<I',data,optional+36)[0],
        'coff_characteristics':struct.unpack_from('<H',data,offset+22)[0],
        'sections':sections}
    return architecture,fields


def _disk_headers(path,identity):
    try:
        with path.open('rb') as stream:
            _require(_stat_identity(os.fstat(stream.fileno()))==identity,'DISK_IMAGE_CHANGED')
            data=stream.read(MAX_DISK_HEADER)
            _require(_stat_identity(os.fstat(stream.fileno()))==identity,'DISK_IMAGE_CHANGED')
    except OSError:
        raise RuntimeError('DISK_IMAGE_UNAVAILABLE') from None
    _require(image_file_identity(path)==identity,'DISK_IMAGE_CHANGED')
    return data


def _canonical_path(value):
    value=str(value)
    if value.startswith('\\\\?\\UNC\\'):value='\\\\'+value[8:]
    elif value.startswith('\\\\?\\'):value=value[4:]
    return ntpath.normcase(ntpath.normpath(value))


def _module_path(entry):
    values=list(entry.szExePath)
    _require(0 in values,'MAPPED_IMAGE_PATH_UNAVAILABLE')
    count=values.index(0)
    _require(count>0,'MAPPED_IMAGE_PATH_UNAVAILABLE')
    raw=C.string_at(C.addressof(entry)+MODULEENTRY32W.szExePath.offset,count*2)
    try:return raw.decode('utf-16-le')
    except UnicodeError:raise RuntimeError('MAPPED_IMAGE_PATH_UNAVAILABLE') from None


def verify_mapped_image(reader,app_path):
    """Fail closed before account reads if the mapped main PE differs from disk.

    The caller must also bind its reviewed disk SHA to an unchanged
    image_file_identity token across hashing and this call. This result does
    not establish byte-for-byte identity of all mapped code.
    """
    _require(C.sizeof(C.c_void_p)==8,'WINDOWS_X64_PYTHON_REQUIRED')
    reader.guard()
    path=Path(app_path);identity=image_file_identity(path)
    disk=_disk_headers(path,identity)
    disk_arch,disk_fields=_parse_headers(disk,identity[2])
    _require(disk_arch==reader.target_architecture,'MAPPED_IMAGE_ARCHITECTURE_MISMATCH')
    k=reader.k
    k.CreateToolhelp32Snapshot.argtypes=[C.c_uint32,C.c_uint32]
    k.CreateToolhelp32Snapshot.restype=C.c_void_p
    k.Module32FirstW.argtypes=[C.c_void_p,C.POINTER(MODULEENTRY32W)]
    k.Module32FirstW.restype=C.c_int
    k.CloseHandle.argtypes=[C.c_void_p];k.CloseHandle.restype=C.c_int
    k.ReadProcessMemory.argtypes=[C.c_void_p,C.c_void_p,C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t)]
    k.ReadProcessMemory.restype=C.c_int
    k.VirtualQueryEx.argtypes=[C.c_void_p,C.c_void_p,C.POINTER(reader.mbi_type),C.c_size_t]
    k.VirtualQueryEx.restype=C.c_size_t
    snapshot=k.CreateToolhelp32Snapshot(0x8|0x10,reader.pid)
    _require(snapshot not in (None,0,C.c_void_p(-1).value),'MODULE_SNAPSHOT_UNAVAILABLE')
    count=0
    try:
        entry=MODULEENTRY32W();entry.dwSize=C.sizeof(entry)
        _require(k.Module32FirstW(snapshot,C.byref(entry)),'MAIN_MODULE_UNAVAILABLE')
        _require(entry.th32ProcessID==reader.pid,'MAPPED_IMAGE_PROCESS_MISMATCH')
        _require(_canonical_path(_module_path(entry))==_canonical_path(path),'MAPPED_IMAGE_PATH_MISMATCH')
        base=entry.modBaseAddr;module_size=entry.modBaseSize
        _require(base is not None and 0x10000<=base<0x800000000000 and
            base+module_size<=0x800000000000 and entry.hModule==base,
            'MAPPED_IMAGE_RANGE_INVALID')
        _require(module_size==disk_fields['image_size'],'MAPPED_IMAGE_HEADER_MISMATCH')
        _require(disk_arch!='x86' or base+module_size<=0x100000000,'MAPPED_IMAGE_ARCHITECTURE_MISMATCH')

        def mapped(offset,size):
            nonlocal count
            reader.guard()
            _require(0<=offset and 0<size and offset+size<=min(module_size,MAX_DISK_HEADER)
                and count+size<=MAX_MAPPED_HEADER,'MAPPED_IMAGE_HEADER_LIMIT')
            _require(reader.read_bytes+size<=MAX_PROCESS_READ,'PROCESS_READ_LIMIT')
            address=base+offset;info=reader.mbi_type()
            _require(k.VirtualQueryEx(reader.handle,address,C.byref(info),C.sizeof(info))==C.sizeof(info)
                and info.kind==0x1000000 and info.state==0x1000 and info.allocation==base
                and not info.protect&0x100 and info.protect&0xff in (2,4,8,32,64,128)
                and info.base is not None and info.base<=address
                and address+size<=info.base+info.size,'MAPPED_IMAGE_MEMORY_UNAVAILABLE')
            buffer=C.create_string_buffer(size);got=C.c_size_t()
            # Charge attempted bytes too: failures cannot provide unmetered reads.
            count+=size;reader.read_bytes+=size
            _require(k.ReadProcessMemory(reader.handle,address,buffer,size,C.byref(got))
                and got.value==size,'MAPPED_IMAGE_MEMORY_UNAVAILABLE')
            reader.guard()
            return buffer.raw

        offset=_pe_offset(mapped(0,64))
        end,_,_=_extent(offset,mapped(offset,24))
        mapped_arch,mapped_fields=_parse_headers(mapped(0,end),identity[2])
        _require(mapped_arch==disk_arch,'MAPPED_IMAGE_ARCHITECTURE_MISMATCH')
        _require(mapped_fields==disk_fields,'MAPPED_IMAGE_HEADER_MISMATCH')
        reader.guard()
        _require(image_file_identity(path)==identity,'DISK_IMAGE_CHANGED')
        fingerprint=hashlib.sha256(json.dumps(disk_fields,sort_keys=True,
            separators=(',',':')).encode()).hexdigest()
        return {'mapped_header_match':True,'target_architecture':disk_arch,
            'header_fingerprint_sha256':fingerprint,'disk_header_bytes_read':len(disk),
            'mapped_header_bytes_read':count,'identity_scope':'mapped_pe_headers_only',
            'mapped_code_hash_verified':False}
    finally:
        _require(k.CloseHandle(snapshot),'MODULE_SNAPSHOT_CLOSE_FAILED')
