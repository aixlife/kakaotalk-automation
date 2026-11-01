"""Synthetic PE headers and fake Win32 calls; no app or native process access."""
import ctypes as C
import json
import os
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import reader_image as image


def pe_image(architecture='x64',timestamp=0x12345678):
    data=bytearray(1536)
    data[:2]=b'MZ';struct.pack_into('<I',data,0x3c,128)
    data[128:132]=b'PE\0\0'
    machine,magic,size=(0x8664,0x20b,240) if architecture=='x64' else (0x14c,0x10b,224)
    struct.pack_into('<HHI',data,132,machine,1,timestamp)
    struct.pack_into('<HH',data,148,size,0x22)
    optional=152
    struct.pack_into('<H',data,optional,magic)
    struct.pack_into('<I',data,optional+16,0x1000)
    struct.pack_into('<Q' if architecture=='x64' else '<I',data,
                     optional+(24 if architecture=='x64' else 28),
                     0x140000000 if architecture=='x64' else 0x400000)
    struct.pack_into('<II',data,optional+32,0x1000,0x200)
    struct.pack_into('<II',data,optional+56,0x3000,0x400)
    section=optional+size
    data[section:section+8]=b'.text\0\0\0'
    struct.pack_into('<IIII',data,section+8,0x200,0x1000,0x200,0x400)
    struct.pack_into('<I',data,section+36,0x60000020)
    return bytes(data)


def integer(value):
    return value.value if hasattr(value,'value') else value


class Function:
    """Permit ctypes-style prototypes while keeping every operation synthetic."""
    def __init__(self,callback):
        self.callback=callback;self.calls=[]
    def __call__(self,*args):
        self.calls.append(args)
        return self.callback(*args)


class MemoryInfo(C.Structure):
    _fields_=[('base',C.c_void_p),('allocation',C.c_void_p),('ap',C.c_uint32),
              ('partition',C.c_uint16),('size',C.c_size_t),('state',C.c_uint32),
              ('protect',C.c_uint32),('kind',C.c_uint32)]


class FakeReader:
    def __init__(self,path,body,architecture='x64'):
        self.path=path;self.body=body;self.target_architecture=architecture
        self.pid=123;self.handle=456;self.mbi_type=MemoryInfo;self.read_bytes=0
        self.base=0x140000000 if architecture=='x64' else 0x500000
        self.module_pid=self.pid;self.module_path=str(path);self.module_size=0x3000
        self.module_handle=self.base;self.snapshot=789
        self.guard_calls=0;self.guard_failure=None
        self.memory_kind=0x1000000;self.memory_protect=2;self.memory_state=0x1000
        self.memory_allocation=self.base;self.memory_region_size=0x3000
        self.memory_available=True;self.partial=False;self.on_read=None
        self.closed=[]
        self.k=SimpleNamespace(
            CreateToolhelp32Snapshot=Function(lambda flags,pid:self.snapshot),
            Module32FirstW=Function(self.module_first),
            CloseHandle=Function(self.close),
            VirtualQueryEx=Function(self.query),
            ReadProcessMemory=Function(self.read))

    def guard(self):
        self.guard_calls+=1
        if self.guard_failure:raise self.guard_failure

    def module_first(self,snapshot,pointer):
        entry=C.cast(pointer,C.POINTER(image.MODULEENTRY32W)).contents
        if entry.dwSize!=C.sizeof(image.MODULEENTRY32W):return 0
        entry.th32ProcessID=self.module_pid
        entry.modBaseAddr=self.base;entry.modBaseSize=self.module_size
        entry.hModule=self.module_handle
        encoded=self.module_path.encode('utf-16-le')
        units=struct.unpack('<'+str(len(encoded)//2)+'H',encoded)
        for index,unit in enumerate(units):entry.szExePath[index]=unit
        return 1

    def close(self,handle):
        self.closed.append(integer(handle));return 1

    def query(self,handle,address,pointer,size):
        info=C.cast(pointer,C.POINTER(MemoryInfo)).contents
        info.base=self.base;info.allocation=self.memory_allocation
        info.size=self.memory_region_size;info.state=self.memory_state
        info.protect=self.memory_protect;info.kind=self.memory_kind
        return C.sizeof(MemoryInfo)

    def read(self,handle,address,buffer,size,got):
        if self.on_read:
            callback=self.on_read;self.on_read=None;callback()
        if not self.memory_available:return 0
        start=integer(address)-self.base;count=integer(size)
        if start<0 or start+count>len(self.body):return 0
        if self.partial:count=max(0,count-1)
        C.memmove(buffer,self.body[start:start+count],count)
        C.cast(got,C.POINTER(C.c_size_t)).contents.value=count
        return 1


class MappedImageTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='fictional-mapped-image-')
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name).resolve()
        self.path=self.root/'KakaoTalk.exe'
        self.path.write_bytes(pe_image())

    def reader(self,architecture='x64',mapped=None):
        body=pe_image(architecture)
        self.path.write_bytes(body)
        return FakeReader(self.path,body if mapped is None else mapped,architecture)

    def test_matching_x64_and_x86_keep_host_sized_module_structure(self):
        native_size=C.sizeof(image.MODULEENTRY32W)
        self.assertEqual(dict(image.MODULEENTRY32W._fields_)['modBaseAddr'],C.c_void_p)
        self.assertEqual(dict(image.MODULEENTRY32W._fields_)['hModule'],C.c_void_p)
        self.assertEqual(C.sizeof(dict(image.MODULEENTRY32W._fields_)['dwSize']),4)
        self.assertEqual(C.sizeof(dict(image.MODULEENTRY32W._fields_)['szExePath']._type_),2)
        self.assertEqual(native_size,1080 if C.sizeof(C.c_void_p)==8 else 1064)
        for architecture in ('x64','x86'):
            with self.subTest(architecture=architecture):
                reader=self.reader(architecture)
                result=image.verify_mapped_image(reader,self.path)
                self.assertTrue(result['mapped_header_match'])
                self.assertEqual(result['target_architecture'],architecture)
                self.assertEqual(C.sizeof(image.MODULEENTRY32W),native_size)
                self.assertEqual(reader.closed,[reader.snapshot])
                self.assertGreater(reader.read_bytes,0)
                self.assertLessEqual(reader.read_bytes,image.MAX_MAPPED_HEADER)
                self.assertGreater(reader.guard_calls,1)

    def test_receipt_is_header_scope_and_has_no_module_addresses_or_path(self):
        reader=self.reader()
        result=image.verify_mapped_image(reader,self.path)
        self.assertEqual(result['identity_scope'],'mapped_pe_headers_only')
        self.assertIs(result['mapped_code_hash_verified'],False)
        self.assertRegex(result['header_fingerprint_sha256'],r'^[a-f0-9]{64}$')
        serialized=json.dumps(result)
        for value in (str(self.path),str(reader.base),hex(reader.base)):
            self.assertNotIn(value,serialized)

    def test_aslr_imagebase_changes_do_not_change_fingerprint(self):
        for architecture in ('x64','x86'):
            with self.subTest(architecture=architecture):
                reader=self.reader(architecture)
                original=image.verify_mapped_image(reader,self.path)
                moved=bytearray(pe_image(architecture))
                struct.pack_into('<Q' if architecture=='x64' else '<I',moved,
                    152+(24 if architecture=='x64' else 28),
                    0x180000000 if architecture=='x64' else 0x900000)
                reader=self.reader(architecture,mapped=bytes(moved))
                relocated=image.verify_mapped_image(reader,self.path)
                self.assertEqual(original['header_fingerprint_sha256'],relocated['header_fingerprint_sha256'])

    def test_stale_timestamp_entrypoint_or_section_layout_cannot_match(self):
        offsets=(136,152+16,152+240+8,152+240+20,152+240+36)
        for offset in offsets:
            with self.subTest(offset=offset):
                body=bytearray(pe_image())
                value=0x200 if offset==152+240+20 else struct.unpack_from('<I',body,offset)[0]^16
                struct.pack_into('<I',body,offset,value)
                reader=self.reader(mapped=bytes(body))
                with self.assertRaisesRegex(RuntimeError,'MAPPED_IMAGE_HEADER_MISMATCH'):
                    image.verify_mapped_image(reader,self.path)
                self.assertEqual(reader.closed,[reader.snapshot])

    def test_empty_raw_extent_pointer_normalizes_without_ignoring_virtual_layout(self):
        for architecture in ('x64','x86'):
            with self.subTest(architecture=architecture):
                section=152+(240 if architecture=='x64' else 224)
                disk=bytearray(pe_image(architecture))
                struct.pack_into('<I',disk,section+16,0)
                mapped=bytearray(disk);struct.pack_into('<I',mapped,section+20,0)
                self.path.write_bytes(disk)
                reader=FakeReader(self.path,bytes(mapped),architecture)
                self.assertTrue(image.verify_mapped_image(reader,self.path)['mapped_header_match'])
                struct.pack_into('<I',mapped,section+8,0x210)
                reader=FakeReader(self.path,bytes(mapped),architecture)
                with self.assertRaisesRegex(RuntimeError,'MAPPED_IMAGE_HEADER_MISMATCH'):
                    image.verify_mapped_image(reader,self.path)

    def test_target_and_mapped_architecture_mismatches_are_blocked(self):
        reader=self.reader();reader.target_architecture='x86'
        with self.assertRaises(RuntimeError):image.verify_mapped_image(reader,self.path)
        self.assertEqual(reader.k.ReadProcessMemory.calls,[])
        reader=self.reader(mapped=pe_image('x86'))
        with self.assertRaises(RuntimeError):image.verify_mapped_image(reader,self.path)
        self.assertEqual(reader.closed,[reader.snapshot])

    def test_wrong_module_pid_or_path_is_rejected_before_memory_read(self):
        for attribute,value in (('module_pid',999),('module_path',str(self.root/'unrelated.exe'))):
            with self.subTest(attribute=attribute):
                reader=self.reader();setattr(reader,attribute,value)
                with self.assertRaises(RuntimeError):image.verify_mapped_image(reader,self.path)
                self.assertEqual(reader.k.ReadProcessMemory.calls,[])
                self.assertEqual(reader.closed,[reader.snapshot])

    def test_invalid_disk_pe_stops_before_any_process_memory_read(self):
        reader=self.reader();self.path.write_bytes(b'not an executable')
        with self.assertRaises(RuntimeError):image.verify_mapped_image(reader,self.path)
        self.assertEqual(reader.k.ReadProcessMemory.calls,[])

    def test_unreadable_partial_or_invalid_mapped_header_is_blocked(self):
        for setting in ('unreadable','partial','invalid'):
            with self.subTest(setting=setting):
                reader=self.reader()
                if setting=='unreadable':reader.memory_available=False
                elif setting=='partial':reader.partial=True
                else:reader.body=b'NO'+reader.body[2:]
                with self.assertRaises(RuntimeError):image.verify_mapped_image(reader,self.path)
                self.assertEqual(reader.closed,[reader.snapshot])

    def test_wrong_memory_mapping_or_protection_blocks_before_copy(self):
        cases=(('memory_kind',0x20000),('memory_protect',0x102),
               ('memory_protect',1),('memory_state',0x2000),
               ('memory_allocation',0x400000),('memory_region_size',32))
        for attribute,value in cases:
            with self.subTest(attribute=attribute,value=value):
                reader=self.reader();setattr(reader,attribute,value)
                with self.assertRaises(RuntimeError):image.verify_mapped_image(reader,self.path)
                self.assertEqual(reader.k.ReadProcessMemory.calls,[])

    def test_symlink_file_and_parent_directory_are_rejected(self):
        reader=self.reader();linked=self.root/'linked.exe'
        try:linked.symlink_to(self.path)
        except OSError as error:self.skipTest('symlink privilege unavailable: '+type(error).__name__)
        with self.assertRaises(RuntimeError):image.verify_mapped_image(reader,linked)
        parent=self.root/'parent-link';parent.symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(RuntimeError):image.verify_mapped_image(reader,parent/self.path.name)
        self.assertEqual(reader.k.ReadProcessMemory.calls,[])

    def test_reparse_attribute_is_rejected_before_memory_read(self):
        reader=self.reader();original=Path.lstat
        def reparse(path,*args,**kwargs):
            value=original(path,*args,**kwargs)
            if path!=self.path:return value
            fields={name:getattr(value,name) for name in dir(value) if name.startswith('st_')}
            fields['st_file_attributes']=0x400
            return SimpleNamespace(**fields)
        with patch.object(Path,'lstat',reparse):
            with self.assertRaises(RuntimeError):image.verify_mapped_image(reader,self.path)
        self.assertEqual(reader.k.ReadProcessMemory.calls,[])

    def test_oversized_disk_image_is_rejected_without_header_read(self):
        reader=self.reader()
        with self.path.open('r+b') as stream:stream.truncate(256*1024*1024+1)
        with self.assertRaises(RuntimeError):image.verify_mapped_image(reader,self.path)
        self.assertEqual(reader.k.ReadProcessMemory.calls,[])

    def test_disk_mutation_during_mapped_read_invalidates_match(self):
        reader=self.reader()
        initial=self.path.stat()
        reader.on_read=lambda:os.utime(self.path,ns=(initial.st_atime_ns,initial.st_mtime_ns+1000000000))
        with self.assertRaises(RuntimeError):image.verify_mapped_image(reader,self.path)
        self.assertEqual(reader.closed,[reader.snapshot])

    def test_process_read_budget_is_not_extended_for_image_headers(self):
        reader=self.reader();reader.read_bytes=image.MAX_PROCESS_READ-32
        with self.assertRaises(RuntimeError):image.verify_mapped_image(reader,self.path)
        self.assertEqual(reader.k.ReadProcessMemory.calls,[])
        self.assertLessEqual(reader.read_bytes,image.MAX_PROCESS_READ)

    def test_reader_ram_guard_can_stop_before_snapshot_or_memory_read(self):
        reader=self.reader();reader.guard_failure=AssertionError('APP_MEMORY_LIMIT')
        with self.assertRaisesRegex((AssertionError,RuntimeError),'APP_MEMORY_LIMIT'):
            image.verify_mapped_image(reader,self.path)
        self.assertEqual(reader.k.CreateToolhelp32Snapshot.calls,[])
        self.assertEqual(reader.k.ReadProcessMemory.calls,[])

    def test_mapped_header_offsets_are_bounded(self):
        reader=self.reader();body=bytearray(reader.body)
        struct.pack_into('<I',body,0x3c,0x10000);reader.body=bytes(body)
        with self.assertRaises(RuntimeError):image.verify_mapped_image(reader,self.path)
        self.assertLessEqual(reader.read_bytes,image.MAX_MAPPED_HEADER)
        self.assertLessEqual(len(reader.k.ReadProcessMemory.calls),2)

    def test_snapshot_or_module_failure_cannot_pass_or_leak_valid_snapshot(self):
        for invalid in (None,0,C.c_void_p(-1).value):
            with self.subTest(invalid_snapshot=invalid):
                reader=self.reader();reader.snapshot=invalid
                with self.assertRaises(RuntimeError):image.verify_mapped_image(reader,self.path)
                self.assertEqual(reader.closed,[])
                self.assertEqual(reader.k.ReadProcessMemory.calls,[])
        reader=self.reader();reader.k.Module32FirstW=Function(lambda *args:0)
        with self.assertRaises(RuntimeError):image.verify_mapped_image(reader,self.path)
        self.assertEqual(reader.closed,[reader.snapshot])
        self.assertEqual(reader.k.ReadProcessMemory.calls,[])
        reader=self.reader();reader.k.CloseHandle=Function(lambda *args:0)
        with self.assertRaisesRegex(RuntimeError,'MODULE_SNAPSHOT_CLOSE_FAILED'):
            image.verify_mapped_image(reader,self.path)


if __name__=='__main__':unittest.main()
