"""Read exactly one live preference using the observed native tree layout.

No setting writes, file writes, remote app calls, credentials or message bodies.
Missing preview key returns the native getter's verified default, 'yes'.
"""
from selfqa_config import ROOT, SOURCE_ROOT, READER_ROOT, PYTHON
import ctypes as C
import json
import struct
from room_reader import Reader

GLOBAL = 0x143129230  # RIP-relative singleton slot in captured 0x14058bd80.
MODE_GLOBAL = 0x1431202F8  # RIP-relative slot in captured 0x14057d800.


def native_preview_enabled(value, mode):
    """Match 0x141553400: only mode 3 consults the saved yes/no value."""
    if value not in ('yes', 'no') or type(mode) is not int:
        raise ValueError('UNRECOGNIZED_PREVIEW_INPUT')
    return value == 'yes' if mode == 3 else True


def inspect():
    reader = Reader()
    reads = 0
    names_compared = 0
    try:
        before = reader.guard()

        def raw(address, size, image=False):
            nonlocal reads
            reader.guard()
            assert reads < 2048 and 0 < size <= 64
            if not image:
                value = reader.memory(address, size)
                assert value is not None, 'PREFERENCE_METADATA_UNREADABLE'
            else:
                region = reader.mbi_type()
                assert reader.k.VirtualQueryEx(reader.handle, address, C.byref(region), C.sizeof(region))
                assert region.allocation == 0x140000000 and region.kind == 0x1000000
                assert region.state == 0x1000 and region.protect in (2, 4)
                assert address + size <= region.base + region.size
                buffer = C.create_string_buffer(size)
                count = C.c_size_t()
                assert reader.k.ReadProcessMemory(reader.handle, address, buffer, size, C.byref(count))
                assert count.value == size
                reader.read_bytes += size
                value = buffer.raw
            reads += 1
            return value

        def pointer(address, image=False, alignment=8):
            value = struct.unpack('<Q', raw(address, 8, image))[0]
            assert alignment in (2, 8)
            assert 0x10000 <= value < 0x7fffffffffff and value % alignment == 0, 'PREFERENCE_POINTER_INVALID'
            return value

        def name(address):
            value = bytearray()
            for index in range(64):
                pair = raw(address + index * 2, 2)
                if pair == b'\0\0':
                    text = value.decode('utf-16-le')
                    assert text.isascii(), 'NON_ASCII_PREF_NAME_NOT_COMPARED'
                    return text
                value.extend(pair)
            raise RuntimeError('PREFERENCE_NAME_LIMIT')

        def lookup(header, wanted):
            nonlocal names_compared
            assert raw(header + 0x19, 1) == b'\1', 'TREE_SENTINEL_INVALID'
            node = pointer(header + 8)
            visited = set()
            for _ in range(64):
                if raw(node + 0x19, 1) == b'\1':
                    assert node == header, 'UNKNOWN_SENTINEL'
                    return None
                assert node not in visited, 'TREE_CYCLE'
                visited.add(node)
                current = name(pointer(node + 0x20, alignment=2))
                names_compared += 1
                if current.casefold() == wanted.casefold():
                    return node
                node = pointer(node if wanted.casefold() < current.casefold() else node + 16)
            raise RuntimeError('PREFERENCE_TREE_LIMIT')

        answers = []
        for _ in range(2):
            mode_object = pointer(MODE_GLOBAL, image=True)
            mode = struct.unpack('<i', raw(mode_object + 0x24, 4))[0]
            singleton = pointer(GLOBAL, image=True)
            section_header = pointer(singleton + 0x38)
            section = lookup(section_header, 'KAKAO_TALK')
            key = lookup(pointer(section + 0x38), 'check_after_send_file') if section else None
            if key:
                value = name(pointer(key + 0x38, alignment=2))
                assert value in ('yes', 'no'), 'UNEXPECTED_PREVIEW_VALUE_NOT_SAVED'
            else:
                value = 'yes'
            answers.append((singleton, section_header, section, key, value,
                            mode_object, mode))
        assert answers[0] == answers[1], 'PREFERENCE_CHANGED_DURING_READ'
        return {'status': 'LIVE_PREVIEW_PREFERENCE_READ', 'section': 'KAKAO_TALK',
                'key': 'check_after_send_file', 'key_present': answers[0][3] is not None,
                'value': answers[0][4], 'native_default': 'yes',
                'preview_enabled': native_preview_enabled(answers[0][4], answers[0][6]),
                'native_mode_check_performed': True,
                'saved_preference_applies': answers[0][6] == 3,
                'false_requires_separate_logged_in_mode_check': False,
                'no_ui_send_route_verified': False,
                'stable_double_read': True, 'metadata_reads': reads,
                'preference_names_compared': names_compared,
                'other_preference_values_read': 0, 'heap_addresses_saved': False,
                'app_private_before': before, 'app_private_after': reader.guard(),
                'process_bytes_read': reader.read_bytes, 'input_calls': 0,
                'clipboard_calls': 0, 'process_write_calls': 0, 'settings_changed': False}
    finally:
        reader.close()


if __name__ == '__main__':
    print(json.dumps(inspect()), flush=True)
