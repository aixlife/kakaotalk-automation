"""Bounded x86 envelope candidate discovery, NOT a proven native layout.

The packed x86 image has not established these object offsets. This adapter
tries one MSVC layout candidate: inline string[16]/uint32 length/capacity,
followed by binding[32] and a three-uint32 identity vector. It does not infer
fixed manager offsets from the observed x64 implementation.

An IKM AES-KW check only yields inputs to the caller. The caller MUST also
validate the selected database's wrapped key AND SQLCipher page HMAC before
accepting a candidate. Synthetic tests are not an actual x86 read result.
No process writes, target calls, GUI access, key logging, or plaintext files.
"""
import hashlib
import hmac
import os
from pathlib import Path
import stat
import struct

from cryptography.hazmat.primitives.keywrap import InvalidUnwrap, aes_key_unwrap


ADDRESS_LIMIT = 1 << 32
MIN_ADDRESS = 0x10000
WINDOW_BYTES = 512
MAX_CANDIDATES = 128
STRING_BYTES = 24
RECORD_BYTES = 24 + 32 + 12
LAYOUT = 'candidate_msvc32_string24_binding32_vector12_not_native_proven'


def _memory(reader, address, size):
    if not (MIN_ADDRESS <= address < ADDRESS_LIMIT and
            0 < size <= 1024 and address + size <= ADDRESS_LIMIT):
        return None
    value = reader.memory(address, size)
    return value if value is not None and len(value) == size else None


def _stat_key(value):
    return (value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode), value.st_size,
            value.st_mtime_ns, getattr(value, 'st_birthtime_ns', value.st_ctime_ns),
            getattr(value, 'st_file_attributes', 0))


def _path_snapshot(path, account):
    """Reject aliases before resolving, including Windows directory junctions."""
    if (not path.is_absolute() or not account.is_absolute() or
            '..' in path.parts or '..' in account.parts or
            not path.is_relative_to(account) or path == account):
        return None
    # Colons outside the anchor can select an NTFS alternate data stream.
    if any(':' in part for part in path.parts[1:]):
        return None
    try:
        target_stat = None
        for entry in reversed((path, *path.parents)):
            value = entry.lstat()
            if (stat.S_ISLNK(value.st_mode) or
                    getattr(value, 'st_file_attributes', 0) & 0x400):
                return None
            if entry != path and not stat.S_ISDIR(value.st_mode):
                return None
            if entry == path:
                target_stat = value
        if (target_stat is None or not stat.S_ISREG(target_stat.st_mode) or
                target_stat.st_size != 40):
            return None
        resolved = path.resolve(strict=True)
        root = account.resolve(strict=True)
        if not resolved.is_relative_to(root):
            return None
        return target_stat
    except (OSError, ValueError, RuntimeError):
        return None


def _read_40(handle):
    handle.seek(0)
    return handle.read(41)


def _checked_container(reader, path, account):
    reader.guard()
    before = _path_snapshot(path, account)
    if before is None:
        return None
    flags = os.O_RDONLY
    for name in ('O_BINARY', 'O_NOFOLLOW', 'O_NONBLOCK', 'O_NOINHERIT'):
        flags |= getattr(os, name, 0)
    files = getattr(reader, 'files', None)
    if files is not None:
        context = files.open(path, max_bytes=40)
    else:
        try:
            descriptor = os.open(path, flags)
        except OSError:
            return None
        context = os.fdopen(descriptor, 'rb', buffering=0)
    with context as handle:
        opened = os.fstat(handle.fileno())
        if _stat_key(opened) != _stat_key(before):
            raise RuntimeError('IKM_CONTAINER_CHANGED')
        first = _read_40(handle)
        reader.guard()
        second = _read_40(handle)
        last = os.fstat(handle.fileno())
    after = _path_snapshot(path, account)
    if (len(first) != 40 or len(second) != 40 or after is None or
            _stat_key(before) != _stat_key(last) or
            _stat_key(before) != _stat_key(after) or
            hashlib.sha256(first).digest() != hashlib.sha256(second).digest()):
        raise RuntimeError('IKM_CONTAINER_CHANGED')
    reader.guard()
    return first


def _candidate(reader, raw):
    length, capacity = struct.unpack_from('<II', raw, 16)
    begin, end, limit = struct.unpack_from('<III', raw, 56)
    if not (0 < length <= 512 and length <= capacity <= 4096 and
            MIN_ADDRESS <= begin < end <= limit < ADDRESS_LIMIT and
            end - begin <= 512 and limit - begin <= 4096):
        return None
    if capacity <= 7:
        if length > 7:
            return None
        wide = raw[:length * 2]
    else:
        pointer = struct.unpack_from('<I', raw)[0]
        wide = _memory(reader, pointer, length * 2)
    if wide is None:
        return None
    try:
        text = wide.decode('utf-16-le')
        if '\x00' in text:
            return None
        path = Path(text)
    except (ValueError, UnicodeError):
        return None
    account = Path(reader.data).parent
    # Scope is checked before opening a file or reading the identity buffer.
    if not path.is_absolute() or not path.is_relative_to(account):
        return None
    wrapped = _checked_container(reader, path, account)
    if wrapped is None:
        return None
    identity = _memory(reader, begin, end - begin)
    if identity is None:
        return None
    binding = raw[24:56]
    try:
        ikm = aes_key_unwrap(
            hmac.new(binding, identity + b'ikm-wrap', hashlib.sha256).digest(),
            wrapped)
    except InvalidUnwrap:
        return None
    return (ikm, binding) if len(ikm) == 32 else None


def try_x86_inputs(reader, salt_address, stats):
    """Yield bounded candidates; only the caller's DB authentication accepts one."""
    stats['x86_candidate_layout'] = LAYOUT
    if (not isinstance(salt_address, int) or isinstance(salt_address, bool) or
            salt_address % 4 or not MIN_ADDRESS + STRING_BYTES <= salt_address or
            salt_address + 32 > ADDRESS_LIMIT):
        return
    reader.guard()
    prefix_address = salt_address - STRING_BYTES
    prefix = _memory(reader, prefix_address, STRING_BYTES)
    if prefix is None or prefix[:3] != b'v2:':
        return
    length, capacity = struct.unpack_from('<II', prefix, 16)
    if length != 3 or not 3 <= capacity <= 15:
        return
    stats['matching_state_prefixes'] = stats.get('matching_state_prefixes', 0) + 1
    start = max(MIN_ADDRESS, salt_address - WINDOW_BYTES)
    start = (start + 3) & ~3
    stop = prefix_address - RECORD_BYTES
    if stop < start:
        return
    window = _memory(reader, start, prefix_address - start)
    for address in range(start, stop + 1, 4)[:MAX_CANDIDATES]:
        reader.guard()
        stats['x86_candidate_windows'] = stats.get('x86_candidate_windows', 0) + 1
        raw = (window[address - start:address - start + RECORD_BYTES]
               if window is not None else _memory(reader, address, RECORD_BYTES))
        if raw is None:
            continue
        inputs = _candidate(reader, raw)
        if inputs is None:
            continue
        stats['x86_candidate_wrap_matches'] = stats.get('x86_candidate_wrap_matches', 0) + 1
        stats['x86_candidate_relative_offset'] = address - salt_address
        stats['ikm_container_wrap_integrity'] = True
        stats['ikm_container_inside_selected_account'] = True
        yield inputs
