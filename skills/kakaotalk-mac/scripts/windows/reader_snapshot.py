"""Bounded, read-only SQLCipher snapshots without plaintext files.

The live source is *not* declared immutable.  Two streaming reads establish a
baseline; every later page read must match its captured ciphertext digest.
Only the virtual, digest-bound view is immutable.  This is the same optimistic
double-read consistency model as the original reader, not an SQLite lock.
"""
from __future__ import annotations

from array import array
from collections import OrderedDict
from contextlib import ExitStack
import hashlib
import hmac
import os
from pathlib import Path
import struct
import time
import uuid

import apsw
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

if not __debug__:
    raise RuntimeError('OPTIMIZED_PYTHON_UNSUPPORTED')

PAGE = 4096
RESERVE = 80
FRAME = PAGE + 24
MAX_DB_BYTES = 512 * 1024 * 1024
MAX_WAL_BYTES = 256 * 1024 * 1024
MAX_LOGICAL_BYTES = 512 * 1024 * 1024
MAX_FILE_IO_BYTES = 3 * 1024 * 1024 * 1024
MAX_BUFFER_BYTES = 28 * 1024 * 1024
SQLITE_HEAP_BYTES = 32 * 1024 * 1024
CACHE_BYTES = 1024 * 1024
CHUNK = 256 * 1024
MAX_VFS_READ = 1024 * 1024
LIMIT_SECONDS = 40


class SnapshotError(RuntimeError):
    """A fixed, non-sensitive reason safe for the reader's failure receipt."""


def _require(condition, reason):
    if not condition:
        raise SnapshotError(reason)


class SnapshotBudget:
    """One budget for all connections/retries in a single reader invocation.

The guard also enforces the caller's original process-memory/app/time limits.
Tracked buffers exclude Python/crypto runtime overhead; the outer 256 MiB Job
and caller's memory guard remain mandatory. SQLite has its own 32 MiB hard cap.
"""

    def __init__(self, guard, *, max_file_io_bytes=MAX_FILE_IO_BYTES,
                 max_buffer_bytes=MAX_BUFFER_BYTES):
        _require(callable(guard), 'SNAPSHOT_GUARD_REQUIRED')
        _require(0 < max_file_io_bytes <= MAX_FILE_IO_BYTES, 'SNAPSHOT_IO_LIMIT_INVALID')
        _require(0 < max_buffer_bytes <= MAX_BUFFER_BYTES, 'SNAPSHOT_BUFFER_LIMIT_INVALID')
        self.guard_callback = guard
        self.started = time.monotonic()
        self.max_file_io_bytes = max_file_io_bytes
        self.max_buffer_bytes = max_buffer_bytes
        self.file_read_bytes = 0
        self.buffer_bytes = 0
        self.peak_buffer_bytes = 0

    def guard(self):
        _require(time.monotonic() - self.started < LIMIT_SECONDS, 'SNAPSHOT_TIME_LIMIT')
        self.guard_callback()

    def consume(self, amount):
        self.guard()
        _require(0 <= amount <= MAX_VFS_READ, 'SNAPSHOT_READ_SIZE_LIMIT')
        _require(self.file_read_bytes + amount <= self.max_file_io_bytes, 'SNAPSHOT_FILE_IO_LIMIT')
        self.file_read_bytes += amount

    def reserve(self, amount):
        self.guard()
        _require(self.buffer_bytes + amount <= self.max_buffer_bytes, 'SNAPSHOT_BUFFER_LIMIT')
        self.buffer_bytes += amount
        self.peak_buffer_bytes = max(self.peak_buffer_bytes, self.buffer_bytes)

    def release(self, amount):
        self.buffer_bytes -= amount
        _require(self.buffer_bytes >= 0, 'SNAPSHOT_BUFFER_ACCOUNTING_FAILED')


def _read_exact(handle, offset, size, budget):
    """All source I/O passes here, including validation and VFS cache misses."""
    budget.consume(size)
    handle.seek(offset)
    value = handle.read(size)
    _require(len(value) == size, 'SNAPSHOT_SOURCE_CHANGED_SHORT_READ')
    return value


def _stamp(value):
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns


def _checksum(data, order, state=(0, 0)):
    s0, s1 = state
    for first, second in struct.iter_unpack(order + 'II', data):
        s0 = (s0 + first + s1) & 0xffffffff
        s1 = (s1 + second + s0) & 0xffffffff
    return s0, s1


class _Snapshot:
    def __init__(self, path, recover_key, budget, kind, opener=None, scope_guard=None):
        self.path = Path(path)
        self.wal_path = self.path.with_name(self.path.name + '-wal')
        self.budget = budget
        self.kind = kind
        self.opener = opener or (lambda path, max_bytes: path.open('rb', buffering=0))
        self.scope_guard = scope_guard
        self.file_contexts = ExitStack()
        self.db = self.wal = None
        self.key = self.hmac_key = None
        self.reserved = 0
        self.cache = OrderedDict()
        self.closed = False
        self.receipt = {}
        try:
            self._capture()
            self.key = recover_key(self.first_page)
            _require(isinstance(self.key, (bytes, bytearray)) and len(self.key) == 32,
                     'SNAPSHOT_KEY_INVALID')
            self.salt = self.first_page[:16]
            self.hmac_key = hashlib.pbkdf2_hmac(
                'sha512', self.key, bytes(v ^ 0x3a for v in self.salt), 2, dklen=32)
            self.first_page = None
            self._authenticate_all()
            # Fixed capacity reservation includes bounded OrderedDict bookkeeping.
            self._reserve(CACHE_BYTES + (CACHE_BYTES // PAGE) * 256)
        except BaseException:
            self.close()
            raise

    def _reserve(self, amount):
        self.budget.reserve(amount)
        self.reserved += amount

    def _release(self, amount):
        self.budget.release(amount)
        self.reserved -= amount

    def guard(self):
        self.budget.guard()
        if self.scope_guard is not None:
            self.scope_guard()

    def _read(self, handle, offset, size):
        if self.scope_guard is not None:
            self.scope_guard()
        # _read_exact consumes the budget and invokes the shared reader guard.
        return _read_exact(handle, offset, size, self.budget)

    def _wal_present(self):
        try:
            self.wal_path.lstat()
        except FileNotFoundError:
            return False
        return True

    def _check_sources(self):
        self.guard()
        try:
            _require(_stamp(self.path.stat()) == self.db_stamp == _stamp(os.fstat(self.db.fileno())),
                     'SNAPSHOT_DB_CHANGED_DURING_READ')
            _require(self._wal_present() == bool(self.wal), 'SNAPSHOT_WAL_APPEARANCE_CHANGED')
            if self.wal:
                _require(_stamp(self.wal_path.stat()) == self.wal_stamp == _stamp(os.fstat(self.wal.fileno())),
                         'SNAPSHOT_WAL_CHANGED_DURING_READ')
        except OSError as exc:
            raise SnapshotError('SNAPSHOT_SOURCE_CHANGED') from exc

    def _hash_file(self, handle, size):
        digest = hashlib.sha256()
        for offset in range(0, size, CHUNK):
            digest.update(self._read(handle, offset, min(CHUNK, size - offset)))
        return digest.digest()

    def _capture(self):
        self.guard()
        self.db = self.file_contexts.enter_context(self.opener(self.path, max_bytes=MAX_DB_BYTES))
        self.db_stamp = _stamp(os.fstat(self.db.fileno()))
        self.db_size = self.db_stamp[2]
        _require(PAGE <= self.db_size <= MAX_DB_BYTES and self.db_size % PAGE == 0,
                 'SNAPSHOT_DB_SIZE_LIMIT')
        self.guard()
        if self._wal_present():
            self.wal = self.file_contexts.enter_context(self.opener(self.wal_path, max_bytes=MAX_WAL_BYTES))
        self.wal_stamp = _stamp(os.fstat(self.wal.fileno())) if self.wal else None
        self.wal_size = self.wal_stamp[2] if self.wal else 0
        _require(self.wal_size <= MAX_WAL_BYTES, 'SNAPSHOT_WAL_SIZE_LIMIT')
        self._check_sources()
        pages = self.db_size // PAGE
        self._reserve(pages * 32)
        self.db_digests = bytearray(pages * 32)
        digest = hashlib.sha256()
        for offset in range(0, self.db_size, CHUNK):
            chunk = self._read(self.db, offset, min(CHUNK, self.db_size - offset))
            digest.update(chunk)
            if not offset:
                self.first_page = chunk[:PAGE]
            for local in range(0, len(chunk), PAGE):
                index = ((offset + local) // PAGE) * 32
                self.db_digests[index:index + 32] = hashlib.sha256(chunk[local:local + PAGE]).digest()
        self.db_hash = digest.digest()
        self._scan_wal()
        self._check_sources()
        _require(self._hash_file(self.db, self.db_size) == self.db_hash,
                 'SNAPSHOT_DB_DOUBLE_READ_MISMATCH')
        if self.wal:
            _require(self._hash_file(self.wal, self.wal_size) == self.wal_hash,
                     'SNAPSHOT_WAL_DOUBLE_READ_MISMATCH')
        self._check_sources()

    def _scan_wal(self):
        self.logical_pages = self.db_size // PAGE
        self.committed_frames = 0
        self.wal_pages_applied = 0
        self.wal_offsets = None
        self.frame_digests = None
        self.wal_hash = hashlib.sha256(b'').digest()
        if not self.wal_size:
            return
        _require(self.wal_size >= 32, 'SNAPSHOT_WAL_HEADER_INCOMPLETE')
        header = self._read(self.wal, 0, 32)
        magic, version, pagesize = struct.unpack_from('>III', header)
        _require(magic in (0x377f0682, 0x377f0683) and version == 3007000 and pagesize == PAGE,
                 'SNAPSHOT_WAL_FORMAT_UNSUPPORTED')
        order = '<' if magic == 0x377f0682 else '>'
        state = _checksum(header[:24], order)
        _require(state == struct.unpack_from('>II', header, 24), 'SNAPSHOT_WAL_HEADER_CHECKSUM_FAILED')
        count = (self.wal_size - 32) // FRAME
        # Packed bounded arrays, never a Python object/dict per DB page or frame.
        capacity = MAX_LOGICAL_BYTES // PAGE
        frames_bytes = count * 32
        offsets_bytes = capacity * 4
        touched_bytes = min(capacity, count) * 4
        self._reserve(frames_bytes + offsets_bytes * 2 + touched_bytes)
        self.frame_digests = bytearray(frames_bytes)
        self.wal_offsets = array('I', [0]) * capacity
        pending = array('I', [0]) * capacity
        touched = array('I', [0]) * min(capacity, count)
        digest = hashlib.sha256(header)
        used = 0
        valid = True
        offset = 32
        try:
            for frame_index in range(count):
                frame = self._read(self.wal, offset, FRAME)
                digest.update(frame)
                if valid:
                    pgno, size = struct.unpack_from('>II', frame)
                    new_state = _checksum(frame[:8] + frame[24:], order, state)
                    if frame[8:16] != header[16:24] or new_state != struct.unpack_from('>II', frame, 16):
                        valid = False
                    else:
                        _require(0 < pgno <= capacity, 'SNAPSHOT_WAL_PAGE_LIMIT')
                        _require(size <= capacity, 'SNAPSHOT_WAL_DATABASE_LIMIT')
                        state = new_state
                        self.frame_digests[frame_index * 32:(frame_index + 1) * 32] = hashlib.sha256(frame[24:]).digest()
                        if not pending[pgno - 1]:
                            touched[used] = pgno - 1
                            used += 1
                        pending[pgno - 1] = frame_index + 1
                        if size:
                            for i in range(used):
                                page_index = touched[i]
                                self.wal_offsets[page_index] = pending[page_index]
                                pending[page_index] = 0
                            used = 0
                            self.logical_pages = size
                            self.committed_frames = frame_index + 1
                offset += FRAME
            if offset < self.wal_size:
                digest.update(self._read(self.wal, offset, self.wal_size - offset))
            self.wal_hash = digest.digest()
            self.wal_pages_applied = sum(bool(self.wal_offsets[i]) for i in range(self.logical_pages))
        finally:
            del pending, touched
            self._release(offsets_bytes + touched_bytes)

    def _cipher_page(self, pgno):
        _require(not self.closed and 1 <= pgno <= self.logical_pages, 'SNAPSHOT_PAGE_OUT_OF_RANGE')
        frame = self.wal_offsets[pgno - 1] if self.wal_offsets is not None else 0
        if frame:
            page = self._read(self.wal, 32 + (frame - 1) * FRAME + 24, PAGE)
            expected = self.frame_digests[(frame - 1) * 32:frame * 32]
        else:
            _require(pgno * PAGE <= self.db_size, 'SNAPSHOT_PAGE_MISSING')
            page = self._read(self.db, (pgno - 1) * PAGE, PAGE)
            expected = self.db_digests[(pgno - 1) * 32:pgno * 32]
        _require(hmac.compare_digest(hashlib.sha256(page).digest(), expected),
                 'SNAPSHOT_PAGE_DIGEST_MISMATCH')
        return page

    def _authenticate(self, page, pgno):
        if not any(page):
            return False
        start = 16 if pgno == 1 else 0
        mac = hmac.new(self.hmac_key, page[start:PAGE - RESERVE + 16] + struct.pack('<I', pgno), hashlib.sha512).digest()
        _require(hmac.compare_digest(mac, page[-64:]), 'SNAPSHOT_PAGE_AUTHENTICATION_FAILED')
        return True

    def _authenticate_all(self):
        authenticated = zero = 0
        for pgno in range(1, self.logical_pages + 1):
            if self._authenticate(self._cipher_page(pgno), pgno):
                authenticated += 1
            else:
                zero += 1
        self.receipt.update(kind=self.kind, committed_wal_frames=self.committed_frames,
                            wal_pages_applied=self.wal_pages_applied,
                            authenticated_pages=authenticated, zero_pages=zero,
                            snapshot_pages=self.logical_pages, double_read_verified=True,
                            snapshot_method='digest-bound-readonly-vfs',
                            plaintext_db_saved=False, source_write_calls=0,
                            snapshot_atomicity='optimistic-double-read')

    def page(self, pgno):
        self.guard()
        if pgno in self.cache:
            self.cache.move_to_end(pgno)
            return self.cache[pgno]
        page = self._cipher_page(pgno)
        if not self._authenticate(page, pgno):
            result = page
        else:
            start = 16 if pgno == 1 else 0
            decryptor = Cipher(algorithms.AES(self.key), modes.CBC(page[PAGE - RESERVE:PAGE - RESERVE + 16])).decryptor()
            body = decryptor.update(page[start:PAGE - RESERVE]) + decryptor.finalize()
            result = (b'SQLite format 3\0' if pgno == 1 else b'') + body + b'\0' * RESERVE
            if pgno == 1:
                # Change only the virtual plaintext header; overlay is already applied.
                result = result[:18] + b'\1\1' + result[20:]
        if len(self.cache) >= CACHE_BYTES // PAGE:
            self.cache.popitem(last=False)
        self.cache[pgno] = result
        return result

    def read(self, amount, offset):
        self.guard()
        _require(0 <= amount <= MAX_VFS_READ and 0 <= offset and offset + amount <= self.logical_pages * PAGE,
                 'SNAPSHOT_VFS_READ_LIMIT')
        if not amount:
            return b''
        first, last = offset // PAGE + 1, (offset + amount - 1) // PAGE + 1
        # The bound above caps this temporary plaintext to one MiB.
        value = b''.join(self.page(pgno) for pgno in range(first, last + 1))
        return value[offset % PAGE:offset % PAGE + amount]

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.cache.clear()
        self.key = self.hmac_key = self.first_page = None
        self.db_digests = self.frame_digests = self.wal_offsets = None
        try:
            # A lease may reject a replaced source at context exit. ExitStack
            # still closes every handle, and our buffers must be released too.
            self.file_contexts.close()
        finally:
            self.budget.release(self.reserved)
            self.reserved = 0


class _SnapshotFile:
    def __init__(self, snapshot):
        self.snapshot = snapshot

    def xRead(self, amount, offset):
        return self.snapshot.read(amount, offset)

    def xFileSize(self):
        return self.snapshot.logical_pages * PAGE

    def xDeviceCharacteristics(self):
        return apsw.SQLITE_IOCAP_IMMUTABLE

    def xSectorSize(self):
        return PAGE

    def xCheckReservedLock(self):
        return False

    def xLock(self, level):
        _require(level <= apsw.SQLITE_LOCK_SHARED, 'SNAPSHOT_WRITE_FORBIDDEN')

    def xUnlock(self, level):
        pass

    def xFileControl(self, op, pointer):
        return False

    def xClose(self):
        pass

    def xWrite(self, data, offset):
        raise SnapshotError('SNAPSHOT_WRITE_FORBIDDEN')

    def xTruncate(self, size):
        raise SnapshotError('SNAPSHOT_WRITE_FORBIDDEN')

    def xSync(self, flags):
        raise SnapshotError('SNAPSHOT_WRITE_FORBIDDEN')


class _SnapshotVFS(apsw.VFS):
    def __init__(self, snapshot):
        self.snapshot = snapshot
        self.name = 'kakao-snapshot-' + uuid.uuid4().hex
        self.filename = self.name + '.sqlite'
        super().__init__(self.name, '')

    def xFullPathname(self, name):
        return name

    def xOpen(self, name, flags):
        actual = name.filename() if isinstance(name, apsw.URIFilename) else name
        _require(actual == self.filename and flags[0] & apsw.SQLITE_OPEN_MAIN_DB and
                 flags[0] & apsw.SQLITE_OPEN_READONLY and
                 not flags[0] & (apsw.SQLITE_OPEN_CREATE | apsw.SQLITE_OPEN_READWRITE),
                 'SNAPSHOT_FILE_OPEN_FORBIDDEN')
        flags[1] = apsw.SQLITE_OPEN_READONLY
        return _SnapshotFile(self.snapshot)

    def xAccess(self, name, flags):
        return False

    def xDelete(self, name, syncdir):
        raise SnapshotError('SNAPSHOT_WRITE_FORBIDDEN')


class SnapshotRow:
    """The indexed/name access used by sqlite3.Row callers, without sqlite3."""
    __slots__ = ('_values', '_names')

    def __init__(self, names, values):
        self._names = names
        self._values = tuple(values)

    def __getitem__(self, key):
        if isinstance(key, str):
            for index, name in enumerate(self._names):
                if name == key or name.isascii() and key.isascii() and name.lower() == key.lower():
                    return self._values[index]
            raise IndexError('No item with that key')
        return self._values[key]

    def __iter__(self):
        return iter(self._values)

    def __len__(self):
        return len(self._values)

    def keys(self):
        return list(self._names)


class _SnapshotCursor:
    """Check the shared deadline even when SQLite serves an already-ready row."""
    def __init__(self, owner, cursor):
        self.owner = owner
        self.cursor = cursor

    def __iter__(self):
        return self

    def __next__(self):
        _require(not self.owner.closed, 'SNAPSHOT_CLOSED')
        self.owner._snapshot.guard()
        row = next(self.cursor)
        self.owner._snapshot.guard()
        return row

    def fetchone(self):
        return next(self, None)

    def fetchall(self):
        return list(self)

    def close(self):
        self.cursor.close()


class SnapshotConnection:
    def __init__(self, snapshot):
        self._snapshot = snapshot
        self._vfs = None
        self._con = None
        self.closed = False
        self.receipt = snapshot.receipt
        try:
            # This cap is process-wide for APSW's private SQLite. Never raise a
            # caller's stricter cap; Python/crypto memory is separately guarded.
            existing = apsw.hard_heap_limit(-1)
            apsw.hard_heap_limit(min(existing, SQLITE_HEAP_BYTES) if existing else SQLITE_HEAP_BYTES)
            self._vfs = _SnapshotVFS(snapshot)
            self._con = apsw.Connection(self._vfs.filename, flags=apsw.SQLITE_OPEN_READONLY,
                                        vfs=self._vfs.name, statementcachesize=8)
            self._con.set_progress_handler(self._progress, 1000)
            for statement in ('PRAGMA query_only=ON', 'PRAGMA trusted_schema=OFF',
                              'PRAGMA temp_store=MEMORY', 'PRAGMA mmap_size=0',
                              'PRAGMA cache_size=-1024', 'PRAGMA cache_spill=OFF'):
                self._con.execute(statement)
            self._con.enable_load_extension(False)
            self._con.set_authorizer(self._authorize)
            check = self._con.execute('PRAGMA quick_check').fetchall()
            _require(check == [('ok',)], 'SNAPSHOT_INTEGRITY_FAILED')
            self.receipt['quick_check'] = 'ok'
            self._con.set_row_trace(lambda cursor, row: SnapshotRow(
                tuple(item[0] for item in cursor.get_description()), row))
            snapshot.guard()
        except BaseException:
            self.close()
            raise

    def _progress(self):
        self._snapshot.guard()
        return False

    @staticmethod
    def _authorize(action, first, second, database, source):
        if action in (apsw.SQLITE_SELECT, apsw.SQLITE_READ, apsw.SQLITE_RECURSIVE):
            return apsw.SQLITE_OK
        if action == apsw.SQLITE_FUNCTION and (second or '').lower() in (
                'max', 'min', 'count', 'substr', 'length', 'typeof', 'instr', 'lower',
                'coalesce', 'abs', 'hex'):
            return apsw.SQLITE_OK
        if action == apsw.SQLITE_PRAGMA and (first or '').lower() in ('table_info', 'quick_check'):
            return apsw.SQLITE_OK
        return apsw.SQLITE_DENY

    def execute(self, sql, parameters=None):
        _require(not self.closed, 'SNAPSHOT_CLOSED')
        self._snapshot.guard()
        cursor = self._con.execute(sql, parameters)
        self._snapshot.guard()
        return _SnapshotCursor(self, cursor)

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            if self._con is not None:
                self._con.close(force=True)
        finally:
            try:
                if self._vfs is not None:
                    self._vfs.unregister()
            finally:
                self._snapshot.close()


def open_snapshot(path, *, recover_key, budget, kind='selected-messages',
                  opener=None, scope_guard=None):
    """Return a fully authenticated/quick-checked, scoped read-only connection.

    The caller must enforce its account/path allowlist and share one budget.
    Production passes its account lease's open(path, max_bytes=...) context
    manager and guard. They bind opened handles before any read and remain
    alive until close; fixture-only callers can use ordinary read-only opens.
    Keys remain in process for lazy decryption and are dropped at close.
    No row may be published until the reader's complete command succeeds.
    """
    _require(isinstance(budget, SnapshotBudget), 'SNAPSHOT_SHARED_BUDGET_REQUIRED')
    _require(opener is None or callable(opener), 'SNAPSHOT_OPENER_INVALID')
    _require(scope_guard is None or callable(scope_guard), 'SNAPSHOT_SCOPE_GUARD_INVALID')
    return SnapshotConnection(_Snapshot(path, recover_key, budget, kind, opener, scope_guard))
