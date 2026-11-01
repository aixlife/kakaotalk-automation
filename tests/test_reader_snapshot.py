"""Synthetic SQLCipher snapshots only: no KakaoTalk or customer data access."""

import ctypes
import hashlib
import hmac
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import apsw
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import reader_snapshot as snapshot


PAGE = 4096
RESERVE = 80
KEY = bytes(range(32))  # Public deterministic fixture material, never a real key.
SALT = bytes(range(16))
HMAC_KEY = hashlib.pbkdf2_hmac(
    'sha512', KEY, bytes(value ^ 0x3A for value in SALT), 2, dklen=32)


def plain_database(rows=3, payload_size=100):
    """Build the plaintext fixture in memory, including SQLCipher's reserve."""
    con = apsw.Connection(':memory:')
    con.execute('PRAGMA page_size=4096')
    reserve = ctypes.c_int(RESERVE)
    assert con.file_control(
        'main', apsw.SQLITE_FCNTL_RESERVE_BYTES, ctypes.addressof(reserve))
    con.execute('VACUUM')
    con.execute('CREATE TABLE messages(id INTEGER PRIMARY KEY, body TEXT NOT NULL, payload BLOB)')
    with con:
        con.executemany('INSERT INTO messages VALUES(?,?,?)', (
            (ident, 'fixture message', b'x' * payload_size)
            for ident in range(1, rows + 1)))
    assert con.serialize('main')[20] == RESERVE
    return con


def encrypt_page(plain, pgno, generation=0):
    assert len(plain) == PAGE
    offset = 16 if pgno == 1 else 0
    iv = hashlib.sha256(struct.pack('<II', pgno, generation)).digest()[:16]
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv)).encryptor()
    encrypted = cipher.update(plain[offset:PAGE - RESERVE]) + cipher.finalize()
    body = encrypted + iv
    digest = hmac.new(HMAC_KEY, body + struct.pack('<I', pgno), hashlib.sha512).digest()
    return (SALT if pgno == 1 else b'') + body + digest


def save_encrypted(path, plain):
    """Only encrypted pages are persisted; plaintext remains in memory."""
    with path.open('wb') as handle:
        for offset in range(0, len(plain), PAGE):
            handle.write(encrypt_page(plain[offset:offset + PAGE], offset // PAGE + 1))


def checksum(data, state=(0, 0), order='<'):
    words = struct.unpack(order + str(len(data) // 4) + 'I', data)
    first, second = state
    for index in range(0, len(words), 2):
        first = (first + words[index] + second) & 0xFFFFFFFF
        second = (second + words[index + 1] + first) & 0xFFFFFFFF
    return first, second


def wal_bytes(frames, order='<'):
    """Encode real WAL headers/checksums around encrypted fixture pages."""
    magic = 0x377F0682 if order == '<' else 0x377F0683
    header = struct.pack('>IIIIII', magic, 3007000, PAGE, 0, 111, 222)
    state = checksum(header, order=order)
    output = bytearray(header + struct.pack('>II', *state))
    for pgno, dbsize, page in frames:
        prefix = struct.pack('>II', pgno, dbsize)
        state = checksum(prefix + page, state, order)
        output.extend(prefix + struct.pack('>II', 111, 222)
                      + struct.pack('>II', *state) + page)
    return bytes(output)


def transaction_frames(before, after, generation=1):
    frames = []
    for offset in range(0, len(after), PAGE):
        page = after[offset:offset + PAGE]
        if before[offset:offset + PAGE] != page:
            pgno = offset // PAGE + 1
            frames.append((pgno, 0, encrypt_page(page, pgno, generation)))
    assert frames
    pgno, _, page = frames[-1]
    frames[-1] = (pgno, len(after) // PAGE, page)
    return frames


def source_digest(path):
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def fixture_reader(data, guard=lambda: None):
    """Exercise production dispatch without constructing/opening any app handle."""
    from room_reader import Reader
    from reader_accounts import select_account_lease
    reader = Reader.__new__(Reader)
    reader.data = data
    _, reader.files = select_account_lease(data.parent.parent)
    def scoped_guard():
        reader.files.guard()
        guard()
    reader.guard = scoped_guard
    reader.key_route = 'codec'
    reader.recover = lambda first: KEY
    reader.snapshots = []
    reader.snapshot_retries = 0
    reader.started = time.monotonic()
    return reader


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='synthetic-reader-snapshot-')
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'synthetic.edb'
        self.con = plain_database()
        self.addCleanup(self.con.close)
        self.before = self.con.serialize('main')
        save_encrypted(self.path, self.before)

    def open(self, **kwargs):
        budget = kwargs.pop('budget', snapshot.SnapshotBudget(guard=lambda: None))
        con = snapshot.open_snapshot(
            self.path, recover_key=lambda first: KEY, budget=budget, **kwargs)
        self.addCleanup(con.close)
        return con, budget

    def save_wal(self, frames, order='<'):
        path = self.path.with_name(self.path.name + '-wal')
        path.write_bytes(wal_bytes(frames, order))
        return path

    def updated_frames(self):
        self.con.execute("UPDATE messages SET body='committed value' WHERE id=1")
        self.con.execute("INSERT INTO messages VALUES(4,'fourth fixture',x'01')")
        return transaction_frames(self.before, self.con.serialize('main'))

    def unused_freelist_page(self):
        self.con.execute('INSERT INTO messages VALUES(5,?,?)', ('deleted fixture', b'y' * 30000))
        self.con.execute('DELETE FROM messages WHERE id=5')
        plain = self.con.serialize('main')
        trunk = struct.unpack_from('>I', plain, 32)[0]
        self.assertGreater(trunk, 0)
        trunk_offset = (trunk - 1) * PAGE
        leaf_count = struct.unpack_from('>I', plain, trunk_offset + 4)[0]
        self.assertGreater(leaf_count, 0)
        leaf = struct.unpack_from('>I', plain, trunk_offset + 8)[0]
        save_encrypted(self.path, plain)
        return leaf, len(plain) // PAGE

    def test_real_encrypted_fixture_and_row_compatibility(self):
        con, _ = self.open(kind='room-list')
        row = con.execute('SELECT count(*) AS total FROM messages').fetchone()
        self.assertEqual(row[0], 3)
        self.assertEqual(row['total'], 3)
        self.assertEqual(row['TOTAL'], 3)
        self.assertEqual(tuple(row), (3,))
        self.assertEqual(list(row.keys()), ['total'])
        self.assertEqual(dict(row), {'total': 3})
        cursor = con.execute('SELECT id FROM messages WHERE id=1')
        self.assertEqual(cursor.fetchone()[0], 1)
        self.assertIsNone(cursor.fetchone())
        receipt = con.receipt
        self.assertEqual(receipt['snapshot_pages'], len(self.before) // PAGE)
        self.assertEqual(receipt['authenticated_pages'], len(self.before) // PAGE)
        self.assertEqual(receipt['zero_pages'], 0)
        self.assertTrue(receipt['double_read_verified'])
        self.assertEqual(receipt['quick_check'], 'ok')
        self.assertNotEqual(self.path.read_bytes()[:16], b'SQLite format 3\0')

    def test_committed_wal_overlays_both_checksum_endiannesses(self):
        frames = self.updated_frames()
        for order in ('<', '>'):
            with self.subTest(order=order):
                self.save_wal(frames, order)
                con, _ = self.open()
                self.assertEqual(con.execute('SELECT count(*) FROM messages').fetchone()[0], 4)
                self.assertEqual(con.execute('SELECT body FROM messages WHERE id=1').fetchone()[0],
                                 'committed value')
                self.assertEqual(con.receipt['committed_wal_frames'], len(frames))
                self.assertEqual(con.receipt['wal_pages_applied'], len({frame[0] for frame in frames}))
                con.close()

    def test_uncommitted_and_partial_tail_cannot_override_commit(self):
        frames = self.updated_frames()
        committed = self.con.serialize('main')
        self.con.execute("UPDATE messages SET body='uncommitted bad' WHERE id=1")
        pending = transaction_frames(committed, self.con.serialize('main'), 2)
        pending = [(pgno, 0, page) for pgno, _, page in pending]
        path = self.save_wal(frames + pending)
        with path.open('ab') as handle:
            handle.write(b'partial-frame')
        con, _ = self.open()
        self.assertEqual(con.execute('SELECT body FROM messages WHERE id=1').fetchone()[0],
                         'committed value')
        self.assertEqual(con.receipt['committed_wal_frames'], len(frames))

    def test_invalid_checksum_tail_stops_at_previous_commit(self):
        frames = self.updated_frames()
        committed = self.con.serialize('main')
        self.con.execute("UPDATE messages SET body='uncommitted bad' WHERE id=1")
        later = transaction_frames(committed, self.con.serialize('main'), 2)
        damaged = bytearray(wal_bytes(frames + later))
        damaged[32 + len(frames) * (PAGE + 24) + 24] ^= 1
        self.path.with_name(self.path.name + '-wal').write_bytes(damaged)
        con, _ = self.open()
        self.assertEqual(con.execute('SELECT body FROM messages WHERE id=1').fetchone()[0],
                         'committed value')
        self.assertEqual(con.receipt['committed_wal_frames'], len(frames))

    def test_multiple_commits_choose_latest_page_and_shrinking_size(self):
        self.con.execute('INSERT INTO messages VALUES(5,?,?)', ('large fixture', b'y' * 30000))
        larger = self.con.serialize('main')
        frames = transaction_frames(self.before, larger)
        self.con.execute('DELETE FROM messages WHERE id=5')
        self.con.execute("UPDATE messages SET body='final committed' WHERE id=1")
        self.con.execute('VACUUM')
        smaller = self.con.serialize('main')
        self.assertLess(len(smaller), len(larger))
        frames += transaction_frames(larger, smaller, 2)
        self.save_wal(frames)
        con, _ = self.open()
        self.assertEqual(con.execute('SELECT count(*) FROM messages').fetchone()[0], 3)
        self.assertEqual(con.execute('SELECT body FROM messages WHERE id=1').fetchone()[0],
                         'final committed')
        self.assertEqual(con.receipt['snapshot_pages'], len(smaller) // PAGE)
        self.assertEqual(con.receipt['committed_wal_frames'], len(frames))

    def test_committed_wal_page_hmac_must_authenticate(self):
        frames = self.updated_frames()
        pgno, size, page = frames[-1]
        corrupt = bytearray(page)
        corrupt[-1] ^= 1
        frames[-1] = (pgno, size, bytes(corrupt))
        self.save_wal(frames)  # Correct WAL checksum does not replace HMAC.
        with self.assertRaisesRegex(RuntimeError, 'AUTH|HMAC'):
            self.open()

    def test_base_page_hmac_corruption_rejected(self):
        with self.path.open('r+b') as handle:
            handle.seek(PAGE + 100)
            old = handle.read(1)
            handle.seek(PAGE + 100)
            handle.write(bytes((old[0] ^ 1,)))
        with self.assertRaisesRegex(RuntimeError, 'AUTH|HMAC'):
            self.open()

    def test_valid_hmac_cannot_hide_structural_corruption(self):
        bad = bytearray(self.before[PAGE:PAGE * 2])
        bad[0] = 0xFF  # Invalid b-tree page type, then authenticate normally.
        with self.path.open('r+b') as handle:
            handle.seek(PAGE)
            handle.write(encrypt_page(bytes(bad), 2, 1))
        with self.assertRaises(Exception):
            self.open()

    def test_zero_allocated_btree_page_fails_integrity(self):
        with self.path.open('r+b') as handle:
            handle.seek(PAGE)
            handle.write(bytes(PAGE))
        with self.assertRaises(Exception):
            self.open()

    def test_zero_unused_freelist_page_is_counted_separately_from_authentication(self):
        leaf, pages = self.unused_freelist_page()
        with self.path.open('r+b') as handle:
            handle.seek((leaf - 1) * PAGE)
            handle.write(bytes(PAGE))
        con, _ = self.open()
        self.assertEqual(con.execute('SELECT count(*) FROM messages').fetchone()[0], 3)
        self.assertEqual(con.receipt['zero_pages'], 1)
        self.assertEqual(con.receipt['authenticated_pages'], pages - 1)
        self.assertEqual(con.receipt['quick_check'], 'ok')

    def test_unused_freelist_page_still_requires_hmac(self):
        leaf, _ = self.unused_freelist_page()
        with self.path.open('r+b') as handle:
            handle.seek((leaf - 1) * PAGE + 100)
            old = handle.read(1)
            handle.seek((leaf - 1) * PAGE + 100)
            handle.write(bytes((old[0] ^ 1,)))
        with self.assertRaisesRegex(RuntimeError, 'AUTH|HMAC'):
            self.open()

    def test_wal_page_commit_bounds_and_missing_growth_page(self):
        max_pages = snapshot.MAX_LOGICAL_BYTES // PAGE
        page = encrypt_page(self.before[:PAGE], 1)
        for pgno, dbsize, error in ((0, 2, 'WAL_PAGE_LIMIT'),
                                   (max_pages + 1, 2, 'WAL_PAGE_LIMIT'),
                                   (1, max_pages + 1, 'WAL_DATABASE_LIMIT'),
                                   (1, len(self.before) // PAGE + 1, 'PAGE_MISSING')):
            with self.subTest(pgno=pgno, dbsize=dbsize):
                self.save_wal([(pgno, dbsize, page)])
                with self.assertRaisesRegex(RuntimeError, error):
                    self.open()

    def test_two_pass_same_size_mutation_never_returns_a_result(self):
        original_read = snapshot._read_exact
        mutated = False

        def read_then_mutate(handle, offset, size, budget):
            nonlocal mutated
            data = original_read(handle, offset, size, budget)
            if not mutated and offset + size >= self.path.stat().st_size:
                mutated = True
                with self.path.open('r+b') as writer:
                    writer.seek(PAGE + 100)
                    old = writer.read(1)
                    writer.seek(PAGE + 100)
                    writer.write(bytes((old[0] ^ 1,)))
            return data

        with mock.patch.object(snapshot, '_read_exact', side_effect=read_then_mutate):
            with self.assertRaisesRegex(RuntimeError, 'CHANGED|MISMATCH|AUTH|HMAC'):
                self.open()
        self.assertTrue(mutated)

    def test_wal_appearance_during_capture_rejected(self):
        original_read = snapshot._read_exact
        appeared = False
        wal_path = self.path.with_name(self.path.name + '-wal')

        def read_then_create_wal(handle, offset, size, budget):
            nonlocal appeared
            data = original_read(handle, offset, size, budget)
            if not appeared and offset + size >= self.path.stat().st_size:
                appeared = True
                wal_path.write_bytes(wal_bytes([]))
            return data

        with mock.patch.object(snapshot, '_read_exact', side_effect=read_then_create_wal):
            with self.assertRaisesRegex(RuntimeError, 'WAL|CHANGED|MISMATCH'):
                self.open()
        self.assertTrue(appeared)

    def test_same_size_wal_mutation_during_capture_rejected(self):
        wal_path = self.save_wal(self.updated_frames())
        original_read = snapshot._read_exact
        mutated = False

        def read_then_mutate_wal(handle, offset, size, budget):
            nonlocal mutated
            data = original_read(handle, offset, size, budget)
            if not mutated and Path(handle.name) == wal_path and offset >= 32:
                mutated = True
                with wal_path.open('r+b') as writer:
                    writer.seek(32 + 24 + 100)
                    old = writer.read(1)
                    writer.seek(32 + 24 + 100)
                    writer.write(bytes((old[0] ^ 1,)))
            return data

        with mock.patch.object(snapshot, '_read_exact', side_effect=read_then_mutate_wal):
            with self.assertRaisesRegex(RuntimeError, 'CHANGED|MISMATCH'):
                self.open()
        self.assertTrue(mutated)

    def test_source_is_readonly_and_no_plaintext_or_journal_file_is_created(self):
        before = {entry.name: source_digest(entry) for entry in self.path.parent.iterdir()}
        con, _ = self.open()
        with self.assertRaises(Exception):
            con.execute("INSERT INTO messages VALUES(99,'must not persist',NULL)")
        with self.assertRaises(Exception):
            con.execute('CREATE TABLE forbidden(id INTEGER)')
        output = self.path.parent / 'must-not-exist.db'
        try:
            con.execute('ATTACH DATABASE ? AS forbidden', (str(output),))
        except Exception:
            pass
        self.assertFalse(output.exists())
        self.assertEqual(con.execute('SELECT count(*) FROM messages').fetchone()[0], 3)
        con.close()
        self.assertEqual(before, {entry.name: source_digest(entry)
                                  for entry in self.path.parent.iterdir()})

    def test_file_io_and_buffer_limits_fail_closed(self):
        for kwargs in ({'max_file_io_bytes': PAGE}, {'max_buffer_bytes': 16}):
            with self.subTest(limits=kwargs):
                budget = snapshot.SnapshotBudget(guard=lambda: None, **kwargs)
                with self.assertRaisesRegex(RuntimeError, 'LIMIT|BUDGET'):
                    self.open(budget=budget)
                self.assertEqual(budget.buffer_bytes, 0)

    def test_oversized_source_and_wal_are_rejected_before_reading_contents(self):
        for constant in ('MAX_DB_BYTES', 'MAX_WAL_BYTES'):
            with self.subTest(constant=constant):
                if constant == 'MAX_WAL_BYTES':
                    self.save_wal(self.updated_frames())
                budget = snapshot.SnapshotBudget(guard=lambda: None)
                with mock.patch.object(snapshot, constant, PAGE):
                    with self.assertRaisesRegex(RuntimeError, 'LIMIT|SIZE'):
                        self.open(budget=budget)
                self.assertEqual(budget.buffer_bytes, 0)

    def test_guard_failure_closes_and_releases_all_owned_buffers(self):
        def guard():
            raise RuntimeError('TEST_GUARD_STOP')

        budget = snapshot.SnapshotBudget(guard=guard)
        with self.assertRaisesRegex(RuntimeError, 'TEST_GUARD_STOP'):
            self.open(budget=budget)
        self.assertEqual(budget.buffer_bytes, 0)

    def test_reader_deadline_is_checked_before_open_and_queries(self):
        budget = snapshot.SnapshotBudget(guard=lambda: None)
        budget.started -= 41
        with self.assertRaisesRegex(RuntimeError, 'TIME_LIMIT'):
            self.open(budget=budget)
        self.assertEqual(budget.buffer_bytes, 0)
        con, active = self.open()
        active.started -= 41
        with self.assertRaisesRegex(RuntimeError, 'TIME_LIMIT'):
            con.execute('SELECT count(*) FROM messages')
        con.close()
        self.assertEqual(active.buffer_bytes, 0)

    def test_reader_deadline_is_checked_when_consuming_an_existing_cursor(self):
        for operation in ('fetchone', 'fetchall', 'iteration'):
            with self.subTest(operation=operation):
                con, budget = self.open()
                cursor = con.execute('SELECT id FROM messages ORDER BY id')
                budget.started -= 41
                with self.assertRaisesRegex(RuntimeError, 'TIME_LIMIT'):
                    if operation == 'iteration':
                        next(iter(cursor))
                    else:
                        getattr(cursor, operation)()
                con.close()
                self.assertEqual(budget.buffer_bytes, 0)

    def test_shared_budget_releases_buffers_after_each_close(self):
        budget = snapshot.SnapshotBudget(guard=lambda: None)
        first, _ = self.open(budget=budget)
        initial_reads = budget.file_read_bytes
        second, _ = self.open(budget=budget)
        self.assertGreater(budget.file_read_bytes, initial_reads)
        self.assertGreater(budget.buffer_bytes, 0)
        first.close()
        self.assertGreater(budget.buffer_bytes, 0)
        second.close()
        self.assertEqual(budget.buffer_bytes, 0)


class ScopedSnapshotTests(unittest.TestCase):
    def setUp(self):
        from reader_accounts import select_account_lease
        self.directory = tempfile.TemporaryDirectory(prefix='synthetic-scoped-snapshot-')
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name).resolve() / 'users'
        self.data = root / 'synthetic-account' / 'chat_data'
        self.data.mkdir(parents=True)
        self.path = self.data / 'chatListInfo.edb'
        plain = plain_database()
        try:
            save_encrypted(self.path, plain.serialize('main'))
        finally:
            plain.close()
        _, self.lease = select_account_lease(root)
        self.budget = snapshot.SnapshotBudget(guard=lambda: None)

    def open(self, **kwargs):
        options = dict(opener=self.lease.open, scope_guard=self.lease.guard)
        options.update(kwargs)
        return snapshot.open_snapshot(self.path, recover_key=lambda first: KEY,
                                      budget=self.budget, **options)

    def test_database_and_wal_opens_use_lease_and_respective_caps(self):
        wal = self.path.with_name(self.path.name + '-wal')
        wal.write_bytes(wal_bytes([]))
        opens = []
        def opener(path, max_bytes):
            opens.append((path, max_bytes))
            return self.lease.open(path, max_bytes=max_bytes)
        checked = mock.Mock(wraps=self.lease.guard)
        con = self.open(opener=opener, scope_guard=checked)
        try:
            before = checked.call_count
            self.assertEqual(con.execute('SELECT count(*) FROM messages').fetchone()[0], 3)
            self.assertGreater(checked.call_count, before)
            self.assertEqual(opens, [(self.path, snapshot.MAX_DB_BYTES),
                                     (wal, snapshot.MAX_WAL_BYTES)])
        finally:
            con.close()
        self.assertEqual(self.budget.buffer_bytes, 0)

    def test_late_database_replacement_is_rejected_before_any_source_read(self):
        real_open = os.open
        descriptors = []
        replacement = self.data / 'replacement.edb'
        replacement.write_bytes(b'unrelated fixture bytes')
        def replaced(path, flags):
            replacement.replace(path)
            descriptor = real_open(path, flags)
            descriptors.append(descriptor)
            return descriptor
        with mock.patch.object(os, 'open', side_effect=replaced), \
                mock.patch.object(snapshot, '_read_exact') as read:
            with self.assertRaisesRegex(RuntimeError, 'ACCOUNT_FILE_CHANGED'):
                self.open()
            read.assert_not_called()
        self.assertEqual(self.budget.file_read_bytes, 0)
        self.assertEqual(self.budget.buffer_bytes, 0)
        for descriptor in descriptors:
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_substituted_wal_descriptor_is_rejected_before_any_source_read(self):
        wal = self.path.with_name(self.path.name + '-wal')
        wal.write_bytes(wal_bytes([]))
        outside = self.data.parent.parent / 'outside-fixture'
        outside.write_bytes(b'unrelated fixture bytes')
        real_open = os.open
        descriptors = []
        def substituted(path, flags):
            descriptor = real_open(outside if Path(path) == wal else path, flags)
            descriptors.append(descriptor)
            return descriptor
        with mock.patch.object(os, 'open', side_effect=substituted), \
                mock.patch.object(snapshot, '_read_exact') as read:
            with self.assertRaisesRegex(RuntimeError, 'ACCOUNT_FILE_CHANGED'):
                self.open()
            read.assert_not_called()
        self.assertEqual(self.budget.file_read_bytes, 0)
        self.assertEqual(self.budget.buffer_bytes, 0)
        for descriptor in descriptors:
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_scope_replacement_blocks_cached_rows_and_releases_contexts(self):
        import reader_files
        from types import SimpleNamespace
        con = self.open()
        cursor = con.execute('SELECT id FROM messages')
        original = reader_files._inspect
        def changed(path):
            value = original(path)
            if path == self.data:
                return SimpleNamespace(st_dev=value.st_dev, st_ino=value.st_ino + 1,
                                       st_mode=value.st_mode)
            return value
        with mock.patch.object(reader_files, '_inspect', side_effect=changed):
            with self.assertRaisesRegex(RuntimeError, 'ACCOUNT_SCOPE_CHANGED'):
                cursor.fetchone()
            with self.assertRaisesRegex(RuntimeError, 'ACCOUNT_SCOPE_CHANGED'):
                con.close()
        self.assertEqual(self.budget.buffer_bytes, 0)
        self.assertTrue(con._snapshot.db.closed)


class LargeSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='synthetic-large-reader-')
        cls.addClassCleanup(cls.directory.cleanup)
        data = Path(cls.directory.name).resolve() / 'users' / 'synthetic-account' / 'chat_data'
        data.mkdir(parents=True)
        cls.path = data / 'large-synthetic.edb'
        con = plain_database(rows=7000, payload_size=3500)
        try:
            plain = con.serialize('main')
            assert len(plain) > 24 * 1024 * 1024
            cls.page_count = len(plain) // PAGE
            offset = plain.index(b'fixture message') // PAGE * PAGE
            cls.first_data_page = offset // PAGE + 1
            cls.first_data_plain = plain[offset:offset + PAGE]
            save_encrypted(cls.path, plain)
        finally:
            con.close()
        cls.small_path = data / 'chatListInfo.edb'
        small = plain_database(rows=3000, payload_size=3500)
        try:
            save_encrypted(cls.small_path, small.serialize('main'))
            assert cls.small_path.stat().st_size < 24 * 1024 * 1024
        finally:
            small.close()

    def test_production_reader_keeps_legacy_and_streaming_connections_open_together(self):
        import sqlite3
        reader = fixture_reader(self.path.parent)
        small = reader.database(self.small_path)
        self.addCleanup(small.close)
        large = reader.database(self.path)
        self.addCleanup(large.close)
        self.assertIsInstance(small, sqlite3.Connection)
        self.assertIsInstance(large, snapshot.SnapshotConnection)
        self.assertEqual(small.execute('SELECT count(*) FROM messages').fetchone()[0], 3000)
        self.assertEqual(large.execute('SELECT count(*) FROM messages').fetchone()[0], 7000)
        self.assertEqual(len(reader.snapshots), 2)
        budget = reader.snapshot_budget
        large.close()
        self.assertEqual(budget.buffer_bytes, 0)
        self.assertEqual(small.execute('SELECT min(id),max(id) FROM messages').fetchone()[1], 3000)

    def test_small_physical_files_with_large_committed_wal_use_streaming_reader(self):
        with tempfile.TemporaryDirectory(prefix='synthetic-wal-growth-') as folder:
            data = Path(folder).resolve() / 'users' / 'synthetic-account' / 'chat_data'
            data.mkdir(parents=True)
            path = data / 'chatListInfo.edb'
            # Fixture serialization duplicates its in-memory SQLite image.
            # Restore the real reader cap before invoking any production code.
            previous_heap = apsw.hard_heap_limit(-1)
            apsw.hard_heap_limit(0)
            plain = None
            try:
                plain = plain_database(rows=5000, payload_size=3500)
                before = plain.serialize('main')
                save_encrypted(path, before)
                with plain:
                    plain.executemany('INSERT INTO messages VALUES(?,?,?)', (
                        (ident, 'fixture message', b'x' * 3500) for ident in range(5001, 7001)))
                after = plain.serialize('main')
                wal = path.with_name(path.name + '-wal')
                wal.write_bytes(wal_bytes(transaction_frames(before, after)))
            finally:
                if plain is not None:
                    plain.close()
                apsw.hard_heap_limit(previous_heap)
            self.assertLess(path.stat().st_size, 24 * 1024 * 1024)
            self.assertLess(wal.stat().st_size, 24 * 1024 * 1024)
            self.assertGreater(len(after), 24 * 1024 * 1024)
            reader = fixture_reader(path.parent)
            con = reader.database(path)
            try:
                self.assertIsInstance(con, snapshot.SnapshotConnection)
                self.assertEqual(con.execute('SELECT count(*) FROM messages').fetchone()[0], 7000)
                self.assertEqual(con.receipt['snapshot_pages'], len(after) // PAGE)
                self.assertEqual(con.receipt['quick_check'], 'ok')
            finally:
                con.close()
            self.assertEqual(reader.snapshot_budget.buffer_bytes, 0)

    def test_over_24mib_full_authentication_with_bounded_buffers(self):
        budget = snapshot.SnapshotBudget(guard=lambda: None)
        con = snapshot.open_snapshot(self.path, recover_key=lambda first: KEY, budget=budget)
        try:
            row = con.execute('SELECT count(*) AS total,min(length(payload)) AS minimum,max(length(payload)) AS maximum FROM messages').fetchone()
            self.assertEqual(row['total'], 7000)
            self.assertEqual(row['minimum'], 3500)
            self.assertEqual(row['maximum'], 3500)
            self.assertEqual(con.receipt['authenticated_pages'], self.page_count)
            self.assertEqual(con.receipt['snapshot_pages'], self.page_count)
            self.assertEqual(con.receipt['quick_check'], 'ok')
            self.assertTrue(con.receipt['double_read_verified'])
            self.assertLessEqual(budget.peak_buffer_bytes, 28 * 1024 * 1024)
            self.assertGreater(budget.file_read_bytes, self.path.stat().st_size * 2)
        finally:
            con.close()
        self.assertEqual(budget.buffer_bytes, 0)

    def test_validly_authenticated_live_mutation_is_rejected_or_cached_original(self):
        budget = snapshot.SnapshotBudget(guard=lambda: None)
        con = snapshot.open_snapshot(self.path, recover_key=lambda first: KEY, budget=budget)
        offset = (self.first_data_page - 1) * PAGE
        replacement = self.first_data_plain.replace(b'fixture message', b'changed message')
        self.assertNotEqual(replacement, self.first_data_plain)
        try:
            with self.path.open('r+b') as writer:
                writer.seek(offset)
                writer.write(encrypt_page(replacement, self.first_data_page, 2))
            try:
                row = con.execute('SELECT body FROM messages WHERE id=1').fetchone()
            except Exception as exc:
                self.assertRegex(str(exc), 'CHANGED|MISMATCH|AUTH|HMAC|IOError|I/O')
            else:
                self.assertEqual(row[0], 'fixture message')
        finally:
            con.close()
            with self.path.open('r+b') as writer:
                writer.seek(offset)
                writer.write(encrypt_page(self.first_data_plain, self.first_data_page))

    def test_large_read_in_fresh_process_stays_under_256mib(self):
        code = r'''
import ctypes,json,os,sys,time
from pathlib import Path
sys.path.insert(0,sys.argv[2])
import reader_snapshot as snapshot
from room_reader import Reader
from reader_accounts import select_account_lease
reader=Reader.__new__(Reader)
reader.data=Path(sys.argv[1]).parent
_,reader.files=select_account_lease(reader.data.parent.parent)
reader.guard=reader.files.guard
reader.key_route='codec'
reader.recover=lambda first:bytes(range(32))
reader.snapshots=[]
reader.snapshot_retries=0
reader.started=time.monotonic()
small=reader.database(Path(sys.argv[3]))
con=reader.database(Path(sys.argv[1]))
budget=reader.snapshot_budget
assert small.execute('SELECT count(*) FROM messages').fetchone()[0]==3000
assert con.execute('SELECT count(*) FROM messages').fetchone()[0]==7000
con.close()
small.close()
if os.name=='nt':
    from ctypes import wintypes as W
    class PM(ctypes.Structure):
        _fields_=[('cb',W.DWORD),('fault',W.DWORD)]+[(name,ctypes.c_size_t) for name in ('peak_ws','ws','peak_paged','paged','peak_nonpaged','nonpaged','pagefile','peak_pagefile','private')]
    info=PM();info.cb=ctypes.sizeof(info)
    kernel=ctypes.WinDLL('kernel32');kernel.GetCurrentProcess.restype=W.HANDLE
    psapi=ctypes.WinDLL('psapi')
    psapi.GetProcessMemoryInfo.argtypes=[W.HANDLE,ctypes.POINTER(PM),W.DWORD]
    assert psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(),ctypes.byref(info),info.cb)
    peak=info.peak_ws
else:
    import resource
    peak=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform!='darwin':peak*=1024
print(json.dumps({'peak_rss_bytes':peak,'file_read_bytes':budget.file_read_bytes,'peak_buffer_bytes':budget.peak_buffer_bytes,'remaining_buffers':budget.buffer_bytes}))
'''
        environment = dict(os.environ)
        environment.pop('PYTHONPATH', None)
        runtime = str(Path(snapshot.__file__).resolve().parent)
        result = subprocess.run([sys.executable, '-c', code, str(self.path), runtime, str(self.small_path)],
                                capture_output=True, text=True, timeout=50, check=True,
                                env=environment, cwd=self.path.parent)
        measured = json.loads(result.stdout)
        self.assertLess(measured['peak_rss_bytes'], 256 * 1024 * 1024)
        self.assertLessEqual(measured['peak_buffer_bytes'], 28 * 1024 * 1024)
        self.assertEqual(measured['remaining_buffers'], 0)


if __name__ == '__main__':
    unittest.main()
