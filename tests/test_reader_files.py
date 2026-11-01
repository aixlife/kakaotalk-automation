"""Synthetic account-bound filesystem races; no application access."""
import io
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import reader_accounts
import reader_files


class ScopedAccountFiles(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='kakao-synthetic-lease-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve() / 'users'
        self.account = self.root / 'synthetic-account'
        self.data = self.account / 'chat_data'
        self.data.mkdir(parents=True)
        self.database = self.data / 'chatListInfo.edb'
        self.database.write_bytes(b'original database bytes')
        selected, self.lease = reader_accounts.select_account_lease(self.root)
        self.assertEqual(selected, self.account)

    def assert_blocked_before_stream(self, action, code):
        with patch.object(os, 'fdopen', side_effect=AssertionError('stream exposed')):
            with self.assertRaisesRegex(RuntimeError, '^' + code + '$'):
                action()

    def symlink(self, link, target, *, target_is_directory=False):
        try:
            link.symlink_to(target, target_is_directory=target_is_directory)
        except OSError as error:
            if getattr(error, 'winerror', None) == 1314:
                self.skipTest('Windows symlink creation privilege unavailable (1314)')
            raise

    def test_valid_database_is_read_and_stream_is_readonly(self):
        with self.lease.open(self.database, max_bytes=1024) as stream:
            self.assertEqual(stream.read(), b'original database bytes')
            with self.assertRaises(io.UnsupportedOperation):
                stream.write(b'never')
        self.assertTrue(stream.closed)
        self.assertEqual(self.lease.bounded_read(self.database, 1024), b'original database bytes')

    def test_allowed_wal_profile_and_appstate_paths(self):
        for path in (self.data / 'chatListInfo.edb-wal', self.data / 'chatLogs_123.edb',
                     self.account / 'TalkUserDB.edb', self.account / 'TalkUserDB.edb-wal',
                     self.account / 'appstate.dat'):
            with self.subTest(name=path.name):
                path.write_bytes(b'fixture')
                self.assertEqual(self.lease.bounded_read(path, 64), b'fixture')

    def test_scoped_40_byte_ikm_requires_explicit_cap(self):
        path = self.account / 'container' / 'opaque.bin'
        path.parent.mkdir()
        path.write_bytes(b'x' * 40)
        self.assertEqual(self.lease.bounded_read(path, 40, exact=40), b'x' * 40)
        self.assert_blocked_before_stream(lambda: self.lease.bounded_read(path, 64),
                                         'ACCOUNT_FILE_OUTSIDE_SCOPE')
        path.write_bytes(b'x' * 39)
        self.assert_blocked_before_stream(lambda: self.lease.bounded_read(path, 40),
                                         'ACCOUNT_FILE_SIZE_CHANGED')

    def test_root_account_and_data_replacement_after_selection_are_rejected(self):
        for level in ('root', 'account', 'data'):
            with self.subTest(level=level):
                target = getattr(self, level)
                moved = target.with_name(target.name + '-moved')
                target.rename(moved)
                target.mkdir()
                try:
                    self.assert_blocked_before_stream(
                        lambda: self.lease.bounded_read(self.database, 1024), 'ACCOUNT_SCOPE_CHANGED')
                    with self.assertRaisesRegex(RuntimeError, '^ACCOUNT_SCOPE_CHANGED$'):
                        self.lease.guard()
                finally:
                    target.rmdir()
                    moved.rename(target)

    def test_directory_timestamp_changes_from_wal_creation_are_allowed(self):
        (self.data / 'chatListInfo.edb-wal').write_bytes(b'wal')
        (self.account / 'new-app-file').write_bytes(b'fixture')
        self.lease.guard()
        self.assertEqual(self.lease.bounded_read(self.database, 1024), b'original database bytes')

    def test_file_symlink_is_rejected(self):
        moved = self.database.with_name('outside-file')
        self.database.rename(moved)
        self.symlink(self.database, moved)
        self.assert_blocked_before_stream(lambda: self.lease.bounded_read(self.database, 1024),
                                         'ACCOUNT_FILE_UNSAFE')

    def test_windows_parent_junction_is_rejected(self):
        original = Path.lstat
        def marked(path):
            value = original(path)
            if path == self.data:
                return SimpleNamespace(st_mode=value.st_mode, st_file_attributes=0x400)
            return value
        with patch.object(Path, 'lstat', marked):
            self.assert_blocked_before_stream(lambda: self.lease.bounded_read(self.database, 1024),
                                             'ACCOUNT_FILE_UNSAFE')

    def test_nested_container_symlink_is_rejected(self):
        outside = self.root.parent / 'outside'
        outside.mkdir()
        (outside / 'opaque').write_bytes(b'x' * 40)
        self.symlink(self.account / 'alias', outside, target_is_directory=True)
        self.assert_blocked_before_stream(
            lambda: self.lease.bounded_read(self.account / 'alias' / 'opaque', 40),
            'ACCOUNT_FILE_UNSAFE')

    def test_outside_relative_ads_and_unrecognized_files_are_rejected(self):
        targets = (self.root / 'outside.edb', Path('chatListInfo.edb'),
                   self.data / '..' / 'TalkUserDB.edb', self.account / 'secret.txt',
                   self.data / 'chatListInfo.edb:private', self.data / 'alias.edb ',
                   self.data / 'nested' / 'database.edb')
        for path in targets:
            with self.subTest(path=path), patch.object(os, 'open') as opened:
                with self.assertRaisesRegex(RuntimeError, '^ACCOUNT_FILE_(OUTSIDE_SCOPE|UNSAFE)$'):
                    self.lease.bounded_read(path, 1024)
                opened.assert_not_called()

    def test_nonregular_and_oversize_are_rejected_before_open(self):
        self.database.unlink()
        self.database.mkdir()
        with patch.object(os, 'open') as opened:
            with self.assertRaisesRegex(RuntimeError, '^ACCOUNT_FILE_NOT_REGULAR$'):
                self.lease.bounded_read(self.database, 1024)
            opened.assert_not_called()
        self.database.rmdir()
        self.database.write_bytes(b'x' * 41)
        with patch.object(os, 'open') as opened:
            with self.assertRaisesRegex(RuntimeError, '^ACCOUNT_FILE_TOO_LARGE$'):
                self.lease.bounded_read(self.database, 40)
            opened.assert_not_called()

    def test_file_replacement_between_lstat_and_open_fails_before_read_and_closes_fd(self):
        real_open = os.open
        descriptors = []
        def replaced(path, flags):
            replacement = self.data / 'new-file'
            replacement.write_bytes(b'private replacement')
            replacement.replace(path)
            descriptor = real_open(path, flags)
            descriptors.append(descriptor)
            return descriptor
        with patch.object(os, 'open', replaced):
            self.assert_blocked_before_stream(lambda: self.lease.bounded_read(self.database, 1024),
                                             'ACCOUNT_FILE_CHANGED')
        self.assertEqual(len(descriptors), 1)
        with self.assertRaises(OSError):
            os.fstat(descriptors[0])

    def test_directory_swap_during_open_fails_before_read_and_closes_fd(self):
        real_open = os.open
        descriptors = []
        def replaced(path, flags):
            self.data.rename(self.data.with_name('old-data'))
            self.data.mkdir()
            self.database.write_bytes(b'private replacement')
            descriptor = real_open(path, flags)
            descriptors.append(descriptor)
            return descriptor
        with patch.object(os, 'open', replaced):
            self.assert_blocked_before_stream(lambda: self.lease.bounded_read(self.database, 1024),
                                             'ACCOUNT_SCOPE_CHANGED')
        with self.assertRaises(OSError):
            os.fstat(descriptors[0])

    def test_opened_descriptor_must_match_lstat_even_if_path_matches(self):
        other = self.account / 'other-file'
        other.write_bytes(b'private replacement')
        real_open = os.open
        descriptors = []
        def wrong_descriptor(path, flags):
            descriptor = real_open(other, flags)
            descriptors.append(descriptor)
            return descriptor
        with patch.object(os, 'open', wrong_descriptor):
            self.assert_blocked_before_stream(lambda: self.lease.bounded_read(self.database, 1024),
                                             'ACCOUNT_FILE_CHANGED')
        with self.assertRaises(OSError):
            os.fstat(descriptors[0])

    def test_scope_is_rechecked_after_context_body_and_stream_closes(self):
        original = reader_files._inspect
        swapped = [False]
        def observed(path):
            value = original(path)
            if swapped[0] and path == self.data:
                return SimpleNamespace(st_dev=value.st_dev, st_ino=value.st_ino + 1,
                                       st_mode=value.st_mode)
            return value
        # Windows may deny an actual rename while a child FD is open. Model
        # the replacement's metadata to check the post-body guard on all OSes.
        with patch.object(reader_files, '_inspect', observed):
            with self.assertRaisesRegex(RuntimeError, '^ACCOUNT_SCOPE_CHANGED$'):
                with self.lease.open(self.database) as stream:
                    swapped[0] = True
        self.assertTrue(stream.closed)

    def test_file_identity_is_rechecked_after_context_body(self):
        original = reader_files._inspect
        swapped = [False]
        def observed(path):
            value = original(path)
            if swapped[0] and path == self.database:
                return SimpleNamespace(st_dev=value.st_dev, st_ino=value.st_ino + 1,
                                       st_mode=value.st_mode, st_size=value.st_size)
            return value
        with patch.object(reader_files, '_inspect', observed):
            with self.assertRaisesRegex(RuntimeError, '^ACCOUNT_FILE_CHANGED$'):
                with self.lease.open(self.database) as stream:
                    swapped[0] = True
        self.assertTrue(stream.closed)

    def test_valid_content_changes_are_left_for_caller_hash_validation(self):
        with self.lease.open(self.database, max_bytes=1024) as stream:
            before = stream.read()
            self.database.write_bytes(b'changed valid contents')
            stream.seek(0)
            after = stream.read()
        self.assertNotEqual(before, after)
        self.lease.guard()

    def test_growth_after_open_reads_at_most_maximum_plus_one(self):
        counts = []
        real_fdopen = os.fdopen
        class GrowingStream:
            def __init__(inner, stream):
                inner.stream = stream
            def read(inner, size):
                counts.append(size)
                self.database.write_bytes(b'x' * 4096)
                return inner.stream.read(size)
            def close(inner):
                inner.stream.close()
            def fileno(inner):
                return inner.stream.fileno()
        def growing(fd, *args, **kwargs):
            return GrowingStream(real_fdopen(fd, *args, **kwargs))
        with patch.object(os, 'fdopen', growing):
            with self.assertRaisesRegex(RuntimeError, '^ACCOUNT_FILE_TOO_LARGE$'):
                self.lease.bounded_read(self.database, 32)
        self.assertEqual(counts, [33])

    def test_exact_read_length_and_invalid_budgets(self):
        with self.assertRaisesRegex(RuntimeError, '^ACCOUNT_FILE_SIZE_CHANGED$'):
            self.lease.bounded_read(self.database, 1024, exact=40)
        for maximum, exact in ((-1, None), (True, None), ('40', None),
                               (32, -1), (32, 33), (32, True)):
            with self.subTest(maximum=maximum, exact=exact), patch.object(os, 'open') as opened:
                with self.assertRaisesRegex(RuntimeError, '^ACCOUNT_FILE_LIMIT_INVALID$'):
                    self.lease.bounded_read(self.database, maximum, exact=exact)
                opened.assert_not_called()

    def test_os_errors_are_path_free_and_fdopen_failure_closes_fd(self):
        descriptors = []
        real_open = os.open
        def tracked(path, flags):
            descriptor = real_open(path, flags)
            descriptors.append(descriptor)
            return descriptor
        with patch.object(os, 'open', tracked), \
             patch.object(os, 'fdopen', side_effect=OSError('private-sensitive-path')):
            with self.assertRaisesRegex(RuntimeError, '^ACCOUNT_FILE_UNAVAILABLE$') as caught:
                self.lease.bounded_read(self.database, 1024)
        self.assertTrue(caught.exception.__suppress_context__)
        with self.assertRaises(OSError):
            os.fstat(descriptors[0])


if __name__ == '__main__':
    unittest.main()
