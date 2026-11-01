"""Fictional RAM/files exercise a candidate layout, not a native x86 read."""
import ctypes
import hashlib
import hmac
import json
import os
from pathlib import Path
import struct
import tempfile
from types import MethodType, SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.keywrap import aes_key_wrap
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import reader_x86 as x86


class FakeReader:
    def __init__(self, account):
        self.data = account / 'chat_data'
        self.regions = {0x20000: bytearray(0x1000)}
        self.calls = []
        self.guard_calls = 0

    def guard(self):
        self.guard_calls += 1
        if hasattr(self, 'files'):
            self.files.guard()

    def memory(self, address, size):
        self.guard()
        self.calls.append((address, size))
        for base, data in self.regions.items():
            if base <= address and address + size <= base + len(data):
                return bytes(data[address - base:address - base + size])
        return None

    def write(self, address, data):
        for base, value in self.regions.items():
            if base <= address and address + len(data) <= base + len(value):
                value[address - base:address - base + len(data)] = data
                return
        self.regions[address] = bytearray(data)


class X86Candidate(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='kakao-synthetic-x86-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.account = self.root / 'account'
        self.account.mkdir()
        self.container = self.account / 'fictional-ikm'
        self.ikm = bytes(range(32))
        self.binding = b'fictional-binding'.ljust(32, b'!')
        self.identity = b'fictional-identity'
        self.wrapped = aes_key_wrap(
            hmac.new(self.binding, self.identity + b'ikm-wrap', hashlib.sha256).digest(),
            self.ikm)
        self.container.write_bytes(self.wrapped)
        self.salt = 0x20400

    def fixture(self, offset=160, path=None, width=32):
        reader = FakeReader(self.account)
        wide = str(path or self.container).encode('utf-16-le')
        reader.write(self.salt - 24, b'v2:' + bytes(13) + struct.pack('<II', 3, 15))
        reader.write(0x50000, wide)
        reader.write(0x40000, self.identity)
        if width == 32:
            raw = struct.pack('<I', 0x50000) + bytes(12)
            raw += struct.pack('<II', len(wide) // 2, len(wide) // 2)
            vector = struct.pack('<III', 0x40000, 0x40000 + len(self.identity), 0x40080)
        else:
            raw = struct.pack('<QQQQ', 0x50000, 0, len(wide) // 2, len(wide) // 2)
            vector = struct.pack('<QQQ', 0x40000, 0x40000 + len(self.identity), 0x40080)
        reader.write(self.salt - offset, raw + self.binding + vector)
        return reader

    def collect(self, reader, salt=None):
        stats = {}
        result = list(x86.try_x86_inputs(reader, self.salt if salt is None else salt, stats))
        return result, stats

    def test_candidate_offset_matrix_without_fixed_manager_offset(self):
        for offset in (92, 96, 160, 256, 512):
            with self.subTest(offset=offset):
                reader = self.fixture(offset)
                result, stats = self.collect(reader)
                self.assertEqual(result, [(self.ikm, self.binding)])
                self.assertEqual(stats['x86_candidate_relative_offset'], -offset)
                self.assertEqual(stats['matching_state_prefixes'], 1)
                self.assertLessEqual(stats['x86_candidate_windows'], 128)
                self.assertIn('not_native_proven', stats['x86_candidate_layout'])
                self.assertNotIn('target_page_hmac', stats)
                self.assertNotIn('selected_room_key_validated', stats)

    def test_candidate_outside_window_or_not_aligned_is_rejected(self):
        for offset in (516, 161):
            with self.subTest(offset=offset):
                self.assertFalse(self.collect(self.fixture(offset))[0])

    def test_x64_record_is_not_treated_as_x86(self):
        self.assertFalse(self.collect(self.fixture(width=64))[0])

    def test_x64_vector_inside_x86_string_record_is_rejected(self):
        reader = self.fixture()
        reader.write(self.salt - 160 + 56,
                     struct.pack('<QQQ', 0x40000, 0x40000 + len(self.identity), 0x40080))
        self.assertFalse(self.collect(reader)[0])

    def test_prefix_length_capacity_and_pointer_width(self):
        for length, capacity in ((2, 15), (3, 2), (3, 16), (0, 0)):
            reader = self.fixture()
            reader.write(self.salt - 8, struct.pack('<II', length, capacity))
            self.assertFalse(self.collect(reader)[0])
        reader = self.fixture()
        reader.write(self.salt - 32, b'v2:' + bytes(13) + struct.pack('<QQ', 3, 15))
        self.assertFalse(self.collect(reader)[0])

    def test_path_lengths_and_capacities_are_bounded(self):
        for length, capacity in ((0, 8), (513, 513), (20, 19), (20, 4097), (8, 7)):
            with self.subTest(length=length, capacity=capacity):
                reader = self.fixture()
                reader.write(self.salt - 160 + 16, struct.pack('<II', length, capacity))
                self.assertFalse(self.collect(reader)[0])

    def test_identity_bounds_and_reversed_vector(self):
        for vector in ((0x40000, 0x40000, 0x40080),
                       (0x40000, 0x40201, 0x40201),
                       (0x40000, 0x40011, 0x41001),
                       (0x40000, 0x40011, 0x40010),
                       (0x100, 0x111, 0x180)):
            reader = self.fixture()
            reader.write(self.salt - 160 + 56, struct.pack('<III', *vector))
            self.assertFalse(self.collect(reader)[0])

    def test_32bit_address_bounds_checked_before_memory_access(self):
        reader = self.fixture()
        for salt in (0, 0x10000, 0x10001, -1, 1 << 32, (1 << 32) - 16, True):
            reader.calls.clear()
            self.assertFalse(self.collect(reader, salt)[0])
            self.assertFalse(reader.calls)
        for pointer in (0x100, (1 << 32) - 8):
            reader = self.fixture()
            reader.write(self.salt - 160, struct.pack('<I', pointer))
            self.assertFalse(self.collect(reader)[0])
            self.assertTrue(all(a >= 0x10000 and a + n <= 1 << 32 for a, n in reader.calls))

    def test_external_and_prefix_sibling_paths_never_opened(self):
        for path in (self.root / 'outside', self.root / 'account-extra' / 'file'):
            reader = self.fixture(path=path)
            with patch.object(x86.os, 'open', side_effect=AssertionError('unexpected open')):
                self.assertFalse(self.collect(reader)[0])

    def test_parent_traversal_and_nul_are_rejected(self):
        for text in (str(self.account / '..' / 'account' / 'fictional-ikm'),
                     str(self.container) + '\x00'):
            reader = self.fixture(path=text)
            with patch.object(x86.os, 'open', side_effect=AssertionError('unexpected open')):
                self.assertFalse(self.collect(reader)[0])

    def test_symlink_file_and_directory_are_rejected(self):
        if os.name == 'nt':
            self.skipTest('Unprivileged Windows symlink creation is not assumed')
        alias = self.account / 'alias'
        alias.symlink_to(self.container)
        directory = self.account / 'linked-directory'
        directory.symlink_to(self.account, target_is_directory=True)
        for path in (alias, directory / self.container.name):
            with patch.object(x86.os, 'open', side_effect=AssertionError('unexpected open')):
                self.assertFalse(self.collect(self.fixture(path=path))[0])

    def test_windows_reparse_attribute_is_rejected(self):
        original = Path.lstat
        for reparse_path in (self.container, self.account):
            def reparse(path):
                value = original(path)
                if path == reparse_path:
                    return SimpleNamespace(st_mode=value.st_mode, st_file_attributes=0x400)
                return value
            with patch.object(Path, 'lstat', reparse), \
                 patch.object(x86.os, 'open', side_effect=AssertionError('unexpected open')):
                self.assertFalse(self.collect(self.fixture())[0])

    def test_changed_container_stops_without_yield(self):
        original = x86._read_40
        calls = 0
        def change(handle):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.container.write_bytes(b'changed'.ljust(40, b'!'))
            return original(handle)
        with patch.object(x86, '_read_40', change):
            with self.assertRaisesRegex(RuntimeError, '^IKM_CONTAINER_CHANGED$'):
                self.collect(self.fixture())

    def test_replaced_container_is_rejected_before_read(self):
        replacement = self.account / 'replacement'
        replacement.write_bytes(self.wrapped)
        original = os.open
        def replace(path, flags):
            self.container.unlink()
            replacement.rename(self.container)
            return original(path, flags)
        with patch.object(x86.os, 'open', replace), \
             patch.object(x86, '_read_40', side_effect=AssertionError('unexpected read')):
            with self.assertRaisesRegex(RuntimeError, '^IKM_CONTAINER_CHANGED$'):
                self.collect(self.fixture())

    def test_growing_container_reads_at_most_41_bytes_per_pass(self):
        original = x86._read_40
        lengths = []
        def grow(handle):
            if not lengths:
                self.container.write_bytes(b'x' * 65536)
            value = original(handle)
            lengths.append(len(value))
            return value
        with patch.object(x86, '_read_40', grow):
            with self.assertRaisesRegex(RuntimeError, '^IKM_CONTAINER_CHANGED$'):
                self.collect(self.fixture())
        self.assertEqual(lengths, [41, 41])

    def test_container_size_and_wrap_integrity(self):
        for content in (self.wrapped[:-1], self.wrapped + b'x', b'bad-wrap'.ljust(40, b'!')):
            self.container.write_bytes(content)
            self.assertFalse(self.collect(self.fixture())[0])

    def test_wrong_size_is_rejected_before_open(self):
        for size in (0, 39, 41, 1024 * 1024):
            self.container.write_bytes(b'x' * size)
            with patch.object(x86.os, 'open', side_effect=AssertionError('unexpected open')):
                self.assertFalse(self.collect(self.fixture())[0])

    def test_inline_wide_path_candidate(self):
        path = Path('C:/k') if os.name == 'nt' else Path('/a/key')
        reader = self.fixture(path=path)
        reader.data = path.parent / 'chat_data'
        wide = str(path).encode('utf-16-le')
        raw = wide.ljust(16, b'\x00') + struct.pack('<II', len(wide) // 2, 7)
        reader.write(self.salt - 160, raw)
        with patch.object(x86, '_checked_container', return_value=self.wrapped) as checked:
            result, _ = self.collect(reader)
        self.assertEqual(result, [(self.ikm, self.binding)])
        checked.assert_called_once_with(reader, path, path.parent)

    def test_fallback_to_bounded_records_when_window_crosses_region(self):
        reader = self.fixture()
        original = reader.memory
        def split(address, size):
            if address == self.salt - 512 and size > 68:
                return None
            return original(address, size)
        reader.memory = split
        result, stats = self.collect(reader)
        self.assertEqual(result, [(self.ikm, self.binding)])
        self.assertLessEqual(stats['x86_candidate_windows'], 128)

    def test_guards_are_not_swallowed(self):
        reader = self.fixture()
        reader.guard = lambda: (_ for _ in ()).throw(AssertionError('TIME_LIMIT'))
        with self.assertRaisesRegex(AssertionError, '^TIME_LIMIT$'):
            self.collect(reader)

    def test_stats_contain_no_path_key_identity_or_address(self):
        _, stats = self.collect(self.fixture())
        serialized = json.dumps(stats)
        for private in (str(self.container), str(self.account), self.ikm.hex(),
                        self.binding.hex(), self.identity.decode(), str(self.salt)):
            self.assertNotIn(private, serialized)
        self.assertTrue(all(isinstance(value, (bool, int, str)) for value in stats.values()))


class FakeKernel:
    """Finite synthetic address map; no Windows API or process is opened."""
    def __init__(self, reader):
        self.reader = reader

    def VirtualQueryEx(self, handle, address, result, size):
        for base, data in sorted(self.reader.regions.items()):
            if address >= base + len(data):
                continue
            value = ctypes.cast(result, ctypes.POINTER(self.reader.mbi_type)).contents
            if address < base:
                value.base = address
                value.size = base - address
                value.kind, value.state, value.protect = 0, 0x10000, 1
            else:
                value.base = base
                value.size = len(data)
                value.kind, value.state, value.protect = 0x20000, 0x1000, 4
            return size
        return 0


def fictional_page(key, page_number=1):
    """Produce a SQLCipher-authenticated page with entirely fictional bytes."""
    salt = bytes(range(16))
    iv = bytes(range(16, 32))
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(b'fictional-page'.ljust(4000, b'!')) + encryptor.finalize()
    mac_key = PBKDF2HMAC(algorithm=hashes.SHA512(), length=32,
                        salt=bytes(value ^ 0x3a for value in salt), iterations=2).derive(key)
    mac = crypto_hmac.HMAC(mac_key, hashes.SHA512())
    mac.update(ciphertext + iv + struct.pack('<I', page_number))
    return salt + ciphertext + iv + mac.finalize()


class X86Recover(unittest.TestCase):
    """Exercise the real recovery chain; these are still NOT live x86 tests."""
    def setUp(self):
        X86Candidate.setUp(self)
        import v2_key_derivation as derivation
        from reader_accounts import select_account_lease
        from room_reader import M, Reader
        from vendor_appstate import AppState

        self.derivation = derivation
        self.reader = X86Candidate.fixture(self)
        self.target_key = hashlib.sha256(b'fictional-selected-database-key').digest()
        self.page = fictional_page(self.target_key)
        self.assertTrue(Reader.valid_page(self.page, self.target_key, 1, self.page[:16]))
        self.target = self.account / 'chat_data' / 'chatListInfo.edb'
        self.target.parent.mkdir()
        self.target.write_bytes(self.page)
        self.state_file = self.account / 'appstate.dat'
        self.state_file.write_bytes(b'fictional-appstate-fixture-read-through-real-lease')
        self.state_salt = hashlib.sha256(b'fictional-envelope-salt').digest()
        self.relative = 'chat_data\\chatListInfo.edb'
        self.target_wrap = aes_key_wrap(
            derivation.file_kek(self.ikm, self.binding, self.state_salt, b'v2:', self.relative),
            self.target_key)
        self.state = AppState(str(self.state_file), b'v2:', self.state_salt,
                              {self.relative: self.target_wrap})
        selected, self.reader.files = select_account_lease(self.root)
        self.assertEqual(selected, self.account)
        self.reader.account_scope = hashlib.sha256(str(selected).casefold().encode()).hexdigest()
        self.reader.target_pointer_bytes = 4
        self.reader.address_limit = 1 << 32
        self.reader.mbi_type = M
        self.reader.k = FakeKernel(self.reader)
        self.reader.handle = object()
        self.reader.valid_page = Reader.valid_page
        self.reader.file_hash = MethodType(Reader.file_hash, self.reader)
        self.reader.validated_keys = []
        self.reader.envelope_stats = None
        self.reader.write(self.salt, self.state_salt)

    def recover(self, page=None):
        # Only metadata decoding is replaced; real leased reads and hashes run.
        with patch.object(self.derivation, 'parse_bytes', return_value=self.state):
            return self.derivation.recover(self.reader, self.target,
                                           self.page if page is None else page)

    def assert_not_promoted(self, prior_keys=()):
        stats = self.reader.envelope_stats or {}
        self.assertFalse(stats.get('target_page_hmac', False))
        self.assertFalse(stats.get('selected_room_key_validated', False))
        self.assertEqual(self.reader.validated_keys, list(prior_keys))

    def other_account(self):
        from reader_accounts import select_account_lease
        other = self.root / 'other-account'
        (other / 'chat_data').mkdir(parents=True)
        (other / 'chat_data' / self.target.name).write_bytes(self.page)
        (other / 'appstate.dat').write_bytes(self.state_file.read_bytes())
        token = hashlib.sha256(str(other).casefold().encode()).hexdigest()
        selected, lease = select_account_lease(self.root, token)
        self.assertEqual(selected, other)
        return other, token, lease

    def test_real_recovery_requires_all_three_crypto_checks(self):
        with patch.object(self.reader, 'valid_page', wraps=self.reader.valid_page) as page_check:
            self.assertEqual(self.recover(), self.target_key)
        page_check.assert_called_once_with(self.page, self.target_key, 1, self.page[:16])
        self.assertEqual(self.reader.validated_keys, [self.target_key])
        stats = self.reader.envelope_stats
        for name in ('ikm_container_wrap_integrity', 'target_wrap_integrity',
                     'target_page_hmac', 'selected_room_key_validated', 'candidate_x86'):
            self.assertTrue(stats[name])
        self.assertIsNone(stats['native_kdf_mode'])
        self.assertIn('not_native_proven', stats['x86_candidate_layout'])
        self.assertEqual(self.reader.envelope_inputs[1], self.reader.account_scope)

    def test_good_ikm_with_bad_target_wrap_cannot_be_promoted(self):
        self.state.wrapped_dek_map[self.relative] = b'wrong-target-wrap'.ljust(40, b'!')
        with patch.object(self.reader, 'valid_page', wraps=self.reader.valid_page) as page_check:
            with self.assertRaisesRegex(RuntimeError, '^V2_SELECTED_DATABASE_KEY_NOT_VALIDATED$'):
                self.recover()
        page_check.assert_not_called()
        self.assertTrue(self.reader.envelope_stats['ikm_container_wrap_integrity'])
        self.assertFalse(self.reader.envelope_stats['target_wrap_integrity'])
        self.assert_not_promoted()

    def test_target_wrap_success_with_bad_page_hmac_is_blocked(self):
        corrupted = bytearray(self.page)
        corrupted[100] ^= 1
        with self.assertRaisesRegex(RuntimeError, '^V2_SELECTED_DATABASE_KEY_NOT_VALIDATED$'):
            self.recover(bytes(corrupted))
        self.assertTrue(self.reader.envelope_stats['ikm_container_wrap_integrity'])
        self.assertTrue(self.reader.envelope_stats['target_wrap_integrity'])
        self.assert_not_promoted()

    def test_authenticated_page_for_wrong_key_or_page_number_is_blocked(self):
        for page in (fictional_page(b'other-key'.ljust(32, b'!')), fictional_page(self.target_key, 2)):
            with self.subTest(page_sha256=hashlib.sha256(page).hexdigest()):
                with self.assertRaisesRegex(RuntimeError, '^V2_SELECTED_DATABASE_KEY_NOT_VALIDATED$'):
                    self.recover(page)
                self.assertTrue(self.reader.envelope_stats['target_wrap_integrity'])
                self.assert_not_promoted()

    def test_bad_ikm_cannot_reach_target_unwrap(self):
        self.container.write_bytes(b'wrong-ikm-wrap'.ljust(40, b'!'))
        with patch.object(self.derivation, 'aes_key_unwrap',
                          wraps=self.derivation.aes_key_unwrap) as target_unwrap:
            with self.assertRaisesRegex(RuntimeError, '^V2_SELECTED_DATABASE_KEY_NOT_VALIDATED$'):
                self.recover()
        target_unwrap.assert_not_called()
        self.assertFalse(self.reader.envelope_stats['ikm_container_wrap_integrity'])
        self.assert_not_promoted()

    def test_cached_inputs_still_require_actual_target_page_authentication(self):
        self.assertEqual(self.recover(), self.target_key)
        corrupted = bytearray(self.page)
        corrupted[-1] ^= 1
        with self.assertRaisesRegex(AssertionError, '^V2_CACHED_TARGET_PAGE_INVALID$'):
            self.recover(bytes(corrupted))
        self.assert_not_promoted(prior_keys=[self.target_key])

    def test_cache_from_another_scope_cannot_bypass_discovery(self):
        self.assertEqual(self.recover(), self.target_key)
        self.reader.account_scope = 'f' * 64
        self.reader.write(self.salt, bytes(32))
        with self.assertRaisesRegex(RuntimeError, '^V2_SELECTED_DATABASE_KEY_NOT_VALIDATED$'):
            self.recover()
        self.assertFalse(self.reader.envelope_stats.get('request_memory_cache_hit', False))
        self.assert_not_promoted(prior_keys=[self.target_key])

    def test_old_account_ram_and_cache_cannot_authenticate_new_account(self):
        self.assertEqual(self.recover(), self.target_key)
        other, token, lease = self.other_account()
        self.reader.data = other / 'chat_data'
        self.reader.account_scope = token
        self.reader.files = lease
        self.target = self.reader.data / self.target.name
        with self.assertRaisesRegex(RuntimeError, '^V2_SELECTED_DATABASE_KEY_NOT_VALIDATED$'):
            self.recover()
        self.assertFalse(self.reader.envelope_stats['ikm_container_wrap_integrity'])
        self.assert_not_promoted(prior_keys=[self.target_key])

    def test_mismatched_file_lease_blocks_before_metadata_or_candidate_read(self):
        _, _, lease = self.other_account()
        self.reader.files = lease
        with patch.object(self.derivation, 'parse_bytes', return_value=self.state) as decode:
            with self.assertRaisesRegex(RuntimeError, '^ACCOUNT_FILE_OUTSIDE_SCOPE$'):
                self.derivation.recover(self.reader, self.target, self.page)
        decode.assert_not_called()
        self.assertFalse(self.reader.calls)
        self.assert_not_promoted()

    def test_changed_lease_after_success_cannot_leave_current_success_stats(self):
        self.assertEqual(self.recover(), self.target_key)
        self.account.rename(self.root / 'previous-account')
        self.account.mkdir()
        with self.assertRaisesRegex(RuntimeError, '^ACCOUNT_SCOPE_CHANGED$'):
            self.recover()
        self.assert_not_promoted(prior_keys=[self.target_key])


if __name__ == '__main__':
    unittest.main()
