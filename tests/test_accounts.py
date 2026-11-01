"""Synthetic, metadata-only checks for local account selection."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import reader_accounts as accounts


class AccountSelection(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='kakao-synthetic-accounts-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve() / 'users'
        self.root.mkdir()

    def account(self, name):
        path = self.root / name
        (path / 'chat_data').mkdir(parents=True)
        (path / 'chat_data' / 'chatListInfo.edb').write_bytes(b'fictional-encrypted-data')
        return path

    def token(self, path):
        return hashlib.sha256(str(path.resolve()).casefold().encode()).hexdigest()

    def symlink(self, link, target, *, target_is_directory=False):
        try:
            link.symlink_to(target, target_is_directory=target_is_directory)
        except OSError as error:
            if getattr(error, 'winerror', None) == 1314:
                self.skipTest('Windows symlink creation privilege unavailable (1314)')
            raise

    def test_one_account_is_selected_and_token_matches_existing_scope(self):
        selected = self.account('private-identifier')
        self.assertEqual(accounts.select_account(self.root), selected)
        inventory = accounts.inventory_accounts(self.root)
        self.assertEqual(inventory[0]['account_token'], self.token(selected))

    def test_multiple_accounts_require_explicit_selection(self):
        first = self.account('private-active')
        backup = self.account('private-backup')
        os.utime(backup, (2000000000, 2000000000))
        with self.assertRaisesRegex(RuntimeError, '^ACCOUNT_SELECTION_REQUIRED$'):
            accounts.select_account(self.root)
        self.assertEqual(accounts.select_account(self.root, self.token(first)), first)
        self.assertEqual(accounts.select_account(self.root, self.token(backup)), backup)

    def test_inventory_never_exposes_paths_names_or_contents(self):
        self.account('private-identifying-active')
        backup = self.account('private-identifying-backup')
        inventory = accounts.inventory_accounts(self.root)
        serialized = json.dumps(inventory)
        for prohibited in (str(self.root), 'private-identifying', 'fictional-encrypted-data',
                           'chatListInfo', 'chat_data'):
            self.assertNotIn(prohibited, serialized)
        self.assertEqual(set(inventory[0]), {'account_token', 'backup_name_hint',
                                           'database_bytes', 'database_modified_at'})
        by_token = {item['account_token']: item for item in inventory}
        self.assertTrue(by_token[self.token(backup)]['backup_name_hint'])
        self.assertEqual(inventory[0]['database_bytes'], len(b'fictional-encrypted-data'))

    def test_invalid_tokens_fail_before_any_inventory(self):
        for token in ('', 'a' * 63, 'a' * 65, 'A' * 64, 'g' * 64,
                      'a' * 64 + '\n', '../private', 123, b'a' * 64):
            with self.subTest(token=token), patch.object(accounts, '_scan') as scan:
                with self.assertRaisesRegex(RuntimeError, '^ACCOUNT_TOKEN_INVALID$'):
                    accounts.select_account(self.root, token)
                scan.assert_not_called()

    def test_unknown_full_token_is_not_an_implicit_default(self):
        self.account('only-private-account')
        with self.assertRaisesRegex(RuntimeError, '^ACCOUNT_TOKEN_NOT_FOUND$'):
            accounts.select_account(self.root, '0' * 64)

    def test_empty_inventory_and_selection_error(self):
        self.assertEqual(accounts.inventory_accounts(self.root), [])
        with self.assertRaisesRegex(RuntimeError, '^ACCOUNT_NOT_FOUND$'):
            accounts.select_account(self.root)

    def test_extra_files_and_unrelated_directories_are_not_accounts(self):
        selected = self.account('private-account')
        (self.root / 'unrelated').mkdir()
        (self.root / 'unrelated' / 'secret.txt').write_text('private content')
        (self.root / 'appstate').write_text('private content')
        (self.root / 'incomplete' / 'chat_data').mkdir(parents=True)
        self.assertEqual(accounts.select_account(self.root), selected)
        self.assertEqual(len(accounts.inventory_accounts(self.root)), 1)

    def test_contents_are_never_opened_or_read(self):
        selected = self.account('private-account')
        with patch('builtins.open', side_effect=AssertionError('content open')), \
             patch.object(Path, 'open', side_effect=AssertionError('content open')), \
             patch('os.open', side_effect=AssertionError('content open')):
            self.assertEqual(accounts.select_account(self.root), selected)
            self.assertEqual(len(accounts.inventory_accounts(self.root)), 1)

    def test_symlink_accounts_are_rejected(self):
        selected = self.account('private-account')
        self.symlink(self.root / 'alias', selected, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, '^ACCOUNT_UNSAFE_PATH$'):
            accounts.inventory_accounts(self.root)

    def test_symlink_root_ancestor_is_rejected(self):
        alias = self.root.parent / 'alias'
        self.symlink(alias, self.root, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, '^ACCOUNT_UNSAFE_PATH$'):
            accounts.select_account(alias)

    def test_symlink_database_or_data_directory_is_rejected(self):
        for component in ('chat_data', 'chatListInfo.edb'):
            with self.subTest(component=component):
                selected = self.account(component)
                target = selected / 'chat_data'
                if component.endswith('.edb'):
                    target /= component
                moved = target.with_name(target.name + '-original')
                target.rename(moved)
                self.symlink(target, moved, target_is_directory=component == 'chat_data')
                with self.assertRaisesRegex(RuntimeError, '^ACCOUNT_UNSAFE_PATH$'):
                    accounts.select_account(self.root)
                target.unlink()
                moved.rename(target)

    def test_windows_reparse_points_are_rejected_without_resolving(self):
        selected = self.account('private-account')
        original = Path.lstat
        def marked(path):
            value = original(path)
            if path == selected:
                return SimpleNamespace(st_mode=value.st_mode, st_file_attributes=0x400)
            return value
        with patch.object(Path, 'lstat', marked):
            with self.assertRaisesRegex(RuntimeError, '^ACCOUNT_UNSAFE_PATH$'):
                accounts.select_account(self.root)

    def test_non_directory_root_and_invalid_layout_are_rejected(self):
        plain = self.root / 'plain'
        plain.write_text('not a directory')
        with self.assertRaisesRegex(RuntimeError, '^ACCOUNT_ROOT_NOT_DIRECTORY$'):
            accounts.select_account(plain)
        (self.root / 'broken').mkdir()
        (self.root / 'broken' / 'chat_data').write_text('not a directory')
        with self.assertRaisesRegex(RuntimeError, '^ACCOUNT_LAYOUT_INVALID$'):
            accounts.select_account(self.root)

    def test_database_must_be_regular_file(self):
        (self.root / 'broken' / 'chat_data' / 'chatListInfo.edb').mkdir(parents=True)
        with self.assertRaisesRegex(RuntimeError, '^ACCOUNT_LAYOUT_INVALID$'):
            accounts.select_account(self.root)

    def test_parent_traversal_and_relative_roots_are_rejected(self):
        for root in (Path('users'), self.root / '..' / 'users'):
            with self.subTest(root=root):
                with self.assertRaisesRegex(RuntimeError, '^ACCOUNT_ROOT_INVALID$'):
                    accounts.select_account(root)

    def test_resolved_candidate_cannot_escape_the_users_root(self):
        selected = self.account('private-account')
        original = Path.resolve
        def escaping(path, **kwargs):
            if path == selected:
                return self.root.parent / 'outside'
            return original(path, **kwargs)
        with patch.object(Path, 'resolve', escaping):
            with self.assertRaisesRegex(RuntimeError, '^ACCOUNT_UNSAFE_PATH$'):
                accounts.select_account(self.root)

    def test_account_set_change_between_scans_is_rejected(self):
        selected = self.account('private-account')
        original = accounts._scan
        calls = []
        def changing(root):
            result = original(root)
            calls.append(1)
            if len(calls) == 1:
                self.account('new-private-account')
            return result
        with patch.object(accounts, '_scan', changing):
            with self.assertRaisesRegex(RuntimeError, '^ACCOUNT_SET_CHANGED$'):
                accounts.select_account(self.root, self.token(selected))
        self.assertEqual(len(calls), 2)

    def test_database_identity_replacement_between_scans_is_rejected(self):
        selected = self.account('private-account')
        original = accounts._scan
        calls = []
        def changing(root):
            result = original(root)
            calls.append(1)
            if len(calls) == 1:
                database = selected / 'chat_data' / 'chatListInfo.edb'
                replacement = selected / 'replacement'
                replacement.write_bytes(b'replacement')
                replacement.replace(database)
            return result
        with patch.object(accounts, '_scan', changing):
            with self.assertRaisesRegex(RuntimeError, '^ACCOUNT_SET_CHANGED$'):
                accounts.select_account(self.root)

    def test_root_replacement_between_scans_is_rejected(self):
        self.account('private-account')
        original = accounts._scan
        calls = []
        def changing(root):
            result = original(root)
            calls.append(1)
            if len(calls) == 1:
                self.root.rename(self.root.with_name('old-root'))
                self.root.mkdir()
                self.account('private-account')
            return result
        with patch.object(accounts, '_scan', changing):
            with self.assertRaisesRegex(RuntimeError, '^ACCOUNT_SET_CHANGED$'):
                accounts.select_account(self.root)

    def test_ordinary_database_content_update_does_not_reselect_account(self):
        selected = self.account('private-account')
        original = accounts._scan
        calls = []
        def changing(root):
            result = original(root)
            calls.append(1)
            if len(calls) == 1:
                (selected / 'chat_data' / 'chatListInfo.edb').write_bytes(b'new bytes')
            return result
        with patch.object(accounts, '_scan', changing):
            self.assertEqual(accounts.select_account(self.root), selected)

    def test_root_entry_limit_stops_scanning_at_bound(self):
        for index in range(5):
            (self.root / str(index)).mkdir()
        original = accounts._inspect
        seen = []
        def counted(path, **kwargs):
            if path.parent == self.root:
                seen.append(path)
            return original(path, **kwargs)
        with patch.object(accounts, 'MAX_ROOT_ENTRIES', 3), \
             patch.object(accounts, '_inspect', counted):
            with self.assertRaisesRegex(RuntimeError, '^ACCOUNT_INVENTORY_LIMIT$'):
                accounts.inventory_accounts(self.root)
        self.assertEqual(len(seen), 3)

    def test_candidate_limit_rejects_instead_of_truncating(self):
        self.account('one')
        self.account('two')
        with patch.object(accounts, 'MAX_ACCOUNTS', 1):
            with self.assertRaisesRegex(RuntimeError, '^ACCOUNT_INVENTORY_LIMIT$'):
                accounts.select_account(self.root)

    def test_each_request_performs_only_two_shallow_scans(self):
        self.account('one')
        original = os.scandir
        with patch.object(os, 'scandir', wraps=original) as scan:
            accounts.select_account(self.root)
        self.assertEqual(scan.call_count, 2)
        self.assertTrue(all(call.args == (self.root,) for call in scan.call_args_list))

    def test_selection_lease_captures_identities_inside_existing_two_scans(self):
        selected = self.account('one')
        original = accounts._stable_accounts
        def changed_after_selection(root):
            result = original(root)
            selected.rename(selected.with_name('old-account'))
            self.account('one')
            return result
        with patch.object(accounts, '_stable_accounts', changed_after_selection):
            with self.assertRaisesRegex(RuntimeError, '^ACCOUNT_SCOPE_CHANGED$'):
                accounts.select_account_lease(self.root)

    def test_selection_lease_does_not_read_contents_or_rescan(self):
        selected = self.account('one')
        original = os.scandir
        with patch.object(os, 'scandir', wraps=original) as scan, \
             patch('builtins.open', side_effect=AssertionError('content open')), \
             patch.object(Path, 'open', side_effect=AssertionError('content open')), \
             patch('os.open', side_effect=AssertionError('content open')):
            path, lease = accounts.select_account_lease(self.root)
            lease.guard()
        self.assertEqual(path, selected)
        self.assertEqual(scan.call_count, 2)

    def test_casefold_token_collision_never_selects_a_candidate(self):
        self.account('one')
        self.account('two')
        digest = SimpleNamespace(hexdigest=lambda: 'a' * 64)
        with patch.object(hashlib, 'sha256', return_value=digest):
            with self.assertRaisesRegex(RuntimeError, '^ACCOUNT_TOKEN_NOT_UNIQUE$'):
                accounts.select_account(self.root, 'a' * 64)

    def test_os_errors_do_not_expose_private_paths(self):
        with patch.object(os, 'scandir', side_effect=PermissionError('private-sensitive-path')):
            with self.assertRaisesRegex(RuntimeError, '^ACCOUNT_INVENTORY_UNAVAILABLE$') as caught:
                accounts.inventory_accounts(self.root)
        self.assertTrue(caught.exception.__suppress_context__)


if __name__ == '__main__':
    unittest.main()
