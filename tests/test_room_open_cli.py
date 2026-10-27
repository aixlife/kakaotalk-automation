"""Portable command/receipt guards. These tests never open a native app."""
from contextlib import contextmanager
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1] / 'experimental/room-open'
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location('room_open_cli', HERE / 'room_open.py')
CLI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLI)


@contextmanager
def unlocked(path):
    yield


class PortableGuards(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.addCleanup(self.temporary.cleanup)

    def receipt(self, age=0):
        stem = 'room-' + '1' * 32
        image = b'BM synthetic private image fixture'
        (self.root / (stem + '-search.bmp')).write_bytes(image)
        snapshot = dict(pid=12, created_at_filetime='123', captured_epoch=time.time() - age,
                        query='Example discussion',
                        capture={'status': 'CAPTURED', 'filename': stem + '-search.bmp',
                                 'sha256': hashlib.sha256(image).hexdigest(), 'bounds': [1, 2, 100, 200]},
                        **{name: {'hwnd': n, 'rect': [1, 2, 100, 200], 'class': name, 'control_id': n}
                           for n, name in enumerate(('main', 'chat_list', 'edit', 'search_list'), 1)})
        record = {'schema': CLI.SCHEMA, 'command': 'search', 'status': 'SEARCHED',
                  'execution': {'exit': 0, 'timeout': False}, 'source_hashes': {'source': 'digest'},
                  'result': {'status': 'SEARCHED', 'foreground_restored': True,
                             'cursor_restored': True, 'snapshot': snapshot}}
        path = self.root / (stem + '-receipt.json')
        path.write_text(json.dumps(record), encoding='utf8')
        return path, record

    def test_open_loads_only_successful_retained_capture(self):
        path, record = self.receipt()
        with patch.object(CLI, 'sources', return_value={'source': 'digest'}):
            target, snapshot = CLI.search_snapshot(path, self.root)
            self.assertEqual(target, 'Example discussion')
            self.assertEqual(snapshot, record['result']['snapshot'])
            for change in ({'status': 'BLOCKED'}, {'command': 'open'}, {'schema': 'other'},
                           {'execution': {'exit': 2, 'timeout': False}},
                           {'execution': {'exit': 0, 'timeout': True}}):
                path.write_text(json.dumps(dict(record, **change)), encoding='utf8')
                with self.assertRaises(RuntimeError):
                    CLI.search_snapshot(path, self.root)

    def test_no_open_after_failed_restoration(self):
        path, record = self.receipt()
        for flag in ('foreground_restored', 'cursor_restored'):
            failed = copy.deepcopy(record)
            failed['result'][flag] = False
            path.write_text(json.dumps(failed), encoding='utf8')
            with patch.object(CLI, 'sources', return_value={'source': 'digest'}):
                with self.assertRaisesRegex(RuntimeError, 'SEARCH_EXECUTION_NOT_VERIFIED'):
                    CLI.search_snapshot(path, self.root)

    def test_expired_or_changed_capture_or_source_blocks(self):
        path, record = self.receipt(age=301)
        with patch.object(CLI, 'sources', return_value={'source': 'digest'}):
            with self.assertRaisesRegex(RuntimeError, 'SNAPSHOT_EXPIRED'):
                CLI.search_snapshot(path, self.root)
        record['result']['snapshot']['captured_epoch'] = time.time()
        path.write_text(json.dumps(record), encoding='utf8')
        with patch.object(CLI, 'sources', return_value={'source': 'changed'}):
            with self.assertRaisesRegex(RuntimeError, 'SOURCE_CHANGED_AFTER_SEARCH'):
                CLI.search_snapshot(path, self.root)
        (self.root / record['result']['snapshot']['capture']['filename']).write_bytes(b'changed')
        with self.assertRaisesRegex(RuntimeError, 'SEARCH_CAPTURE_CHANGED'):
            CLI.search_snapshot(path, self.root)

    def test_capture_paths_and_receipt_locations_are_bound(self):
        path, record = self.receipt()
        record['result']['snapshot']['capture']['filename'] = '../outside.bmp'
        path.write_text(json.dumps(record), encoding='utf8')
        with self.assertRaisesRegex(RuntimeError, 'SEARCH_CAPTURE_REQUIRED'):
            CLI.search_snapshot(path, self.root)
        with self.assertRaisesRegex(RuntimeError, 'PRIVATE_RECORD_INVALID'):
            CLI.read(path, self.root / 'different')

    def test_record_writes_are_exclusive_bounded_and_do_not_overwrite(self):
        path = self.root / 'new.json'
        CLI.write(path, {'status': 'original'})
        with self.assertRaisesRegex(RuntimeError, 'RECORD_ALREADY_EXISTS'):
            CLI.write(path, {'status': 'replacement'})
        self.assertEqual(json.loads(path.read_text())['status'], 'original')
        with self.assertRaisesRegex(RuntimeError, 'RECORD_SIZE_LIMIT'):
            CLI.write(self.root / 'oversized.json', {'text': 'x' * CLI.MAX_RECORD})
        self.assertFalse((self.root / 'oversized.json').exists())

    def test_redirected_private_file_rejected(self):
        source = self.root / 'actual.json'
        source.write_text('{}')
        link = self.root / 'link.json'
        try:
            link.symlink_to(source)
        except OSError as exc:
            if getattr(exc, 'winerror', None) != 1314:
                raise
            # A normal Windows account cannot create symlinks. Exercise the
            # same rejection from a real file's reparse-point metadata without
            # enabling privileges or weakening the production path check.
            link.write_text('{}', encoding='utf8')
            original = Path.lstat
            def redirected(path):
                info = original(path)
                return types.SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400) if path == link else info
            with patch.object(Path, 'lstat', redirected):
                with self.assertRaisesRegex(RuntimeError, 'PRIVATE_PATH_REDIRECTED'):
                    CLI.read(link, self.root)
            return
        with self.assertRaisesRegex(RuntimeError, 'PRIVATE_PATH_REDIRECTED'):
            CLI.read(link, self.root)

    def test_ui_flags_checked_before_state_or_native_access(self):
        for args, reason in [(['search', '--name', 'Example'], 'UI_CONSENT_REQUIRED'),
                             (['open', '--search-receipt', 'ignored', '--point', '1', '2',
                               '--allow-ui'], 'ROW_NOT_VERIFIED')]:
            with patch.object(CLI, 'state_paths') as state, patch('sys.stdout', new_callable=io.StringIO) as output:
                self.assertEqual(CLI.main(args), 2)
                state.assert_not_called()
                self.assertEqual(json.loads(output.getvalue())['reason'], reason)

    def test_check_request_has_no_ui_permission(self):
        args = CLI.parser().parse_args(['check', '--name', 'Example', '--check-preview'])
        request = CLI.request_for(args, self.root)
        self.assertEqual(request, {'action': 'surface', 'allow_ui': False,
                                  'target': 'Example', 'check': True, 'check_preview': True})

    def test_timeout_persists_unknown_outcome_without_retry(self):
        args = CLI.parser().parse_args(['search', '--name', 'Example', '--allow-ui'])
        calls = []
        def runner(argv, output, seconds):
            calls.append((argv, output, seconds))
            output.write_text('partial')
            return {'exit': 124, 'timeout': True}
        with patch.object(CLI, 'serial_lock', unlocked), patch.object(CLI, 'sources', return_value={}):
            result = CLI.run_command(args, self.root, self.root / 'lock', runner=runner)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][2], 17)
        self.assertEqual(result['status'], 'UI_OUTCOME_UNKNOWN_NO_RETRY')
        self.assertFalse(result['automatic_retry_allowed'])
        self.assertFalse(result['send_ready'])
        self.assertEqual(CLI.read(Path(result['receipt_path']), self.root), result)
        self.assertEqual(len(list(self.root.glob('*-request.json'))), 1)

    def test_worker_failure_and_bad_output_still_saved(self):
        args = CLI.parser().parse_args(['inspect'])
        def failure(argv, output, seconds):
            raise RuntimeError('JOB_ASSIGN_FAILED')
        with patch.object(CLI, 'serial_lock', unlocked), patch.object(CLI, 'sources', return_value={}):
            result = CLI.run_command(args, self.root, self.root / 'lock', runner=failure)
        self.assertEqual(result['status'], 'INSPECTION_INCOMPLETE')
        self.assertEqual(result['reason'], 'JOB_ASSIGN_FAILED')
        self.assertTrue(Path(result['receipt_path']).is_file())

    def test_complete_worker_receipt_is_retained(self):
        args = CLI.parser().parse_args(['check', '--name', 'Example'])
        def runner(argv, output, seconds):
            output.write_text(json.dumps({'status': 'PRE_SEND_SURFACE_CHECKED',
                                         'send_ready': False, 'actual_send': 'NOT_RUN', 'actual_sends': 0}))
            return {'exit': 0, 'timeout': False}
        with patch.object(CLI, 'serial_lock', unlocked), patch.object(CLI, 'sources', return_value={}):
            result = CLI.run_command(args, self.root, self.root / 'lock', runner=runner)
        self.assertEqual(result['status'], 'PRE_SEND_SURFACE_CHECKED')
        self.assertEqual(CLI.read(Path(result['receipt_path']), self.root), result)

    def test_same_search_cannot_be_opened_twice_even_after_timeout(self):
        path, record = self.receipt()
        args = CLI.parser().parse_args(['open', '--search-receipt', str(path),
                                       '--point', '10', '20', '--confirm-row', '--allow-ui'])
        calls = []
        def runner(argv, output, seconds):
            calls.append(argv)
            return {'exit': 124, 'timeout': True}
        with patch.object(CLI, 'serial_lock', unlocked), patch.object(CLI, 'sources', return_value={'source': 'digest'}):
            result = CLI.run_command(args, self.root, self.root / 'lock', runner=runner)
            self.assertEqual(result['status'], 'UI_OUTCOME_UNKNOWN_NO_RETRY')
            with self.assertRaisesRegex(RuntimeError, 'SEARCH_ALREADY_CLAIMED_NO_RETRY'):
                CLI.run_command(args, self.root, self.root / 'lock', runner=runner)
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(list(self.root.glob('*-open-claimed.json'))), 1)

    def test_receipt_failure_has_emergency_record_and_is_never_success(self):
        receipt = self.root / ('room-' + '2' * 32 + '-receipt.json')
        record = {'command': 'search', 'status': 'SEARCHED', 'receipt_path': str(receipt)}
        real_write = CLI.write
        def fail_primary(path, value):
            if path == receipt:
                raise OSError('fsync failed')
            real_write(path, value)
        with patch.object(CLI, 'write', fail_primary):
            CLI.save_receipt(receipt, record)
        self.assertEqual(record['status'], 'UI_OUTCOME_UNKNOWN_NO_RETRY')
        self.assertEqual(record['observed_status_before_receipt_failure'], 'SEARCHED')
        self.assertTrue(record['receipt_saved'])
        self.assertEqual(CLI.read(Path(record['receipt_path']), self.root), record)
        with patch.object(CLI, 'write', side_effect=OSError('disk full')):
            CLI.save_receipt(receipt, record)
        self.assertEqual(record['status'], 'UI_OUTCOME_UNKNOWN_NO_RETRY')
        self.assertFalse(record['receipt_saved'])
        self.assertEqual(record['reason'], 'ALL_RECEIPT_SAVES_FAILED')

    def test_fsync_failure_never_publishes_successful_primary_receipt(self):
        path, record = self.receipt()
        path.unlink()  # This test owns the synthetic fixture.
        record['receipt_path'] = str(path)
        real_sync = CLI.os.fsync
        calls = []
        def fail_first_sync(fd):
            calls.append(fd)
            if len(calls) == 1:
                raise OSError('synthetic fsync failure after complete write')
            return real_sync(fd)
        with patch.object(CLI.os, 'fsync', fail_first_sync):
            CLI.save_receipt(path, record)
        self.assertFalse(path.exists())
        self.assertEqual(record['status'], 'UI_OUTCOME_UNKNOWN_NO_RETRY')
        self.assertTrue(record['receipt_saved'])
        self.assertTrue(Path(record['receipt_path']).is_file())
        self.assertEqual(len(list(self.root.glob('*.pending-*'))), 1)
        with self.assertRaisesRegex(RuntimeError, 'PRIVATE_RECORD_INVALID'):
            CLI.search_snapshot(path, self.root)

    def test_shared_lock_releases_and_conflict_never_enters(self):
        events = []
        fake = types.SimpleNamespace(LK_NBLCK=1, LK_UNLCK=2,
                                     locking=lambda fd, action, count: events.append((action, count)))
        path = self.root / 'serial.lock'
        with patch.dict(sys.modules, {'msvcrt': fake}):
            with CLI.serial_lock(path):
                events.append('entered')
        self.assertEqual(events, [(1, 1), 'entered', (2, 1)])
        def denied(*args):
            raise OSError('busy')
        fake.locking = denied
        with patch.dict(sys.modules, {'msvcrt': fake}):
            with self.assertRaisesRegex(RuntimeError, 'ANOTHER_KAKAO_AUTOMATION_RUNNING'):
                with CLI.serial_lock(path):
                    self.fail('must not enter locked region')

    def test_package_sources_and_common_lock_contract(self):
        hashes = CLI.sources()
        self.assertEqual(len(hashes), 13)
        self.assertIn('preview/attachment_runtime_preview.py', hashes)
        self.assertIn('room-open/hybrid_ui_win.py', hashes)
        self.assertTrue(all(len(value) == 64 for value in hashes.values()))
        source = (HERE / 'room_open.py').read_text(encoding='utf8')
        self.assertIn("base / 'self-attachment-qa'", source)
        self.assertIn("lock_parent / 'serial.lock'", source)
        self.assertNotIn('C:\\Users\\', source)


if __name__ == '__main__':
    unittest.main()
