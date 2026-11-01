"""Synthetic probe proof and local owner-review tests; no app or network reads."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import marshal
from pathlib import Path
import tempfile
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('owner_windows_probe', ROOT / 'tools/windows_probe.py')
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)
X64 = 'd7781cf275a6f4f23547e8e698005d0e8dbb78e205a34baa2eda3ea158fc64d1'
X86 = '86f384d1694c74a611181e6c88509e8f59eb8d9739ae3d7789711a9355757500'
PINS = {name: hashlib.sha256(name.encode()).hexdigest() for name in probe.MINIMUM_SOURCES}
RID = 'a' * 32


def sample(architecture='x64'):
    execution = {'exit': 0, 'timeout': False, 'elapsed_sec': 3.2,
                 'job_memory_limit': 268435456, 'peak_job_commit_bytes': 64000000,
                 'source_execution': 'verified-source-bytes',
                 'source_manifest_sha256': probe.manifest_digest(PINS)}
    argv = ['messages', '--name', 'FICTIONAL_PRIVATE_ROOM', '--hours', '87600',
            '--limit', '3', '--key-route', 'envelope']
    if architecture == 'x86':
        argv.append('--candidate-x86')
    snapshot = {'authenticated_pages': 9, 'zero_pages': 1, 'snapshot_pages': 10,
                'double_read_verified': True, 'quick_check': 'ok'}
    result = {'status': 'MESSAGES_READ', 'input_calls': 0, 'clipboard_calls': 0,
        'send_calls': 0, 'process_dump_saved': False, 'key_saved': False,
        'plaintext_db_saved': False, 'messages_read_from_selected_room_only': True,
        'server_history_fetched': False, 'source': 'windows-local-cache',
        'connection': {'installation_sha256': X86 if architecture == 'x86' else X64,
                       'app_architecture': architecture, 'pid': 12345,
                       'candidate_only': architecture == 'x86',
                       'image_identity': {'mapped_header_match': True,
                           'identity_scope': 'mapped_pe_headers_only',
                           'mapped_code_hash_verified': False,
                           'target_architecture': architecture,
                           'header_fingerprint_sha256': 'f' * 64,
                           'disk_header_bytes_read': 512, 'mapped_header_bytes_read': 512},
                       'created_at_filetime': '123456789', 'cached_pid_reused': False,
                       'decryption_material_saved': False, 'discovery': 'fresh-process-enumeration'},
        'messages': [{'text': 'FICTIONAL_PRIVATE_BODY_' + str(index), 'text_truncated': False,
                      'sent_at_kst': '2026-11-02T12:34:56+09:00',
                      'author_id': 'FICTIONAL_AUTHOR', 'log_id': str(index + 100)}
                     for index in range(3)],
        'snapshots': [dict(snapshot, kind='room-list'), dict(snapshot, kind='selected-messages')],
        'envelope': {'ikm_container_wrap_integrity': True, 'target_wrap_integrity': True,
                     'target_page_hmac': True, 'unexpected_secret': 'FICTIONAL_SECRET'},
        'app_private_before': 200000000, 'app_private_after': 210000000,
        'process_read_bytes': 10000000, 'elapsed_sec': 2.4,
        'unexpected_private': 'C:\\Users\\FICTIONAL_OWNER\\private-data',
        'room': {'chat_id': 'FICTIONAL_ROOM_ID', 'title': 'FICTIONAL_PRIVATE_ROOM'}}
    return {'request_id': RID, 'request': {'source_sha256': PINS['room_reader.py'],
            'source_hashes': dict(PINS), 'args': argv}, 'source_hashes': dict(PINS),
            'execution': dict(execution), 'outer_execution': dict(execution), 'result': result}


class ProofValidation(unittest.TestCase):
    def test_x64_and_x86_valid_read_remains_pending_until_owner_ack(self):
        for architecture in ('x64', 'x86'):
            with self.subTest(architecture=architecture):
                pending = probe.validate_record(sample(architecture), PINS)
                self.assertEqual(pending['status'], 'READ_VERIFIED_PENDING_OWNER_MATCH')
                self.assertFalse(pending['owner_match_ack'])
                confirmed = probe.validate_record(sample(architecture), PINS, owner_matched=True)
                self.assertEqual(confirmed['status'], 'PASS')
                self.assertEqual(confirmed['message_count'], 3)
                self.assertEqual(confirmed['independent_log_id_comparison'], 'NOT_RUN')
                self.assertFalse(confirmed['stable_eligible'])
                self.assertFalse(confirmed['automatically_promotes_support'])

    def test_allowlisted_proof_excludes_all_private_and_unexpected_fields(self):
        proof = probe.validate_record(sample(), PINS, owner_matched=True)
        raw = json.dumps(proof)
        for text in ('FICTIONAL_', '12345', '123456789', '2026-11-02',
                     'C:\\Users', '"chat_id":', '"author_id":', '"log_id":', 'sent_at_kst'):
            self.assertNotIn(text, raw)
        self.assertEqual(proof['source_hashes'], PINS)
        self.assertTrue(proof['maintainer_review_required'])

    def test_nonzero_or_timeout_never_pass_even_when_status_says_messages_read(self):
        for receipt in ('execution', 'outer_execution'):
            for field, value in (('exit', 2), ('exit', None), ('exit', False),
                                 ('timeout', True), ('timeout', None)):
                with self.subTest(receipt=receipt, field=field, value=value):
                    record = sample(); record[receipt][field] = value
                    with self.assertRaisesRegex(probe.ProbeError, 'PROBE_EXECUTION_FAILED'):
                        probe.validate_record(record, PINS, owner_matched=True)

    def test_missing_either_job_receipt_blocks(self):
        for field in ('execution', 'outer_execution'):
            record = sample(); del record[field]
            with self.assertRaisesRegex(probe.ProbeError, 'PROBE_EXECUTION_FAILED'):
                probe.validate_record(record, PINS)

    def test_both_jobs_must_bind_cache_free_source_execution(self):
        for field in ('execution', 'outer_execution'):
            for key, value in (('source_execution', None), ('source_manifest_sha256', '0' * 64)):
                record = sample(); record[field][key] = value
                with self.assertRaisesRegex(probe.ProbeError, 'PROBE_SOURCE_EXECUTION_NOT_VERIFIED'):
                    probe.validate_record(record, PINS)

    def test_mapped_header_identity_is_bounded_and_never_claims_full_code_hash(self):
        proof = probe.validate_record(sample(), PINS)
        self.assertFalse(proof['image_identity']['mapped_code_hash_verified'])
        self.assertFalse(proof['candidate_only'])
        self.assertTrue(probe.validate_record(sample('x86'), PINS)['candidate_only'])
        for key, value in (('mapped_header_match', False), ('target_architecture', 'x86'),
                ('disk_header_bytes_read', 8193), ('mapped_header_bytes_read', 32769),
                ('mapped_code_hash_verified', True), ('header_fingerprint_sha256', 'PRIVATE')):
            record = sample(); record['result']['connection']['image_identity'][key] = value
            with self.assertRaisesRegex(probe.ProbeError, 'PROBE_IMAGE_IDENTITY_NOT_VERIFIED'):
                probe.validate_record(record, PINS)

    def test_memory_time_and_read_bounds_are_required(self):
        cases = [('execution', 'peak_job_commit_bytes', 0),
                 ('execution', 'peak_job_commit_bytes', 268435457),
                 ('execution', 'job_memory_limit', 512 * 1024 * 1024),
                 ('execution', 'elapsed_sec', 45.001),
                 ('outer_execution', 'elapsed_sec', 50.001),
                 ('outer_execution', 'elapsed_sec', float('nan')),
                 ('result', 'app_private_after', 469893120),
                 ('result', 'app_private_before', -1),
                 ('result', 'process_read_bytes', probe.READ_LIMIT + 1),
                 ('result', 'elapsed_sec', 40.001)]
        for group, key, value in cases:
            with self.subTest(group=group, key=key, value=value):
                record = sample(); record[group][key] = value
                with self.assertRaisesRegex(probe.ProbeError, 'PROBE_RESOURCE_BOUND_FAILED'):
                    probe.validate_record(record, PINS)

    def test_empty_more_than_three_blank_or_truncated_rows_cannot_pass(self):
        records = []
        empty = sample(); empty['result']['messages'] = []; records.append(empty)
        many = sample(); many['result']['messages'] *= 2; records.append(many)
        blank = sample()
        for row in blank['result']['messages']: row['text'] = '   '
        records.append(blank)
        truncated = sample(); truncated['result']['messages'][0]['text_truncated'] = True
        records.append(truncated)
        for record in records:
            with self.assertRaises(probe.ProbeError):
                probe.validate_record(record, PINS, owner_matched=True)

    def test_local_review_requires_valid_original_kst_time(self):
        for stamp in (None, 'FICTIONAL_PRIVATE_VALUE', '2026-11-02T12:34:56+00:00'):
            record = sample(); record['result']['messages'][0]['sent_at_kst'] = stamp
            with self.assertRaisesRegex(probe.ProbeError, 'PROBE_MESSAGE_TIME_INVALID'):
                probe.validate_record(record, PINS)

    def test_known_hash_exact_architecture_and_explicit_candidate_flag_required(self):
        records = []
        unknown = sample(); unknown['result']['connection']['installation_sha256'] = '0' * 64
        records.append(unknown)
        wrong = sample(); wrong['result']['connection']['app_architecture'] = 'x86'
        records.append(wrong)
        missing = sample('x86'); missing['request']['args'].remove('--candidate-x86')
        records.append(missing)
        extra = sample(); extra['request']['args'].append('--candidate-x86'); records.append(extra)
        for record in records:
            with self.assertRaises(probe.ProbeError):
                probe.validate_record(record, PINS)

    def test_every_source_binding_is_exact(self):
        for field in ('top', 'request', 'entry'):
            record = sample()
            if field == 'top': record['source_hashes']['room_reader.py'] = '0' * 64
            elif field == 'request': record['request']['source_hashes']['room_reader.py'] = '0' * 64
            else: record['request']['source_sha256'] = '0' * 64
            with self.assertRaisesRegex(probe.ProbeError, 'PROBE_SOURCE_BINDING_MISMATCH'):
                probe.validate_record(record, PINS)

    def test_request_cannot_expand_scope_or_message_limit(self):
        variants = [lambda a: a.__setitem__(0, 'self'),
            lambda a: a.__setitem__(a.index('--limit') + 1, '100'),
            lambda a: a.__setitem__(a.index('--key-route') + 1, 'codec'),
            lambda a: a.extend(['--after-id', '10']),
            lambda a: a.extend(['--account-token', 'not-a-token']),
            lambda a: a.extend(['--name', 'SECOND_PRIVATE_ROOM'])]
        for mutation in variants:
            record = sample(); mutation(record['request']['args'])
            with self.assertRaisesRegex(probe.ProbeError, 'PROBE_REQUEST_SCOPE_INVALID'):
                probe.validate_record(record, PINS)

    def test_side_effect_fields_cannot_be_missing_true_or_nonzero(self):
        for field in ('input_calls', 'clipboard_calls', 'send_calls', 'process_dump_saved',
                      'key_saved', 'plaintext_db_saved'):
            for value in (None, True, 1):
                record = sample(); record['result'][field] = value
                with self.assertRaisesRegex(probe.ProbeError, 'PROBE_UNEXPECTED_SIDE_EFFECT'):
                    probe.validate_record(record, PINS)

    def test_snapshot_and_envelope_integrity_are_required(self):
        cases = [('double_read_verified', False), ('quick_check', 'corrupt'),
                 ('authenticated_pages', 0), ('snapshot_pages', 11)]
        for key, value in cases:
            record = sample(); record['result']['snapshots'][0][key] = value
            with self.assertRaisesRegex(probe.ProbeError, 'PROBE_SNAPSHOT_PROOF_INVALID'):
                probe.validate_record(record, PINS)
        for key in ('ikm_container_wrap_integrity', 'target_wrap_integrity', 'target_page_hmac'):
            record = sample(); record['result']['envelope'][key] = False
            with self.assertRaisesRegex(probe.ProbeError, 'PROBE_KEY_AUTHENTICATION_MISSING'):
                probe.validate_record(record, PINS)

    def test_safe_reader_failure_is_preserved_but_private_error_is_withheld(self):
        record = sample(); record['execution']['exit'] = 2
        record['result'].update(status='BLOCKED', reason='ACCOUNT_SELECTION_REQUIRED')
        with self.assertRaisesRegex(probe.ProbeError, '^ACCOUNT_SELECTION_REQUIRED$'):
            probe.validate_record(record, PINS)
        record['result']['reason'] = 'C:\\Users\\FICTIONAL_OWNER\\private-room'
        with self.assertRaisesRegex(probe.ProbeError, '^PROBE_READER_BLOCKED$'):
            probe.validate_record(record, PINS)


class LocalFlow(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='kakao-probe-fictional-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.state = self.root / 'receipts'; self.state.mkdir()
        self.proofs = self.root / 'proofs'; self.proofs.mkdir()
        self.record = sample()
        probe._save_unique(self.state / (RID + '.json'), self.record)

    def accept(self):
        record = dict(self.record, receipt_path=str(self.state / (RID + '.json')))
        return probe.accept_record(record, self.state, self.proofs, PINS)

    def test_complete_local_review_confirm_flow_never_runs_reader(self):
        with patch.object(probe, '_runtime', side_effect=AssertionError('NO_APP_CALL')):
            pending, ident, name = self.accept()
            self.assertEqual(pending['status'], 'READ_VERIFIED_PENDING_OWNER_MATCH')
            self.assertNotIn('FICTIONAL_PRIVATE', (self.proofs / name).read_text())
            view = probe.local_review(self.state, ident, PINS)
            self.assertEqual(view['privacy'], 'PRIVATE_LOCAL_REVIEW_DO_NOT_SHARE')
            self.assertEqual(len(view['messages']), 3)
            self.assertIn('FICTIONAL_PRIVATE_BODY', view['messages'][0]['text'])
            proof, final = probe.confirm(self.state, self.proofs, ident, PINS, True)
            self.assertEqual(proof['status'], 'PASS')
            self.assertFalse(proof['stable_eligible'])
            before = (self.proofs / final).read_bytes()
            again, _ = probe.confirm(self.state, self.proofs, ident, PINS, True)
            self.assertEqual(proof, again)
            self.assertEqual(before, (self.proofs / final).read_bytes())
            self.assertNotIn('FICTIONAL_', before.decode())

    def test_confirm_requires_explicit_ack_and_prior_local_review(self):
        self.accept()
        with self.assertRaisesRegex(probe.ProbeError, 'PROBE_OWNER_ACK_REQUIRED'):
            probe.confirm(self.state, self.proofs, RID, PINS, False)
        with self.assertRaisesRegex(probe.ProbeError, 'PROBE_LOCAL_REVIEW_REQUIRED'):
            probe.confirm(self.state, self.proofs, RID, PINS, True)

    def test_private_receipt_change_is_not_accepted_after_read(self):
        self.accept()
        path = self.state / (RID + '.json')
        changed = copy.deepcopy(self.record); changed['result']['messages'][0]['text'] = 'CHANGED'
        path.write_bytes(probe.encoded(changed))
        with self.assertRaisesRegex(probe.ProbeError, 'PROBE_PRIVATE_RECEIPT_CHANGED'):
            probe.local_review(self.state, RID, PINS)

    def test_changed_review_or_confirmed_proof_is_preserved_and_blocked(self):
        self.accept(); probe.local_review(self.state, RID, PINS)
        proof, name = probe.confirm(self.state, self.proofs, RID, PINS, True)
        (self.proofs / name).write_text('{"owner_file":"keep"}')
        with self.assertRaisesRegex(probe.ProbeError, 'PROBE_CONFIRMED_RESULT_CHANGED'):
            probe.confirm(self.state, self.proofs, RID, PINS, True)
        self.assertEqual((self.proofs / name).read_text(), '{"owner_file":"keep"}')

    def test_saved_receipt_must_equal_the_just_returned_result(self):
        different = copy.deepcopy(self.record); different['result']['messages'][0]['text'] = 'CHANGED'
        with self.assertRaisesRegex(probe.ProbeError, 'PROBE_PRIVATE_RECEIPT_CHANGED'):
            probe.accept_record(different, self.state, self.proofs, PINS)

    def test_invalid_request_ids_cannot_escape_private_receipt_directory(self):
        for ident in ('../../secret', 'A' * 32, 'a' * 31, 'a' * 33):
            with self.assertRaisesRegex(probe.ProbeError, 'PROBE_REQUEST_ID_INVALID'):
                probe.local_review(self.state, ident, PINS)

    def test_existing_results_and_duplicate_json_are_never_overwritten(self):
        path = self.proofs / 'saved.json'; path.write_text('owner file')
        with self.assertRaisesRegex(probe.ProbeError, 'PROBE_RESULT_ALREADY_EXISTS'):
            probe._save_unique(path, {'new': True})
        self.assertEqual(path.read_text(), 'owner file')
        for raw in (b'{"status":1,"status":2}', b'{"bad":NaN}'):
            with self.assertRaisesRegex(probe.ProbeError, 'PROBE_JSON_INVALID'):
                probe._parse(raw)

    def test_symlink_receipt_is_rejected(self):
        link = self.state / ('b' * 32 + '.json')
        try:
            link.symlink_to(self.state / (RID + '.json'))
        except (OSError, NotImplementedError):
            self.skipTest('Symlink creation is unavailable for this synthetic test user')
        with self.assertRaisesRegex(probe.ProbeError, 'PROBE_UNSAFE_PATH'):
            probe._load(link)

    def test_source_pins_fail_closed_and_changed_or_extra_source_is_rejected(self):
        runtime = self.root / 'runtime'; runtime.mkdir()
        pins = {}
        for name in PINS:
            data = ('# fictional ' + name + '\n').encode(); (runtime / name).write_bytes(data)
            pins[name] = hashlib.sha256(data).hexdigest()
        with patch.object(probe, 'RUNTIME', runtime), patch.object(probe, 'EXPECTED_SOURCE_HASHES', {}):
            with self.assertRaisesRegex(probe.ProbeError, 'PROBE_SOURCE_PINS_MISSING'):
                probe.source_hashes()
        with patch.object(probe, 'RUNTIME', runtime), patch.object(probe, 'EXPECTED_SOURCE_HASHES', pins):
            self.assertEqual(probe.source_hashes(), pins)
            (runtime / 'room_reader.py').write_text('# local modification')
            with self.assertRaisesRegex(probe.ProbeError, 'PROBE_SOURCE_CHANGED'):
                probe.source_hashes()
            (runtime / 'unexpected.py').write_text('# unknown module')
            with self.assertRaisesRegex(probe.ProbeError, 'PROBE_SOURCE_SET_MISMATCH'):
                probe.source_hashes()

    def test_pinned_loader_ignores_valid_timestamp_pyc_and_executes_verified_source(self):
        source = self.root / 'fictional_source.py'
        data = b'VALUE = "PINNED_SOURCE"\n'; source.write_bytes(data)
        cache = Path(importlib.util.cache_from_source(str(source)))
        cache.parent.mkdir()
        code = compile('VALUE = "UNPINNED_BYTECODE"', str(source), 'exec')
        header = importlib.util.MAGIC_NUMBER + struct.pack('<III', 0,
            int(source.stat().st_mtime) & 0xffffffff, len(data))
        cache.write_bytes(header + marshal.dumps(code))
        # Establish that this fixture really would be accepted by Python's
        # ordinary cached loader; neither module has any external side effects.
        ordinary = importlib.util.spec_from_file_location('fictional_cache_control', source)
        cached = importlib.util.module_from_spec(ordinary); ordinary.loader.exec_module(cached)
        self.assertEqual(cached.VALUE, 'UNPINNED_BYTECODE')
        loader = probe.PinnedSourceLoader('fictional_pinned_source', source, hashlib.sha256(data).hexdigest())
        spec = importlib.util.spec_from_file_location('fictional_pinned_source', source, loader=loader)
        actual = importlib.util.module_from_spec(spec); spec.loader.exec_module(actual)
        self.assertEqual(actual.VALUE, 'PINNED_SOURCE')
        source.write_text('VALUE = "CHANGED_SOURCE"\n')
        with self.assertRaisesRegex(probe.ProbeError, 'PROBE_SOURCE_CHANGED'):
            spec.loader.exec_module(actual)

    def test_default_cli_output_contains_proof_only_and_uses_fixed_scope(self):
        module = Mock()
        module.read.return_value = dict(self.record, receipt_path=str(self.state / (RID + '.json')))
        with patch.object(probe, 'source_hashes', return_value=PINS), \
             patch.object(probe, 'private_state', return_value=(self.state, self.proofs)), \
             patch.object(probe, '_runtime', return_value=module), \
             patch.object(probe, 'choose_profile', return_value='x64'), \
             patch.dict('sys.modules', {'reader_queries': SimpleNamespace(query_spec=lambda args: {})}):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(probe.main(['--name', 'FICTIONAL_PRIVATE_ROOM']), 0)
        raw = output.getvalue(); parsed = json.loads(raw)
        self.assertEqual(parsed['proof']['status'], 'READ_VERIFIED_PENDING_OWNER_MATCH')
        self.assertNotIn('FICTIONAL_', raw)
        self.assertNotIn(str(self.root), raw)
        arguments = module.read.call_args.args[0]
        self.assertEqual((arguments.command, arguments.limit, arguments.hours), ('messages', 3, 87600))
        self.assertFalse(arguments.candidate_x86)

    def test_explicit_candidate_cli_passes_choice_to_profile_and_read(self):
        record = sample('x86')
        (self.state / (RID + '.json')).write_bytes(probe.encoded(record))
        module = Mock()
        module.read.return_value = dict(record, receipt_path=str(self.state / (RID + '.json')))
        with patch.object(probe, 'source_hashes', return_value=PINS), \
             patch.object(probe, 'private_state', return_value=(self.state, self.proofs)), \
             patch.object(probe, '_runtime', return_value=module), \
             patch.object(probe, 'choose_profile', return_value='x86') as choose, \
             patch.dict('sys.modules', {'reader_queries': SimpleNamespace(query_spec=lambda args: {})}):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(probe.main(['run', '--candidate-x86', '--name', 'FICTIONAL_PRIVATE_ROOM']), 0)
        choose.assert_called_once_with(module, candidate_requested=True)
        self.assertTrue(module.read.call_args.args[0].candidate_x86)

    def test_run_help_exposes_candidate_choice_without_touching_runtime(self):
        output = io.StringIO()
        with patch.object(probe, 'source_hashes', side_effect=AssertionError('NO_RUNTIME_READ')), \
             contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit) as exited:
                probe.main(['run', '--help'])
        self.assertEqual(exited.exception.code, 0)
        self.assertIn('--candidate-x86', output.getvalue())

    def test_local_review_uses_utf8_for_legacy_or_ascii_redirected_stdio(self):
        message = '가상 한글 대화입니다. 😀'
        self.record['result']['messages'][0]['text'] = message
        (self.state / (RID + '.json')).write_bytes(probe.encoded(self.record))
        self.accept()
        for encoding in ('ascii', 'cp1252', 'cp949'):
            with self.subTest(encoding=encoding):
                out_bytes = io.BytesIO(); err_bytes = io.BytesIO()
                with io.TextIOWrapper(out_bytes, encoding=encoding) as stdout, \
                     io.TextIOWrapper(err_bytes, encoding=encoding) as stderr:
                    with patch.object(probe, 'source_hashes', return_value=PINS), \
                         patch.object(probe, 'private_state', return_value=(self.state, self.proofs)), \
                         contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                        self.assertEqual(probe.main(['review', '--request-id', RID,
                                                     '--show-local-review']), 0)
                        print(json.dumps({'text': message}, ensure_ascii=False), file=stderr)
                    stdout.flush(); stderr.flush()
                    review = json.loads(out_bytes.getvalue().decode('utf8'))
                    diagnostic = json.loads(err_bytes.getvalue().decode('utf8'))
                    self.assertEqual(review['messages'][0]['text'], message)
                    self.assertEqual(diagnostic['text'], message)

    def test_blocked_error_details_cannot_leak_into_proof(self):
        for error in (OSError('C:\\Users\\FICTIONAL_OWNER\\private'),
                      probe.ProbeError('FICTIONAL_PRIVATE_REASON')):
            output = io.StringIO()
            with patch.object(probe, 'source_hashes', side_effect=error), contextlib.redirect_stdout(output):
                self.assertEqual(probe.main(['run', '--name', 'FICTIONAL_PRIVATE_ROOM']), 2)
            self.assertNotIn('FICTIONAL_', output.getvalue())
            self.assertEqual(json.loads(output.getvalue())['proof']['reason'], 'PROBE_INTERNAL_ERROR')

    def test_argument_errors_do_not_echo_private_values_to_stdout_or_stderr(self):
        for argv in (['run', '--name', 'FICTIONAL', 'PRIVATE_ROOM'],
                     ['run', '--unknown', 'FICTIONAL_PRIVATE_TOKEN'],
                     ['confirm', '--request-id', RID]):
            stdout = io.StringIO(); stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(probe.main(argv), 2)
            self.assertEqual(stderr.getvalue(), '')
            self.assertNotIn('FICTIONAL', stdout.getvalue())
            self.assertNotIn('PRIVATE', stdout.getvalue())
            self.assertEqual(json.loads(stdout.getvalue())['proof']['reason'], 'PROBE_ARGUMENTS_INVALID')

    def test_resume_only_fetches_same_request_without_doctor(self):
        module = Mock()
        resumed = dict(self.record, receipt_path=str(self.state / (RID + '.json')))
        module.read.return_value = resumed
        with patch.object(probe, 'source_hashes', return_value=PINS), \
             patch.object(probe, 'private_state', return_value=(self.state, self.proofs)), \
             patch.object(probe, '_runtime', return_value=module), \
             patch.object(probe, 'choose_profile', side_effect=AssertionError('NO_DOCTOR')):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(probe.main(['resume', '--request-id', RID]), 0)
        args = module.read.call_args.args[0]
        self.assertEqual(args.command, 'resume'); self.assertEqual(args.request_id, RID)

    def test_interrupted_pending_proof_publication_recovers_without_reread(self):
        save = probe._save_unique
        def fail_pending(path, value):
            if path.name.endswith('-pending.json'):
                raise OSError('fictional interrupted publication')
            return save(path, value)
        with patch.object(probe, '_save_unique', side_effect=fail_pending):
            with self.assertRaises(OSError):
                self.accept()
        self.assertTrue(probe._binding_path(self.state, RID).exists())
        with patch.object(probe, 'source_hashes', return_value=PINS), \
             patch.object(probe, 'private_state', return_value=(self.state, self.proofs)), \
             patch.object(probe, '_runtime', side_effect=AssertionError('NO_REEXECUTION')):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(probe.main(['resume', '--request-id', RID]), 0)
        self.assertEqual(json.loads(output.getvalue())['proof']['status'], 'READ_VERIFIED_PENDING_OWNER_MATCH')


class ProfileSelection(unittest.TestCase):
    def report(self, architecture, sha):
        return {'installation_sha256': sha, 'app_architecture': architecture,
                'app_version': '26.9.1.5339', 'status': 'READY', 'windows_x64': True}

    def test_x86_uses_second_explicit_candidate_doctor(self):
        report = self.report('x86', X86)
        with patch.object(probe, '_doctor', side_effect=[(2, report), (0, report)]) as doctor:
            self.assertEqual(probe.choose_profile(object()), 'x86')
            self.assertEqual(doctor.call_count, 2)
            self.assertEqual(doctor.call_args.kwargs, {'candidate': True})

    def test_default_x64_choice_is_unchanged(self):
        module = object()
        with patch.object(probe, '_doctor', return_value=(0, self.report('x64', X64))) as doctor:
            self.assertEqual(probe.choose_profile(module), 'x64')
            doctor.assert_called_once_with(module)

    def test_explicit_x86_choice_ignores_other_installed_x64_file(self):
        module = object()
        def doctor_result(_module, candidate=False):
            return (0, self.report('x86', X86) if candidate else self.report('x64', X64))
        with patch.object(probe, '_doctor', side_effect=doctor_result) as doctor:
            self.assertEqual(probe.choose_profile(module, candidate_requested=True), 'x86')
            doctor.assert_called_once_with(module, candidate=True)

    def test_explicit_candidate_rejects_wrong_architecture_or_unknown_hash(self):
        for report in (self.report('x64', X64), self.report('x86', '0' * 64)):
            with self.subTest(report=report), patch.object(probe, '_doctor', return_value=(0, report)) as doctor:
                with self.assertRaises(probe.ProbeError):
                    probe.choose_profile(object(), candidate_requested=True)
                self.assertEqual(doctor.call_count, 1)

    def test_doctor_unknown_hash_or_architecture_mismatch_stays_blocked(self):
        for report in (self.report('x86', '0' * 64), self.report('x86', X64)):
            with patch.object(probe, '_doctor', return_value=(0, report)):
                with self.assertRaises(probe.ProbeError):
                    probe.choose_profile(object())

    def test_x86_app_identity_cannot_change_between_doctor_calls(self):
        with patch.object(probe, '_doctor', side_effect=[(2, self.report('x86', X86)),
                (0, self.report('x64', X64))]):
            with self.assertRaisesRegex(probe.ProbeError, 'PROBE_APP_IDENTITY_CHANGED'):
                probe.choose_profile(object())


if __name__ == '__main__':
    unittest.main()
