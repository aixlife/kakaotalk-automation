"""Data-only publisher manifest checks: no application data or network."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('reader_release_manifest', ROOT / 'tools/release_manifest.py')
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def rehash_qa(qa):
    """Rebind synthetic proof bytes without fixing their semantic assertions."""
    qa['probe_sha256'] = digest(release.canonical_bytes(qa['probe']))
    qa['promotion']['probe_sha256'] = qa['probe_sha256']
    return qa


def qa_fixture(sources, app, report_sha256, *, method='independent-local-source'):
    """Body-free synthetic test data; never evidence of a real read or approval."""
    owner = method == 'owner-visible-text-time'
    source_sha = release.file_manifest_sha(sources)
    job = {'exit': 0, 'timeout': False, 'job_memory_limit': 268435456,
           'peak_job_commit_bytes': 1048576, 'elapsed_sec': 0.05,
           'source_execution': 'verified-source-bytes', 'source_manifest_sha256': source_sha}
    probe = {
        'schema': 'windows-kakao-reader-probe/v1',
        'status': 'PASS' if owner else 'READ_VERIFIED_PENDING_OWNER_MATCH',
        'capability': 'reader-only', 'stable_eligible': False,
        'maintainer_review_required': True, 'automatically_promotes_support': False,
        'candidate_only': False,
        'app': {'sha256': app['app_sha256'], 'architecture': app['architecture'], 'version': app['version']},
        'image_identity': {'mapped_header_match': True, 'identity_scope': 'mapped_pe_headers_only',
                           'mapped_code_hash_verified': False, 'target_architecture': app['architecture'],
                           'fingerprint_sha256': 'd' * 64},
        'source_verification': 'PINNED_RELEASE_FILES', 'source_hashes': dict(sources),
        'source_manifest_sha256': source_sha, 'message_count': 3,
        'owner_match_ack': owner,
        'owner_match_method': 'manual_original_text_and_time' if owner else 'NOT_RUN',
        'independent_log_id_comparison': 'NOT_RUN',
        'execution': {'inner': dict(job), 'outer': dict(job)},
        'snapshots': [{'kind': kind, 'snapshot_pages': 10, 'authenticated_pages': 10,
                       'zero_pages': 0, 'double_read_verified': True, 'quick_check': 'ok'}
                      for kind in ('room-list', 'selected-messages')],
        'resource_observations': {'app_private_before': 52428800, 'app_private_after': 52428800,
                                  'process_read_bytes': 65536, 'elapsed_sec': 0.05},
        'safety': {'input_calls': 0, 'clipboard_calls': 0, 'send_calls': 0,
                   'process_dump_saved': False, 'key_saved': False, 'plaintext_db_saved': False,
                   'server_history_fetched': False},
        'authentication': {'ikm_wrap': True, 'selected_key_wrap': True, 'selected_page_hmac': True},
        'contains_chat_content': False, 'contains_account_or_room_identifiers': False,
    }
    return rehash_qa({'probe': probe, 'probe_sha256': '', 'promotion': {
        'schema': 1, 'maintainer_approved': True, 'comparison_method': method,
        'message_count': 3, 'id_matches': None if owner else 3, 'text_matches': 3,
        'time_matches': 3 if owner else None, 'probe_sha256': '', 'report_sha256': report_sha256,
        'source_manifest_sha256': source_sha}})


def fixture():
    files = {'LICENSE': digest(b'license'), 'SKILL.md': digest(b'skill')}
    files.update({'scripts/windows/' + name: digest(name.encode()) for name in release.RUNTIME})
    sources = {name.rsplit('/', 1)[1]: value for name, value in files.items() if name.endswith('.py')}
    app = {'architecture': 'x64', 'app_sha256': 'c' * 64, 'version': '26.9.1.5339'}
    app['qa'] = qa_fixture(sources, app, 'b' * 64)
    return {'schema': 1, 'manager_revision': 1, 'channel': 'stable', 'sequence': 1,
        'tag': 'v0.4.0', 'commit': 'a' * 40, 'capability': 'reader-only', 'files': files,
        'manifest_sha256': release.file_manifest_sha(files),
        'report': {'path': 'docs/qa.md', 'sha256': 'b' * 64},
        'compatible_apps': [app]}


class ManifestTests(unittest.TestCase):
    def test_both_jobs_require_the_exact_verified_source_execution_binding(self):
        for job in ('inner','outer'):
            for key in ('source_execution','source_manifest_sha256'):
                for operation in ('missing','none','mismatch'):
                    with self.subTest(job=job,key=key,operation=operation):
                        value = fixture()
                        qa = value['compatible_apps'][0]['qa']
                        record = qa['probe']['execution'][job]
                        if operation == 'missing':
                            del record[key]
                        else:
                            record[key] = None if operation == 'none' else ('0'*64 if key.endswith('sha256') else 'bytecode-cache')
                        rehash_qa(qa)
                        with self.assertRaises(release.ManifestError):
                            release.validate_manifest(value)

    def test_actual_probe_producer_output_is_consumed_without_dropping_auth_fields(self):
        # Invoke only the data-only producer validator on its synthetic receipt.
        # No runtime import, process, app, DB, or network action is performed.
        from test_windows_probe import probe, sample
        value = fixture()
        sources = value['compatible_apps'][0]['qa']['probe']['source_hashes']
        record = sample()
        record['source_hashes'] = dict(sources)
        record['request']['source_hashes'] = dict(sources)
        record['request']['source_sha256'] = sources['room_reader.py']
        for job in ('execution','outer_execution'):
            record[job]['source_manifest_sha256'] = release.file_manifest_sha(sources)
        produced = probe.validate_record(record,sources)
        app = {'architecture':produced['app']['architecture'],
               'app_sha256':produced['app']['sha256'],'version':produced['app']['version']}
        app['qa'] = qa_fixture(sources,app,value['report']['sha256'])
        app['qa']['probe'] = produced
        rehash_qa(app['qa'])
        value['compatible_apps'] = [app]
        parsed = release.validate_manifest(value)
        self.assertEqual(parsed['compatible_apps'][0]['qa']['probe'],produced)
        for job in ('inner','outer'):
            self.assertEqual(len(produced['execution'][job]),7)
            self.assertEqual(produced['execution'][job]['source_execution'],'verified-source-bytes')

    def test_committed_v04_actual_sanitized_proof_matches_consumer_schema(self):
        # This archived proof remains bound to its own source map, not whatever
        # newer runtime happens to be checked out when this regression runs.
        raw = (ROOT/'docs/qa-windows-v0.4.0-proof.json').read_bytes()
        proof = json.loads(raw)
        app = {'architecture':proof['app']['architecture'],
               'app_sha256':proof['app']['sha256'],'version':proof['app']['version']}
        release._probe(proof,proof['source_hashes'],app)
        self.assertEqual(proof['source_manifest_sha256'],release.file_manifest_sha(proof['source_hashes']))
        self.assertEqual((ROOT/'docs/qa-windows-v0.4.0-proof.json').read_bytes(),raw)

    def test_valid_roundtrip_canonical_and_copy_isolation(self):
        value = fixture()
        parsed = release.parse_manifest(release.canonical_bytes(value))
        self.assertEqual(parsed, value)
        parsed['compatible_apps'][0]['qa']['probe']['source_hashes'].clear()
        self.assertTrue(value['compatible_apps'][0]['qa']['probe']['source_hashes'])
        self.assertEqual(release.canonical_bytes({'b': 1, 'a': '한글'}),
                         '{"a":"한글","b":1}'.encode())

    def test_unknown_fields_rejected_at_every_schema_level(self):
        for level in ('root', 'report', 'app', 'qa', 'probe', 'probe-app', 'execution', 'inner',
                      'outer', 'snapshot', 'resources', 'safety', 'authentication', 'image', 'promotion'):
            with self.subTest(level=level):
                value = fixture()
                qa = value['compatible_apps'][0]['qa']
                probe = qa['probe']
                targets = {'root': value, 'report': value['report'], 'app': value['compatible_apps'][0],
                    'qa': qa, 'probe': probe, 'probe-app': probe['app'],
                    'execution': probe['execution'],
                    'inner': probe['execution']['inner'], 'outer': probe['execution']['outer'],
                    'snapshot': probe['snapshots'][0], 'resources': probe['resource_observations'],
                    'safety': probe['safety'], 'authentication': probe['authentication'],
                    'image': probe['image_identity'],
                    'promotion': qa['promotion']}
                targets[level]['raw_messages'] = ['private material must not be accepted']
                rehash_qa(qa)
                with self.assertRaises(release.ManifestError):
                    release.validate_manifest(value)

    def test_old_shallow_pass_and_candidate_only_are_never_stable(self):
        value = fixture()
        sources = value['compatible_apps'][0]['qa']['probe']['source_hashes']
        value['compatible_apps'][0]['qa'] = {
            'status': 'PASS', 'source_hashes': sources, 'message_count': 3,
            'id_matches': 3, 'text_matches': 3, 'exit_code': 0, 'timeout': False,
            'input_calls': 0, 'clipboard_calls': 0, 'process_dump_saved': False,
            'key_saved': False, 'plaintext_db_saved': False}
        with self.assertRaises(release.ManifestError):
            release.validate_manifest(value)
        value = fixture()
        app = value['compatible_apps'][0]
        app['architecture'] = 'x86'
        app['qa']['probe']['app']['architecture'] = 'x86'
        app['qa']['probe']['image_identity']['target_architecture'] = 'x86'
        app['qa']['probe']['candidate_only'] = True
        rehash_qa(app['qa'])
        with self.assertRaises(release.ManifestError):
            release.validate_manifest(value)

    def test_probe_nonempty_scope_and_approval_are_explicit(self):
        for field, bad in (('message_count', 0), ('message_count', 4), ('message_count', True),
                ('schema', 'windows-kakao-reader-probe/v0'), ('status', 'NOT_RUN'),
                ('capability', 'send'), ('owner_match_ack', True),
                ('source_verification', 'ASSUMED'),
                ('candidate_only', True), ('candidate_only', 0),
                ('stable_eligible', True), ('maintainer_review_required', False),
                ('automatically_promotes_support', True), ('contains_chat_content', True),
                ('contains_account_or_room_identifiers', True), ('independent_log_id_comparison', 'PASS')):
            with self.subTest(field=field, bad=bad):
                value = fixture()
                qa = value['compatible_apps'][0]['qa']
                qa['probe'][field] = bad
                rehash_qa(qa)
                with self.assertRaises(release.ManifestError):
                    release.validate_manifest(value)

    def test_missing_full_probe_and_promotion_fields_rejected(self):
        original = fixture()
        paths = ((), ('probe',), ('probe', 'app'), ('probe', 'execution'),
                 ('probe', 'execution', 'inner'), ('probe', 'execution', 'outer'),
                 ('probe', 'safety'), ('probe', 'resource_observations'),
                 ('probe', 'authentication'), ('probe', 'image_identity'), ('promotion',))
        for path in paths:
            target = original['compatible_apps'][0]['qa']
            for component in path:
                target = target[component]
            for field in target:
                with self.subTest(path=path, field=field):
                    value = copy.deepcopy(original)
                    qa = value['compatible_apps'][0]['qa']
                    broken = qa
                    for component in path:
                        broken = broken[component]
                    del broken[field]
                    if path and path[0] == 'probe':
                        rehash_qa(qa)
                    with self.assertRaises(release.ManifestError):
                        release.validate_manifest(value)

    def test_both_job_results_and_limits_must_be_valid(self):
        bad_fields = {'exit': [2, False], 'timeout': [True, 0],
                      'job_memory_limit': [268435455, 268435457, 0, True],
                      'peak_job_commit_bytes': [0, 268435457, True],
                      'elapsed_sec': [-1, 51, 10**400, True, float('inf'), float('nan')]}
        for job in ('inner', 'outer'):
            for field, values in bad_fields.items():
                for bad in values:
                    with self.subTest(job=job, field=field, bad=bad):
                        value = fixture()
                        qa = value['compatible_apps'][0]['qa']
                        qa['probe']['execution'][job][field] = bad
                        with self.assertRaises(release.ManifestError):
                            rehash_qa(qa)
                            release.validate_manifest(value)
        value = fixture()
        qa = value['compatible_apps'][0]['qa']
        qa['probe']['execution']['inner']['elapsed_sec'] = 46
        rehash_qa(qa)
        with self.assertRaises(release.ManifestError):
            release.validate_manifest(value)

    def test_all_safety_and_authentication_claims_are_required(self):
        for section, field, bad in (
                *(('safety', field, bad) for field in ('input_calls', 'clipboard_calls', 'send_calls')
                  for bad in (1, False)),
                *(('safety', field, bad) for field in ('process_dump_saved', 'key_saved',
                    'plaintext_db_saved', 'server_history_fetched') for bad in (True, 0)),
                *(('authentication', field, bad) for field in ('ikm_wrap', 'selected_key_wrap',
                    'selected_page_hmac') for bad in (False, 1))):
            with self.subTest(section=section, field=field, bad=bad):
                value = fixture()
                qa = value['compatible_apps'][0]['qa']
                qa['probe'][section][field] = bad
                rehash_qa(qa)
                with self.assertRaises(release.ManifestError):
                    release.validate_manifest(value)

    def test_every_snapshot_requires_authentication_double_read_and_quickcheck(self):
        for index in (0, 1):
            for field, bad in (('kind', 'other'), ('snapshot_pages', 0), ('snapshot_pages', 131073),
                    ('authenticated_pages', 9), ('authenticated_pages', 0), ('zero_pages', 1),
                    ('double_read_verified', False), ('double_read_verified', 1), ('quick_check', 'failed')):
                with self.subTest(index=index, field=field, bad=bad):
                    value = fixture()
                    qa = value['compatible_apps'][0]['qa']
                    qa['probe']['snapshots'][index][field] = bad
                    rehash_qa(qa)
                    with self.assertRaises(release.ManifestError):
                        release.validate_manifest(value)
        for replacement in ([], [fixture()['compatible_apps'][0]['qa']['probe']['snapshots'][0]]):
            value = fixture()
            qa = value['compatible_apps'][0]['qa']
            qa['probe']['snapshots'] = replacement
            rehash_qa(qa)
            with self.assertRaises(release.ManifestError):
                release.validate_manifest(value)

    def test_resource_observations_enforce_actual_read_bounds(self):
        for field, values in {'app_private_before': [0, 469893120, True],
                'app_private_after': [0, 469893120, True], 'process_read_bytes': [0, 402653185, True],
                'elapsed_sec': [-1, 40.1, 10**400, True]}.items():
            for bad in values:
                with self.subTest(field=field, bad=bad):
                    value = fixture()
                    qa = value['compatible_apps'][0]['qa']
                    qa['probe']['resource_observations'][field] = bad
                    rehash_qa(qa)
                    with self.assertRaises(release.ManifestError):
                        release.validate_manifest(value)

    def test_promotion_methods_have_distinct_comparison_and_owner_claims(self):
        for method in ('independent-local-source', 'owner-visible-text-time'):
            value = fixture()
            app = value['compatible_apps'][0]
            app['qa'] = qa_fixture(app['qa']['probe']['source_hashes'], app,
                                   value['report']['sha256'], method=method)
            self.assertEqual(release.validate_manifest(value), value)
            for field, bad in (('maintainer_approved', False), ('maintainer_approved', 1),
                    ('message_count', 2), ('message_count', True), ('text_matches', 2),
                    ('text_matches', True),
                    ('comparison_method', 'assumed'), ('schema', True),
                    ('id_matches', 3 if method == 'owner-visible-text-time' else None),
                    ('time_matches', None if method == 'owner-visible-text-time' else 3)):
                with self.subTest(method=method, field=field):
                    broken = copy.deepcopy(value)
                    broken['compatible_apps'][0]['qa']['promotion'][field] = bad
                    with self.assertRaises(release.ManifestError):
                        release.validate_manifest(broken)
        value = fixture()
        app = value['compatible_apps'][0]
        app['qa'] = qa_fixture(app['qa']['probe']['source_hashes'], app, value['report']['sha256'],
                               method='owner-visible-text-time')
        app['qa']['probe']['owner_match_ack'] = False
        rehash_qa(app['qa'])
        with self.assertRaises(release.ManifestError):
            release.validate_manifest(value)

    def test_probe_hash_and_promotion_bind_probe_report_and_source(self):
        for section, field in (('qa', 'probe_sha256'), ('promotion', 'probe_sha256'),
                               ('promotion', 'report_sha256'), ('promotion', 'source_manifest_sha256')):
            value = fixture()
            qa = value['compatible_apps'][0]['qa']
            target = qa if section == 'qa' else qa[section]
            target[field] = '0' * 64
            with self.subTest(section=section, field=field), self.assertRaises(release.ManifestError):
                release.validate_manifest(value)
        value = fixture()
        value['compatible_apps'][0]['qa']['probe']['resource_observations']['elapsed_sec'] = 0.1
        with self.assertRaises(release.ManifestError):
            release.validate_manifest(value)

    def test_probe_app_identity_must_match_manifest_app(self):
        for field, bad in (('sha256', 'd' * 64), ('architecture', 'x86'), ('version', '26.8.2.5324')):
            value = fixture()
            qa = value['compatible_apps'][0]['qa']
            qa['probe']['app'][field] = bad
            rehash_qa(qa)
            with self.subTest(field=field), self.assertRaises(release.ManifestError):
                release.validate_manifest(value)

    def test_mapped_header_identity_is_required_without_claiming_code_authentication(self):
        for field, bad in (('mapped_header_match', False), ('mapped_header_match', 1),
                ('identity_scope', 'full_image'), ('mapped_code_hash_verified', True),
                ('mapped_code_hash_verified', 0), ('target_architecture', 'x86'),
                ('fingerprint_sha256', ''), ('fingerprint_sha256', 'D' * 64)):
            with self.subTest(field=field, bad=bad):
                value = fixture()
                qa = value['compatible_apps'][0]['qa']
                qa['probe']['image_identity'][field] = bad
                rehash_qa(qa)
                with self.assertRaises(release.ManifestError):
                    release.validate_manifest(value)

    def test_source_hashes_bind_all_runtime_files(self):
        for change in ('missing', 'changed', 'extra', 'new-unbound-file', 'missing-runtime'):
            with self.subTest(change=change):
                value = fixture()
                qa = value['compatible_apps'][0]['qa']
                sources = qa['probe']['source_hashes']
                if change == 'missing':
                    sources.pop('reader_config.py')
                elif change == 'changed':
                    sources['reader_config.py'] = '0' * 64
                elif change == 'extra':
                    sources['unrun.py'] = '0' * 64
                elif change == 'new-unbound-file':
                    value['files']['scripts/windows/new_reader.py'] = '0' * 64
                else:
                    del value['files']['scripts/windows/reader_config.py']
                    del sources['reader_config.py']
                value['manifest_sha256'] = release.file_manifest_sha(value['files'])
                qa['probe']['source_manifest_sha256'] = release.file_manifest_sha(sources)
                qa['promotion']['source_manifest_sha256'] = qa['probe']['source_manifest_sha256']
                rehash_qa(qa)
                with self.assertRaises(release.ManifestError):
                    release.validate_manifest(value)

    def test_missing_fields_and_bad_hashes(self):
        value = fixture()
        for field in value:
            bad = copy.deepcopy(value)
            del bad[field]
            with self.assertRaises(release.ManifestError):
                release.validate_manifest(bad)
        for digest_value in ('', 'A' * 64, '0' * 63, None):
            bad = fixture()
            bad['files']['SKILL.md'] = digest_value
            bad['manifest_sha256'] = release.file_manifest_sha(bad['files'])
            with self.assertRaises(release.ManifestError):
                release.validate_manifest(bad)
        value['manifest_sha256'] = '0' * 64
        with self.assertRaises(release.ManifestError):
            release.validate_manifest(value)

    def test_reject_prerelease_aliases_wrong_capability_and_bool_numbers(self):
        for field, values in {'schema': [True, 2], 'manager_revision': [True, 2],
                'sequence': [True, 0, -1, 1.0, 2**63], 'channel': ['beta'],
                'capability': ['send', 'all'], 'commit': ['main', 'A' * 40, 'a' * 39],
                'tag': ['v1.2.3-rc1', 'latest', 'v01.2.3', 'v1.2.3+build', 'v1.2']}.items():
            for bad in values:
                with self.subTest(field=field, bad=bad):
                    value = fixture()
                    value[field] = bad
                    with self.assertRaises(release.ManifestError):
                        release.validate_manifest(value)

    def test_duplicate_keys_utf8_and_limits(self):
        raw = json.dumps(fixture()).encode()
        samples = [raw.replace(b'"schema": 1', b'"schema": 1, "schema": 1', 1),
                   raw.replace(b'"source_verification": "PINNED_RELEASE_FILES"',
                               b'"source_verification": "PINNED_RELEASE_FILES", "source_verification": "PINNED_RELEASE_FILES"', 1),
                   b'\xff', b'', b'NaN', b'[]', b' ' * (release.MAX_JSON + 1)]
        for bad in samples:
            with self.assertRaises(release.ManifestError):
                release.parse_manifest(bad)
        with self.assertRaises(release.ManifestError):
            release.parse_manifest(raw.decode())

    def test_windows_paths_and_case_aliases(self):
        for name in ('/a', '../a', 'a/../b', 'a//b', 'a\\b', 'C:/a', 'a:stream',
                     'a/CON.txt', 'AUX', 'COM1.py', 'lpt9', 'CONIN$', 'a.', 'a ',
                     'a\x00b', 'a\nb', 'a?.md', 'a/*', './a'):
            with self.subTest(name=name), self.assertRaises(release.ManifestError):
                release.validate_path(name)
        value = fixture()
        value['files']['skill.md'] = '0' * 64
        value['manifest_sha256'] = release.file_manifest_sha(value['files'])
        with self.assertRaisesRegex(release.ManifestError, 'CASE_COLLISION'):
            release.validate_manifest(value)

    def test_app_identity_and_report_restrictions(self):
        for field, values in {'architecture': ['arm64', '32bit'],
                'app_sha256': ['A' * 64, 'x', None],
                'version': ['26.9.1', '26.9.1.5339-beta', '026.9.1.5339', '26.9.1.65536']}.items():
            for bad in values:
                value = fixture()
                value['compatible_apps'][0][field] = bad
                with self.assertRaises(release.ManifestError):
                    release.validate_manifest(value)
        value = fixture()
        value['compatible_apps'].append(copy.deepcopy(value['compatible_apps'][0]))
        with self.assertRaises(release.ManifestError):
            release.validate_manifest(value)
        for path in ('../docs/a.md', 'README.md', 'docs/NUL.md'):
            value = fixture()
            value['report']['path'] = path
            with self.assertRaises(release.ManifestError):
                release.validate_manifest(value)

    def test_generated_files_and_file_directory_aliases_rejected(self):
        for names in (('scripts/windows/frozen.pyc',), ('scripts/windows/__pycache__/x',),
                      ('.DS_Store',), ('references', 'references/guide.md'),
                      ('References/a.md', 'references/b.md')):
            with self.subTest(names=names):
                value = fixture()
                value['files'].update({name: '0' * 64 for name in names})
                value['manifest_sha256'] = release.file_manifest_sha(value['files'])
                with self.assertRaises(release.ManifestError):
                    release.validate_manifest(value)


class RuntimeProfilesTests(unittest.TestCase):
    def setUp(self):
        self.apps = fixture()['compatible_apps']
        self.sha = self.apps[0]['app_sha256']

    def source(self, supported=None, candidates=None, extra=''):
        supported = "{EXPECTED: '26.9.1.5339'}" if supported is None else supported
        candidates = '{}' if candidates is None else candidates
        return ("EXPECTED = '" + self.sha + "'\nREADER_SUPPORTED = " + supported +
                "\nX86_CANDIDATES = " + candidates + '\n' + extra).encode()

    def test_literal_runtime_profiles_are_read_without_execution(self):
        release.validate_runtime_profiles(self.source(extra="raise RuntimeError('must not execute')\n"), self.apps)
        release.validate_runtime_profiles(self.source(supported="{'" + self.sha + "': '26.9.1.5339'}"), self.apps)

    def test_candidate_map_cannot_be_promoted_by_forging_probe_flag(self):
        candidate = "{'" + self.sha + "': '26.9.1.5339'}"
        for supported in ('{}', "{EXPECTED: '26.9.1.5339'}"):
            with self.subTest(supported=supported), self.assertRaises(release.ManifestError):
                release.validate_runtime_profiles(self.source(supported=supported, candidates=candidate), self.apps)

    def test_unreviewed_hash_and_wrong_version_are_rejected(self):
        for supported in ("{'" + 'e' * 64 + "': '26.9.1.5339'}", "{EXPECTED: '26.8.2.5324'}"):
            with self.subTest(supported=supported), self.assertRaises(release.ManifestError):
                release.validate_runtime_profiles(self.source(supported=supported), self.apps)

    def test_dynamic_duplicate_and_unpack_profile_expressions_rejected(self):
        sources = [self.source(supported="dict([(EXPECTED, '26.9.1.5339')])"),
                   self.source(supported="{EXPECTED: version()}"),
                   self.source(supported="{OTHER: '26.9.1.5339'}"),
                   self.source(supported="{**{'" + self.sha + "': '26.9.1.5339'}}"),
                   self.source(supported="{EXPECTED: '26.9.1.5339', EXPECTED: '26.9.1.5339'}"),
                   self.source(extra="READER_SUPPORTED = {EXPECTED: '26.9.1.5339'}\n"),
                   self.source(candidates='dict()'), b'\xff', b'not python(']
        for source in sources:
            with self.subTest(source=source[:80]), self.assertRaises(release.ManifestError):
                release.validate_runtime_profiles(source, self.apps)

    def test_policy_reassignment_subscript_and_mutator_calls_rejected(self):
        for extra in ("def change():\n    global EXPECTED\n    EXPECTED, other = ('x', None)\n",
                      "READER_SUPPORTED[EXPECTED] = '26.8.2.5324'\n",
                      "X86_CANDIDATES.update({})\n"):
            with self.subTest(extra=extra), self.assertRaises(release.ManifestError):
                release.validate_runtime_profiles(self.source(extra=extra), self.apps)

    def test_policy_alias_mutations_from_security_review_are_rejected(self):
        for extra in ("a=READER_SUPPORTED\na['"+'e'*64+"']='99.0.0.0'\n",
                      "a=X86_CANDIDATES\na[EXPECTED]='26.9.1.5339'\n",
                      "a=READER_SUPPORTED\nb=a\nb.clear()\n",
                      "a=X86_CANDIDATES if condition else READER_SUPPORTED\na.pop(EXPECTED)\n",
                      "a=READER_SUPPORTED\na |= {}\n",
                      "a=READER_SUPPORTED\ndel a[EXPECTED]\n"):
            with self.subTest(extra=extra), self.assertRaises(release.ManifestError):
                release.validate_runtime_profiles(self.source(extra=extra), self.apps)

    def test_policy_and_alias_cannot_escape_into_calls_containers_or_returns(self):
        for value in ('READER_SUPPORTED', 'X86_CANDIDATES', 'a'):
            prefix = 'a=READER_SUPPORTED\n' if value == 'a' else ''
            for body in ('mutator('+value+')\n', 'box=['+value+']\n',
                         'box={"policy":'+value+'}\n', 'result=lambda: '+value+'\n',
                         'def expose():\n    return '+value+'\n',
                         'holder.policy='+value+'\n'):
                with self.subTest(value=value,body=body), self.assertRaises(release.ManifestError):
                    release.validate_runtime_profiles(self.source(extra=prefix+body),self.apps)

    def test_read_only_alias_membership_and_immutable_key_copy_are_allowed(self):
        source = self.source(extra='a=READER_SUPPORTED\nb=a\n'
            'present=EXPECTED in b\nmissing=EXPECTED not in b\nkeys=tuple(b)\n')
        release.validate_runtime_profiles(source,self.apps)

    def test_shadowed_tuple_is_not_treated_as_read_only_copy(self):
        for definition in ('tuple=lambda value:value.clear()\n',
                           'from external import mutate as tuple\n'):
            with self.subTest(definition=definition), self.assertRaises(release.ManifestError):
                release.validate_runtime_profiles(self.source(extra=definition+'keys=tuple(READER_SUPPORTED)\n'),self.apps)

    def test_reader_argument_sink_must_consume_policy_without_escaping(self):
        safe = ('class Reader:\n'
                '    def __init__(self, *, allowed_installations=None):\n'
                '        allowed=() if allowed_installations is None else tuple(allowed_installations)\n'
                '        policy=X86_CANDIDATES if candidate else READER_SUPPORTED\n'
                '        assert all(value in policy for value in allowed)\n')
        call = 'reader=Reader(allowed_installations=READER_SUPPORTED)\n'
        release.validate_runtime_profiles(self.source(extra=safe+call),self.apps)
        bad = (
            safe.replace('        allowed=()', '        mutator(allowed_installations)\n        allowed=()'),
            safe.replace('        allowed=()', '        box=[allowed_installations]\n        allowed=()'),
            safe+'Reader=lambda **values: values["allowed_installations"].clear()\n',
            safe+'alias=Reader\nalias.__init__=mutator\n',
            safe+'    if condition:\n        __new__=mutator\n')
        for source in bad:
            with self.subTest(source=source),self.assertRaises(release.ManifestError):
                release.validate_runtime_profiles(self.source(extra=source+call),self.apps)

    def test_current_runtime_reader_read_only_policy_shape_remains_supported(self):
        source = ROOT/'skills/kakaotalk-mac/scripts/windows/room_reader.py'
        apps = [{'app_sha256':'d7781cf275a6f4f23547e8e698005d0e8dbb78e205a34baa2eda3ea158fc64d1',
                 'version':'26.9.1.5339'}]
        found = release.validate_runtime_profiles(source.read_bytes(),apps)
        self.assertEqual(found[apps[0]['app_sha256']],apps[0]['version'])

    def test_all_literal_profile_versions_reject_leading_zero_and_overflow(self):
        for version in ('026.9.1.5339', '26.9.1.65536'):
            supported = "{EXPECTED: '26.9.1.5339', '" + 'e' * 64 + "': '" + version + "'}"
            with self.subTest(version=version), self.assertRaises(release.ManifestError):
                release.validate_runtime_profiles(self.source(supported=supported), self.apps)

    def test_future_x86_requires_explicit_stable_source_and_complete_non_candidate_proof(self):
        value = fixture()
        app = value['compatible_apps'][0]
        app['architecture'] = 'x86'
        app['qa'] = qa_fixture(app['qa']['probe']['source_hashes'], app, value['report']['sha256'])
        release.validate_manifest(value)
        release.validate_runtime_profiles(self.source(), value['compatible_apps'])


class GitBuilderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name).resolve()
        self.git('init', '-q')
        self.git('config', 'user.name', 'Synthetic QA')
        self.git('config', 'user.email', 'qa@example.invalid')
        self.git('config', 'core.autocrlf', 'false')
        self.value = fixture()
        for name in self.value['files']:
            path = self.repo / release.PREFIX / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if name == 'scripts/windows/room_reader.py':
                sha = self.value['compatible_apps'][0]['app_sha256']
                path.write_text("EXPECTED = '" + sha + "'\nREADER_SUPPORTED = {EXPECTED: '26.9.1.5339'}\n"
                                "X86_CANDIDATES = {}\nraise RuntimeError('synthetic source must never execute')\n")
            else:
                path.write_bytes(name.encode() + b'\n')
        report = self.repo / 'docs/qa.md'
        report.parent.mkdir()
        report.write_bytes(b'Synthetic proof only.\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'fixture')
        self.commit = self.git('rev-parse', 'HEAD').strip()
        sources = {name: digest((self.repo / release.PREFIX / 'scripts/windows' / name).read_bytes())
                   for name in release.RUNTIME}
        app = self.value['compatible_apps'][0]
        app['qa'] = qa_fixture(sources, app, digest(report.read_bytes()))
        self.proof = {'compatible_apps': self.value['compatible_apps']}

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args], stderr=subprocess.DEVNULL, text=True)

    def build(self, **changes):
        args = dict(repo=self.repo, commit=self.commit, tag='v0.4.0', sequence=2,
                    report_path='docs/qa.md', proof=self.proof)
        args.update(changes)
        return release.build_manifest(**args)

    def test_builder_reads_commit_and_ignores_dirty_untracked_files(self):
        original = self.build()
        (self.repo / release.PREFIX / 'SKILL.md').write_text('dirty checkout')
        (self.repo / release.PREFIX / 'private-untracked.txt').write_text('not a package input')
        (self.repo / 'docs/qa.md').write_text('dirty report')
        self.assertEqual(self.build(), original)

    def test_builder_refuses_unbound_proof_and_uncommitted_report(self):
        qa = self.proof['compatible_apps'][0]['qa']
        qa['probe']['source_hashes']['room_reader.py'] = '0' * 64
        rehash_qa(qa)
        with self.assertRaises(release.ManifestError):
            self.build()
        with self.assertRaises(release.ManifestError):
            self.build(commit='HEAD')
        (self.repo / 'docs/new.md').write_text('uncommitted')
        with self.assertRaises(release.ManifestError):
            self.build(report_path='docs/new.md')

    def test_git_output_is_bounded_before_full_capture(self):
        with self.assertRaisesRegex(release.ManifestError, 'GIT_OUTPUT_SIZE_LIMIT'):
            release._git(self.repo, 'ls-tree', '-r', self.commit, maximum=1)

    def test_git_replacements_cannot_change_committed_payload(self):
        original = self.build()
        (self.repo / release.PREFIX / 'SKILL.md').write_text('replacement content')
        self.git('add', '.')
        self.git('commit', '-qm', 'replacement object fixture')
        replacement = self.git('rev-parse', 'HEAD').strip()
        self.git('replace', self.commit, replacement)
        self.assertEqual(self.build(), original)

    def test_builder_rejects_symlink_git_modes_without_creating_live_link(self):
        blob = self.git('rev-parse', self.commit + ':docs/qa.md').strip()
        self.git('update-index', '--add', '--cacheinfo', '120000,' + blob + ',docs/link.md')
        self.git('commit', '-qm', 'synthetic symlink object')
        commit = self.git('rev-parse', 'HEAD').strip()
        with self.assertRaisesRegex(release.ManifestError, 'REGULAR_FILE'):
            self.build(commit=commit, report_path='docs/link.md')
        self.git('update-index', '--add', '--cacheinfo', '120000,' + blob + ',' + release.PREFIX + 'link')
        self.git('commit', '-qm', 'synthetic package symlink')
        with self.assertRaisesRegex(release.ManifestError, 'NONREGULAR'):
            self.build(commit=self.git('rev-parse', 'HEAD').strip())

    def test_cli_requires_explicit_fresh_output_and_sanitized_proof(self):
        qa = self.repo / 'qa.json'
        qa.write_bytes(release.canonical_bytes(self.proof))
        output = self.repo / 'release.json'
        args = ['--repo', str(self.repo), '--commit', self.commit, '--tag', 'v0.4.0',
                '--sequence', '2', '--report', 'docs/qa.md', '--qa', str(qa), '--output', str(output)]
        self.assertEqual(release.main(args), 0)
        before = output.read_bytes()
        self.assertEqual(release.main(args), 2)
        self.assertEqual(output.read_bytes(), before)

    def test_known_v03_manifest_matches_exact_git_tag(self):
        try:
            commit = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'v0.3.0^{commit}'],
                                             stderr=subprocess.DEVNULL, text=True).strip()
        except subprocess.CalledProcessError:
            self.skipTest('Released Git objects are not included in this source copy')
        raw = subprocess.check_output(['git', '-C', str(ROOT), 'ls-tree', '-r', '-z', commit, '--', release.PREFIX])
        expected = {}
        for entry in raw.split(b'\0'):
            if not entry:
                continue
            meta, name = entry.split(b'\t', 1)
            oid = meta.split()[2].decode()
            path = name.decode()[len(release.PREFIX):]
            expected[path] = digest(subprocess.check_output(['git', '-C', str(ROOT), 'cat-file', 'blob', oid]))
            for parent in PurePosixPath(path).parents:
                if str(parent) != '.':
                    expected[str(parent) + '/'] = None
        record = json.loads((ROOT / 'tools/known_skill_manifests.json').read_text())['releases']['v0.3.0']
        self.assertEqual(record['commit'], commit)
        self.assertEqual(record['manifest'], expected)
        self.assertEqual(record['manifest_sha256'], release.file_manifest_sha(expected))


if __name__ == '__main__':
    unittest.main()
