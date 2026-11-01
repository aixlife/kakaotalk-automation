"""Build and validate data-only reader release manifests; never run app code."""
import argparse
import ast
import copy
from concurrent.futures import ThreadPoolExecutor, TimeoutError
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import unicodedata

MAX_JSON = 256 * 1024
MAX_FILE = 1024 * 1024
MAX_PAYLOAD = 8 * 1024 * 1024
PREFIX = 'skills/kakaotalk-mac/'
HASH = re.compile(r'[0-9a-f]{64}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
TAG = re.compile(r'v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z')
RUNTIME = frozenset(('reader_source.py', 'reader_config.py', 'kakao_read_win.py', 'reader_rpc.py',
    'reader_job.py', 'room_reader.py', 'reader_queries.py', 'reader_envelope.py',
    'v2_key_derivation.py', 'vendor_appstate.py', 'reader_files.py',
    'reader_image.py', 'reader_source.py'))
PROBE_KEYS = frozenset(('schema', 'status', 'capability', 'stable_eligible',
    'maintainer_review_required', 'automatically_promotes_support', 'app',
    'source_verification', 'source_hashes', 'source_manifest_sha256',
    'message_count', 'owner_match_ack', 'owner_match_method',
    'independent_log_id_comparison', 'execution', 'snapshots',
    'resource_observations', 'safety', 'authentication', 'contains_chat_content',
    'contains_account_or_room_identifiers', 'candidate_only', 'image_identity'))
PROMOTION_KEYS = frozenset(('schema', 'maintainer_approved', 'comparison_method',
    'message_count', 'id_matches', 'text_matches', 'time_matches', 'probe_sha256',
    'report_sha256', 'source_manifest_sha256'))


class ManifestError(ValueError):
    pass


def _require(condition, reason):
    if not condition:
        raise ManifestError(reason)


def _keys(value, expected, label):
    _require(type(value) is dict and set(value) == set(expected), label + '_FIELDS')


def canonical_bytes(value):
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True,
                          separators=(',', ':'), allow_nan=False).encode('utf8')
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ManifestError('CANONICAL_JSON_INVALID') from exc


def file_manifest_sha(files):
    return hashlib.sha256(canonical_bytes(files)).hexdigest()


def validate_path(value):
    """Reject aliases and special paths on every supported consumer platform."""
    _require(type(value) is str and 0 < len(value) <= 240, 'PATH_INVALID')
    _require(not any(ord(c) < 32 or c in '\\<>:"|?*' for c in value), 'PATH_INVALID')
    _require(unicodedata.normalize('NFC', value) == value, 'PATH_NORMALIZATION')
    for part in value.split('/'):
        _require(part not in ('', '.', '..') and not part.endswith((' ', '.')), 'PATH_INVALID')
        stem = part.split('.', 1)[0].upper()
        _require(stem not in ('CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$') and
                 not re.fullmatch(r'(?:COM|LPT)[1-9¹²³]', stem), 'WINDOWS_RESERVED_PATH')
    canonical_bytes(value)
    return value


def _file_map(files):
    _require(type(files) is dict and 1 <= len(files) <= 128, 'FILES_INVALID')
    seen, spellings = set(), {}
    for name, digest in files.items():
        validate_path(name)
        folded = name.casefold()
        _require(folded not in seen, 'PATH_CASE_COLLISION')
        seen.add(folded)
        parts = name.split('/')
        _require('__pycache__' not in [p.casefold() for p in parts] and
                 not name.casefold().endswith(('.pyc', '.pyo')) and parts[-1] != '.DS_Store',
                 'GENERATED_PAYLOAD_FORBIDDEN')
        for end in range(1, len(parts) + 1):
            prefix = '/'.join(parts[:end])
            _require(spellings.setdefault(prefix.casefold(), prefix) == prefix, 'PATH_CASE_COLLISION')
        _require(type(digest) is str and HASH.fullmatch(digest), 'FILE_HASH_INVALID')
    for name in files:
        _require(not any('/'.join(name.casefold().split('/')[:end]) in seen
                         for end in range(1, len(name.split('/')))), 'PATH_FILE_DIRECTORY_COLLISION')
    _require('SKILL.md' in files and 'LICENSE' in files, 'SKILL_FILES_REQUIRED')
    runtime = {}
    for name, digest in files.items():
        if name.casefold().endswith('.py'):
            _require(name.startswith('scripts/windows/') and name.count('/') == 2,
                     'PYTHON_SOURCE_LAYOUT_UNSUPPORTED')
            runtime[name.rsplit('/', 1)[1]] = digest
    _require(RUNTIME <= set(runtime), 'RUNTIME_SOURCE_SET_INCOMPLETE')
    return runtime


def _integer(value, low, high, reason):
    _require(type(value) is int and low <= value <= high, reason)


def _seconds(value, maximum):
    _require(type(value) in (int, float) and 0 <= value <= maximum and
             math.isfinite(value), 'PROBE_RESOURCE_BOUND_FAILED')


def _execution(value, maximum):
    _keys(value, ('exit', 'timeout', 'job_memory_limit', 'peak_job_commit_bytes',
                  'elapsed_sec'), 'PROBE_EXECUTION')
    _integer(value['exit'], 0, 0, 'PROBE_EXECUTION_FAILED')
    _require(value['timeout'] is False, 'PROBE_EXECUTION_FAILED')
    _integer(value['job_memory_limit'], 268435456, 268435456, 'PROBE_RESOURCE_BOUND_FAILED')
    _integer(value['peak_job_commit_bytes'], 1, 268435456, 'PROBE_RESOURCE_BOUND_FAILED')
    _seconds(value['elapsed_sec'], maximum)


def _probe(probe, runtime, app):
    """Validate sanitized data without importing or executing the probe/runtime."""
    _keys(probe, PROBE_KEYS, 'PROBE')
    _require(probe['schema'] == 'windows-kakao-reader-probe/v1' and
             probe['capability'] == 'reader-only', 'PROBE_PROTOCOL_UNSUPPORTED')
    for field in ('stable_eligible', 'automatically_promotes_support',
                  'contains_chat_content', 'contains_account_or_room_identifiers', 'candidate_only'):
        _require(probe[field] is False, 'PROBE_SCOPE_INVALID')
    _require(probe['maintainer_review_required'] is True, 'PROBE_SCOPE_INVALID')
    _keys(probe['app'], ('sha256', 'architecture', 'version'), 'PROBE_APP')
    _require(probe['app'] == {'sha256': app['app_sha256'],
             'architecture': app['architecture'], 'version': app['version']}, 'PROBE_APP_MISMATCH')
    identity = probe['image_identity']
    _keys(identity, ('mapped_header_match', 'identity_scope', 'mapped_code_hash_verified',
                     'target_architecture', 'fingerprint_sha256'), 'PROBE_IMAGE_IDENTITY')
    _require(identity['mapped_header_match'] is True and
             identity['identity_scope'] == 'mapped_pe_headers_only' and
             identity['mapped_code_hash_verified'] is False and
             identity['target_architecture'] == app['architecture'] and
             type(identity['fingerprint_sha256']) is str and HASH.fullmatch(identity['fingerprint_sha256']),
             'PROBE_IMAGE_IDENTITY_INVALID')
    _require(probe['source_verification'] == 'PINNED_RELEASE_FILES' and
             type(probe['source_hashes']) is dict and probe['source_hashes'] == runtime and
             probe['source_manifest_sha256'] == file_manifest_sha(runtime),
             'QA_SOURCE_BINDING_MISMATCH')
    _integer(probe['message_count'], 1, 3, 'QA_MESSAGES_REQUIRED')
    _require(probe['independent_log_id_comparison'] == 'NOT_RUN', 'PROBE_COMPARISON_INVALID')
    if probe['status'] == 'PASS':
        _require(probe['owner_match_ack'] is True and
                 probe['owner_match_method'] == 'manual_original_text_and_time', 'PROBE_OWNER_ACK_REQUIRED')
    else:
        _require(probe['status'] == 'READ_VERIFIED_PENDING_OWNER_MATCH' and
                 probe['owner_match_ack'] is False and probe['owner_match_method'] == 'NOT_RUN',
                 'PROBE_OWNER_ACK_INVALID')
    _keys(probe['execution'], ('inner', 'outer'), 'PROBE_EXECUTION')
    _execution(probe['execution']['inner'], 45)
    _execution(probe['execution']['outer'], 50)
    snapshots = probe['snapshots']
    _require(type(snapshots) is list and 2 <= len(snapshots) <= 8, 'PROBE_SNAPSHOTS_REQUIRED')
    kinds = set()
    for snapshot in snapshots:
        _keys(snapshot, ('kind', 'snapshot_pages', 'authenticated_pages', 'zero_pages',
                         'double_read_verified', 'quick_check'), 'PROBE_SNAPSHOT')
        _require(snapshot['kind'] in ('room-list', 'selected-messages', 'profiles',
                 'self-author-identity') and snapshot['double_read_verified'] is True and
                 snapshot['quick_check'] == 'ok', 'PROBE_SNAPSHOT_INVALID')
        pages = snapshot['snapshot_pages']
        _integer(pages, 1, 131072, 'PROBE_SNAPSHOT_INVALID')
        _integer(snapshot['authenticated_pages'], 1, pages, 'PROBE_SNAPSHOT_INVALID')
        _integer(snapshot['zero_pages'], 0, pages, 'PROBE_SNAPSHOT_INVALID')
        _require(snapshot['authenticated_pages'] + snapshot['zero_pages'] == pages, 'PROBE_SNAPSHOT_INVALID')
        kinds.add(snapshot['kind'])
    _require({'room-list', 'selected-messages'} <= kinds, 'PROBE_SNAPSHOTS_REQUIRED')
    resources = probe['resource_observations']
    _keys(resources, ('app_private_before', 'app_private_after', 'process_read_bytes',
                      'elapsed_sec'), 'PROBE_RESOURCES')
    for field in ('app_private_before', 'app_private_after'):
        _integer(resources[field], 1, 469893119, 'PROBE_RESOURCE_BOUND_FAILED')
    _integer(resources['process_read_bytes'], 1, 384 * 1024 * 1024, 'PROBE_RESOURCE_BOUND_FAILED')
    _seconds(resources['elapsed_sec'], 40)
    safety = probe['safety']
    _keys(safety, ('input_calls', 'clipboard_calls', 'send_calls', 'process_dump_saved',
                   'key_saved', 'plaintext_db_saved', 'server_history_fetched'), 'PROBE_SAFETY')
    for field in ('input_calls', 'clipboard_calls', 'send_calls'):
        _integer(safety[field], 0, 0, 'PROBE_UNEXPECTED_SIDE_EFFECT')
    for field in ('process_dump_saved', 'key_saved', 'plaintext_db_saved', 'server_history_fetched'):
        _require(safety[field] is False, 'PROBE_UNEXPECTED_SIDE_EFFECT')
    _keys(probe['authentication'], ('ikm_wrap', 'selected_key_wrap', 'selected_page_hmac'),
          'PROBE_AUTHENTICATION')
    _require(all(value is True for value in probe['authentication'].values()), 'PROBE_AUTHENTICATION_FAILED')


def _qa(qa, runtime, app, report_sha256):
    _keys(qa, ('probe', 'probe_sha256', 'promotion'), 'QA')
    probe = qa['probe']
    _probe(probe, runtime, app)
    _require(qa['probe_sha256'] == file_manifest_sha(probe), 'PROBE_HASH_MISMATCH')
    promotion = qa['promotion']
    _keys(promotion, PROMOTION_KEYS, 'PROMOTION')
    _integer(promotion['schema'], 1, 1, 'PROMOTION_SCHEMA_UNSUPPORTED')
    _require(promotion['maintainer_approved'] is True, 'MAINTAINER_APPROVAL_REQUIRED')
    _require(promotion['probe_sha256'] == qa['probe_sha256'] and
             promotion['report_sha256'] == report_sha256 and
             promotion['source_manifest_sha256'] == file_manifest_sha(runtime), 'PROMOTION_BINDING_MISMATCH')
    count = probe['message_count']
    for field in ('message_count', 'text_matches'):
        _integer(promotion[field], count, count, 'PROMOTION_MATCH_REQUIRED')
    if promotion['comparison_method'] == 'independent-local-source':
        _integer(promotion['id_matches'], count, count, 'PROMOTION_ID_MATCH_REQUIRED')
        _require(promotion['time_matches'] is None, 'PROMOTION_COMPARISON_INVALID')
    else:
        _require(promotion['comparison_method'] == 'owner-visible-text-time' and
                 probe['status'] == 'PASS' and probe['owner_match_ack'] is True and
                 promotion['id_matches'] is None, 'PROMOTION_OWNER_ACK_REQUIRED')
        _integer(promotion['time_matches'], count, count, 'PROMOTION_TIME_MATCH_REQUIRED')


def validate_manifest(value):
    _keys(value, ('schema', 'manager_revision', 'channel', 'sequence', 'tag', 'commit',
                  'capability', 'files', 'manifest_sha256', 'report', 'compatible_apps'), 'MANIFEST')
    for field in ('schema', 'manager_revision'):
        _require(type(value[field]) is int and value[field] == 1, field.upper() + '_UNSUPPORTED')
    _require(value['channel'] == 'stable' and value['capability'] == 'reader-only', 'CHANNEL_OR_CAPABILITY')
    _require(type(value['sequence']) is int and 0 < value['sequence'] <= 2**63 - 1, 'SEQUENCE_INVALID')
    _require(type(value['tag']) is str and len(value['tag']) <= 64 and TAG.fullmatch(value['tag']), 'TAG_INVALID')
    _require(type(value['commit']) is str and COMMIT.fullmatch(value['commit']), 'COMMIT_INVALID')
    runtime = _file_map(value['files'])
    _require(value['manifest_sha256'] == file_manifest_sha(value['files']), 'MANIFEST_HASH_MISMATCH')
    _keys(value['report'], ('path', 'sha256'), 'REPORT')
    report = validate_path(value['report']['path'])
    _require(report.startswith('docs/') and type(value['report']['sha256']) is str and
             HASH.fullmatch(value['report']['sha256']), 'REPORT_INVALID')
    apps = value['compatible_apps']
    _require(type(apps) is list and 1 <= len(apps) <= 16, 'COMPATIBLE_APPS_REQUIRED')
    seen = set()
    for app in apps:
        _keys(app, ('architecture', 'app_sha256', 'version', 'qa'), 'APP')
        _require(app['architecture'] in ('x86', 'x64'), 'APP_ARCHITECTURE_INVALID')
        sha = app['app_sha256']
        _require(type(sha) is str and HASH.fullmatch(sha) and sha not in seen, 'APP_HASH_INVALID_OR_DUPLICATE')
        seen.add(sha)
        version = app['version']
        _require(type(version) is str and re.fullmatch(r'(?:0|[1-9][0-9]{0,4})(?:\.(?:0|[1-9][0-9]{0,4})){3}', version)
                 and all(int(part) <= 65535 for part in version.split('.')), 'APP_VERSION_INVALID')
        _qa(app['qa'], runtime, app, value['report']['sha256'])
    _require(len(canonical_bytes(value)) <= MAX_JSON, 'MANIFEST_SIZE_LIMIT')
    return copy.deepcopy(value)


def _validate_policy_loads(tree):
    """Allow the reader's narrow read-only policy uses, not arbitrary Python.

    This is a source-shape contract for literal policy extraction. It does not
    prove whole-program behavior or sandbox reflective Python code.
    """
    nodes = list(ast.walk(tree))
    parents = {id(child): node for node in nodes for child in ast.iter_child_nodes(node)}
    tainted = {'READER_SUPPORTED', 'X86_CANDIDATES'}
    alias_assignments, alias_targets = set(), set()

    def expression(node, depth=0):
        _require(depth <= 16, 'RUNTIME_PROFILE_EXPRESSION_LIMIT')
        if isinstance(node, ast.Name):
            return node.id in tainted
        return (isinstance(node, ast.IfExp) and expression(node.body, depth+1) and
                expression(node.orelse, depth+1))

    def aliases():
        while True:
            before = set(tainted)
            for node in nodes:
                if isinstance(node, ast.Assign) and expression(node.value):
                    _require(len(node.targets) == 1 and isinstance(node.targets[0], ast.Name),
                             'RUNTIME_PROFILE_ALIAS_ESCAPE')
                    tainted.add(node.targets[0].id)
                    alias_assignments.add(id(node))
                    alias_targets.add(id(node.targets[0]))
            _require(len(tainted) <= 32, 'RUNTIME_PROFILE_ALIAS_LIMIT')
            if before == tainted:
                return

    aliases()
    reader_calls = {id(node) for node in nodes if isinstance(node, ast.Call) and
        isinstance(node.func, ast.Name) and node.func.id == 'Reader' and
        any(keyword.arg == 'allowed_installations' and expression(keyword.value)
            for keyword in node.keywords)}
    parameter = None
    if reader_calls:
        classes = [node for node in nodes if isinstance(node, ast.ClassDef) and node.name == 'Reader']
        _require(len(classes) == 1 and classes[0] in tree.body and not classes[0].bases and
                 not classes[0].keywords and not classes[0].decorator_list, 'RUNTIME_PROFILE_READER_SINK')
        cls = classes[0]
        initializers = [node for node in cls.body if isinstance(node, ast.FunctionDef) and
                        node.name == '__init__']
        _require(len(initializers) == 1 and not initializers[0].decorator_list,
                 'RUNTIME_PROFILE_READER_SINK')
        initializer = initializers[0]
        parameters = [arg for arg in (initializer.args.posonlyargs + initializer.args.args +
                      initializer.args.kwonlyargs) if arg.arg == 'allowed_installations']
        _require(len(parameters) == 1, 'RUNTIME_PROFILE_READER_SINK')
        parameter = parameters[0]
        for node in nodes:
            if isinstance(node, ast.Name) and node.id == 'Reader':
                parent = parents[id(node)]
                _require(isinstance(node.ctx, ast.Load) and isinstance(parent, ast.Call) and
                         parent.func is node, 'RUNTIME_PROFILE_READER_SINK')
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == 'Reader':
                _require(node is cls, 'RUNTIME_PROFILE_READER_SINK')
            if isinstance(node, ast.arg):
                _require(node.arg != 'Reader', 'RUNTIME_PROFILE_READER_SINK')
            if isinstance(node, ast.alias):
                _require((node.asname or node.name.split('.')[0]) != 'Reader', 'RUNTIME_PROFILE_READER_SINK')
            _require(node is cls or (getattr(node, 'name', None) != 'Reader' and
                                    getattr(node, 'rest', None) != 'Reader'), 'RUNTIME_PROFILE_READER_SINK')
        for node in ast.walk(cls):
            _require(not (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and
                          node.name == '__new__'), 'RUNTIME_PROFILE_READER_SINK')
            _require(not (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and
                          node.name == '__init__' and node is not initializer), 'RUNTIME_PROFILE_READER_SINK')
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                _require(not any(isinstance(part, ast.Name) and part.id in ('__init__', '__new__')
                                 for target in targets for part in ast.walk(target)), 'RUNTIME_PROFILE_READER_SINK')
        tainted.add('allowed_installations')
        aliases()

    tuple_shadowed = any(
        isinstance(node, ast.Name) and node.id == 'tuple' and isinstance(node.ctx, (ast.Store, ast.Del)) or
        isinstance(node, ast.arg) and node.arg == 'tuple' or
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == 'tuple' or
        isinstance(node, ast.alias) and (node.asname or node.name.split('.')[0]) == 'tuple' or
        isinstance(node, ast.ExceptHandler) and node.name == 'tuple' or
        type(node).__name__ in ('MatchAs', 'MatchStar', 'MatchMapping') and
        (getattr(node, 'name', None) == 'tuple' or getattr(node, 'rest', None) == 'tuple')
        for node in nodes)
    for node in nodes:
        if isinstance(node, ast.arg) and node.arg in tainted:
            _require(node is parameter, 'RUNTIME_PROFILE_ALIAS_BINDING')
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            _require(node.name not in tainted, 'RUNTIME_PROFILE_ALIAS_BINDING')
        if isinstance(node, ast.alias):
            _require((node.asname or node.name.split('.')[0]) not in tainted, 'RUNTIME_PROFILE_ALIAS_BINDING')
        if isinstance(node, ast.ExceptHandler):
            _require(node.name not in tainted, 'RUNTIME_PROFILE_ALIAS_BINDING')
        if type(node).__name__ in ('MatchAs', 'MatchStar', 'MatchMapping'):
            _require(getattr(node, 'name', None) not in tainted and getattr(node, 'rest', None) not in tainted,
                     'RUNTIME_PROFILE_ALIAS_BINDING')
        if not isinstance(node, ast.Name) or node.id not in tainted:
            continue
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            root_declaration = (isinstance(node.ctx, ast.Store) and node.id in
                ('READER_SUPPORTED', 'X86_CANDIDATES') and parents[id(node)] in tree.body)
            _require(root_declaration or id(node) in alias_targets, 'RUNTIME_PROFILE_ALIAS_MUTATION')
            continue
        value, parent = node, parents[id(node)]
        while isinstance(parent, ast.IfExp) and value in (parent.body, parent.orelse) and expression(parent):
            value, parent = parent, parents[id(parent)]
        if id(parent) in alias_assignments:
            continue
        if isinstance(parent, ast.Compare) and len(parent.ops) == 1:
            if (parent.comparators[0] is value and isinstance(parent.ops[0], (ast.In, ast.NotIn))):
                continue
            if isinstance(parent.ops[0], (ast.Is, ast.IsNot)):
                other = parent.comparators[0] if parent.left is value else parent.left
                if isinstance(other, ast.Constant) and other.value is None:
                    continue
        if (isinstance(parent, ast.Call) and isinstance(parent.func, ast.Name) and
                parent.func.id == 'tuple' and parent.args == [value] and not parent.keywords):
            _require(not tuple_shadowed, 'RUNTIME_PROFILE_TUPLE_SHADOWED')
            continue
        if (isinstance(parent, ast.keyword) and parent.arg == 'allowed_installations' and
                id(parents[id(parent)]) in reader_calls):
            continue
        raise ManifestError('RUNTIME_PROFILE_ALIAS_ESCAPE')


def validate_runtime_profiles(source_bytes, compatible_apps):
    """Inspect literal stable policy data only; never import or execute payload code."""
    _require(type(source_bytes) is bytes and 0 < len(source_bytes) <= MAX_JSON,
             'RUNTIME_PROFILE_SOURCE_SIZE')
    try:
        tree = ast.parse(source_bytes.decode('utf8'), filename='room_reader.py')
    except (SyntaxError, UnicodeError, ValueError, RecursionError) as error:
        raise ManifestError('RUNTIME_PROFILE_SOURCE_INVALID') from error
    _require(sum(1 for _ in ast.walk(tree)) <= 50000, 'RUNTIME_PROFILE_AST_LIMIT')
    declarations, declaration_targets = {}, set()
    policy_names = ('EXPECTED', 'READER_SUPPORTED', 'X86_CANDIDATES')
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and
                target.id in policy_names for target in node.targets):
            _require(len(node.targets) == 1 and isinstance(node.targets[0], ast.Name), 'RUNTIME_PROFILE_DECLARATION')
            name = node.targets[0].id
            _require(name not in declarations, 'RUNTIME_PROFILE_DUPLICATE_DECLARATION')
            declarations[name] = node.value
            declaration_targets.add(id(node.targets[0]))
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)) and isinstance(node.target, ast.Name):
            _require(node.target.id not in policy_names,
                     'RUNTIME_PROFILE_DECLARATION')
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in policy_names and isinstance(node.ctx, (ast.Store, ast.Del)):
            _require(id(node) in declaration_targets, 'RUNTIME_PROFILE_MUTATION_UNSUPPORTED')
        if isinstance(node, ast.Subscript) and isinstance(node.ctx, (ast.Store, ast.Del)):
            _require(not any(isinstance(item, ast.Name) and item.id in policy_names
                             for item in ast.walk(node.value)), 'RUNTIME_PROFILE_MUTATION_UNSUPPORTED')
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            _require(node.func.value.id not in policy_names or node.func.attr not in
                     ('update', 'setdefault', 'clear', 'pop', 'popitem', '__setitem__', '__delitem__'),
                     'RUNTIME_PROFILE_MUTATION_UNSUPPORTED')
    expected = declarations.get('EXPECTED')
    if expected is not None:
        _require(isinstance(expected, ast.Constant) and type(expected.value) is str and
                 HASH.fullmatch(expected.value), 'RUNTIME_PROFILE_EXPECTED_INVALID')
        expected = expected.value
    _require('READER_SUPPORTED' in declarations, 'RUNTIME_STABLE_PROFILES_MISSING')
    _validate_policy_loads(tree)
    profiles = {}
    for name in ('READER_SUPPORTED', 'X86_CANDIDATES'):
        declaration = declarations.get(name)
        if declaration is None:
            profiles[name] = {}
            continue
        _require(isinstance(declaration, ast.Dict) and len(declaration.keys) <= 64, 'RUNTIME_PROFILE_LITERAL_REQUIRED')
        values = {}
        for key, value in zip(declaration.keys, declaration.values):
            if isinstance(key, ast.Name):
                _require(key.id == 'EXPECTED' and expected is not None, 'RUNTIME_PROFILE_LITERAL_REQUIRED')
                key = expected
            else:
                _require(isinstance(key, ast.Constant) and type(key.value) is str, 'RUNTIME_PROFILE_LITERAL_REQUIRED')
                key = key.value
            _require(HASH.fullmatch(key) and key not in values and isinstance(value, ast.Constant) and
                     type(value.value) is str and
                     re.fullmatch(r'(?:0|[1-9][0-9]{0,4})(?:\.(?:0|[1-9][0-9]{0,4})){3}', value.value) and
                     all(int(part) <= 65535 for part in value.value.split('.')),
                     'RUNTIME_PROFILE_INVALID_OR_DUPLICATE')
            values[key] = value.value
        profiles[name] = values
    _require(type(compatible_apps) is list and 1 <= len(compatible_apps) <= 16, 'COMPATIBLE_APPS_REQUIRED')
    for app in compatible_apps:
        _require(type(app) is dict and type(app.get('app_sha256')) is str and
                 type(app.get('version')) is str, 'RUNTIME_APP_IDENTITY_INVALID')
        sha = app['app_sha256']
        _require(sha not in profiles['X86_CANDIDATES'] and
                 profiles['READER_SUPPORTED'].get(sha) == app['version'], 'RUNTIME_PROFILE_NOT_STABLE')
    return dict(profiles['READER_SUPPORTED'])


def _object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def _parse(raw):
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_JSON, 'JSON_SIZE_OR_TYPE')
    try:
        return json.loads(raw.decode('utf8'), object_pairs_hook=_object,
                          parse_constant=_invalid_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ManifestError(str(exc) if isinstance(exc, ManifestError) else 'JSON_INVALID') from exc


def _invalid_constant(_value):
    raise ManifestError('JSON_CONSTANT_INVALID')


def parse_manifest(rawbytes):
    return validate_manifest(_parse(rawbytes))


def _git(repo, *args, maximum=MAX_FILE):
    env = dict(os.environ, GIT_ALLOW_PROTOCOL='', GIT_NO_LAZY_FETCH='1', GIT_TERMINAL_PROMPT='0')
    with subprocess.Popen(['git', '--no-replace-objects', '-C', str(repo), *args],
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env) as process:
        with ThreadPoolExecutor(max_workers=1) as pool:
            try:
                data = pool.submit(process.stdout.read, maximum + 1).result(timeout=15)
                _require(len(data) <= maximum, 'GIT_OUTPUT_SIZE_LIMIT')
                _require(process.wait(timeout=2) == 0, 'GIT_OBJECT_UNAVAILABLE')
                return data
            except BaseException as error:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=2)
                if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)):
                    raise ManifestError('GIT_TIMEOUT') from error
                raise


def _blob(repo, object_name):
    size = int(_git(repo, 'cat-file', '-s', object_name, maximum=32).strip())
    _require(0 <= size <= MAX_FILE, 'GIT_FILE_SIZE_LIMIT')
    return _git(repo, 'cat-file', 'blob', object_name)


def build_manifest(repo, commit, tag, sequence, report_path, proof):
    """Bind every package/proof hash to immutable Git objects, not the checkout."""
    _require(type(commit) is str and COMMIT.fullmatch(commit), 'FULL_COMMIT_REQUIRED')
    _require(_git(repo, 'cat-file', '-t', commit, maximum=32).strip() == b'commit', 'COMMIT_REQUIRED')
    _keys(proof, ('compatible_apps',), 'PROOF')
    validate_path(report_path)
    _require(report_path.startswith('docs/'), 'REPORT_INVALID')
    entries = _git(repo, 'ls-tree', '-r', '-z', commit, '--', PREFIX).split(b'\0')
    entries = [entry for entry in entries if entry]
    _require(1 <= len(entries) <= 128, 'FILES_INVALID')
    files, total, profile_source = {}, 0, None
    for entry in entries:
        meta, raw_path = entry.split(b'\t', 1)
        mode, kind, oid = meta.decode('ascii').split()
        name = raw_path.decode('utf8')
        _require(mode in ('100644', '100755') and kind == 'blob' and name.startswith(PREFIX), 'NONREGULAR_PAYLOAD')
        name = validate_path(name[len(PREFIX):])
        data = _blob(repo, oid)
        total += len(data)
        _require(total <= MAX_PAYLOAD, 'PAYLOAD_SIZE_LIMIT')
        files[name] = hashlib.sha256(data).hexdigest()
        if name == 'scripts/windows/room_reader.py':
            profile_source = data
    entry = _git(repo, 'ls-tree', '-z', commit, '--', report_path).rstrip(b'\0')
    _require(bool(entry) and b'\0' not in entry, 'REPORT_FILE_REQUIRED')
    meta, name = entry.split(b'\t', 1)
    mode, kind, oid = meta.decode('ascii').split()
    _require(mode in ('100644', '100755') and kind == 'blob' and name.decode('utf8') == report_path,
             'REPORT_REGULAR_FILE_REQUIRED')
    report = _blob(repo, oid)
    _require(bool(report), 'REPORT_FILE_EMPTY')
    manifest = validate_manifest({'schema': 1, 'manager_revision': 1, 'channel': 'stable',
        'sequence': sequence, 'tag': tag, 'commit': commit, 'capability': 'reader-only',
        'files': files, 'manifest_sha256': file_manifest_sha(files),
        'report': {'path': report_path, 'sha256': hashlib.sha256(report).hexdigest()},
        'compatible_apps': proof['compatible_apps']})
    validate_runtime_profiles(profile_source, manifest['compatible_apps'])
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--commit', required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--sequence', type=int, required=True)
    parser.add_argument('--report', required=True)
    parser.add_argument('--qa', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        with args.qa.open('rb') as stream:
            proof = _parse(stream.read(MAX_JSON + 1))
        value = build_manifest(args.repo, args.commit, args.tag, args.sequence, args.report, proof)
        output = args.output.absolute()
        _require(not any(p.is_symlink() for p in (output, *output.parents)), 'OUTPUT_SYMLINK')
        with output.open('xb') as stream:
            stream.write(canonical_bytes(value) + b'\n')
            stream.flush()
            os.fsync(stream.fileno())
        print(json.dumps({'status': 'BUILT', 'manifest_sha256': value['manifest_sha256'], 'output': str(output)}))
        return 0
    except (ManifestError, OSError, subprocess.SubprocessError) as exc:
        print(json.dumps({'status': 'BLOCKED', 'reason': str(exc)}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
