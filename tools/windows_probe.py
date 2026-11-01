"""Owner-run Windows reader verification; no send, GUI, upload, or app writes.

Only the JSON files under KakaoReader/proofs are shareable. Existing reader
receipts stay private. A successful read is not PASS until the owner explicitly
compares the displayed messages with their original text and time. That manual
acknowledgment is not an independent ID match or permission for stable release.
"""
import argparse
import contextlib
from datetime import datetime, timedelta
import hashlib
import importlib
import importlib.machinery
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import struct
import sys
from types import SimpleNamespace
import uuid

REPO = Path(__file__).resolve().parents[1]
RUNTIME = REPO / 'skills/kakaotalk-mac/scripts/windows'
# The publisher fills these pins after integrating the runtime. Empty pins fail
# closed. The probe lives outside SOURCE_NAMES, so these hashes are not circular.
EXPECTED_SOURCE_HASHES = {
    "kakao_read_win.py": "9a479ae87c82e523476ee46e70b6703530592298dca78908c9f5b63823b44310",
    "reader_accounts.py": "4f20df38507106c27af51371358089933bc55483f5d7551dd9d19087118db1f0",
    "reader_config.py": "2bd83981286ab4a9d8b729cf1011b21a9165cfba1bd833441ab36043bf2d1f23",
    "reader_envelope.py": "872f293b705e1923b88755202b8c7f7073435eb37defecbdbbaa2cd79be1f338",
    "reader_files.py": "832f4d9c8a53f71472ffd4c9b51ffaf0770fe819fcb9024954d56a7994b345f5",
    "reader_image.py": "9bfe35482418a9047cf1809f680d749b57c034abcbeb7068e8243fb727053fb3",
    "reader_job.py": "9ecba014b6865695837b8626e3052b023dd3b581411a44c638d73d3d07a38e53",
    "reader_queries.py": "8665fef1d8f1e7d9efa71de68e69dd5342c52269661447297f89af4c036ed0e5",
    "reader_rpc.py": "23e2c0be9c0594d9b36b2c3a068e4de6d8c9e52f32b83193aa46be31506dd5fb",
    "reader_snapshot.py": "f8395951e947b4af887386d25ac913967bd8d3f0c7f70ac210915be29ed41337",
    "reader_source.py": "bcdf2e1ef9ebdc4ae8e3f865026a1fc257589db31c69306b1f67efc3d22f41d3",
    "reader_x86.py": "5ce697237c775781c2f69fe7396fbda9df3ebda1bba09170c8cd075df038f032",
    "room_reader.py": "17e39adaa8fda22953c4db51aa9e5621f177fb63f0a59945d921368f64a06e26",
    "v2_key_derivation.py": "01db4ff6290480b4a7319a696b6ef8770fb8c26e002dde681c413a72f714194f",
    "vendor_appstate.py": "d08f5316e06781eb8fa84506929fa584db79515dc9d1f012b2718a73a0096e87"
}
MINIMUM_SOURCES = frozenset(('reader_config.py', 'kakao_read_win.py',
    'reader_rpc.py', 'reader_job.py', 'room_reader.py', 'reader_queries.py',
    'reader_envelope.py', 'v2_key_derivation.py', 'vendor_appstate.py'))
APP_PROFILES = {
    'abf66658c84c7a9a2f8300f9c3304a858bcacf8e3867bad33a79d769fd5321c1':
        ('x64', '26.8.2.5324'),
    'd7781cf275a6f4f23547e8e698005d0e8dbb78e205a34baa2eda3ea158fc64d1':
        ('x64', '26.9.1.5339'),
    '86f384d1694c74a611181e6c88509e8f59eb8d9739ae3d7789711a9355757500':
        ('x86', '26.9.1.5339'),
}
SCHEMA = 'windows-kakao-reader-probe/v1'
MEMORY_LIMIT = 268435456
APP_PRIVATE_LIMIT = 469893120
READ_LIMIT = 384 * 1024 * 1024
MAX_JSON = 2 * 1024 * 1024
IDENT = re.compile(r'[0-9a-f]{32}\Z')
DIGEST = re.compile(r'[0-9a-f]{64}\Z')
SAFE_READER_ERRORS = frozenset((
    'ACCOUNT_SELECTION_REQUIRED', 'ACCOUNT_NOT_FOUND', 'ACCOUNT_TOKEN_INVALID',
    'ACCOUNT_TOKEN_NOT_FOUND', 'ACCOUNT_TOKEN_NOT_UNIQUE', 'ACCOUNT_SET_CHANGED',
    'ACCOUNT_UNSAFE_PATH', 'ACCOUNT_INVENTORY_LIMIT', 'ACCOUNT_METADATA_INVALID',
    'ACCOUNT_NOT_UNIQUE', 'ACCOUNT_SCOPE_CHANGED', 'FILE_CHANGED',
    'ACCOUNT_FILE_CHANGED', 'ACCOUNT_FILE_LIMIT_INVALID', 'ACCOUNT_FILE_NOT_DIRECTORY',
    'ACCOUNT_FILE_NOT_REGULAR', 'ACCOUNT_FILE_OUTSIDE_SCOPE', 'ACCOUNT_FILE_SIZE_CHANGED',
    'ACCOUNT_FILE_TOO_LARGE', 'ACCOUNT_FILE_UNAVAILABLE', 'ACCOUNT_FILE_UNSAFE',
    'FILE_IDENTITY_CHANGED', 'DB_UNSAFE_PATH', 'APP_NOT_FOUND', 'APP_MEMORY_LIMIT',
    'DISK_IMAGE_CHANGED', 'MAPPED_IMAGE_IDENTITY_MISMATCH', 'MAPPED_IMAGE_HEADER_INVALID',
    'MAPPED_IMAGE_UNAVAILABLE', 'MAPPED_IMAGE_READ_FAILED',
    'DISK_IMAGE_LINK_OR_REPARSE', 'DISK_IMAGE_PATH_UNSAFE', 'DISK_IMAGE_SIZE_LIMIT',
    'DISK_IMAGE_UNAVAILABLE', 'IMAGE_ARCHITECTURE_UNSUPPORTED', 'IMAGE_HEADERS_INVALID',
    'IMAGE_HEADER_LIMIT', 'MAIN_MODULE_UNAVAILABLE', 'MAPPED_IMAGE_ARCHITECTURE_MISMATCH',
    'MAPPED_IMAGE_HEADER_LIMIT', 'MAPPED_IMAGE_HEADER_MISMATCH',
    'MAPPED_IMAGE_MEMORY_UNAVAILABLE', 'MAPPED_IMAGE_PATH_MISMATCH',
    'MAPPED_IMAGE_PATH_UNAVAILABLE', 'MAPPED_IMAGE_PROCESS_MISMATCH',
    'MAPPED_IMAGE_RANGE_INVALID', 'MODULE_SNAPSHOT_CLOSE_FAILED', 'MODULE_SNAPSHOT_UNAVAILABLE',
    'APP_EXITED_RETRY_READ', 'APP_MEMORY_QUERY_FAILED', 'OWN_MEMORY_LIMIT',
    'INSTALLATION_CHANGED', 'CANDIDATE_INSTALLATION_CHANGED',
    'INSTALLATION_NOT_REVIEWED', 'APP_X86_UNSUPPORTED',
    'PROCESS_READ_UNAVAILABLE', 'PROCESS_IDENTITY_CHANGED',
    'PROCESS_NOT_FOUND', 'PROCESS_NOT_UNIQUE', 'APP_NOT_RUNNING',
    'APP_PROCESS_NOT_UNIQUE', 'PROCESS_READ_LIMIT', 'TIME_LIMIT',
    'DB_SIZE_LIMIT', 'WAL_SIZE_LIMIT', 'DB_OUTSIDE_ACCOUNT',
    'DB_CHANGED_DURING_READ', 'DB_DOUBLE_READ_MISMATCH',
    'WAL_APPEARANCE_CHANGED', 'WAL_CHANGED_DURING_READ',
    'WAL_DOUBLE_READ_MISMATCH', 'WAL_FORMAT_UNSUPPORTED',
    'WAL_HEADER_CHECKSUM_FAILED', 'PAGE_AUTHENTICATION_FAILED',
    'SNAPSHOT_INTEGRITY_FAILED', 'SNAPSHOT_PAGE_MISSING',
    'SNAPSHOT_SOURCE_CHANGED', 'SNAPSHOT_FILE_IO_LIMIT',
    'SNAPSHOT_MEMORY_LIMIT', 'SNAPSHOT_TIME_LIMIT',
    'ENVELOPE_SIZE_LIMIT', 'ENVELOPE_VERSION_UNSUPPORTED',
    'ENVELOPE_CHANGED_DURING_READ', 'ENVELOPE_REGION_LIMIT',
    'ENVELOPE_SALT_MATCH_LIMIT', 'IKM_CONTAINER_CHANGED',
    'SELECTED_WRAPPED_KEY_MISSING', 'V2_SELECTED_DATABASE_KEY_NOT_VALIDATED',
    'V2_CACHED_TARGET_WRAP_INVALID', 'V2_CACHED_TARGET_PAGE_INVALID',
    'EXACT_ROOM_NAME_REQUIRED', 'ROOM_NOT_UNIQUE_OR_NOT_FOUND',
    'MESSAGE_SCHEMA_UNSUPPORTED', 'PROFILE_SCHEMA_UNSUPPORTED',
    'RPC_RESULT_PENDING', 'RPC_READER_JOB_FAILED',
    'READER_TIMEOUT_NO_RESULT_ACCEPTED', 'RPC_RESPONSE_NOT_AVAILABLE',
    'WINDOWS_X64_PYTHON_REQUIRED', 'READINESS_CHECK_FAILED',
))
SAFE_PROBE_ERRORS = frozenset((
    'PROBE_ALREADY_RECORDED_USE_REVIEW', 'PROBE_ARGUMENTS_INVALID', 'PROBE_APP_IDENTITY_CHANGED',
    'PROBE_APP_IDENTITY_MISMATCH', 'PROBE_APP_IDENTITY_MISSING', 'PROBE_APP_NOT_REVIEWED',
    'PROBE_BINDING_MISMATCH', 'PROBE_COMPLETE_MESSAGES_REQUIRED',
    'PROBE_CONFIRMED_RESULT_CHANGED', 'PROBE_EXECUTION_FAILED', 'PROBE_FILE_CHANGED',
    'PROBE_FILE_INVALID', 'PROBE_FILE_NOT_FOUND', 'PROBE_INTERNAL_ERROR',
    'PROBE_JSON_INVALID', 'PROBE_KEY_AUTHENTICATION_MISSING', 'PROBE_LOCALAPPDATA_REQUIRED',
    'PROBE_LOCAL_REVIEW_REQUIRED', 'PROBE_MESSAGE_TIME_INVALID',
    'PROBE_IMAGE_IDENTITY_NOT_VERIFIED', 'PROBE_SOURCE_EXECUTION_NOT_VERIFIED',
    'PROBE_NONEMPTY_MESSAGES_REQUIRED', 'PROBE_NONEMPTY_TEXT_REQUIRED',
    'PROBE_NOT_READY', 'PROBE_OWNER_ACK_REQUIRED', 'PROBE_PRIVATE_RECEIPT_CHANGED',
    'PROBE_PENDING_RESULT_CHANGED',
    'PROBE_PROCESS_IDENTITY_NOT_VERIFIED', 'PROBE_READER_BLOCKED', 'PROBE_RECORD_INVALID',
    'PROBE_REQUEST_ID_INVALID', 'PROBE_REQUEST_SCOPE_INVALID', 'PROBE_RESOURCE_BOUND_FAILED',
    'PROBE_RESULT_ALREADY_EXISTS', 'PROBE_REVIEW_MARKER_CHANGED', 'PROBE_ROOM_NAME_INVALID',
    'PROBE_RUNTIME_LOCATION_CHANGED', 'PROBE_RUNTIME_ALREADY_IMPORTED', 'PROBE_SNAPSHOT_PROOF_INVALID',
    'PROBE_SNAPSHOT_PROOF_MISSING', 'PROBE_SOURCE_BINDING_MISMATCH', 'PROBE_SOURCE_CHANGED',
    'PROBE_SOURCE_PINS_INVALID', 'PROBE_SOURCE_PINS_MISSING', 'PROBE_SOURCE_SET_MISMATCH',
    'PROBE_UNEXPECTED_SIDE_EFFECT', 'PROBE_UNSAFE_PATH',
))


class ProbeError(RuntimeError):
    """Only fixed, non-personal reason codes may cross the proof boundary."""


class PrivateArgumentParser(argparse.ArgumentParser):
    def error(self, _message):
        # argparse normally echoes unrecognized values, including room names.
        raise ProbeError('PROBE_ARGUMENTS_INVALID')


def require(value, reason):
    if not value:
        raise ProbeError(reason)


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf8')


def manifest_digest(hashes):
    return hashlib.sha256(encoded(hashes)).hexdigest()


def _not_link(path):
    info = path.lstat()
    require(not stat.S_ISLNK(info.st_mode) and
            not getattr(info, 'st_file_attributes', 0) & 0x400,
            'PROBE_UNSAFE_PATH')
    return info


def _directory(path, create=False):
    path = Path(path).absolute()
    for part in reversed((path, *path.parents)):
        if part.exists() or part.is_symlink():
            require(stat.S_ISDIR(_not_link(part).st_mode), 'PROBE_UNSAFE_PATH')
        elif create:
            part.mkdir(mode=0o700)
        else:
            raise ProbeError('PROBE_FILE_NOT_FOUND')
    return path


def _read_bytes(path, maximum=MAX_JSON):
    _directory(path.parent)
    before = _not_link(path)
    require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum and
            before.st_nlink == 1, 'PROBE_FILE_INVALID')
    with path.open('rb') as stream:
        raw = stream.read(maximum + 1)
        opened = os.fstat(stream.fileno())
    after = _not_link(path)
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)
    require(identity(before) == identity(opened) == identity(after) and
            len(raw) == before.st_size, 'PROBE_FILE_CHANGED')
    return raw


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'PROBE_JSON_INVALID')
        result[key] = value
    return result


def _constant(_value):
    raise ProbeError('PROBE_JSON_INVALID')


def _parse(raw):
    try:
        value = json.loads(raw.decode('utf8'), object_pairs_hook=_pairs,
                           parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ProbeError('PROBE_JSON_INVALID') from None
    require(type(value) is dict, 'PROBE_JSON_INVALID')
    return value


def _load(path):
    raw = _read_bytes(path)
    return _parse(raw), hashlib.sha256(raw).hexdigest()


def _save_unique(path, value):
    """Publish a complete file exclusively; never replace an existing result."""
    _directory(path.parent, create=True)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.pending')
    created = False
    try:
        with temporary.open('xb') as stream:
            created = True
            stream.write(encoded(value) + b'\n')
            stream.flush()
            os.fsync(stream.fileno())
        # An exclusive hard link is atomic on NTFS, APFS, and the test FS.
        # Windows os.rename is also exclusive, but POSIX rename can overwrite.
        os.link(temporary, path)
    except FileExistsError:
        raise ProbeError('PROBE_RESULT_ALREADY_EXISTS') from None
    finally:
        if created:
            temporary.unlink()


def source_hashes():
    pins = EXPECTED_SOURCE_HASHES
    require(type(pins) is dict and MINIMUM_SOURCES <= set(pins) and
            len(pins) <= 32, 'PROBE_SOURCE_PINS_MISSING')
    require(all(type(name) is str and re.fullmatch(r'[a-z0-9_]+\.py', name) and
                type(digest) is str and DIGEST.fullmatch(digest)
                for name, digest in pins.items()), 'PROBE_SOURCE_PINS_INVALID')
    _directory(RUNTIME)
    require({p.name for p in RUNTIME.iterdir() if p.suffix == '.py'} == set(pins),
            'PROBE_SOURCE_SET_MISMATCH')
    found = {name: hashlib.sha256(_read_bytes(RUNTIME / name, 1024 * 1024)).hexdigest()
             for name in pins}
    require(found == pins, 'PROBE_SOURCE_CHANGED')
    return found


class PinnedSourceLoader(importlib.machinery.SourceFileLoader):
    """Compile the verified source bytes; never consult a .pyc cache."""
    def __init__(self, name, path, digest):
        super().__init__(name, str(path))
        self.expected_digest = digest

    def get_code(self, fullname):
        data = _read_bytes(Path(self.path), 1024 * 1024)
        require(hashlib.sha256(data).hexdigest() == self.expected_digest, 'PROBE_SOURCE_CHANGED')
        return compile(data, self.path, 'exec', dont_inherit=True, optimize=0)


class PinnedSourceFinder:
    def __init__(self, root, hashes):
        self.root = root
        self.hashes = dict(hashes)

    def find_spec(self, fullname, path=None, target=None):
        name = fullname + '.py'
        if path is not None or name not in self.hashes:
            return None
        source = self.root / name
        loader = PinnedSourceLoader(fullname, source, self.hashes[name])
        return importlib.util.spec_from_file_location(fullname, source, loader=loader)


def _runtime():
    source_hashes()
    require(not any(name[:-3] in sys.modules for name in EXPECTED_SOURCE_HASHES),
            'PROBE_RUNTIME_ALREADY_IMPORTED')
    sys.dont_write_bytecode = True
    sys.path[:] = [path for path in sys.path if path and Path(path).resolve() != RUNTIME.resolve()]
    sys.meta_path.insert(0, PinnedSourceFinder(RUNTIME, EXPECTED_SOURCE_HASHES))
    module = importlib.import_module('kakao_read_win')
    require(Path(module.__file__).resolve() == RUNTIME.resolve() / 'kakao_read_win.py',
            'PROBE_RUNTIME_LOCATION_CHANGED')
    require(set(module.SOURCE_NAMES) == set(EXPECTED_SOURCE_HASHES),
            'PROBE_SOURCE_SET_MISMATCH')
    return module


def _doctor(module, candidate=False):
    output = io.StringIO()
    previous = sys.argv
    try:
        sys.argv = ['kakao_read_win.py', 'doctor'] + (['--candidate-x86'] if candidate else [])
        with contextlib.redirect_stdout(output):
            code = module.main()
    finally:
        sys.argv = previous
    report = _parse(output.getvalue().encode('utf8'))
    return code, report


def choose_profile(module, candidate_requested=False):
    code, report = (_doctor(module, candidate=True) if candidate_requested else _doctor(module))
    sha = report.get('installation_sha256')
    require(sha in APP_PROFILES, 'PROBE_APP_NOT_REVIEWED')
    architecture, version = APP_PROFILES[sha]
    require(report.get('app_architecture') == architecture and
            report.get('app_version') == version, 'PROBE_APP_IDENTITY_MISMATCH')
    require(not candidate_requested or architecture == 'x86', 'PROBE_APP_IDENTITY_MISMATCH')
    if architecture == 'x86' and not candidate_requested:
        code, candidate = _doctor(module, candidate=True)
        require(candidate.get('installation_sha256') == sha and
                candidate.get('app_architecture') == architecture and
                candidate.get('app_version') == version, 'PROBE_APP_IDENTITY_CHANGED')
        report = candidate
    require(code == 0 and report.get('status') in ('READY', 'CANDIDATE_READY') and
            report.get('windows_x64') is True, 'PROBE_NOT_READY')
    return architecture


def _integer(value, minimum, maximum, reason):
    require(type(value) is int and minimum <= value <= maximum, reason)
    return value


def _seconds(value, maximum):
    require(type(value) in (int, float) and math.isfinite(value) and
            0 <= value <= maximum, 'PROBE_RESOURCE_BOUND_FAILED')
    return value


def _execution(value, seconds, source_manifest):
    require(type(value) is dict and type(value.get('exit')) is int and
            value['exit'] == 0 and value.get('timeout') is False,
            'PROBE_EXECUTION_FAILED')
    require(type(value.get('job_memory_limit')) is int and
            value['job_memory_limit'] == MEMORY_LIMIT, 'PROBE_RESOURCE_BOUND_FAILED')
    require(value.get('source_execution') == 'verified-source-bytes' and
            value.get('source_manifest_sha256') == source_manifest,
            'PROBE_SOURCE_EXECUTION_NOT_VERIFIED')
    return {'exit': 0, 'timeout': False, 'job_memory_limit': MEMORY_LIMIT,
            'peak_job_commit_bytes': _integer(value.get('peak_job_commit_bytes'), 1,
                MEMORY_LIMIT, 'PROBE_RESOURCE_BOUND_FAILED'),
            'elapsed_sec': _seconds(value.get('elapsed_sec'), seconds),
            'source_execution': 'verified-source-bytes',
            'source_manifest_sha256': source_manifest}


def _request_args(args):
    require(type(args) is list and 1 <= len(args) <= 24 and args[0] == 'messages',
            'PROBE_REQUEST_SCOPE_INVALID')
    values = {}; candidate = False; index = 1
    allowed = {'--name', '--limit', '--hours', '--since', '--until',
               '--account-token', '--key-route'}
    while index < len(args):
        key = args[index]
        require(type(key) is str, 'PROBE_REQUEST_SCOPE_INVALID')
        if key == '--candidate-x86':
            require(not candidate, 'PROBE_REQUEST_SCOPE_INVALID')
            candidate = True; index += 1; continue
        require(key in allowed and key not in values and index + 1 < len(args),
                'PROBE_REQUEST_SCOPE_INVALID')
        value = args[index + 1]
        require(type(value) is str and 0 < len(value) <= 100 and
                all(ord(char) >= 32 for char in value), 'PROBE_REQUEST_SCOPE_INVALID')
        values[key] = value; index += 2
    require(values.get('--limit') == '3' and values.get('--key-route') == 'envelope'
            and '--name' in values, 'PROBE_REQUEST_SCOPE_INVALID')
    hours = values.get('--hours', '')
    require(re.fullmatch(r'[1-9][0-9]{0,4}', hours) and int(hours) <= 87600,
            'PROBE_REQUEST_SCOPE_INVALID')
    if '--account-token' in values:
        require(DIGEST.fullmatch(values['--account-token']), 'PROBE_REQUEST_SCOPE_INVALID')
    return candidate


def validate_record(record, pins, *, owner_matched=False):
    """Return only allowlisted, body-free proof fields; never echo input data."""
    require(type(record) is dict, 'PROBE_RECORD_INVALID')
    require(type(record.get('request_id')) is str and IDENT.fullmatch(record['request_id']),
            'PROBE_REQUEST_ID_INVALID')
    request = record.get('request')
    require(type(request) is dict and record.get('source_hashes') == pins and
            request.get('source_hashes') == pins and
            request.get('source_sha256') == pins.get('room_reader.py'),
            'PROBE_SOURCE_BINDING_MISMATCH')
    candidate = _request_args(request.get('args'))
    result = record.get('result')
    require(type(result) is dict, 'PROBE_RECORD_INVALID')
    if result.get('status') != 'MESSAGES_READ':
        reason = result.get('reason')
        raise ProbeError(reason if reason in SAFE_READER_ERRORS else 'PROBE_READER_BLOCKED')
    inner = _execution(record.get('execution'), 45, manifest_digest(pins))
    outer = _execution(record.get('outer_execution'), 50, manifest_digest(pins))
    connection = result.get('connection')
    require(type(connection) is dict, 'PROBE_APP_IDENTITY_MISSING')
    sha = connection.get('installation_sha256')
    require(sha in APP_PROFILES, 'PROBE_APP_NOT_REVIEWED')
    architecture, version = APP_PROFILES[sha]
    require(connection.get('app_architecture') == architecture and
            candidate == (architecture == 'x86'), 'PROBE_APP_IDENTITY_MISMATCH')
    require(type(connection.get('candidate_only')) is bool and
            connection['candidate_only'] == candidate, 'PROBE_APP_IDENTITY_MISMATCH')
    image = connection.get('image_identity')
    require(type(image) is dict and image.get('mapped_header_match') is True and
            image.get('identity_scope') == 'mapped_pe_headers_only' and
            image.get('mapped_code_hash_verified') is False and
            image.get('target_architecture') == architecture and
            type(image.get('header_fingerprint_sha256')) is str and
            DIGEST.fullmatch(image['header_fingerprint_sha256']),
            'PROBE_IMAGE_IDENTITY_NOT_VERIFIED')
    _integer(image.get('disk_header_bytes_read'), 1, 8192, 'PROBE_IMAGE_IDENTITY_NOT_VERIFIED')
    _integer(image.get('mapped_header_bytes_read'), 1, 32768, 'PROBE_IMAGE_IDENTITY_NOT_VERIFIED')
    require(connection.get('cached_pid_reused') is False and
            connection.get('decryption_material_saved') is False and
            connection.get('discovery') == 'fresh-process-enumeration',
            'PROBE_PROCESS_IDENTITY_NOT_VERIFIED')
    _integer(connection.get('pid'), 1, 2**32 - 1, 'PROBE_PROCESS_IDENTITY_NOT_VERIFIED')
    require(type(connection.get('created_at_filetime')) is str and
            re.fullmatch(r'[1-9][0-9]{0,19}', connection['created_at_filetime']),
            'PROBE_PROCESS_IDENTITY_NOT_VERIFIED')
    for field in ('input_calls', 'clipboard_calls', 'send_calls'):
        _integer(result.get(field), 0, 0, 'PROBE_UNEXPECTED_SIDE_EFFECT')
    for field in ('process_dump_saved', 'key_saved', 'plaintext_db_saved'):
        require(result.get(field) is False, 'PROBE_UNEXPECTED_SIDE_EFFECT')
    require(result.get('messages_read_from_selected_room_only') is True and
            result.get('server_history_fetched') is False and
            result.get('source') == 'windows-local-cache', 'PROBE_REQUEST_SCOPE_INVALID')
    messages = result.get('messages')
    require(type(messages) is list and 1 <= len(messages) <= 3, 'PROBE_NONEMPTY_MESSAGES_REQUIRED')
    for message in messages:
        require(type(message) is dict and type(message.get('text')) is str and
                len(message['text']) <= 4000 and message.get('text_truncated') is False,
                'PROBE_COMPLETE_MESSAGES_REQUIRED')
        stamp = message.get('sent_at_kst')
        require(type(stamp) is str and len(stamp) <= 40, 'PROBE_MESSAGE_TIME_INVALID')
        try:
            parsed = datetime.fromisoformat(stamp)
        except ValueError:
            raise ProbeError('PROBE_MESSAGE_TIME_INVALID') from None
        require(parsed.utcoffset() == timedelta(hours=9), 'PROBE_MESSAGE_TIME_INVALID')
    require(any(message['text'].strip() for message in messages), 'PROBE_NONEMPTY_TEXT_REQUIRED')
    snapshots = result.get('snapshots')
    require(type(snapshots) is list and 2 <= len(snapshots) <= 8,
            'PROBE_SNAPSHOT_PROOF_MISSING')
    summaries = []
    for snapshot in snapshots:
        require(type(snapshot) is dict and snapshot.get('kind') in
                ('room-list', 'selected-messages', 'profiles', 'self-author-identity') and
                snapshot.get('double_read_verified') is True and
                snapshot.get('quick_check') == 'ok', 'PROBE_SNAPSHOT_PROOF_INVALID')
        pages = _integer(snapshot.get('snapshot_pages'), 1, 131072, 'PROBE_SNAPSHOT_PROOF_INVALID')
        authenticated = _integer(snapshot.get('authenticated_pages'), 1, pages,
                                 'PROBE_SNAPSHOT_PROOF_INVALID')
        zeros = _integer(snapshot.get('zero_pages'), 0, pages, 'PROBE_SNAPSHOT_PROOF_INVALID')
        require(authenticated + zeros == pages, 'PROBE_SNAPSHOT_PROOF_INVALID')
        summaries.append({'kind': snapshot['kind'], 'snapshot_pages': pages,
                          'authenticated_pages': authenticated, 'zero_pages': zeros,
                          'double_read_verified': True, 'quick_check': 'ok'})
    require({'room-list', 'selected-messages'} <= {s['kind'] for s in summaries},
            'PROBE_SNAPSHOT_PROOF_MISSING')
    envelope = result.get('envelope')
    require(type(envelope) is dict and all(envelope.get(key) is True for key in
            ('ikm_container_wrap_integrity', 'target_wrap_integrity', 'target_page_hmac')),
            'PROBE_KEY_AUTHENTICATION_MISSING')
    require(type(owner_matched) is bool, 'PROBE_OWNER_ACK_REQUIRED')
    return {
        'schema': SCHEMA, 'status': 'PASS' if owner_matched else 'READ_VERIFIED_PENDING_OWNER_MATCH',
        'capability': 'reader-only', 'stable_eligible': False,
        'candidate_only': candidate,
        'maintainer_review_required': True, 'automatically_promotes_support': False,
        'app': {'sha256': sha, 'architecture': architecture, 'version': version},
        'image_identity': {'mapped_header_match': True,
            'identity_scope': 'mapped_pe_headers_only', 'mapped_code_hash_verified': False,
            'target_architecture': architecture,
            'fingerprint_sha256': image['header_fingerprint_sha256']},
        'source_verification': 'PINNED_RELEASE_FILES', 'source_hashes': dict(pins),
        'source_manifest_sha256': manifest_digest(pins),
        'message_count': len(messages), 'owner_match_ack': owner_matched,
        'owner_match_method': 'manual_original_text_and_time' if owner_matched else 'NOT_RUN',
        'independent_log_id_comparison': 'NOT_RUN',
        'execution': {'inner': inner, 'outer': outer}, 'snapshots': summaries,
        'resource_observations': {
            'app_private_before': _integer(result.get('app_private_before'), 1, APP_PRIVATE_LIMIT - 1,
                                           'PROBE_RESOURCE_BOUND_FAILED'),
            'app_private_after': _integer(result.get('app_private_after'), 1, APP_PRIVATE_LIMIT - 1,
                                          'PROBE_RESOURCE_BOUND_FAILED'),
            'process_read_bytes': _integer(result.get('process_read_bytes'), 1, READ_LIMIT,
                                           'PROBE_RESOURCE_BOUND_FAILED'),
            'elapsed_sec': _seconds(result.get('elapsed_sec'), 40)},
        'safety': {'input_calls': 0, 'clipboard_calls': 0, 'send_calls': 0,
                   'process_dump_saved': False, 'key_saved': False,
                   'plaintext_db_saved': False, 'server_history_fetched': False},
        'authentication': {'ikm_wrap': True, 'selected_key_wrap': True, 'selected_page_hmac': True},
        'contains_chat_content': False, 'contains_account_or_room_identifiers': False,
    }


def private_state():
    require(os.name == 'nt' and struct.calcsize('P') == 8 and sys.version_info >= (3, 11),
            'WINDOWS_X64_PYTHON_REQUIRED')
    local = os.environ.get('LOCALAPPDATA')
    require(type(local) is str and bool(local), 'PROBE_LOCALAPPDATA_REQUIRED')
    base = _directory(Path(local) / 'KakaoReader', create=True)
    return _directory(base / 'receipts', create=True), _directory(base / 'proofs', create=True)


def _ident(value):
    require(type(value) is str and IDENT.fullmatch(value), 'PROBE_REQUEST_ID_INVALID')
    return value


def _binding_path(state, ident):
    return state / ('probe-' + _ident(ident) + '.json')


def _record_bound(state, ident, pins):
    binding, _ = _load(_binding_path(state, ident))
    require(binding.get('schema') == SCHEMA and binding.get('request_id') == ident and
            binding.get('source_hashes') == pins, 'PROBE_BINDING_MISMATCH')
    record, digest = _load(state / (ident + '.json'))
    require(binding.get('private_receipt_sha256') == digest and record.get('request_id') == ident,
            'PROBE_PRIVATE_RECEIPT_CHANGED')
    validate_record(record, pins)
    return record, digest


def accept_record(record, state, proofs, pins):
    proof = validate_record(record, pins)
    ident = _ident(record['request_id'])
    saved, digest = _load(state / (ident + '.json'))
    # read() adds receipt_path in memory only. Do not put it in a shareable proof.
    require({key: value for key, value in record.items() if key != 'receipt_path'} == saved,
            'PROBE_PRIVATE_RECEIPT_CHANGED')
    validate_record(saved, pins)
    binding_path = _binding_path(state, ident)
    binding = {'schema': SCHEMA, 'request_id': ident,
        'private_receipt_sha256': digest, 'source_hashes': pins}
    if binding_path.exists():
        previous, _ = _load(binding_path)
        require(previous == binding, 'PROBE_BINDING_MISMATCH')
    else:
        _save_unique(binding_path, binding)
    name = 'probe-' + ident + '-pending.json'
    if (proofs / name).exists():
        previous, _ = _load(proofs / name)
        require(previous == proof, 'PROBE_PENDING_RESULT_CHANGED')
    else:
        _save_unique(proofs / name, proof)
    return proof, ident, name


def local_review(state, ident, pins):
    record, digest = _record_bound(state, _ident(ident), pins)
    rows = record['result']['messages']
    # This explicit local-only view is the sole path that prints message text.
    view = {'privacy': 'PRIVATE_LOCAL_REVIEW_DO_NOT_SHARE',
            'instruction': 'Compare every message with its original text and time. Confirm only if all match.',
            'messages': [{'number': index + 1, 'text': row['text'],
                'sent_at_kst': row.get('sent_at_kst')} for index, row in enumerate(rows)]}
    marker = state / ('probe-' + ident + '-reviewed.json')
    value = {'schema': SCHEMA, 'private_receipt_sha256': digest, 'local_review_shown': True}
    if marker.exists():
        previous, _ = _load(marker)
        require(previous == value, 'PROBE_REVIEW_MARKER_CHANGED')
    else:
        _save_unique(marker, value)
    return view


def confirm(state, proofs, ident, pins, matched):
    require(matched is True, 'PROBE_OWNER_ACK_REQUIRED')
    record, digest = _record_bound(state, _ident(ident), pins)
    marker = state / ('probe-' + ident + '-reviewed.json')
    require(marker.exists(), 'PROBE_LOCAL_REVIEW_REQUIRED')
    value, _ = _load(marker)
    require(value == {'schema': SCHEMA, 'private_receipt_sha256': digest,
                      'local_review_shown': True}, 'PROBE_REVIEW_MARKER_CHANGED')
    proof = validate_record(record, pins, owner_matched=True)
    name = 'probe-' + ident + '-confirmed.json'
    path = proofs / name
    if path.exists():
        previous, _ = _load(path)
        require(previous == proof, 'PROBE_CONFIRMED_RESULT_CHANGED')
    else:
        _save_unique(path, proof)
    return proof, name


def _run_args(args, candidate):
    require(type(args.name) is str and 1 <= len(args.name) <= 100 and
            all(ord(char) >= 32 for char in args.name), 'PROBE_ROOM_NAME_INVALID')
    require(args.account_token is None or DIGEST.fullmatch(args.account_token),
            'ACCOUNT_TOKEN_INVALID')
    return SimpleNamespace(command='messages', name=args.name, hours=87600, limit=3,
        after_id=None, before_id=None, since=args.since, until=args.until,
        query=None, cursor=None, key_route='envelope', account_token=args.account_token,
        candidate_x86=candidate, request_id=None)


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8', errors='strict')
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0].startswith('--') and argv[0] not in ('--help', '-h'):
        argv.insert(0, 'run')
    parser = PrivateArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    run = commands.add_parser('run', help='Read at most three messages from one exact room')
    run.add_argument('--name', required=True)
    run.add_argument('--candidate-x86', action='store_true',
                     help='Explicitly select the reviewed x86 candidate when both app files exist')
    run.add_argument('--account-token')
    run.add_argument('--since')
    run.add_argument('--until')
    run.add_argument('--show-local-review', action='store_true')
    resume = commands.add_parser('resume', help='Fetch the same existing reader request; never execute again')
    resume.add_argument('--request-id', required=True)
    review = commands.add_parser('review', help='Display messages locally for the owner comparison')
    review.add_argument('--request-id', required=True)
    review.add_argument('--show-local-review', action='store_true', required=True)
    final = commands.add_parser('confirm', help='Attest that every displayed original text/time matched')
    final.add_argument('--request-id', required=True)
    final.add_argument('--matched', action='store_true', required=True)
    state = proofs = None; ident = None
    try:
        args = parser.parse_args(argv)
        pins = source_hashes()
        state, proofs = private_state()
        if args.command == 'review':
            view = local_review(state, args.request_id, pins)
            print(json.dumps(view, ensure_ascii=False, indent=2)); return 0
        if args.command == 'confirm':
            proof, name = confirm(state, proofs, args.request_id, pins, args.matched)
            ident = args.request_id
        else:
            if args.command == 'resume':
                ident = _ident(args.request_id)
                if _binding_path(state, ident).exists():
                    record, _ = _record_bound(state, ident, pins)
                else:
                    module = _runtime()
                    record = module.read(SimpleNamespace(command='resume', request_id=ident))
            else:
                module = _runtime()
                architecture = choose_profile(module, candidate_requested=args.candidate_x86)
                arguments = _run_args(args, architecture == 'x86')
                from reader_queries import query_spec
                query_spec(arguments)
                source_hashes()
                record = module.read(arguments)
            if type(record) is dict and type(record.get('request_id')) is str and IDENT.fullmatch(record['request_id']):
                ident = record['request_id']
            require(source_hashes() == pins, 'PROBE_SOURCE_CHANGED')
            proof, ident, name = accept_record(record, state, proofs, pins)
            if args.command == 'run' and args.show_local_review:
                print(json.dumps(local_review(state, ident, pins), ensure_ascii=False, indent=2))
        print(json.dumps({'proof': proof, 'request_id': ident,
            'share_only': 'KakaoReader/proofs/' + name,
            'next_action': 'Share only the proof JSON; keep receipts and local review private.' if proof['status'] == 'PASS'
                else 'Review the original text/time locally, then run confirm --request-id <id> --matched.'},
            ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        reason = (str(exc) if isinstance(exc, ProbeError) and
                  str(exc) in SAFE_PROBE_ERRORS | SAFE_READER_ERRORS else 'PROBE_INTERNAL_ERROR')
        failure = {'schema': SCHEMA, 'status': 'BLOCKED', 'reason': reason,
            'stable_eligible': False, 'contains_chat_content': False,
            'contains_account_or_room_identifiers': False}
        output = {'proof': failure}
        if ident is not None:
            output['request_id'] = ident
            output['next_action'] = 'Preserve this request ID; resume fetches it without a new app read.'
        if proofs is not None:
            name = 'probe-' + uuid.uuid4().hex + '-blocked.json'
            try:
                _save_unique(proofs / name, failure)
                output['share_only'] = 'KakaoReader/proofs/' + name
            except Exception:
                output['proof_file_saved'] = False
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
