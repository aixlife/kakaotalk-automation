"""Opt-in stable reader updates. No app installation, credentials, schedules or sends.

The publisher trust boundary is the fixed HTTPS GitHub repository plus an
immutable commit and complete file hashes; this is not a digital signature.
A fixed bootstrap stores immutable reader payloads outside skill discovery.
"""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
import io

from release_manifest import (ManifestError, parse_manifest, validate_manifest,
                              canonical_bytes, validate_path, validate_runtime_profiles)

REPO = 'aixlife/kakaotalk-automation'
API = 'https://api.github.com/repos/' + REPO
RAW = 'https://raw.githubusercontent.com/' + REPO
ASSET = 'verified-reader-update.json'
REVISION = 1
ROOT_NAME = '.kakaotalk-reader'
MAX_ARCHIVE = 8 * 1024 * 1024
MAX_EXPANDED = 16 * 1024 * 1024
MAX_FILE = 1024 * 1024
CHECK_INTERVAL = 3600
UPDATE_SECONDS = 30
BOOTSTRAP_FILES = ('reader_manager.py', 'release_manifest.py')
ALLOWED_HOSTS = frozenset(('api.github.com', 'github.com', 'raw.githubusercontent.com',
    'codeload.github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'))
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
HEX40 = re.compile(r'[0-9a-f]{40}\Z')
TAG = re.compile(r'v[0-9]+\.[0-9]+\.[0-9]+\Z')
# Kept in the manually installed bootstrap. Never import an unchecked payload
# helper to obtain this command; compile its exact release-pinned bytes first.
SOURCE_BOOTSTRAP = """import hashlib,json,pathlib,sys,types
root=pathlib.Path(sys.argv[1]); hashes=json.loads(sys.argv[2]); entry=sys.argv[3]; args=sys.argv[4:]
path=root/'reader_source.py'
if not path.is_file() or not 0<path.stat().st_size<=1048576: raise RuntimeError('READER_SOURCE_BOOTSTRAP_INVALID')
with path.open('rb') as stream: body=stream.read(1048577)
if len(body)>1048576 or hashlib.sha256(body).hexdigest()!=hashes.get('reader_source.py'): raise RuntimeError('READER_SOURCE_BOOTSTRAP_CHANGED')
module=types.ModuleType('reader_source'); module.__file__=str(path); module.__verified_source_sha256__=hashes['reader_source.py']
sys.modules['reader_source']=module
exec(compile(body,str(path),'exec',dont_inherit=True,optimize=0),module.__dict__)
module.execute(root,hashes,entry,args)
"""


class UpdateError(Exception):
    def __init__(self, reason, **details):
        super().__init__(reason)
        self.reason = reason
        self.details = details


class NetworkUnavailable(UpdateError):
    pass


def require(condition, reason):
    if not condition:
        raise UpdateError(reason)


def safe_path(value):
    path = Path(os.path.abspath(Path(value).expanduser()))
    require('..' not in Path(value).parts, 'PARENT_TRAVERSAL')
    for part in (path, *path.parents):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        require(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400,
                'LINK_OR_REPARSE_POINT')
        if stat.S_ISREG(info.st_mode):
            require(info.st_nlink == 1, 'HARD_LINK_UNSUPPORTED')
    return path


def project_path(value):
    path = safe_path(value)
    require(path.is_dir() and path != Path(path.anchor) and path != Path.home().absolute(),
            'EXISTING_PROJECT_REQUIRED')
    return path


def load_json(path, maximum=262144):
    path = safe_path(path)
    with path.open('rb') as stream:
        raw = stream.read(maximum + 1)
    require(len(raw) <= maximum, 'STATE_SIZE_LIMIT')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    try:
        return json.loads(raw.decode('utf8'), object_pairs_hook=pairs)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise UpdateError('INVALID_STATE_JSON') from exc


def write_json(path, value, *, absent=False):
    path = safe_path(path)
    temporary = path.with_name(path.name + '.pending-' + uuid.uuid4().hex)
    data = canonical_bytes(value)
    require(len(data) <= 262144, 'STATE_SIZE_LIMIT')
    with temporary.open('xb') as stream:
        os.chmod(temporary, 0o600)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    safe_path(path)
    if absent:
        # A racing writer must never be replaced during creation/recovery.
        os.link(temporary, path, follow_symlinks=False)
        temporary.unlink()
    else:
        os.replace(temporary, path)


@contextmanager
def manager_lock(root):
    """The lock file persists; the OS releases ownership when the process dies."""
    path = safe_path(root / 'manager.lock')
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    locked = False
    try:
        require(os.fstat(descriptor).st_nlink == 1, 'LOCK_HARD_LINK')
        if os.fstat(descriptor).st_size == 0:
            os.write(descriptor, b'\0')
        require(os.fstat(descriptor).st_size == 1, 'UNKNOWN_LOCK_FORMAT')
        os.lseek(descriptor, 0, os.SEEK_SET)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, BlockingIOError) as exc:
            raise UpdateError('UPDATE_BUSY') from exc
        locked = True
        yield
    finally:
        if locked and os.name == 'nt':
            import msvcrt
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        os.close(descriptor)


def rename_new(source, target):
    """Directory publication must refuse every existing destination."""
    source, target = safe_path(source), safe_path(target)
    if os.name == 'nt':
        os.rename(source, target)
        return
    import ctypes
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == 'darwin':
        call = library.renamex_np
        call.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        result = call(os.fsencode(source), os.fsencode(target), 4)
    elif sys.platform.startswith('linux') and hasattr(library, 'renameat2'):
        call = library.renameat2
        call.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        result = call(-100, os.fsencode(source), -100, os.fsencode(target), 1)
    else:
        raise UpdateError('EXCLUSIVE_RENAME_UNAVAILABLE')
    if result:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), str(target))


def deadline_check(deadline):
    require(time.monotonic() < deadline, 'UPDATE_TIME_LIMIT')


def release_id(manifest):
    # Metadata-only releases may reuse identical source files with new proof.
    return hashlib.sha256(canonical_bytes(manifest)).hexdigest()


def stream_hash(stream, maximum):
    digest, count = hashlib.sha256(), 0
    while True:
        block = stream.read(min(65536, maximum+1-count))
        if not block:
            return digest.hexdigest()
        count += len(block)
        require(count <= maximum, 'FILE_SIZE_LIMIT')
        digest.update(block)


def trusted_url(url):
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == 'https' and parsed.hostname in ALLOWED_HOSTS and
            parsed.port in (None, 443) and not parsed.username and not parsed.password and
            not parsed.fragment, 'UNTRUSTED_UPDATE_URL')
    return url


class _Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        trusted_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class _DirectHttpTransport:
    """No token, custom origin, proxy credential or caller-selected channel URL."""
    def get(self, url, maximum, deadline):
        trusted_url(url)
        deadline_check(deadline)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _Redirects())
        request = urllib.request.Request(url, headers={
            'User-Agent': 'KakaoReaderManager/1', 'Accept': 'application/vnd.github+json'})
        try:
            with opener.open(request, timeout=min(5, max(.1, deadline-time.monotonic()))) as response:
                require(response.status == 200, 'HTTP_STATUS')
                content = response.headers.get('Content-Length')
                require(content is None or (content.isdigit() and int(content) <= maximum),
                        'DOWNLOAD_SIZE_LIMIT')
                result = bytearray()
                while True:
                    deadline_check(deadline)
                    block = response.read(min(65536, maximum + 1-len(result)))
                    if not block:
                        return bytes(result)
                    result.extend(block)
                    require(len(result) <= maximum, 'DOWNLOAD_SIZE_LIMIT')
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            # Do not copy signed redirect URLs or proxy details into diagnostics.
            raise NetworkUnavailable('UPDATE_NETWORK_UNAVAILABLE') from exc


class HttpTransport:
    """Bound DNS, redirects and socket I/O in one disposable, no-app child."""
    def get(self, url, maximum, deadline):
        trusted_url(url)
        deadline_check(deadline)
        require(type(maximum) is int and 0 < maximum <= MAX_ARCHIVE, 'DOWNLOAD_SIZE_LIMIT')
        seconds = min(6.0, deadline-time.monotonic())
        command = [sys.executable, '-E', '-s', '-B', str(Path(__file__).resolve()),
                   '__fetch__', url, str(maximum), str(seconds)]
        worker = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL,
                                  creationflags=0x08000000 if os.name == 'nt' else 0)
        try:
            output, _ = worker.communicate(timeout=seconds)
        except subprocess.TimeoutExpired as exc:
            worker.kill()
            worker.communicate(timeout=2)
            raise NetworkUnavailable('UPDATE_NETWORK_TIMEOUT') from exc
        if worker.returncode == 94:
            raise NetworkUnavailable('UPDATE_NETWORK_TIMEOUT')
        require(worker.returncode == 0, 'UPDATE_FETCH_WORKER_FAILED')
        if output == b'NETWORK\n':
            raise NetworkUnavailable('UPDATE_NETWORK_UNAVAILABLE')
        require(output.startswith(b'OK\n') and len(output)-3 <= maximum, 'UPDATE_FETCH_REJECTED')
        return output[3:]


def fetch_worker(arguments):
    # This private protocol is bootstrap code only, never downloaded code.
    try:
        require(len(arguments) == 3, 'FETCH_ARGUMENTS_INVALID')
        url, maximum, seconds = arguments[0], int(arguments[1]), float(arguments[2])
        require(0 < maximum <= MAX_ARCHIVE and 0 < seconds <= 6, 'FETCH_ARGUMENTS_INVALID')
        # A parent crash must not leave a DNS-blocked fetch process behind.
        import threading
        watchdog = threading.Timer(seconds, lambda: os._exit(94))
        watchdog.daemon = True
        watchdog.start()
        try:
            body = _DirectHttpTransport().get(url, maximum, time.monotonic()+seconds)
        finally:
            watchdog.cancel()
        sys.stdout.buffer.write(b'OK\n'+body)
    except NetworkUnavailable:
        sys.stdout.buffer.write(b'NETWORK\n')
    except (UpdateError, OSError, ValueError):
        sys.stdout.buffer.write(b'BLOCKED\n')
    return 0


def json_bytes(raw):
    require(len(raw) <= 262144, 'RELEASE_METADATA_LIMIT')
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise UpdateError('RELEASE_METADATA_INVALID') from exc
    require(isinstance(value, dict), 'RELEASE_METADATA_INVALID')
    return value


def fetch_release(transport, deadline):
    release = json_bytes(transport.get(API+'/releases/latest', 262144, deadline))
    tag = release.get('tag_name')
    require(isinstance(tag, str) and TAG.fullmatch(tag) and release.get('draft') is False and
            release.get('prerelease') is False, 'STABLE_RELEASE_REQUIRED')
    assets = release.get('assets')
    require(isinstance(assets, list) and len(assets) <= 100, 'RELEASE_ASSETS_INVALID')
    selected = [a for a in assets if isinstance(a, dict) and a.get('name') == ASSET]
    url = 'https://github.com/'+REPO+'/releases/download/'+tag+'/'+ASSET
    require(len(selected) == 1 and selected[0].get('browser_download_url') == url,
            'VERIFIED_MANIFEST_MISSING')
    manifest = parse_manifest(transport.get(url, 262144, deadline))
    require(manifest['tag'] == tag and manifest['manager_revision'] == REVISION,
            'RELEASE_IDENTITY_MISMATCH')
    ref = json_bytes(transport.get(API+'/git/ref/tags/'+tag, 65536, deadline)).get('object')
    require(isinstance(ref, dict) and HEX40.fullmatch(str(ref.get('sha', ''))), 'TAG_REFERENCE_INVALID')
    if ref.get('type') == 'tag':
        ref = json_bytes(transport.get(API+'/git/tags/'+ref['sha'], 65536, deadline)).get('object')
    require(isinstance(ref, dict) and ref.get('type') == 'commit' and
            ref.get('sha') == manifest['commit'], 'TAG_COMMIT_MISMATCH')
    report_path = urllib.parse.quote(manifest['report']['path'], safe='/')
    report = transport.get(RAW+'/'+manifest['commit']+'/'+report_path,
                           262144, deadline)
    require(hashlib.sha256(report).hexdigest() == manifest['report']['sha256'],
            'QA_REPORT_HASH_MISMATCH')
    return manifest


def app_metadata():
    """Read installation files only; no process, account, window or DB query."""
    require(os.name == 'nt' and struct.calcsize('P') == 8 and sys.version_info >= (3, 11),
            'WINDOWS_X64_PYTHON_REQUIRED')
    paths = {
        Path(os.environ.get('ProgramFiles', r'C:\Program Files'))/'Kakao/KakaoTalk/KakaoTalk.exe',
        Path(os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)'))/'Kakao/KakaoTalk/KakaoTalk.exe'}
    paths = [safe_path(path) for path in paths if path.is_file()]
    require(len(paths) == 1, 'APP_NOT_FOUND_OR_NOT_UNIQUE')
    path = paths[0]
    require(64 <= path.stat().st_size <= 256*1024*1024, 'APP_FILE_SIZE_LIMIT')
    with path.open('rb') as stream:
        header = stream.read(64)
        require(len(header) == 64 and header[:2] == b'MZ', 'APP_PE_INVALID')
        offset = struct.unpack_from('<I', header, 0x3c)[0]
        require(64 <= offset <= min(1024*1024, path.stat().st_size-26), 'APP_PE_INVALID')
        stream.seek(offset)
        pe = stream.read(26)
        require(len(pe) == 26 and pe[:4] == b'PE\0\0', 'APP_PE_INVALID')
        machine, magic = struct.unpack_from('<H', pe, 4)[0], struct.unpack_from('<H', pe, 24)[0]
        architecture = {(0x14c, 0x10b): 'x86', (0x8664, 0x20b): 'x64'}.get((machine, magic))
        require(architecture is not None, 'APP_ARCHITECTURE_UNSUPPORTED')
        stream.seek(0)
        digest = stream_hash(stream,256*1024*1024)
    return {'architecture': architecture, 'sha256': digest}


def compatible(manifest, app):
    return any(item['architecture'] == app['architecture'] and item['app_sha256'] == app['sha256']
               for item in manifest['compatible_apps'])


def file_hash(path):
    path = safe_path(path)
    require(path.is_file() and path.stat().st_size <= MAX_FILE, 'PAYLOAD_FILE_SIZE_LIMIT')
    with path.open('rb') as stream:
        return stream_hash(stream,MAX_FILE)


def verify_package(path, expected=None):
    path = safe_path(path)
    metadata = safe_path(path/'release.json')
    require(metadata.is_file() and metadata.stat().st_size <= 262144, 'PAYLOAD_METADATA_SIZE_LIMIT')
    with metadata.open('rb') as stream:
        manifest = parse_manifest(stream.read(262145))
    if expected is not None:
        require(manifest == expected, 'PAYLOAD_MANIFEST_CHANGED')
    require(path.name == release_id(manifest) or path.name.startswith('.stage-'),
            'PAYLOAD_DIRECTORY_MISMATCH')
    files = {}
    count = total = directory_count = 0
    expected_directories = {parent.as_posix() for name in manifest['files']
                            for parent in Path(name).parents if str(parent) != '.'}
    for folder, directories, names in os.walk(path, followlinks=False):
        for name in directories:
            directory = safe_path(Path(folder)/name)
            directory_count += 1
            require(directory_count <= 128 and directory.relative_to(path).as_posix()
                    in expected_directories, 'LOCAL_PAYLOAD_MODIFIED')
        for name in names:
            file = safe_path(Path(folder)/name)
            count += 1
            require(count <= 129, 'PAYLOAD_ENTRY_LIMIT')
            require(file.stat().st_size <= MAX_FILE, 'PAYLOAD_FILE_SIZE_LIMIT')
            total += file.stat().st_size
            require(total <= MAX_EXPANDED, 'PAYLOAD_SIZE_LIMIT')
            relative = file.relative_to(path).as_posix()
            if relative == 'release.json':
                continue
            files[relative] = file_hash(file)
    require(files == manifest['files'], 'LOCAL_PAYLOAD_MODIFIED')
    with (path/'scripts/windows/room_reader.py').open('rb') as stream:
        validate_runtime_profiles(stream.read(MAX_FILE+1), manifest['compatible_apps'])
    return manifest


def check_dependencies(path):
    requirement = safe_path(path/'scripts/windows/requirements.txt')
    require(requirement.is_file() and requirement.stat().st_size <= 4096, 'REQUIREMENTS_MISSING')
    missing, seen = [], set()
    for line in requirement.read_text(encoding='utf8').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        match = re.fullmatch(r'(cryptography|apsw)==([0-9]+(?:\.[0-9]+)+)', line, re.IGNORECASE)
        require(match is not None, 'DEPENDENCY_POLICY_UNSUPPORTED')
        name, required = match.groups()
        name = name.lower()
        require(name not in seen, 'DEPENDENCY_POLICY_UNSUPPORTED')
        seen.add(name)
        try:
            present = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            present = None
        if present != required:
            missing.append(name+'=='+required)
    require('cryptography' in seen, 'DEPENDENCY_POLICY_UNSUPPORTED')
    if missing:
        raise UpdateError('DEPENDENCY_MISSING', required=missing,
                          action='Install the documented pinned requirements explicitly; updater never runs pip.')


def stage_package(root, manifest, archive, deadline):
    require(len(archive) <= MAX_ARCHIVE, 'ARCHIVE_SIZE_LIMIT')
    packages = safe_path(root/'packages')
    packages.mkdir(exist_ok=True)
    require(len(list(packages.iterdir())) <= 64, 'PACKAGE_RETENTION_LIMIT')
    destination = safe_path(packages/release_id(manifest))
    if destination.exists():
        verify_package(destination, manifest)
        check_dependencies(destination)
        return destination
    prefix = 'kakaotalk-automation-'+manifest['commit']+'/'
    payload = prefix+'skills/kakaotalk-mac/'
    selected = {}
    seen, member_names = {}, set()
    expanded = 0
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
            members = zipped.infolist()
            require(len(members) <= 512, 'ARCHIVE_ENTRY_LIMIT')
            for member in members:
                deadline_check(deadline)
                name = member.filename
                require(name.startswith(prefix) and '\\' not in name and '\0' not in name,
                        'ARCHIVE_PATH_INVALID')
                validate_path(name.rstrip('/'))
                parts = name.rstrip('/').split('/')
                require(name not in member_names, 'ARCHIVE_DUPLICATE_MEMBER')
                member_names.add(name)
                for i in range(1, len(parts)+1):
                    part = '/'.join(parts[:i])
                    key = part.casefold()
                    require(key not in seen or seen[key] == part, 'ARCHIVE_CASE_COLLISION')
                    seen[key] = part
                mode = member.external_attr >> 16
                require(stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR) and
                        not (member.flag_bits & 1), 'ARCHIVE_LINK_OR_ENCRYPTION')
                require(member.file_size <= MAX_FILE and member.compress_type in
                        (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED), 'ARCHIVE_MEMBER_INVALID')
                expanded += member.file_size
                require(expanded <= MAX_EXPANDED, 'ARCHIVE_EXPANSION_LIMIT')
                if member.is_dir():
                    continue
                if name.startswith(payload):
                    relative = name[len(payload):]
                    require(relative in manifest['files'], 'ARCHIVE_UNEXPECTED_PAYLOAD_FILE')
                    with zipped.open(member) as stream:
                        body = stream.read(MAX_FILE + 1)
                    require(len(body) <= MAX_FILE, 'ARCHIVE_MEMBER_INVALID')
                    require(hashlib.sha256(body).hexdigest() == manifest['files'][relative],
                            'ARCHIVE_FILE_HASH_MISMATCH')
                    require(relative not in selected, 'ARCHIVE_DUPLICATE_MEMBER')
                    selected[relative] = body
    except (zipfile.BadZipFile, RuntimeError) as exc:
        raise UpdateError('ARCHIVE_INVALID') from exc
    require(set(selected) == set(manifest['files']), 'ARCHIVE_PAYLOAD_INCOMPLETE')
    stage = safe_path(packages/('.stage-'+uuid.uuid4().hex))
    stage.mkdir(mode=0o700)
    for name, body in selected.items():
        file = safe_path(stage/name)
        file.parent.mkdir(parents=True, exist_ok=True)
        with file.open('xb') as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
    write_json(stage/'release.json', manifest, absent=True)
    verify_package(stage, manifest)
    check_dependencies(stage)
    rename_new(stage, destination)
    return destination


def pointer_valid(value):
    require(isinstance(value, dict) and set(value) ==
            {'schema','current','previous','highest_sequence'}, 'ACTIVE_STATE_INVALID')
    require(value['schema'] == 1 and HEX64.fullmatch(str(value['current'])) and
            (value['previous'] is None or HEX64.fullmatch(str(value['previous']))) and
            type(value['highest_sequence']) is int and value['highest_sequence'] > 0,
            'ACTIVE_STATE_INVALID')
    return value


class Manager:
    def __init__(self, project, agent):
        self.project = project_path(project)
        require(agent in ('codex', 'claude'), 'AGENT_INVALID')
        self.agent = agent
        self.root = safe_path(self.project/ROOT_NAME)
        self.state = safe_path(self.root/'state'/agent)
        self.active_path = self.state/'active.json'

    def config(self):
        value = load_json(self.state/'config.json')
        require(isinstance(value, dict) and set(value) ==
                {'schema','manager_revision','repo','agent','enabled'}, 'CONFIG_INVALID')
        require(value == {'schema':1,'manager_revision':REVISION,'repo':REPO,
                          'agent':self.agent,'enabled':value['enabled']} and
                type(value['enabled']) is bool, 'CONFIG_INVALID')
        return value

    def active(self):
        if not self.active_path.exists():
            return None
        return pointer_valid(load_json(self.active_path))

    def package(self, digest):
        require(HEX64.fullmatch(str(digest)), 'PAYLOAD_ID_INVALID')
        return safe_path(self.root/'packages'/digest)

    def validate_pointer(self, value):
        pointer_valid(value)
        current = verify_package(self.package(value['current']))
        require(current['sequence'] == value['highest_sequence'], 'ACTIVE_SEQUENCE_INVALID')
        if value['previous']:
            verify_package(self.package(value['previous']))
        return current

    def recover(self):
        path = self.state/'transaction.json'
        if not path.exists():
            return
        journal = load_json(path)
        require(isinstance(journal, dict) and set(journal) ==
                {'schema','transaction','phase','before','after'}, 'RECOVERY_CONFLICT')
        require(journal['schema'] == 1 and re.fullmatch('[0-9a-f]{32}', str(journal['transaction']))
                and journal['phase'] in ('PREPARED','COMMITTED','ROLLED_BACK'), 'RECOVERY_CONFLICT')
        after = pointer_valid(journal['after'])
        before = journal['before']
        if before is not None:
            pointer_valid(before)
        if journal['phase'] != 'PREPARED':
            return
        if before is not None:
            self.validate_pointer(before)
        self.validate_pointer(after)
        actual = self.active()
        if actual == after:
            journal['phase'] = 'COMMITTED'
        elif actual == before:
            journal['phase'] = 'ROLLED_BACK'
        elif actual is None and before is not None:
            write_json(self.active_path, before, absent=True)
            journal['phase'] = 'ROLLED_BACK'
        else:
            raise UpdateError('RECOVERY_CONFLICT')
        write_json(path, journal)

    def activate(self, manifest):
        verify_package(self.package(release_id(manifest)), manifest)
        before = self.active()
        if before:
            self.validate_pointer(before)
            require(manifest['sequence'] > before['highest_sequence'], 'UPDATE_ROLLBACK_REJECTED')
        after = {'schema':1,'current':release_id(manifest),
                 'previous':before['current'] if before else None,
                 'highest_sequence':manifest['sequence']}
        journal = {'schema':1,'transaction':uuid.uuid4().hex,'phase':'PREPARED',
                   'before':before,'after':after}
        write_json(self.state/'transaction.json', journal)
        if before:
            write_json(self.state/'active.previous.json', before)
        write_json(self.active_path, after, absent=before is None)
        journal['phase'] = 'COMMITTED'
        write_json(self.state/'transaction.json', journal)

    def check(self, app, *, force=False, transport=None, now=None):
        require(self.config()['enabled'], 'AUTO_UPDATES_DISABLED')
        require(isinstance(app, dict) and set(app) == {'architecture','sha256'} and
                app['architecture'] in ('x86','x64') and HEX64.fullmatch(str(app['sha256'])),
                'APP_IDENTITY_INVALID')
        transport = transport or HttpTransport()
        now = time.time() if now is None else now
        with manager_lock(self.root):
            self.recover()
            active = self.active()
            current = self.validate_pointer(active) if active else None
            cache_path = self.state/'check.json'
            cached = load_json(cache_path) if cache_path.exists() else None
            if cached is not None:
                require(type(cached) is dict and set(cached) == {'at','app','current'} and
                        type(cached['at']) in (int,float) and
                        type(cached['app']) is dict and set(cached['app']) == {'architecture','sha256'} and
                        cached['app']['architecture'] in ('x86','x64') and
                        HEX64.fullmatch(str(cached['app']['sha256'])) and
                        (cached['current'] is None or HEX64.fullmatch(str(cached['current']))),
                        'CHECK_STATE_INVALID')
            if (not force and cached and cached.get('app') == app and active and
                    cached.get('current') == active['current'] and
                    type(cached.get('at')) in (int,float) and 0 <= now-cached['at'] < CHECK_INTERVAL):
                require(current is not None and compatible(current, app), 'NO_VERIFIED_UPDATE')
                check_dependencies(self.package(active['current']))
                return {'status':'CURRENT','tag':current['tag'],'checked':'cached'}
            # Once a fresh check starts, its failure must not resurrect an older
            # successful cache entry on the very next reader request.
            write_json(cache_path, {'at':now,'app':app,'current':None})
            deadline = time.monotonic()+UPDATE_SECONDS
            try:
                manifest = fetch_release(transport, deadline)
            except NetworkUnavailable:
                if current is None or not compatible(current, app):
                    raise
                check_dependencies(self.package(active['current']))
                return {'status':'CURRENT_OFFLINE','tag':current['tag'],'checked':'network_unavailable'}
            require(compatible(manifest, app), 'NO_VERIFIED_UPDATE')
            if active:
                require(manifest['sequence'] >= active['highest_sequence'], 'UPDATE_ROLLBACK_REJECTED')
                if manifest['sequence'] == active['highest_sequence']:
                    require(manifest == current, 'RELEASE_SEQUENCE_REUSED')
                    check_dependencies(self.package(active['current']))
                    write_json(cache_path, {'at':now,'app':app,'current':active['current']})
                    return {'status':'CURRENT','tag':current['tag'],'checked':'network'}
            try:
                archive = transport.get('https://codeload.github.com/'+REPO+'/zip/'+manifest['commit'],
                                        MAX_ARCHIVE, deadline)
            except NetworkUnavailable:
                if current is None or not compatible(current, app):
                    raise
                check_dependencies(self.package(active['current']))
                return {'status':'CURRENT_OFFLINE','tag':current['tag'],'checked':'network_unavailable'}
            stage_package(self.root, manifest, archive, deadline)
            deadline_check(deadline)
            self.activate(manifest)
            write_json(cache_path, {'at':now,'app':app,'current':release_id(manifest)})
            return {'status':'UPDATED','tag':manifest['tag'],'manifest_sha256':manifest['manifest_sha256'],
                    'previous':active['current'] if active else None}

    def reader_selection(self, app):
        active = self.active()
        require(active is not None, 'NO_VERIFIED_PAYLOAD')
        manifest = self.validate_pointer(active)
        require(compatible(manifest, app), 'APP_NOT_IN_VERIFIED_PAYLOAD')
        check_dependencies(self.package(active['current']))
        return self.package(active['current'])/'scripts/windows/kakao_read_win.py', manifest

    def reader_path(self, app):
        return self.reader_selection(app)[0]

    def reader_command(self, app, arguments):
        reader_arguments(arguments)
        source, manifest = self.reader_selection(app)
        hashes = {name.rsplit('/',1)[1]:digest for name,digest in manifest['files'].items()
                  if name.startswith('scripts/windows/') and name.endswith('.py')}
        require('reader_source.py' in hashes, 'VERIFIED_SOURCE_BOOTSTRAP_REQUIRED')
        return [sys.executable,'-I','-B','-X','utf8','-c',SOURCE_BOOTSTRAP,str(source.parent),
                canonical_bytes(hashes).decode('utf8'),'kakao_read_win.py',*arguments]


def bootstrap(project):
    project = project_path(project)
    target = safe_path(project/ROOT_NAME)
    source = Path(__file__).resolve().parent
    hashes = {name:file_hash(source/name) for name in BOOTSTRAP_FILES}
    origin = {'schema':1,'manager_revision':REVISION,'repo':REPO,'files':hashes}
    if target.exists():
        require(load_json(target/'bootstrap.json') == origin, 'BOOTSTRAP_MANUAL_UPGRADE_REQUIRED')
        require(all(file_hash(target/name) == digest for name,digest in hashes.items()), 'BOOTSTRAP_MODIFIED')
        return target
    stage = safe_path(project/(ROOT_NAME+'.stage-'+uuid.uuid4().hex))
    stage.mkdir(mode=0o700)
    for name, expected in hashes.items():
        body = (source/name).read_bytes()
        require(hashlib.sha256(body).hexdigest() == expected, 'BOOTSTRAP_SOURCE_CHANGED')
        with (stage/name).open('xb') as stream:
            stream.write(body);stream.flush();os.fsync(stream.fileno())
    (stage/'state').mkdir(mode=0o700)
    (stage/'packages').mkdir(mode=0o700)
    write_json(stage/'bootstrap.json', origin, absent=True)
    rename_new(stage, target)
    return target


def enable(project, agent):
    require(agent in ('codex','claude'), 'AGENT_INVALID')
    root = bootstrap(project)
    state = safe_path(root/'state'/agent)
    with manager_lock(root):
        state.mkdir(mode=0o700, exist_ok=True)
        path = state/'config.json'
        if path.exists():
            config = Manager(project, agent).config()
        else:
            config = {'schema':1,'manager_revision':REVISION,'repo':REPO,'agent':agent,'enabled':False}
        config['enabled'] = True
        write_json(path, config)
    return {'status':'ENABLED','scope':'project','agent':agent,'channel':'stable',
            'check_interval_seconds':CHECK_INTERVAL,'schedule_created':False,
            'launcher':str(root/'reader_manager.py'),'downloads_started':False}


def disable(project, agent):
    manager = Manager(project, agent)
    with manager_lock(manager.root):
        config = manager.config()
        config['enabled'] = False
        write_json(manager.state/'config.json', config)
    return {'status':'DISABLED','payloads_preserved':True,'schedule_changed':False}


def reader_arguments(argv):
    require(argv and argv[0] in ('doctor','schema','accounts','rooms','self','messages','search','resume'),
            'READ_ONLY_COMMAND_REQUIRED')
    parser = argparse.ArgumentParser(add_help=False, exit_on_error=False)
    parser.add_argument('command')
    parser.add_argument('--name')
    parser.add_argument('--limit', type=int, default=20)
    parser.add_argument('--hours', type=int, default=24)
    parser.add_argument('--after-id', type=int)
    parser.add_argument('--before-id', type=int)
    parser.add_argument('--since')
    parser.add_argument('--until')
    parser.add_argument('--query')
    parser.add_argument('--cursor')
    parser.add_argument('--request-id')
    parser.add_argument('--account-token')
    parser.add_argument('--key-route', choices=('codec','envelope'))
    try:
        values, unknown = parser.parse_known_args(argv)
    except (argparse.ArgumentError, SystemExit) as exc:
        raise UpdateError('READER_ARGUMENTS_INVALID') from exc
    require(not unknown and all(isinstance(v, str) and len(v) <= 2048 for v in argv),
            'READER_ARGUMENTS_INVALID')
    require(1 <= values.limit <= 100 and 1 <= values.hours <= 87600, 'READER_QUERY_LIMIT')
    require(values.name is None or 1 <= len(values.name) <= 100, 'READER_ROOM_NAME_LIMIT')
    require(values.request_id is None or re.fullmatch('[0-9a-f]{32}', values.request_id),
            'READER_REQUEST_ID_INVALID')
    require(values.account_token is None or HEX64.fullmatch(values.account_token), 'ACCOUNT_TOKEN_INVALID')
    require(values.after_id is None or values.after_id > 0, 'READER_CURSOR_ID_INVALID')
    require(values.before_id is None or values.before_id > 0, 'READER_CURSOR_ID_INVALID')
    return argv


def configure_stdio():
    """Use UTF-8 for this CLI process, including redirected Windows pipes."""
    for stream in (sys.stdout,sys.stderr):
        reconfigure = getattr(stream,'reconfigure',None)
        if callable(reconfigure):
            reconfigure(encoding='utf-8',errors='backslashreplace')


def main(argv=None):
    configure_stdio()
    argv = list(sys.argv[1:] if argv is None else argv)
    separator = argv.index('--') if '--' in argv else len(argv)
    arguments = argv[separator+1:]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('enable','disable','status','check','read'))
    parser.add_argument('--project')
    parser.add_argument('--agent', required=True, choices=('codex','claude'))
    parser.add_argument('--force', action='store_true')
    args = parser.parse_args(argv[:separator])
    try:
        # Installed bootstrap resolves its project; no manifest can supply it.
        project = args.project or (str(Path(__file__).resolve().parent.parent)
                                   if Path(__file__).parent.name == ROOT_NAME else None)
        require(project is not None, 'PROJECT_REQUIRED')
        require(args.command == 'read' or not arguments, 'UNEXPECTED_ARGUMENTS')
        if args.command == 'enable':
            result = enable(project, args.agent)
        elif args.command == 'disable':
            result = disable(project, args.agent)
        elif args.command == 'status':
            manager = Manager(project, args.agent)
            result = {'status':'ENABLED' if manager.config()['enabled'] else 'DISABLED',
                      'active':manager.active(),'schedule_created':False}
        else:
            manager = Manager(project, args.agent)
            if args.command == 'read':
                reader_arguments(arguments)
            app = app_metadata()
            result = manager.check(app, force=args.force)
            if args.command == 'read':
                command = manager.reader_command(app,arguments)
                # The selected immutable tree survives future pointer changes.
                print(json.dumps({'update':result},ensure_ascii=False),file=sys.stderr,flush=True)
                os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
                os.execv(sys.executable, command)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except (UpdateError, ManifestError, OSError, ValueError) as exc:
        reason = (exc.reason if isinstance(exc, UpdateError) else str(exc)
                  if isinstance(exc, ManifestError) else type(exc).__name__)
        details = exc.details if isinstance(exc, UpdateError) else {}
        print(json.dumps({'status':'BLOCKED','reason':reason,**details},ensure_ascii=False))
        return 2


if __name__ == '__main__':
    raise SystemExit(fetch_worker(sys.argv[2:]) if sys.argv[1:2] == ['__fetch__'] else main())
