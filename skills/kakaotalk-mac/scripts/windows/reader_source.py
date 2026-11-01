"""Execute a bounded, hash-bound reader source graph without bytecode caches.

Dependencies outside this graph remain part of the installed Python environment.
This is source-integrity validation, not a sandbox or an independent signature.
"""
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import types

MAX_FILE = 1024 * 1024
MAX_TOTAL = 8 * 1024 * 1024
ENTRY_NAMES = frozenset(('reader_job.py', 'room_reader.py', 'kakao_read_win.py'))
SOURCE_METHOD = 'verified-source-bytes'


def require(value, reason):
    if not value:
        raise RuntimeError(reason)


def manifest_sha256(hashes):
    data = json.dumps(hashes, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf8')
    return hashlib.sha256(data).hexdigest()


def _root(value):
    root = Path(value)
    require(root.is_absolute(), 'READER_SOURCE_ROOT_INVALID')
    for path in (root, *root.parents):
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and
                not getattr(info, 'st_file_attributes', 0) & 0x400,
                'READER_SOURCE_UNSAFE_PATH')
    return root.resolve()


def _hashes(value, entry=None):
    require(type(value) is dict and 3 <= len(value) <= 32, 'READER_SOURCE_HASHES_INVALID')
    required = {'reader_source.py', 'reader_config.py'} | ({entry} if entry else set())
    require(required <= set(value), 'READER_SOURCE_HASHES_INCOMPLETE')
    for name, digest in value.items():
        require(type(name) is str and re.fullmatch(r'[a-z][a-z0-9_]{0,63}\.py', name) and
                type(digest) is str and re.fullmatch(r'[0-9a-f]{64}', digest),
                'READER_SOURCE_HASHES_INVALID')
    return dict(value)


def _bytes(root, name, digest=None):
    path = root / name
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
            not getattr(before, 'st_file_attributes', 0) & 0x400 and
            0 < before.st_size <= MAX_FILE, 'READER_SOURCE_FILE_INVALID')
    with path.open('rb') as stream:
        data = stream.read(MAX_FILE + 1)
        opened = os.fstat(stream.fileno())
    after = path.lstat()
    identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
    require(identity(before) == identity(opened) == identity(after) and
            len(data) == before.st_size, 'READER_SOURCE_CHANGED')
    require(digest is None or hashlib.sha256(data).hexdigest() == digest, 'READER_SOURCE_CHANGED')
    return data


def validate_sources(root, hashes):
    root = _root(root); hashes = _hashes(hashes)
    require({path.name for path in root.iterdir() if path.suffix == '.py'} == set(hashes),
            'READER_SOURCE_SET_CHANGED')
    total = 0
    for name, digest in hashes.items():
        total += len(_bytes(root, name, digest))
        require(total <= MAX_TOTAL, 'READER_SOURCE_TOTAL_LIMIT')
    return root, hashes


class PinnedSourceLoader(importlib.machinery.SourceFileLoader):
    def __init__(self, root, name, digest):
        super().__init__(name[:-3], str(root / name))
        self.root = root; self.source_name = name; self.digest = digest

    def get_code(self, fullname):
        # Compile these exact checked bytes. SourceFileLoader's normal get_code
        # can consume a timestamp-valid or unchecked .pyc; it is not used here.
        data = _bytes(self.root, self.source_name, self.digest)
        return compile(data, self.path, 'exec', dont_inherit=True, optimize=0)

    def exec_module(self, module):
        super().exec_module(module)
        module.__verified_source_sha256__ = self.digest


class PinnedSourceFinder:
    def __init__(self, root, hashes):
        self.root = root; self.hashes = dict(hashes)

    def find_spec(self, fullname, path=None, target=None):
        name = fullname + '.py'
        if path is not None or name not in self.hashes:
            return None
        loader = PinnedSourceLoader(self.root, name, self.hashes[name])
        return importlib.util.spec_from_file_location(fullname, self.root / name, loader=loader)


def _activate(root, hashes):
    require(not sys.flags.optimize, 'READER_OPTIMIZED_PYTHON_UNSUPPORTED')
    for name, digest in hashes.items():
        old = sys.modules.get(name[:-3])
        if old is not None:
            require(name == 'reader_source.py' and
                    getattr(old, '__verified_source_sha256__', None) == digest and
                    Path(getattr(old, '__file__', '')).resolve() == root / name,
                    'READER_SOURCE_ALREADY_IMPORTED')
    # The source finder resolves only the pinned modules. Removing the runtime
    # directory from normal search also prevents later unpinned .py/.pyd files
    # there from shadowing a dependency.
    sys.path[:] = [path for path in sys.path if path and Path(path).resolve() != root]
    sys.meta_path.insert(0, PinnedSourceFinder(root, hashes))
    sys.dont_write_bytecode = True
    sys._kakao_verified_source_bootstrap = manifest_sha256(hashes)
    import reader_config
    require(reader_config.SOURCE_NAMES == frozenset(hashes) and
            Path(reader_config.ROOT).resolve() == root, 'READER_SOURCE_CONFIG_MISMATCH')


def _utf8_stdio():
    """Keep manual CLI pipes UTF-8 too, without replacing redirected streams."""
    for stream in (sys.stdout, sys.stderr):
        configure = getattr(stream, 'reconfigure', None)
        if callable(configure):
            options = {'encoding': 'utf-8'}
            errors = getattr(stream, 'errors', None)
            if errors is not None:
                options['errors'] = errors
            configure(**options)


def execute(root, hashes, entry, args):
    _utf8_stdio()
    require(entry in ENTRY_NAMES, 'READER_SOURCE_ENTRY_NOT_ALLOWED')
    hashes = _hashes(hashes, entry)
    _arguments(args)
    root, hashes = validate_sources(root, hashes)
    _activate(root, hashes)
    body = _bytes(root, entry, hashes[entry])
    main = types.ModuleType('__main__')
    main.__file__ = str(root / entry)
    main.__package__ = None
    main.__spec__ = None
    main.__verified_source_sha256__ = hashes[entry]
    sys.modules['__main__'] = main
    sys.argv = [main.__file__, *args]
    try:
        exec(compile(body, main.__file__, 'exec', dont_inherit=True, optimize=0), main.__dict__)
    finally:
        # Even a main() that printed a success result cannot produce a successful
        # process receipt after its sources change during execution.
        validate_sources(root, hashes)


def _arguments(args):
    require(type(args) is list and len(args) <= 32 and
            all(type(arg) is str and len(arg) <= 2048 and '\0' not in arg for arg in args),
            'READER_SOURCE_ARGUMENTS_INVALID')


BOOTSTRAP = """import hashlib,json,pathlib,sys,types
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


def verified_argv(root, hashes, entry, args):
    require(entry in ENTRY_NAMES, 'READER_SOURCE_ENTRY_NOT_ALLOWED')
    hashes = _hashes(hashes, entry); _arguments(args)
    root, hashes = validate_sources(root, hashes)
    # -I ignores PYTHONIOENCODING. Pin UTF-8 on this child explicitly so
    # redirected Korean JSON does not use the Windows locale code page.
    return [sys.executable, '-I', '-B', '-X', 'utf8', '-c', BOOTSTRAP, str(root),
            json.dumps(hashes, sort_keys=True, separators=(',', ':')), entry, *args]


def bootstrap_current(script, args):
    """Manual CLI: bind current source bytes before any local module import.

    This local binding is not release approval. The separately pinned probe and
    managed stable installer enforce their published source manifests.
    """
    script = Path(script)
    root = _root(script.parent)
    names = sorted(path.name for path in root.iterdir() if path.suffix == '.py')
    require(3 <= len(names) <= 32, 'READER_SOURCE_SET_CHANGED')
    hashes = {name: hashlib.sha256(_bytes(root, name)).hexdigest() for name in names}
    execute(root, hashes, script.name, args)
