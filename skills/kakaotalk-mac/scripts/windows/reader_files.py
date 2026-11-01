"""Read-only file opens bound to a metadata-validated account selection.

File bytes are never read until lstat/open/fstat identity checks and the
selection-time directory checks pass. Cryptographic snapshot validation
remains the caller's responsibility: content changes do not change a lease.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import stat

from reader_accounts import MAX_PATH_COMPONENTS, _identity


def _fail(code):
    raise RuntimeError(code) from None


def _inspect(path):
    try:
        value = path.lstat()
    except (OSError, ValueError):
        _fail('ACCOUNT_FILE_UNAVAILABLE')
    if stat.S_ISLNK(value.st_mode) or getattr(value, 'st_file_attributes', 0) & 0x400:
        _fail('ACCOUNT_FILE_UNSAFE')
    return value


def _limit(value, *, optional=False):
    if optional and value is None:
        return
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        _fail('ACCOUNT_FILE_LIMIT_INVALID')


def _size(value, maximum):
    if not stat.S_ISREG(value.st_mode):
        _fail('ACCOUNT_FILE_NOT_REGULAR')
    if value.st_size < 0 or (maximum is not None and value.st_size > maximum):
        _fail('ACCOUNT_FILE_TOO_LARGE')


class ScopedFiles:
    """A directory-identity lease created by select_account_lease.

    This object holds no OS locks, does not freeze contents, and writes
    nothing. The captured identities deliberately exclude directory mtime.
    """
    def __init__(self, account, directory_identities):
        self.account = Path(account)
        self._directories = tuple(directory_identities)

    def guard(self):
        """Reject renamed/replaced selected directories and ancestor aliases."""
        for path, expected in self._directories:
            current = _inspect(path)
            if not stat.S_ISDIR(current.st_mode) or _identity(current) != expected:
                _fail('ACCOUNT_SCOPE_CHANGED')

    def _path(self, path, maximum):
        try:
            path = Path(path)
        except (TypeError, ValueError):
            _fail('ACCOUNT_FILE_OUTSIDE_SCOPE')
        if (not path.is_absolute() or '..' in path.parts or
                len(path.parts) > MAX_PATH_COMPONENTS or
                not path.is_relative_to(self.account) or path == self.account):
            _fail('ACCOUNT_FILE_OUTSIDE_SCOPE')
        # Reject NTFS alternate data streams and alias spellings even when
        # synthetic tests run on a non-Windows host.
        if any(':' in part or '\\' in part or part.endswith(('.', ' '))
               for part in path.parts[1:]):
            _fail('ACCOUNT_FILE_UNSAFE')
        relative = path.relative_to(self.account)
        name = path.name.casefold()
        allowed = (
            len(relative.parts) == 2 and relative.parts[0] == 'chat_data' and
            (name.endswith('.edb') or name.endswith('.edb-wal'))
        ) or (len(relative.parts) == 1 and name in
              ('talkuserdb.edb', 'talkuserdb.edb-wal', 'appstate.dat'))
        if not allowed and maximum != 40:
            _fail('ACCOUNT_FILE_OUTSIDE_SCOPE')
        return path, not allowed

    def _snapshot(self, path, maximum, exact_container):
        self.guard()
        # IKM containers can live in nested directories. Every component is
        # checked without following links, including ones not in the lease.
        current = self.account
        parents = []
        for component in path.relative_to(self.account).parts[:-1]:
            current /= component
            value = _inspect(current)
            if not stat.S_ISDIR(value.st_mode):
                _fail('ACCOUNT_FILE_NOT_DIRECTORY')
            parents.append((current, _identity(value)))
        before = _inspect(path)
        _size(before, maximum)
        if exact_container and before.st_size != 40:
            _fail('ACCOUNT_FILE_SIZE_CHANGED')
        return before, tuple(parents)

    def _recheck(self, path, descriptor, expected, parents, maximum, exact_container):
        self.guard()
        for parent, identity in parents:
            value = _inspect(parent)
            if not stat.S_ISDIR(value.st_mode) or _identity(value) != identity:
                _fail('ACCOUNT_SCOPE_CHANGED')
        current = _inspect(path)
        opened = os.fstat(descriptor)
        _size(current, maximum)
        _size(opened, maximum)
        if _identity(current) != expected or _identity(opened) != expected:
            _fail('ACCOUNT_FILE_CHANGED')
        if exact_container and (current.st_size != 40 or opened.st_size != 40):
            _fail('ACCOUNT_FILE_SIZE_CHANGED')

    @contextmanager
    def open(self, path, max_bytes=None):
        """Yield an unbuffered read-only stream after all identity checks.

        Unrecognized account-local files are allowed only as an exact 40-byte
        IKM candidate, explicitly requested with max_bytes=40. The yielded
        stream supports seek/read/readinto/fileno; callers retain read budgets.
        """
        _limit(max_bytes, optional=True)
        path, exact_container = self._path(path, max_bytes)
        before, parents = self._snapshot(path, max_bytes, exact_container)
        expected = _identity(before)
        descriptor = None
        stream = None
        try:
            flags = os.O_RDONLY
            for name in ('O_BINARY', 'O_NOFOLLOW', 'O_NONBLOCK', 'O_NOINHERIT', 'O_CLOEXEC'):
                flags |= getattr(os, name, 0)
            descriptor = os.open(path, flags)
            # This is deliberately before fdopen/yield: neither an I/O wrapper
            # nor the caller can read substituted file bytes before rejection.
            self._recheck(path, descriptor, expected, parents, max_bytes, exact_container)
            stream = os.fdopen(descriptor, 'rb', buffering=0)
            descriptor = None
            yield stream
            self._recheck(path, stream.fileno(), expected, parents, max_bytes, exact_container)
        except (OSError, ValueError):
            _fail('ACCOUNT_FILE_UNAVAILABLE')
        finally:
            if stream is not None:
                stream.close()
            if descriptor is not None:
                os.close(descriptor)

    def bounded_read(self, path, maximum, exact=None):
        """Read at most maximum+1 bytes, reject oversized/growing files."""
        _limit(maximum)
        _limit(exact, optional=True)
        if exact is not None and exact > maximum:
            _fail('ACCOUNT_FILE_LIMIT_INVALID')
        with self.open(path, max_bytes=maximum) as stream:
            result = stream.read(maximum + 1)
            if len(result) > maximum:
                _fail('ACCOUNT_FILE_TOO_LARGE')
            if exact is not None and len(result) != exact:
                _fail('ACCOUNT_FILE_SIZE_CHANGED')
        return result
