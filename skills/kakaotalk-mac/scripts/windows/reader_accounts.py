"""Bounded, content-free account inventory and explicit local selection.

Tokens identify a canonical local path, not an authenticated Kakao identity.
No database, process, message, registry, or app-state content is opened here.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import stat


MAX_ROOT_ENTRIES = 128
MAX_ACCOUNTS = 32
MAX_PATH_COMPONENTS = 64
_REPARSE_POINT = 0x400


def _fail(code):
    raise RuntimeError(code) from None


def _identity(info):
    # Windows synthesizes execute permission from a filename's extension;
    # fstat has no filename. Object type, not those permission bits, is identity.
    return (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode),
            getattr(info, 'st_file_attributes', 0) & _REPARSE_POINT,
            getattr(info, 'st_reparse_tag', 0))


def _inspect(path, *, missing_ok=False):
    try:
        info = path.lstat()
    except FileNotFoundError:
        if missing_ok:
            return None
        _fail('ACCOUNT_PATH_UNAVAILABLE')
    except (OSError, ValueError):
        _fail('ACCOUNT_PATH_UNAVAILABLE')
    if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & _REPARSE_POINT:
        _fail('ACCOUNT_UNSAFE_PATH')
    return info


def _checked_root(users_root):
    try:
        root = Path(users_root)
    except (TypeError, ValueError):
        _fail('ACCOUNT_ROOT_INVALID')
    if not root.is_absolute() or '..' in root.parts or len(root.parts) > MAX_PATH_COMPONENTS:
        _fail('ACCOUNT_ROOT_INVALID')
    chain = tuple(reversed(root.parents)) + (root,)
    identities = []
    for part in chain:
        info = _inspect(part)
        if not stat.S_ISDIR(info.st_mode):
            _fail('ACCOUNT_ROOT_NOT_DIRECTORY')
        identities.append(_identity(info))
    try:
        canonical = root.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        _fail('ACCOUNT_PATH_UNAVAILABLE')
    # A resolve that changes the chain after inspection may have crossed a
    # replaced link. Reinspect the canonical chain before accepting it.
    if canonical != root:
        _fail('ACCOUNT_UNSAFE_PATH')
    return canonical, tuple(identities)


@dataclass(frozen=True)
class _Account:
    path: Path
    token: str
    backup_hint: bool
    database_bytes: int
    database_mtime: float
    identities: tuple
    directory_identities: tuple


def _scan(users_root):
    root, root_identities = _checked_root(users_root)
    entries = []
    accounts = []
    try:
        with os.scandir(root) as iterator:
            for entry in iterator:
                if len(entries) >= MAX_ROOT_ENTRIES:
                    _fail('ACCOUNT_INVENTORY_LIMIT')
                account = root / entry.name
                info = _inspect(account)
                entries.append((entry.name, _identity(info)))
                if not stat.S_ISDIR(info.st_mode):
                    continue
                data = _inspect(account / 'chat_data', missing_ok=True)
                if data is None:
                    continue
                if not stat.S_ISDIR(data.st_mode):
                    _fail('ACCOUNT_LAYOUT_INVALID')
                database = _inspect(account / 'chat_data' / 'chatListInfo.edb', missing_ok=True)
                if database is None:
                    continue
                if not stat.S_ISREG(database.st_mode):
                    _fail('ACCOUNT_LAYOUT_INVALID')
                if len(accounts) >= MAX_ACCOUNTS:
                    _fail('ACCOUNT_INVENTORY_LIMIT')
                try:
                    canonical = account.resolve(strict=True)
                except (OSError, RuntimeError, ValueError):
                    _fail('ACCOUNT_PATH_UNAVAILABLE')
                if canonical.parent != root or canonical != account:
                    _fail('ACCOUNT_UNSAFE_PATH')
                token = hashlib.sha256(str(canonical).casefold().encode()).hexdigest()
                accounts.append(_Account(
                    canonical, token, 'backup' in entry.name.casefold(),
                    database.st_size, database.st_mtime,
                    (_identity(info), _identity(data), _identity(database)),
                    tuple(zip(tuple(reversed(root.parents)) + (root,), root_identities)) +
                    ((canonical, _identity(info)), (canonical / 'chat_data', _identity(data)))))
    except (OSError, ValueError):
        _fail('ACCOUNT_INVENTORY_UNAVAILABLE')
    final_root, final_identities = _checked_root(users_root)
    if final_root != root or final_identities != root_identities:
        _fail('ACCOUNT_SET_CHANGED')
    fingerprint = (str(root), root_identities, tuple(sorted(entries)),
                   tuple(sorted((a.token, a.identities) for a in accounts)))
    return accounts, fingerprint


def _stable_accounts(users_root):
    _, fingerprint = _scan(users_root)
    second, second_fingerprint = _scan(users_root)
    if fingerprint != second_fingerprint:
        _fail('ACCOUNT_SET_CHANGED')
    tokens = [account.token for account in second]
    if len(tokens) != len(set(tokens)):
        _fail('ACCOUNT_TOKEN_NOT_UNIQUE')
    return second


def inventory_accounts(users_root):
    """Return opaque tokens and stat metadata only; never local names/paths.

    At most two bounded shallow scans are performed. Symlinks and Windows
    reparse points in the inspected paths are rejected without traversal.
    Empty roots return an empty list. No account is selected by a name hint.
    """
    result = []
    for account in sorted(_stable_accounts(users_root), key=lambda item: item.token):
        try:
            modified = datetime.fromtimestamp(account.database_mtime, timezone.utc).isoformat()
        except (OSError, OverflowError, ValueError):
            _fail('ACCOUNT_METADATA_INVALID')
        result.append({
            'account_token': account.token,
            'backup_name_hint': account.backup_hint,
            'database_bytes': account.database_bytes,
            'database_modified_at': modified,
        })
    return result


def _selected_account(users_root, token):
    if token is not None and (not isinstance(token, str) or
                              re.fullmatch(r'[0-9a-f]{64}', token) is None):
        _fail('ACCOUNT_TOKEN_INVALID')
    accounts = _stable_accounts(users_root)
    if not accounts:
        _fail('ACCOUNT_NOT_FOUND')
    if token is None:
        if len(accounts) != 1:
            _fail('ACCOUNT_SELECTION_REQUIRED')
        return accounts[0]
    matches = [account for account in accounts if account.token == token]
    if not matches:
        _fail('ACCOUNT_TOKEN_NOT_FOUND')
    if len(matches) != 1:
        _fail('ACCOUNT_TOKEN_NOT_UNIQUE')
    return matches[0]


def select_account(users_root, token=None):
    """Return the canonical account Path for metadata-only internal use.

    One account may be selected implicitly; multiple accounts require the
    full lowercase SHA256 token. Use select_account_lease for content reads.
    """
    return _selected_account(users_root, token).path


def select_account_lease(users_root, token=None):
    """Return (canonical Path, ScopedFiles) bound to selection-time identities.

    The lease uses the identities captured inside the second matching scan,
    never a fresh capture after selection. No file contents are read here.
    """
    from reader_files import ScopedFiles
    selected = _selected_account(users_root, token)
    lease = ScopedFiles(selected.path, selected.directory_identities)
    lease.guard()
    return selected.path, lease
