"""Copy the reader skill into one project; inspection is the default."""
import argparse
from contextlib import contextmanager
import ctypes
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import uuid


class InstallError(Exception):
    pass


def safe_path(value):
    path = Path(value).expanduser()
    if '..' in path.parts:
        raise InstallError('Parent traversal is not allowed')
    path = Path(os.path.abspath(path))
    for item in (path, *path.parents):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise InstallError('Symbolic links and reparse points are not allowed')
    return path


def manifest(root):
    root = safe_path(root)
    if not root.is_dir():
        raise InstallError('Expected an existing directory')
    result = {}
    def visit(directory):
        for item in sorted(directory.iterdir()):
            # Reject links even when their names look generated. Do not descend
            # into an actual cache directory or read any of its children.
            safe_path(item)
            mode = item.lstat().st_mode
            name = item.relative_to(root).as_posix()
            if stat.S_ISDIR(mode):
                if item.name == '__pycache__':
                    continue
                result[name + '/'] = None
                visit(item)
            elif stat.S_ISREG(mode):
                if item.name == '.DS_Store' or item.suffix in ('.pyc', '.pyo'):
                    continue
                result[name] = hashlib.sha256(item.read_bytes()).hexdigest()
            else:
                raise InstallError('Only regular files and directories are allowed')
    visit(root)
    return result


def manifest_sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True,
        separators=(',', ':')).encode()).hexdigest()


def identity(path):
    info = path.lstat()
    return info.st_dev, info.st_ino


def rollback(created):
    """Remove only unchanged files and empty directories made by this attempt."""
    preserved = []
    for path, inode, digest in reversed(created):
        try:
            safe_path(path)
            if identity(path) != inode:
                preserved.append(str(path))
            elif digest is None:
                path.rmdir()
            elif hashlib.sha256(path.read_bytes()).hexdigest() == digest:
                path.unlink()
            else:
                preserved.append(str(path))
        except FileNotFoundError:
            pass
        except (OSError, InstallError):
            preserved.append(str(path))
    return preserved


def make_directory(path, created):
    safe_path(path)
    path.mkdir()
    created.append((path, identity(path), None))


def copy_file(source, target, expected, created):
    safe_path(source)
    safe_path(target)
    data = source.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise InstallError('Source changed during installation')
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL |
             getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
    descriptor = os.open(target, flags, 0o644)
    inode = identity(target)
    digest = hashlib.sha256()
    created.append((target, inode, digest.hexdigest()))
    try:
        offset = 0
        while offset < len(data):
            count = os.write(descriptor, data[offset:])
            if count <= 0:
                raise OSError('Incomplete write')
            digest.update(data[offset:offset + count])
            offset += count
            created[-1] = (target, inode, digest.hexdigest())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def prepare(source, project, agent, strict=False):
    if agent not in ('codex', 'claude'):
        raise InstallError('Unsupported agent')
    source = safe_path(source)
    project = safe_path(project)
    if not project.is_dir():
        raise InstallError('Project directory must already exist')
    if project == Path(project.anchor) or project == Path.home().absolute():
        raise InstallError('Choose a project directory, not the filesystem root or home')
    expected = upgrade_manifest(source) if strict else manifest(source)
    if 'SKILL.md' not in expected:
        raise InstallError('Source skill has no SKILL.md')
    agent_root = project / ('.agents' if agent == 'codex' else '.claude')
    skills = agent_root / 'skills'
    target = safe_path(skills / 'kakaotalk-mac')
    if source == target or source in target.parents or target in source.parents:
        raise InstallError('Source and target must not overlap')
    for parent in (agent_root, skills):
        safe_path(parent)
        if parent.exists() and not parent.is_dir():
            raise InstallError('Installation parent is not a directory')
    result = {'target': str(target), 'manifest_sha256': manifest_sha(expected),
              'files': sum(value is not None for value in expected.values())}
    return source, project, target, expected, result, (agent_root, skills)


@contextmanager
def installation_lock(project, agent):
    """One nonblocking lock shared by install and upgrade; never evict a lock."""
    project = safe_path(project)
    if not project.is_dir() or project == Path(project.anchor) or project == Path.home().absolute():
        raise InstallError('Choose an existing project directory, not root or home')
    if agent not in ('codex', 'claude'):
        raise InstallError('Unsupported agent')
    path = safe_path(project / ('.kakaotalk-mac-' + agent + '-install.lock'))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise InstallError('Installation is locked; no stale lock was removed: ' + str(path)) from exc
    inode = identity(path)
    try:
        yield
    finally:
        os.close(descriptor)
        try:
            safe_path(path)
            if identity(path) == inode and path.stat().st_size == 0:
                path.unlink()
        except (FileNotFoundError, InstallError):
            pass


def install(source, project, agent, apply=False):
    if not apply:
        return _install(source, project, agent, False)
    with installation_lock(project, agent):
        return _install(source, project, agent, True)


def _install(source, project, agent, apply):
    source, project, target, expected, result, parents = prepare(source, project, agent)
    if target.exists():
        if manifest(target) != expected:
            raise InstallError('Existing skill differs; no files were overwritten')
        return dict(result, status='UNCHANGED')
    if not apply:
        return dict(result, status='READY', changed=False)
    created = []
    try:
        for parent in parents:
            if not parent.exists():
                make_directory(parent, created)
        make_directory(target, created)
        for name, digest in expected.items():
            destination = target / name.rstrip('/')
            if digest is None:
                make_directory(destination, created)
            else:
                copy_file(source / name, destination, digest, created)
        if manifest(source) != expected or manifest(target) != expected:
            raise InstallError('Exact content verification failed')
        return dict(result, status='INSTALLED', changed=True)
    except Exception as exc:
        preserved = rollback(created)
        detail = '; modified or nonempty paths preserved' if preserved else '; own changes rolled back'
        raise InstallError(str(exc) + detail) from exc


def rename_exclusive(source, target):
    """Atomic rename that cannot replace even an empty concurrent directory."""
    safe_path(source)
    safe_path(target)
    if os.name == 'nt':
        os.rename(source, target)  # Windows refuses every existing destination.
        return
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == 'darwin':
        call = library.renamex_np
        call.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        code = call(os.fsencode(source), os.fsencode(target), 4)  # RENAME_EXCL
    elif sys.platform.startswith('linux') and hasattr(library, 'renameat2'):
        call = library.renameat2
        call.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        code = call(-100, os.fsencode(source), -100, os.fsencode(target), 1)  # RENAME_NOREPLACE
    else:
        raise InstallError('Exclusive directory rename is unavailable on this platform')
    if code:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), str(target))


def upgrade_manifest(root):
    """Bound upgrade inspection and reject links, including inside ignored caches."""
    root = safe_path(root)
    count = total = 0
    stack = [root]
    while stack:
        directory = stack.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                count += 1
                if count > 512:
                    raise InstallError('Upgrade inspection exceeded 512 entries')
                path = safe_path(entry.path)
                info = path.lstat()
                if stat.S_ISDIR(info.st_mode):
                    stack.append(path)
                elif stat.S_ISREG(info.st_mode):
                    total += info.st_size
                    if info.st_size > 1024 * 1024 or total > 16 * 1024 * 1024:
                        raise InstallError('Upgrade inspection size limit exceeded')
                else:
                    raise InstallError('Only regular files and directories are allowed')
    return manifest(root)


def known_releases():
    path = safe_path(Path(__file__).absolute().with_name('known_skill_manifests.json'))
    with path.open('rb') as stream:
        data = stream.read(65537)
    if len(data) > 65536:
        raise InstallError('Known release manifest size limit exceeded')
    try:
        record = json.loads(data)
        if record['schema'] != 1 or not isinstance(record['releases'], dict):
            raise ValueError()
        for value in record['releases'].values():
            if not isinstance(value['manifest'], dict) or manifest_sha(value['manifest']) != value['manifest_sha256']:
                raise ValueError()
        return record['releases']
    except (ValueError, KeyError, TypeError) as exc:
        raise InstallError('Known release manifest is invalid') from exc


def upgrade(source, project, agent, apply=False):
    if not apply:
        return _upgrade(source, project, agent, False)
    with installation_lock(project, agent):
        return _upgrade(source, project, agent, True)


def _upgrade(source, project, agent, apply):
    source, project, target, expected, result, _ = prepare(source, project, agent, strict=True)
    # Inspection does not create a missing installation. Use --install for that.
    if not target.is_dir():
        raise InstallError('No installed skill to upgrade; use --install')
    if upgrade_manifest(source) != expected:
        raise InstallError('Source changed during inspection')
    original = upgrade_manifest(target)
    if original == expected:
        return dict(result, status='UNCHANGED', changed=False)
    version = next((name for name, value in known_releases().items()
                    if value['manifest'] == original), None)
    if version is None:
        raise InstallError('Existing skill is modified or not a known release; no files were overwritten')
    result['previous_version'] = version
    result['previous_manifest_sha256'] = manifest_sha(original)
    if not apply:
        return dict(result, status='READY_UPGRADE', changed=False)
    original_identity = identity(target)
    suffix = uuid.uuid4().hex
    stage = target.with_name('.' + target.name + '.stage-' + suffix)
    # Keep the old SKILL.md outside both agents' skill-discovery directories.
    backup_root = project / '.kakaotalk-mac-backups' / agent
    backup = backup_root / ('kakaotalk-mac-' + suffix)
    created, backup_created = [], []
    moved = published = False
    try:
        make_directory(stage, created)
        for name, digest in expected.items():
            destination = stage / name.rstrip('/')
            if digest is None:
                make_directory(destination, created)
            else:
                copy_file(source / name, destination, digest, created)
        if upgrade_manifest(source) != expected or upgrade_manifest(stage) != expected:
            raise InstallError('Staged content verification failed')
        if identity(target) != original_identity or upgrade_manifest(target) != original:
            raise InstallError('Installed skill changed during upgrade')
        for parent in (backup_root.parent, backup_root):
            safe_path(parent)
            if not parent.exists():
                make_directory(parent, backup_created)
            elif not parent.is_dir():
                raise InstallError('Backup parent is not a directory')
        if backup_root.stat().st_dev != target.stat().st_dev:
            raise InstallError('Backup and installation must share a filesystem')
        rename_exclusive(target, backup)
        moved = True
        if identity(backup) != original_identity or upgrade_manifest(backup) != original:
            raise InstallError('Backup changed during upgrade')
        if upgrade_manifest(source) != expected or upgrade_manifest(stage) != expected:
            raise InstallError('Staged content changed before activation')
        rename_exclusive(stage, target)
        published = True
        if upgrade_manifest(target) != expected:
            raise InstallError('Activated content verification failed')
        return dict(result, status='UPGRADED', changed=True, backup=str(backup))
    except Exception as exc:
        detail = ''
        if moved and not published:
            try:
                rename_exclusive(backup, target)
                detail = '; previous installation restored'
            except (OSError, InstallError):
                detail = '; previous installation preserved at ' + str(backup)
        elif published:
            # Another writer may have changed the activated folder; preserve it.
            detail = '; activated folder preserved; previous installation at ' + str(backup)
        preserved = rollback(created)
        rollback(backup_created)  # Removes empty own-created parents only.
        if preserved:
            detail += '; modified staging paths preserved at ' + str(stage)
        raise InstallError(str(exc) + detail) from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent', required=True, choices=('codex', 'claude'))
    parser.add_argument('--project', required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--check', action='store_true')
    mode.add_argument('--dry-run', action='store_true')
    mode.add_argument('--install', action='store_true')
    mode.add_argument('--upgrade-check', action='store_true', help='Inspect an upgrade without changing files')
    mode.add_argument('--upgrade', action='store_true', help='Back up and upgrade an unchanged known release')
    args = parser.parse_args(argv)
    source = Path(__file__).absolute().parents[1] / 'skills' / 'kakaotalk-mac'
    try:
        result = (upgrade(source, args.project, args.agent, args.upgrade)
                  if args.upgrade or args.upgrade_check else install(source, args.project, args.agent, args.install))
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except (InstallError, OSError) as exc:
        print(json.dumps({'status': 'BLOCKED', 'reason': str(exc)}, ensure_ascii=False))
        return 2


if __name__ == '__main__':
    sys.exit(main())
