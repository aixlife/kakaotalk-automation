"""Copy the reader skill into one project; inspection is the default."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys


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


def install(source, project, agent, apply=False):
    if agent not in ('codex', 'claude'):
        raise InstallError('Unsupported agent')
    source = safe_path(source)
    project = safe_path(project)
    if not project.is_dir():
        raise InstallError('Project directory must already exist')
    if project == Path(project.anchor) or project == Path.home().absolute():
        raise InstallError('Choose a project directory, not the filesystem root or home')
    expected = manifest(source)
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
    if target.exists():
        if manifest(target) != expected:
            raise InstallError('Existing skill differs; no files were overwritten')
        return dict(result, status='UNCHANGED')
    if not apply:
        return dict(result, status='READY', changed=False)
    created = []
    try:
        for parent in (agent_root, skills):
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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent', required=True, choices=('codex', 'claude'))
    parser.add_argument('--project', required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--check', action='store_true')
    mode.add_argument('--dry-run', action='store_true')
    mode.add_argument('--install', action='store_true')
    args = parser.parse_args(argv)
    source = Path(__file__).absolute().parents[1] / 'skills' / 'kakaotalk-mac'
    try:
        print(json.dumps(install(source, args.project, args.agent, args.install), ensure_ascii=False))
        return 0
    except (InstallError, OSError) as exc:
        print(json.dumps({'status': 'BLOCKED', 'reason': str(exc)}, ensure_ascii=False))
        return 2


if __name__ == '__main__':
    sys.exit(main())
