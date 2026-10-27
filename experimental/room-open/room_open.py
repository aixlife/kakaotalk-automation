#!/usr/bin/env python3
"""Search/open one reviewed room or inspect it without sending anything.

Run --help for commands. UI commands need --allow-ui; opening also requires
the successful search receipt, a reviewed row point and --confirm-row.
Receipts and scoped captures are private local files, never release artifacts.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys
import time
import uuid

HERE = Path(__file__).resolve().parent
CHECKOUT = HERE.parents[1]
READER = CHECKOUT / 'skills/kakaotalk-mac/scripts/windows'
PREVIEW = HERE.parent / 'self-attachments'
sys.path.insert(0, str(READER))
SCHEMA = 'kakao-room-open/v1'
MAX_RECORD = 256 * 1024
JOB_SECONDS = 17
SUCCESS = {'inspect': 'INSPECTED', 'search': 'SEARCHED',
           'open': 'OPENED_EXACT_TITLE_STRUCTURE', 'check': 'PRE_SEND_SURFACE_CHECKED'}


def require(value, code):
    if not value:
        raise RuntimeError(code)


def safe_error(exc):
    value = str(exc)
    return value if re.fullmatch('[A-Z0-9_]{1,120}', value) else type(exc).__name__


def safe_path(path):
    path = Path(os.path.abspath(path))
    for entry in (path, *path.parents):
        try:
            info = entry.lstat()
        except FileNotFoundError:
            continue
        require(not entry.is_symlink() and not getattr(info, 'st_file_attributes', 0) & 0x400,
                'PRIVATE_PATH_REDIRECTED')
    return path


def state_paths():
    require(__debug__, 'OPTIMIZED_PYTHON_UNSUPPORTED')
    require(os.name == 'nt' and struct.calcsize('P') == 8 and sys.version_info >= (3, 11),
            'WINDOWS_X64_PYTHON_3_11_REQUIRED')
    local = os.environ.get('LOCALAPPDATA')
    require(local and Path(local).is_absolute(), 'LOCALAPPDATA_REQUIRED')
    base = safe_path(Path(local) / 'KakaoReader')
    require(base != CHECKOUT and CHECKOUT not in base.parents, 'PRIVATE_STATE_INSIDE_CHECKOUT')
    root = safe_path(base / 'room-open')
    # Same lock as the existing self-attachment experiment, not a second lock.
    lock_parent = safe_path(base / 'self-attachment-qa')
    root.mkdir(parents=True, exist_ok=True)
    lock_parent.mkdir(parents=True, exist_ok=True)
    safe_path(root)
    safe_path(lock_parent)
    return root, safe_path(lock_parent / 'serial.lock')


@contextmanager
def serial_lock(path):
    import msvcrt
    path = safe_path(path)
    with path.open('a+b') as stream:
        stream.seek(0, 2)
        require(stream.tell() <= 16, 'PRIVATE_LOCK_INVALID')
        if stream.tell() == 0:
            stream.write(b'0')
            stream.flush()
        stream.seek(0)
        try:
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            raise RuntimeError('ANOTHER_KAKAO_AUTOMATION_RUNNING') from None
        try:
            yield
        finally:
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)


def digest(path, maximum=512 * 1024):
    path = safe_path(path)
    require(path.is_file() and 0 < path.stat().st_size <= maximum, 'SOURCE_OR_CAPTURE_SIZE_INVALID')
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def sources():
    from reader_config import SOURCE_NAMES
    paths = {'room-open/' + name: HERE / name for name in ('room_open.py', 'hybrid_ui_win.py')}
    paths.update({'reader/' + name: READER / name for name in SOURCE_NAMES})
    paths.update({'preview/' + name: PREVIEW / name
                  for name in ('selfqa_config.py', 'attachment_runtime_preview.py')})
    return {key: digest(path) for key, path in sorted(paths.items())}


def write(path, record):
    safe_path(path)
    body = json.dumps(record, ensure_ascii=True, indent=2).encode('utf8')
    require(0 < len(body) <= MAX_RECORD, 'RECORD_SIZE_LIMIT')
    require(not path.exists(), 'RECORD_ALREADY_EXISTS')
    pending = path.with_name(path.name + '.pending-' + uuid.uuid4().hex)
    with pending.open('xb') as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())
    # link() publishes atomically and refuses an existing destination on both
    # Windows and POSIX. A failed write/fsync leaves only a private pending file,
    # which no receipt loader accepts. Do not use rename-overwrite semantics.
    os.link(pending, path)
    try:
        pending.unlink()
    except OSError:
        pass  # Publication already succeeded; a retained private link is harmless.


def read(path, root, maximum=MAX_RECORD):
    path = safe_path(path)
    require(path.parent == root and path.is_file() and 0 < path.stat().st_size <= maximum,
            'PRIVATE_RECORD_INVALID')
    value = json.loads(path.read_text(encoding='utf-8-sig'))
    require(isinstance(value, dict), 'PRIVATE_RECORD_INVALID')
    return value


def search_snapshot(path, root, now=None):
    """Accept only a successful, fresh search and its exact retained capture."""
    path = safe_path(path)
    require(re.fullmatch(r'room-[0-9a-f]{32}-receipt\.json', path.name), 'SEARCH_RECEIPT_NAME_INVALID')
    record = read(path, root)
    require(record.get('schema') == SCHEMA and record.get('command') == 'search'
            and record.get('status') == 'SEARCHED', 'SUCCESSFUL_SEARCH_RECEIPT_REQUIRED')
    execution, result = record.get('execution', {}), record.get('result', {})
    require(execution.get('exit') == 0 and execution.get('timeout') is False
            and result.get('status') == 'SEARCHED'
            and result.get('foreground_restored') is True and result.get('cursor_restored') is True,
            'SEARCH_EXECUTION_NOT_VERIFIED')
    snapshot = result.get('snapshot')
    require(isinstance(snapshot, dict), 'SNAPSHOT_REQUIRED')
    from hybrid_ui_win import check_snapshot
    check_snapshot(snapshot, snapshot, snapshot.get('query'), now=now)
    target = snapshot.get('query')
    require(isinstance(target, str) and 0 < len(target) <= 100, 'SEARCH_TARGET_INVALID')
    capture = snapshot.get('capture', {})
    filename = capture.get('filename')
    expected_name = path.name.removesuffix('-receipt.json') + '-search.bmp'
    require(capture.get('status') == 'CAPTURED' and filename == expected_name,
            'SEARCH_CAPTURE_REQUIRED')
    require(digest(root / filename, 3 * 1024 * 1024) == capture.get('sha256'),
            'SEARCH_CAPTURE_CHANGED')
    require(record.get('source_hashes') == sources(), 'SOURCE_CHANGED_AFTER_SEARCH')
    return target, snapshot


def request_for(args, root):
    request = {'action': args.command, 'allow_ui': getattr(args, 'allow_ui', False)}
    if args.command in ('search', 'open'):
        require(request['allow_ui'] is True, 'UI_CONSENT_REQUIRED')
    if args.command == 'open':
        require(args.confirm_row is True, 'ROW_NOT_VERIFIED')
        target, snapshot = search_snapshot(Path(args.search_receipt), root)
        request.update(target=target, expected=snapshot, row_point=args.point, row_verified=True)
    elif args.command != 'inspect':
        request['target'] = args.name
    if args.command == 'search':
        request['replace_existing_search'] = args.replace_search
    elif args.command == 'check':
        request.update(action='surface', check=True, check_preview=args.check_preview)
    from hybrid_ui_win import validate_request
    validate_request(request)
    return request


def worker(name, root):
    require(re.fullmatch(r'room-[0-9a-f]{32}-request\.json', name), 'WORKER_REQUEST_INVALID')
    request_path = root / name
    request = read(request_path, root)
    require(request.get('schema') == SCHEMA and request.get('source_hashes') == sources(),
            'WORKER_SOURCE_CHANGED')
    # Only the immediate launcher holding the shared lock may dispatch a worker.
    # The Job's kill-on-close rule owns child termination if that launcher exits.
    require(type(request.get('launcher_pid')) is int
            and request['launcher_pid'] == os.getppid(), 'LOCKED_LAUNCHER_REQUIRED')
    require(type(request.get('created_epoch')) in (int, float)
            and 0 <= time.time() - request['created_epoch'] <= JOB_SECONDS,
            'WORKER_REQUEST_EXPIRED')
    stem = name.removesuffix('-request.json')
    # Exclusive claim prevents replay even when an earlier UI outcome is unknown.
    write(root / (stem + '-claimed.json'), {'schema': SCHEMA, 'claimed_epoch': time.time(),
                                         'request_sha256': digest(request_path)})
    from hybrid_ui_win import execute
    result = execute(request['request'], root / (stem + '-search.bmp'))
    # Tree children are not needed for replay binding or row review.
    if isinstance(result.get('snapshot'), dict):
        result['snapshot'].pop('children', None)
    print(json.dumps(result, ensure_ascii=True), flush=True)
    return 2 if result['status'] == 'BLOCKED' else 0


def save_receipt(receipt, record):
    """Preserve a second immutable receipt if the primary write/fsync fails."""
    record['receipt_saved'] = True
    try:
        write(receipt, record)
        return
    except Exception as exc:
        record['observed_status_before_receipt_failure'] = record['status']
        record['primary_receipt_error'] = safe_error(exc)
    record['status'] = ('UI_OUTCOME_UNKNOWN_NO_RETRY' if record['command'] in ('search', 'open')
                        else 'INSPECTION_INCOMPLETE')
    emergency = receipt.with_name(receipt.name.removesuffix('-receipt.json') + '-emergency.json')
    record.update(reason='PRIMARY_RECEIPT_SAVE_FAILED', primary_receipt_path=str(receipt),
                  receipt_path=str(emergency), emergency_receipt=True)
    try:
        write(emergency, record)
    except Exception as exc:
        # This console record is the last bounded evidence when the filesystem
        # cannot retain either file. Never turn that situation into success.
        record.update(receipt_saved=False, reason='ALL_RECEIPT_SAVES_FAILED',
                      emergency_receipt_error=safe_error(exc))


def run_command(args, root, lock_path, runner=None):
    from reader_job import run as bounded
    runner = runner or bounded
    with serial_lock(lock_path):
        request = request_for(args, root)
        hashes = sources()
        stem = 'room-' + uuid.uuid4().hex
        request_path = root / (stem + '-request.json')
        output = root / (stem + '-worker.json')
        receipt = root / (stem + '-receipt.json')
        record = {'schema': SCHEMA, 'command': args.command, 'status': 'BLOCKED',
                  'created_epoch': time.time(), 'receipt_path': str(receipt),
                  'request_path': str(request_path), 'source_hashes': hashes,
                  'send_ready': False, 'actual_send': 'NOT_RUN', 'actual_sends': 0,
                  'automatic_retry_allowed': False}
        write(request_path, {'schema': SCHEMA, 'request': request, 'source_hashes': hashes,
                             'launcher_pid': os.getpid(), 'created_epoch': time.time()})
        if args.command == 'open':
            reviewed = safe_path(Path(args.search_receipt))
            claim = root / (reviewed.name.removesuffix('-receipt.json') + '-open-claimed.json')
            require(not claim.exists(), 'SEARCH_ALREADY_CLAIMED_NO_RETRY')
            write(claim, {'schema': SCHEMA, 'request_path': request_path.name,
                          'search_receipt_sha256': digest(reviewed), 'claimed_epoch': time.time(),
                          'automatic_retry_allowed': False})
        try:
            execution = runner([sys.executable, str(HERE / 'room_open.py'), '--worker', request_path.name],
                               output, JOB_SECONDS)
            record['execution'] = execution
            if execution.get('timeout') or execution.get('exit') not in (0, 2):
                record.update(status='UI_OUTCOME_UNKNOWN_NO_RETRY' if args.command in ('search', 'open')
                              else 'INSPECTION_INCOMPLETE', reason='WORKER_DID_NOT_COMPLETE')
            else:
                result = read(output, root)
                record['result'] = result
                require(result.get('send_ready') is False and result.get('actual_send') == 'NOT_RUN'
                        and result.get('actual_sends') == 0, 'WORKER_CONTRACT_INVALID')
                record['status'] = (result['status'] if execution['exit'] == 0
                                    and result.get('status') == SUCCESS[args.command] else 'BLOCKED')
                if args.command == 'search' and result.get('snapshot', {}).get('capture', {}).get('status') == 'CAPTURED':
                    record['capture_path'] = str(root / (stem + '-search.bmp'))
                    record['capture_bounds'] = result['snapshot']['capture']['bounds']
        except Exception as exc:
            record.update(status='UI_OUTCOME_UNKNOWN_NO_RETRY' if args.command in ('search', 'open')
                          else 'INSPECTION_INCOMPLETE', reason=safe_error(exc))
        finally:
            record['completed_epoch'] = time.time()
            save_receipt(receipt, record)
        return record


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--worker', help=argparse.SUPPRESS)
    commands = p.add_subparsers(dest='command')
    commands.add_parser('inspect', help='Read main-window metadata; no UI changes')
    search = commands.add_parser('search', help='Temporarily show search and save a private row capture')
    search.add_argument('--name', required=True)
    search.add_argument('--allow-ui', action='store_true')
    search.add_argument('--replace-search', action='store_true', help='Explicitly replace the existing search query')
    opening = commands.add_parser('open', help='Open one visually reviewed row from a saved search')
    opening.add_argument('--search-receipt', required=True)
    opening.add_argument('--point', nargs=2, type=int, required=True, metavar=('X', 'Y'))
    opening.add_argument('--confirm-row', action='store_true')
    opening.add_argument('--allow-ui', action='store_true')
    check = commands.add_parser('check', help='Check an already-open exact-title room in the background')
    check.add_argument('--name', required=True)
    check.add_argument('--check-preview', action='store_true', help='Read the applied attachment-preview setting; never change it')
    return p


def main(argv=None):
    p = parser()
    args = p.parse_args(argv)
    if not args.command and not args.worker:
        p.error('a command is required')
    try:
        if args.command in ('search', 'open'):
            require(args.allow_ui is True, 'UI_CONSENT_REQUIRED')
        if args.command == 'open':
            require(args.confirm_row is True, 'ROW_NOT_VERIFIED')
        root, lock_path = state_paths()
        if args.worker:
            return worker(args.worker, root)
        result = run_command(args, root, lock_path)
        print(json.dumps(result, ensure_ascii=True), flush=True)
        return 0 if result['status'] == SUCCESS[args.command] else 2
    except Exception as exc:
        print(json.dumps({'schema': SCHEMA, 'status': 'BLOCKED', 'reason': safe_error(exc),
                          'send_ready': False, 'actual_send': 'NOT_RUN', 'actual_sends': 0,
                          'automatic_retry_allowed': False}), flush=True)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
