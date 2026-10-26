"""One-shot self-chat file-drop QA. Never changes focus, clipboard or settings.

Windows may create a preview window. Execution is blocked unless that exact QA
has an explicit owner approval for the preview UI, or a require-no-UI request
has a stable native preview-OFF preflight. Original fixed-fixture behavior has live self-chat evidence. This portable
package requires its own validation and remains an experimental QA tool.
"""
import ctypes as C
import ctypes.wintypes as W
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import time

from selfqa_config import ROOT, SOURCE_ROOT, READER_ROOT, PYTHON
MAX_FILE = 262144


def drop_payload(path):
    if '\0' in path or not re.match(r'^[A-Za-z]:\\', path):
        raise ValueError('ABSOLUTE_WINDOWS_FILE_PATH_REQUIRED')
    return struct.pack('<IiiII', 20, 0, 0, 0, 1) + (path + '\0\0').encode('utf-16-le')


def validate_request(request):
    rid = request.get('request_id', '')
    if not isinstance(rid, str) or not re.fullmatch('[a-f0-9]{32}', rid):
        raise ValueError('REQUEST_ID_REQUIRED')
    if type(request.get('execute')) is not bool:
        raise ValueError('EXPLICIT_EXECUTE_BOOLEAN_REQUIRED')
    if type(request.get('owner_authorized_self_qa', False)) is not bool:
        raise ValueError('SELF_QA_APPROVAL_MUST_BE_BOOLEAN')
    if request['execute'] and request.get('owner_authorized_self_qa') is not True:
        raise ValueError('EXPLICIT_SELF_QA_APPROVAL_REQUIRED')
    if request.get('kind') not in ('file', 'image'):
        raise ValueError('FILE_OR_IMAGE_ONLY')
    if request.get('destination') != 'SELF_CHAT_ONLY':
        raise ValueError('SELF_CHAT_ONLY')
    if request.get('owner_approved_preview_ui', False) is not False and request.get('owner_approved_preview_ui') is not True:
        raise ValueError('PREVIEW_APPROVAL_MUST_BE_BOOLEAN')
    if type(request.get('require_no_ui', False)) is not bool:
        raise ValueError('REQUIRE_NO_UI_MUST_BE_BOOLEAN')
    if request.get('require_no_ui') and request.get('owner_approved_preview_ui'):
        raise ValueError('NO_UI_REQUEST_CANNOT_APPROVE_PREVIEW')
    if not isinstance(request.get('file_sha256'), str) or not re.fullmatch('[a-f0-9]{64}', request['file_sha256']):
        raise ValueError('FILE_HASH_REQUIRED')
    if not re.fullmatch('attachment-qa-[a-f0-9]{12}\\.(txt|png)', request.get('file_name', '')):
        raise ValueError('FIXTURE_NAME_ONLY')


def preview_gate(request, state):
    """Select the reviewed branch without changing the user's preference."""
    if request.get('require_no_ui') is True:
        if request.get('owner_approved_preview_ui') is True:
            raise RuntimeError('NO_UI_REQUEST_CANNOT_APPROVE_PREVIEW')
        if not all(state.get(k) is True for k in
                   ('native_mode_check_performed', 'saved_preference_applies', 'stable_double_read')):
            raise RuntimeError('NO_UI_NATIVE_STATE_UNVERIFIED_NO_DROP')
        if state.get('preview_enabled') is not False or state.get('value') != 'no':
            raise RuntimeError('PREVIEW_ENABLED_OR_UNKNOWN_NO_UI_DROP_BLOCKED')
        return 'NATIVE_PREVIEW_OFF_SELF_QA_CANDIDATE'
    if request.get('owner_approved_preview_ui') is not True:
        raise RuntimeError('PREVIEW_UI_NOT_APPROVED_NO_DROP')
    if state.get('preview_enabled') is not True:
        raise RuntimeError('UNREVIEWED_PREVIEW_BRANCH')
    return 'OWNER_APPROVED_PREVIEW_SELF_QA'


def validate_fixture(request, path, expected_stat=None):
    """Re-read the bounded fixture at the boundary; stat alone is insufficient."""
    if path.is_symlink() or path.parent != ROOT.resolve() or not path.is_file():
        raise RuntimeError('FIXTURE_PATH_NOT_ALLOWED')
    before = path.stat()
    if not 0 < before.st_size <= MAX_FILE:
        raise RuntimeError('FIXTURE_SIZE_LIMIT')
    if expected_stat is not None and (before.st_size, before.st_mtime_ns) != (
            expected_stat.st_size, expected_stat.st_mtime_ns):
        raise RuntimeError('FIXTURE_CHANGED_BEFORE_DROP')
    with path.open('rb') as stream:
        data = stream.read(MAX_FILE + 1)
    if len(data) > MAX_FILE:
        raise RuntimeError('FIXTURE_SIZE_CHANGED_DURING_READ')
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise RuntimeError('FIXTURE_CHANGED_DURING_READ')
    if hashlib.sha256(data).hexdigest() != request['file_sha256']:
        raise RuntimeError('FIXTURE_HASH_CHANGED')
    if request['kind'] == 'image' and (path.suffix != '.png' or not data.startswith(b'\x89PNG\r\n\x1a\n')):
        raise RuntimeError('PNG_EXTENSION_AND_CONTENT_REQUIRED')
    if request.get('require_no_ui') and request['kind'] == 'image':
        width, height = struct.unpack('>II', data[16:24])
        if (type(request.get('image_width')) is not int or type(request.get('image_height')) is not int
                or (width, height) != (request['image_width'], request['image_height'])
                or request.get('file_bytes') != len(data)):
            raise RuntimeError('QA_IMAGE_METADATA_MISMATCH')
    if request['kind'] == 'file' and (path.suffix != '.txt' or not data.startswith(b'KakaoTalk self-chat attachment QA\n')):
        raise RuntimeError('HARMLESS_TEXT_FIXTURE_REQUIRED')
    return after


def validate_window(snapshot, require_no_ui):
    if not snapshot['complete'] or not snapshot['foreground_unchanged'] or not snapshot['cursor_unchanged']:
        raise RuntimeError('WINDOW_PREFLIGHT_INCOMPLETE')
    if require_no_ui and snapshot.get('foreground_is_kakao'):
        raise RuntimeError('KAKAO_FOREGROUND_NO_UI_QA_BLOCKED')
    if len(snapshot['self_windows']) != 1:
        raise RuntimeError('ONE_ALREADY_OPEN_SELF_WINDOW_REQUIRED')
    target = snapshot['self_windows'][0]
    if not all(target.get(k) for k in ('visible', 'enabled', 'active_popup_is_self')):
        raise RuntimeError('SELF_WINDOW_NOT_READY')
    if target['minimized'] or target['input_count'] != 1 or target['message_list_count'] != 1:
        raise RuntimeError('SELF_WINDOW_SIGNATURE_OR_STATE_CHANGED')
    if not (target.get('input_is_actually_empty') or target.get('input_is_placeholder')):
        raise RuntimeError('USER_DRAFT_PRESENT')
    return target


def require_clean_observation(observation):
    if (observation.get('complete') is not True
            or observation.get('new_visible_app_top_count') != 0
            or observation.get('app_foreground_events') != 0
            or observation.get('foreground_unchanged') is not True
            or observation.get('cursor_unchanged') is not True):
        raise RuntimeError('UI_CHANGED_OR_OBSERVATION_INCOMPLETE_NO_DROP')


def external_observer_guard(request, reader):
    stem = request.get('observer_stem', '')
    if not re.fullmatch(r'headless-observer-[a-f0-9]{32}', stem):
        raise RuntimeError('CONTINUOUS_OBSERVER_REQUIRED_NO_DROP')
    if (ROOT / (stem + '-result.json')).exists():
        raise RuntimeError('CONTINUOUS_OBSERVER_ENDED_NO_DROP')
    def load(suffix):
        path = ROOT / (stem + suffix)
        if path.is_symlink() or path.stat().st_size > 16384:
            raise RuntimeError('OBSERVER_RECEIPT_INVALID')
        return json.loads(path.read_text(encoding='utf-8-sig'))
    ready, state = load('-ready.json'), load('-state.json')
    if (ready.get('status') != 'READY' or ready.get('pid') != reader.pid
            or ready.get('created_at_filetime') != str(reader.created_at_filetime)
            or state.get('status') != 'OBSERVING'
            or not 0 <= time.time() - state.get('epoch', 0) < 1.5):
        raise RuntimeError('CONTINUOUS_OBSERVER_STALE_OR_UNBOUND_NO_DROP')
    require_clean_observation(state.get('observation') or {})


def run(request):
    from attachment_runtime_preview import inspect as preview_state
    from attachment_window_probe import inspect as window_state
    from room_reader import Reader
    from reader_job import run as bounded

    validate_request(request)
    rid = request['request_id']
    source_path = ROOT / request['file_name']
    if source_path.is_symlink():
        raise RuntimeError('FIXTURE_SYMLINK_NOT_ALLOWED')
    path = source_path.resolve()
    if path.parent != ROOT.resolve() or not path.is_file():
        raise RuntimeError('FIXTURE_PATH_NOT_ALLOWED')
    stat = validate_fixture(request, path)
    phase = 'execute' if request['execute'] else 'plan'
    evidence = ROOT / ('attachment-send-' + rid + '-' + phase + '-self.json')
    cli = READER_ROOT / 'kakao_read_win.py'
    execution = bounded([PYTHON, str(cli), 'self', '--limit', '3'], evidence, 20)
    if execution['exit'] != 0 or execution['timeout']:
        raise RuntimeError('SELF_READER_FAILED_BEFORE_DROP')
    own = json.loads(evidence.read_text(encoding='utf-8-sig'))['result']
    if own.get('status') != 'MESSAGES_READ' or own['room']['type'] != 'MemoChat' or not own['messages']:
        raise RuntimeError('SELF_ROOM_UNVERIFIED')
    if not all(message.get('author_is_self') for message in own['messages']):
        raise RuntimeError('SELF_AUTHOR_UNVERIFIED')
    selected = {'title': own['room']['title'], 'room_type': 'MemoChat', 'all_author_self': True}
    snapshot = window_state(selected)
    target = validate_window(snapshot, request.get('require_no_ui', False))
    preview = preview_state()
    approved = request.get('owner_approved_preview_ui') is True
    route = preview_gate(request, preview)
    result = {'status': 'PREFLIGHT_READY_NOT_EXECUTED', 'request_id': rid,
              'destination': 'SELF_CHAT_ONLY', 'file_name': path.name,
              'file_sha256': request['file_sha256'], 'file_bytes': stat.st_size,
              'kind': request['kind'], 'window': snapshot, 'preview': preview,
              'route': route, 'require_no_ui': request.get('require_no_ui', False),
              'no_ui_e2e_verified': False,
              'owner_approved_preview_ui': approved, 'input_calls': 0,
              'clipboard_calls': 0, 'settings_changed': False,
              'send_attempted': False, 'delivery_observed': False,
              'automatic_retry_allowed': False, 'ui_side_effect_possible': True}
    if not request['execute']:
        return result
    reader = Reader()
    user = C.WinDLL('user32', use_last_error=True)
    kernel = C.WinDLL('kernel32', use_last_error=True)
    user.PostMessageW.argtypes = [W.HWND, W.UINT, W.WPARAM, W.LPARAM]
    user.PostMessageW.restype = W.BOOL
    user.GetForegroundWindow.restype = W.HWND
    user.GetWindowThreadProcessId.argtypes = [W.HWND, C.POINTER(W.DWORD)]
    kernel.GlobalAlloc.argtypes = [W.UINT, C.c_size_t]
    kernel.GlobalAlloc.restype = W.HGLOBAL
    kernel.GlobalLock.argtypes = [W.HGLOBAL]
    kernel.GlobalLock.restype = C.c_void_p
    kernel.GlobalUnlock.argtypes = [W.HGLOBAL]
    kernel.GlobalFree.argtypes = [W.HGLOBAL]
    kernel.GlobalFree.restype = W.HGLOBAL
    handle = None
    watch = None
    queued = False
    ledger = ROOT / ('attachment-send-' + rid + '-ledger.json')
    try:
        if reader.pid != snapshot['pid']:
            raise RuntimeError('APP_RESTARTED_BEFORE_DROP')
        pid = W.DWORD()
        user.GetWindowThreadProcessId(target['hwnd'], C.byref(pid))
        if pid.value != reader.pid:
            raise RuntimeError('TARGET_OWNERSHIP_CHANGED')
        point = W.POINT()
        if not user.GetCursorPos(C.byref(point)) or [point.x, point.y] != snapshot['cursor_after']:
            raise RuntimeError('USER_CURSOR_CHANGED_BEFORE_DROP')
        if user.GetForegroundWindow() != snapshot['foreground_after']:
            raise RuntimeError('FOREGROUND_CHANGED_BEFORE_DROP')
        reader.guard()
        # Re-read identity, draft, popup, preview mode/value and content just
        # before ownership transfer. Unknown/racing state blocks the drop.
        fresh = window_state(selected)
        fresh_target = validate_window(fresh, request.get('require_no_ui', False))
        if fresh['pid'] != reader.pid or fresh_target['hwnd'] != target['hwnd']:
            raise RuntimeError('SELF_WINDOW_CHANGED_BEFORE_DROP')
        if (fresh['foreground_after'] != snapshot['foreground_after'] or
                fresh['cursor_after'] != snapshot['cursor_after']):
            raise RuntimeError('USER_SURFACE_CHANGED_BEFORE_DROP')
        fresh_preview = preview_state()
        if preview_gate(request, fresh_preview) != route:
            raise RuntimeError('PREVIEW_ROUTE_CHANGED_BEFORE_DROP')
        validate_fixture(request, path, stat)
        result['boundary_preview'] = fresh_preview
        if request.get('require_no_ui'):
            from no_ui_window_watch import WindowWatch
            watch = WindowWatch(reader.pid,self_hwnd=target['hwnd'])
            watch.__enter__()
            if watch.created != reader.created_at_filetime:
                raise RuntimeError('WATCH_APP_RESTARTED_BEFORE_DROP')
            # The watcher installation itself must not be used as a stale gate.
            if preview_gate(request, preview_state()) != route:
                raise RuntimeError('PREVIEW_ROUTE_CHANGED_AFTER_WATCH')
            latest = window_state(selected)
            latest_target = validate_window(latest, True)
            if (latest['pid'] != reader.pid or latest_target['hwnd'] != target['hwnd']
                    or latest['foreground_after'] != snapshot['foreground_after']
                    or latest['cursor_after'] != snapshot['cursor_after']):
                raise RuntimeError('WINDOW_CHANGED_AFTER_WATCH')
            validate_fixture(request, path, stat)
            result['boundary_ui_observation'] = watch.checkpoint()
            require_clean_observation(result['boundary_ui_observation'])
            external_observer_guard(request, reader)
        payload = drop_payload(str(path))
        handle = kernel.GlobalAlloc(0x42, len(payload))
        if not handle:
            raise RuntimeError('OWN_DROP_BUFFER_ALLOCATION_FAILED')
        pointer = kernel.GlobalLock(handle)
        if not pointer:
            raise RuntimeError('OWN_DROP_BUFFER_LOCK_FAILED')
        C.memmove(pointer, payload, len(payload))  # Writes only this helper's own allocation.
        kernel.GlobalUnlock(handle)
        with (ROOT / ('attachment-content-' + request['file_sha256'] + '-once.json')).open('x', encoding='utf8') as stream:
            json.dump({'request_id': rid, 'file_sha256': request['file_sha256'],
                       'status': 'ONE_SHOT_CLAIMED', 'automatic_retry_allowed': False}, stream)
        with ledger.open('x', encoding='utf8') as stream:
            json.dump({'request_id': rid, 'status': 'SEND_BOUNDARY_ENTERING',
                       'file_name': path.name, 'file_sha256': request['file_sha256'],
                       'kind': request['kind'], 'target_hwnd': target['hwnd'],
                       'preflight_self_sha256': hashlib.sha256(evidence.read_bytes()).hexdigest(),
                       'pid': reader.pid, 'created_at_filetime': reader.created_at_filetime,
                       'epoch': time.time(), 'automatic_retry_allowed': False}, stream)
        if watch:
            require_clean_observation(watch.checkpoint())
            external_observer_guard(request, reader)
        result['send_attempted'] = True
        result['input_calls'] = 1
        result['preflight_self_sha256'] = hashlib.sha256(evidence.read_bytes()).hexdigest()
        if not user.PostMessageW(target['hwnd'], 0x233, int(handle), 0):
            raise RuntimeError('DROP_QUEUE_REJECTED_NO_RETRY')
        queued = True
        result['drop_buffer_ownership_transferred'] = True
        if watch:
            result['ui_observation'] = watch.finish(seconds=3.0)
            watch.__exit__(None, None, None)
            watch = None
        else:
            time.sleep(.5)
        result['status'] = 'DROP_QUEUED_RECEIPT_UNVERIFIED'
        if request.get('require_no_ui'):
            try:
                require_clean_observation(result['ui_observation'])
            except RuntimeError:
                result['status'] = 'DROP_QUEUED_UI_OBSERVATION_FAILED_NO_RETRY'
        result['queue_accepted_not_delivery_proof'] = True
        result['app_private_after'] = reader.guard()
        with ledger.open('w', encoding='utf8') as stream:
            json.dump({k: v for k, v in result.items() if k not in ('window', 'preview', 'boundary_preview')}, stream)
        return result
    finally:
        if watch:
            watch.__exit__(None, None, None)
        if handle and not queued:
            kernel.GlobalFree(handle)
        reader.close()


def main():
    assert len(sys.argv) == 2 and re.fullmatch('attachment-send-[a-f0-9]{32}\\.json', sys.argv[1])
    path = ROOT / sys.argv[1]
    assert path.stat().st_size <= 4096
    request = json.loads(path.read_text(encoding='utf-8-sig'))
    result = {'status': 'BLOCKED', 'send_attempted': False, 'automatic_retry_allowed': False}
    try:
        result = run(request)
    except Exception as error:
        result['reason'] = str(error)
        # Caller must inspect the immutable one-shot ledger before any recovery.
        result['check_same_ledger_before_recovery'] = True
        rid = request.get('request_id', '')
        if isinstance(rid, str) and re.fullmatch('[a-f0-9]{32}', rid):
            if (ROOT / ('attachment-send-' + rid + '-ledger.json')).is_file():
                result['status'] = 'UNCERTAIN_AFTER_SEND_BOUNDARY'
                result['send_attempted'] = 'unknown'
    print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
