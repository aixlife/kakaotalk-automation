"""Bounded observation-only child. No subprocess, UI actions or send API.

Only the launching parent's fixed QA job may start this helper. It owns one
WinEvent loop on its main thread; checkpoint continuously drains that thread.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import threading
import time
import uuid

from selfqa_config import ROOT, SOURCE_ROOT, READER_ROOT, PYTHON


def validate_request(name, request):
    if not isinstance(name, str) or not re.fullmatch(r'headless-observer-[0-9a-f]{32}\.json', name):
        raise ValueError('OBSERVER_REQUEST_NAME_INVALID')
    if type(request.get('pid')) is not int or request['pid'] <= 0:
        raise ValueError('OBSERVER_PID_INVALID')
    created = request.get('created_at_filetime')
    if not isinstance(created, str) or not re.fullmatch('[0-9]{1,20}', created) or int(created) <= 0:
        raise ValueError('OBSERVER_CREATION_TIME_INVALID')
    digest = request.get('source_sha256')
    if not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest):
        raise ValueError('OBSERVER_SOURCE_HASH_REQUIRED')
    if type(request.get('seconds')) is not int or request['seconds'] != 35:
        raise ValueError('OBSERVER_SECONDS_MUST_BE_35')
    if type(request.get('self_hwnd')) is not int or request['self_hwnd']<=0:
        raise ValueError('OBSERVER_VERIFIED_SELF_REQUIRED')


def clean(checkpoint):
    return (checkpoint.get('complete') is True
            and checkpoint.get('overflow') is False
            and checkpoint.get('errors') == []
            and type(checkpoint.get('new_visible_app_top_count')) is int
            and checkpoint['new_visible_app_top_count'] == 0
            and type(checkpoint.get('app_foreground_events')) is int
            and checkpoint['app_foreground_events'] == 0
            and checkpoint.get('foreground_unchanged') is True
            and checkpoint.get('cursor_unchanged') is True)


def publish(path, value, immutable):
    """Publish complete JSON without exposing a partially written final path."""
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        with temporary.open('x', encoding='utf8') as stream:
            json.dump(value, stream, ensure_ascii=True)
            stream.flush()
        if immutable:
            # On Windows os.rename refuses an existing destination. Never use
            # replace for immutable ready/result receipts.
            os.rename(temporary, path)
        else:
            os.replace(temporary, path)
    finally:
        if temporary.exists(): temporary.unlink()


def run(name):
    if os.name != 'nt': raise RuntimeError('WINDOWS_REQUIRED')
    if not re.fullmatch(r'headless-observer-[0-9a-f]{32}\.json', name):
        raise ValueError('OBSERVER_REQUEST_NAME_INVALID')
    request_path = ROOT / name
    if request_path.is_symlink() or not 0 < request_path.stat().st_size <= 4096:
        raise RuntimeError('OBSERVER_REQUEST_FILE_INVALID')
    request = json.loads(request_path.read_text(encoding='utf-8-sig'))
    validate_request(name, request)
    stem = name[:-5]
    ready_path = ROOT / (stem + '-ready.json')
    state_path = ROOT / (stem + '-state.json')
    result_path = ROOT / (stem + '-result.json')
    stop_path = ROOT / (stem + '-stop.json')
    if any(p.exists() for p in (ready_path, state_path, result_path, stop_path)):
        raise RuntimeError('OBSERVER_REQUEST_ALREADY_USED')
    # Exclusive claim also prevents simultaneous starts with the same stem.
    with (ROOT / (stem + '-claim.json')).open('x', encoding='utf8') as stream:
        json.dump({'pid': os.getpid(), 'epoch': time.time()}, stream)
    observed_start = None
    ready_published = False
    observation = None
    final_checkpoint = None
    stop_reason = 'ERROR'
    errors = []
    # The parent supplies a Job memory/time cap. This additional deadline only
    # ends our own process; it never terminates KakaoTalk or other processes.
    watchdog = threading.Timer(45, lambda: os._exit(124))
    watchdog.daemon = True; watchdog.start()
    try:
        source = SOURCE_ROOT / 'no_ui_window_watch.py'
        if hashlib.sha256(source.read_bytes()).hexdigest() != request['source_sha256']:
            raise RuntimeError('OBSERVER_WATCH_SOURCE_CHANGED')
        from no_ui_window_watch import WindowWatch
        with WindowWatch(request['pid'], max_total_seconds=45, self_hwnd=request['self_hwnd']) as watch:
            observed_start = time.time() - (time.monotonic() - watch.hook_started)
            if str(watch.created) != request['created_at_filetime']:
                raise RuntimeError('OBSERVER_PROCESS_IDENTITY_CHANGED')
            initial = watch.checkpoint()
            if not clean(initial):
                final_checkpoint = initial
                raise RuntimeError('OBSERVER_INITIAL_CHECKPOINT_NOT_CLEAN')
            start_monotonic = time.monotonic()
            publish(ready_path, {'status': 'READY', 'pid': request['pid'],
                'created_at_filetime': request['created_at_filetime'],
                'observation': initial, 'monotonic': start_monotonic,
                'epoch': time.time(), 'send_attempted': False,
                'input_calls': 0, 'focus_calls': 0, 'clipboard_calls': 0}, True)
            ready_published = True
            deadline = start_monotonic + request['seconds']
            heartbeat = 0.0
            while True:
                final_checkpoint = watch.checkpoint()
                now = time.monotonic()
                if now >= heartbeat:
                    publish(state_path, {'status': 'OBSERVING' if clean(final_checkpoint) else 'OBSERVATION_NOT_CLEAN',
                        'epoch': time.time(), 'monotonic': now,
                        'observation': final_checkpoint, 'send_attempted': False,
                        'input_calls': 0, 'focus_calls': 0, 'clipboard_calls': 0}, False)
                    heartbeat = now + .25
                if not clean(final_checkpoint):
                    stop_reason = 'OBSERVATION_NOT_CLEAN'; break
                if stop_path.exists():
                    stop_reason = 'STOP_FILE'; break
                if now >= deadline:
                    stop_reason = 'DEADLINE_35_SECONDS'; break
                time.sleep(min(.02, max(0, deadline - now)))
            observation = watch.finish(seconds=0)
        # __exit__ has now unhooked and can mark this same observation dict
        # incomplete if unhook failed.
    except Exception as exc:
        errors.append(str(exc) if isinstance(exc, (RuntimeError, ValueError, AssertionError)) else type(exc).__name__)
        if not ready_published:
            publish(ready_path, {'status': 'NOT_READY', 'epoch': time.time(),
                'monotonic': time.monotonic(), 'observation': final_checkpoint,
                'errors': errors, 'send_attempted': False,
                'input_calls': 0, 'focus_calls': 0, 'clipboard_calls': 0}, True)
    finally:
        try:
            observed_end = time.time()
            complete = not errors and observation is not None and clean(observation)
            result = {'status': 'OBSERVATION_COMPLETE' if complete else 'OBSERVATION_INCOMPLETE',
                'complete': complete, 'observed_start_epoch': observed_start,
                'observed_end_epoch': observed_end, 'stop_reason': stop_reason,
                'observation': observation, 'final_checkpoint': final_checkpoint,
                'errors': errors, 'send_attempted': False,
                'input_calls': 0, 'focus_calls': 0, 'clipboard_calls': 0,
                'process_write_calls': 0, 'settings_changed': False,
                'later_ui_absence_proven': False}
            publish(result_path, result, True)
            publish(state_path, {'status': result['status'], 'complete': complete,
                'epoch': observed_end, 'monotonic': time.monotonic(),
                'observation': observation, 'send_attempted': False,
                'input_calls': 0, 'focus_calls': 0, 'clipboard_calls': 0}, False)
        finally:
            watchdog.cancel()


if __name__ == '__main__':
    if len(sys.argv) != 2: raise RuntimeError('ONE_OBSERVER_REQUEST_REQUIRED')
    run(sys.argv[1])
