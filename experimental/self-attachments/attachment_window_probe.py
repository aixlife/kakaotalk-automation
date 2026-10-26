"""Read-only self-chat attachment preflight in the existing user session.

The request is produced from the bounded reader's verified MemoChat result.
This file does not open windows, deliver drops, read clipboard or send input.
"""
from selfqa_config import ROOT, SOURCE_ROOT, READER_ROOT, PYTHON
import ctypes as C
import ctypes.wintypes as W
import json
from pathlib import Path
import re
import sys
import time
from room_reader import Reader


def inspect(request):
    assert request.get('room_type') == 'MemoChat' and request.get('all_author_self') is True
    selected = request['title']
    assert isinstance(selected, str) and 0 < len(selected) <= 100
    reader = Reader()
    started = time.monotonic()
    user = C.WinDLL('user32', use_last_error=True)
    kernel = C.WinDLL('kernel32', use_last_error=True)
    user.GetForegroundWindow.restype = W.HWND
    user.GetWindowThreadProcessId.argtypes = [W.HWND, C.POINTER(W.DWORD)]
    user.GetWindowTextW.argtypes = [W.HWND, W.LPWSTR, C.c_int]
    user.GetClassNameW.argtypes = [W.HWND, W.LPWSTR, C.c_int]
    user.GetDlgCtrlID.argtypes = [W.HWND]
    user.IsWindowVisible.argtypes = [W.HWND]
    user.IsWindowEnabled.argtypes = [W.HWND]
    user.IsIconic.argtypes = [W.HWND]
    user.GetLastActivePopup.argtypes = [W.HWND]
    user.GetLastActivePopup.restype = W.HWND
    user.SendMessageTimeoutW.argtypes = [W.HWND, W.UINT, W.WPARAM, W.LPARAM,
                                       W.UINT, W.UINT, C.POINTER(C.c_size_t)]
    user.SendMessageTimeoutW.restype = W.LPARAM
    kernel.ProcessIdToSessionId.argtypes = [W.DWORD, C.POINTER(W.DWORD)]
    callback = C.WINFUNCTYPE(W.BOOL, W.HWND, W.LPARAM)
    user.EnumWindows.argtypes = [callback, W.LPARAM]
    user.EnumChildWindows.argtypes = [W.HWND, callback, W.LPARAM]

    def point():
        value = W.POINT()
        assert user.GetCursorPos(C.byref(value))
        return [value.x, value.y]

    def owner(hwnd):
        value = W.DWORD()
        user.GetWindowThreadProcessId(hwnd, C.byref(value))
        return value.value

    def class_name(hwnd):
        value = C.create_unicode_buffer(128)
        user.GetClassNameW(hwnd, value, len(value))
        return value.value

    def message(hwnd, number, wparam=0, lparam=0):
        value = C.c_size_t()
        assert user.SendMessageTimeoutW(hwnd, number, wparam, lparam, 2, 250,
                                        C.byref(value)), 'READ_MESSAGE_TIMEOUT'
        return value.value

    try:
        current = W.DWORD()
        target = W.DWORD()
        assert kernel.ProcessIdToSessionId(kernel.GetCurrentProcessId(), C.byref(current))
        assert kernel.ProcessIdToSessionId(reader.pid, C.byref(target))
        assert current.value > 0 and current.value == target.value, 'USER_SESSION_UNAVAILABLE'
        foreground = user.GetForegroundWindow()
        assert foreground, 'FOREGROUND_UNAVAILABLE'
        cursor = point()
        app_private = reader.guard()
        candidates = []
        seen = []
        visits = []

        @callback
        def each(hwnd, _):
            if owner(hwnd) != reader.pid:
                return True
            seen.append(hwnd)
            if len(seen) >= 500 or time.monotonic() - started >= 8:
                return False
            title = C.create_unicode_buffer(256)
            user.GetWindowTextW(hwnd, title, len(title))
            if title.value != selected:
                return True
            children = []

            @callback
            def child(handle, _):
                visits.append(handle)
                if len(visits) >= 2000:
                    return False
                children.append((handle, class_name(handle).upper(), user.GetDlgCtrlID(handle)))
                return True

            user.EnumChildWindows(hwnd, child, 0)
            inputs = [x for x in children if x[1:] == ('RICHEDIT50W', 1006)]
            lists = [x for x in children if x[1:] == ('EVA_VH_LISTCONTROL_DBLCLK', 100)]
            candidate = {'hwnd': int(hwnd), 'class': class_name(hwnd),
                         'visible': bool(user.IsWindowVisible(hwnd)),
                         'enabled': bool(user.IsWindowEnabled(hwnd)),
                         'minimized': bool(user.IsIconic(hwnd)),
                         'active_popup_is_self': user.GetLastActivePopup(hwnd) == hwnd,
                         'input_count': len(inputs), 'message_list_count': len(lists)}
            if len(inputs) == 1:
                handle = inputs[0][0]
                length = message(handle, 14)
                candidate['input_length'] = length
                candidate['input_is_actually_empty'] = length == 0
                if 0 < length <= 20:
                    buffer = C.create_unicode_buffer(21)
                    message(handle, 13, 21, C.addressof(buffer))
                    candidate['input_is_placeholder'] = buffer.value == '메시지 입력'
                    for offset in range(len(buffer)):
                        buffer[offset] = '\0'
                candidate['input_hwnd'] = int(handle)
            candidates.append(candidate)
            return True

        complete = bool(user.EnumWindows(each, 0)) and len(seen) < 500 and len(visits) < 2000
        after = user.GetForegroundWindow()
        after_cursor = point()
        return {'status': 'READ_ONLY_PREFLIGHT', 'pid': reader.pid,
                'session': current.value, 'complete': complete,
                'self_identity_source': 'BOUNDED_READER_MEMOCHAT_AND_AUTHOR_SELF',
                'app_top_windows': len(seen), 'self_windows': candidates,
                'foreground_is_kakao': owner(foreground) == reader.pid,
                'foreground_before': int(foreground), 'foreground_after': int(after or 0),
                'foreground_unchanged': foreground == after,
                'cursor_before': cursor, 'cursor_after': after_cursor,
                'cursor_unchanged': cursor == after_cursor,
                'app_private_before': app_private, 'app_private_after': reader.guard(),
                'input_calls': 0, 'clipboard_calls': 0, 'file_drop_calls': 0,
                'window_open_calls': 0, 'raw_input_saved': False}
    finally:
        reader.close()


def main():
    assert len(sys.argv) == 2 and re.fullmatch('attachment-preflight-[a-f0-9]{32}\\.json', sys.argv[1])
    path = ROOT / sys.argv[1]
    assert path.stat().st_size < 4096
    result = inspect(json.loads(path.read_text(encoding='utf-8-sig')))
    print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
