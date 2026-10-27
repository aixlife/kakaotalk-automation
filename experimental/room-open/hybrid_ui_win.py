"""Bounded, ctypes-only Kakao main-window inspect/search/open. Never sends.

Internal worker for room_open.py (existing 256 MiB Job, same interactive session).
inspect: {"action":"inspect"}
search: {"action":"search","target":"exact title","expected":prior_snapshot?}
Search may explicitly replace existing text with replace_existing_search:true.
open: {"action":"open","target":"exact title","expected":search_snapshot,
       "row_point":[screen_x,screen_y],"row_verified":true}
Only search-owned text can be replaced. Snapshot age limit is 300 seconds.
The caller must visually verify the result row before supplying row_point.
No chat-id binding is inferred from a window title. send_ready is always false.
"""
import ctypes as C
import ctypes.wintypes as W
import hashlib
import json
import os
import re
from pathlib import Path
import sys
import struct
import threading
import time

APP_PRIVATE_STOP = 469893120
JOB_LIMIT = 256 * 1024 * 1024
SOFT_SECONDS = 11.5
HARD_SECONDS = 14.5
SNAPSHOT_SECONDS = 300
CAPTURE_LIMIT = 3 * 1024 * 1024
STRUCTURAL_TITLES = {'ChatRoomListView', 'SearchListCtrl', 'KakaoTalk', '카카오톡'}
MAIN_TITLES = {'KakaoTalk', '카카오톡'}


class GuardError(RuntimeError):
    pass


def require(condition, code):
    if not condition:
        raise GuardError(code)


def validate_request(request):
    require(isinstance(request, dict), 'REQUEST_INVALID')
    require(request.get('action') in ('inspect', 'surface', 'search', 'open'), 'ACTION_INVALID')
    if request['action'] in ('search', 'open'):
        require(request.get('allow_ui') is True, 'UI_CONSENT_REQUIRED')
    if 'replace_existing_search' in request:
        require(request['action'] == 'search' and type(request['replace_existing_search']) is bool,
                'REPLACE_SEARCH_OPTION_INVALID')
    if request['action'] != 'inspect':
        target = request.get('target')
        require(isinstance(target, str) and 0 < len(target) <= 100
                and all(ord(c) >= 32 and ord(c) != 127 for c in target), 'TARGET_INVALID')
    if request['action'] == 'open':
        point = request.get('row_point')
        require(request.get('row_verified') is True, 'ROW_NOT_VERIFIED')
        require(isinstance(point, list) and len(point) == 2
                and all(type(v) is int for v in point), 'ROW_POINT_INVALID')
        require(isinstance(request.get('expected'), dict), 'SNAPSHOT_REQUIRED')
        capture = request['expected'].get('capture')
        require(isinstance(capture, dict) and capture.get('status') == 'CAPTURED',
                'SEARCH_CAPTURE_REQUIRED')
        require(isinstance(capture.get('sha256'), str)
                and re.fullmatch('[a-f0-9]{64}', capture['sha256']), 'CAPTURE_HASH_REQUIRED')
        bounds = capture.get('bounds')
        require(isinstance(bounds, list) and len(bounds) == 4
                and all(type(v) is int for v in bounds) and point_in_rect(point, bounds),
                'ROW_OUTSIDE_REVIEWED_CAPTURE')


def check_snapshot(expected, current, target=None, now=None):
    require(isinstance(expected, dict), 'SNAPSHOT_REQUIRED')
    now = time.time() if now is None else now
    stamp = expected.get('captured_epoch')
    require(type(stamp) in (int, float) and 0 <= now - stamp <= SNAPSHOT_SECONDS,
            'SNAPSHOT_EXPIRED')
    for key in ('pid', 'created_at_filetime'):
        require(expected.get(key) == current.get(key), 'PROCESS_IDENTITY_CHANGED')
    for name in ('main', 'chat_list', 'edit', 'search_list'):
        old, new = expected.get(name), current.get(name)
        require(isinstance(old, dict) and isinstance(new, dict), 'CONTROL_SNAPSHOT_INCOMPLETE')
        for key in ('hwnd', 'rect', 'class', 'control_id'):
            require(old.get(key) == new.get(key), 'CONTROL_SNAPSHOT_CHANGED')
    if target is not None:
        require(expected.get('query') == target, 'SNAPSHOT_QUERY_MISMATCH')


def point_in_rect(point, rect):
    return rect[0] <= point[0] < rect[2] and rect[1] <= point[1] < rect[3]


def capture_layout(width, height):
    require(type(width) is int and type(height) is int
            and 0 < width <= 1024 and 0 < height <= 768, 'CAPTURE_DIMENSION_LIMIT')
    stride = (width * 3 + 3) & ~3
    require(54 + stride * height <= CAPTURE_LIMIT, 'CAPTURE_BYTE_LIMIT')
    return stride, stride * height


def structural_title(raw):
    # Only fixed container identifiers survive, even if app text has a suffix.
    found = [marker for marker in ('ChatRoomListView', 'SearchListCtrl') if marker in raw]
    return found[0] if len(found) == 1 else (raw if raw in MAIN_TITLES else None)


class BASIC(C.Structure):
    _fields_ = [('a', C.c_longlong), ('b', C.c_longlong), ('flags', W.DWORD),
                ('minimum', C.c_size_t), ('maximum', C.c_size_t), ('active', W.DWORD),
                ('affinity', C.c_size_t), ('priority', W.DWORD), ('scheduling', W.DWORD)]


class EXTENDED(C.Structure):
    _fields_ = [('basic', BASIC), ('io', C.c_ulonglong * 6), ('process', C.c_size_t),
                ('job', C.c_size_t), ('peakprocess', C.c_size_t), ('peakjob', C.c_size_t)]


class GUIINFO(C.Structure):
    _fields_ = [('cbSize', W.DWORD), ('flags', W.DWORD)] + [
        (name, W.HWND) for name in ('active', 'focus', 'capture', 'menu', 'move', 'caret')
    ] + [('caret_rect', W.RECT)]


class KEY(C.Structure):
    _fields_ = [('vk', W.WORD), ('scan', W.WORD), ('flags', W.DWORD),
                ('time', W.DWORD), ('extra', C.c_size_t)]


class MOUSE(C.Structure):
    _fields_ = [('dx', W.LONG), ('dy', W.LONG), ('data', W.DWORD),
                ('flags', W.DWORD), ('time', W.DWORD), ('extra', C.c_size_t)]


class INPUTUNION(C.Union):
    _fields_ = [('key', KEY), ('mouse', MOUSE)]


class INPUT(C.Structure):
    _anonymous_ = ('value',)
    _fields_ = [('type', W.DWORD), ('value', INPUTUNION)]


class BITMAPHEADER(C.Structure):
    _fields_ = [('size', W.DWORD), ('width', W.LONG), ('height', W.LONG),
                ('planes', W.WORD), ('bits', W.WORD), ('compression', W.DWORD),
                ('image_size', W.DWORD), ('xppm', W.LONG), ('yppm', W.LONG),
                ('used', W.DWORD), ('important', W.DWORD)]


class BITMAPINFO(C.Structure):
    _fields_ = [('header', BITMAPHEADER), ('colors', W.DWORD * 1)]


class Windows:
    def __init__(self, started):
        require(os.name == 'nt', 'WINDOWS_REQUIRED')
        self.started, self.reader, self.input_calls = started, None, 0
        self.messages = 0
        self.u = C.WinDLL('user32', use_last_error=True)
        self.k = C.WinDLL('kernel32', use_last_error=True)
        self.callback = C.WINFUNCTYPE(W.BOOL, W.HWND, W.LPARAM)
        signatures = {
            'GetForegroundWindow': ([], W.HWND), 'GetParent': ([W.HWND], W.HWND),
            'GetWindowThreadProcessId': ([W.HWND, C.POINTER(W.DWORD)], W.DWORD),
            'GetClassNameW': ([W.HWND, W.LPWSTR, C.c_int], C.c_int),
            'GetDlgCtrlID': ([W.HWND], C.c_int), 'IsWindow': ([W.HWND], W.BOOL),
            'IsWindowVisible': ([W.HWND], W.BOOL), 'IsWindowEnabled': ([W.HWND], W.BOOL),
            'IsIconic': ([W.HWND], W.BOOL), 'IsChild': ([W.HWND, W.HWND], W.BOOL),
            'GetWindowRect': ([W.HWND, C.POINTER(W.RECT)], W.BOOL),
            'GetClientRect': ([W.HWND, C.POINTER(W.RECT)], W.BOOL),
            'ClientToScreen': ([W.HWND, C.POINTER(W.POINT)], W.BOOL),
            'GetDC': ([W.HWND], W.HDC), 'ReleaseDC': ([W.HWND, W.HDC], C.c_int),
            'GetCursorPos': ([C.POINTER(W.POINT)], W.BOOL),
            'SetCursorPos': ([C.c_int, C.c_int], W.BOOL),
            'WindowFromPoint': ([W.POINT], W.HWND),
            'SetForegroundWindow': ([W.HWND], W.BOOL), 'SetFocus': ([W.HWND], W.HWND),
            'ShowWindowAsync': ([W.HWND, C.c_int], W.BOOL),
            'AttachThreadInput': ([W.DWORD, W.DWORD, W.BOOL], W.BOOL),
            'GetGUIThreadInfo': ([W.DWORD, C.POINTER(GUIINFO)], W.BOOL),
            'GetAsyncKeyState': ([C.c_int], C.c_short),
            'SendInput': ([W.UINT, C.POINTER(INPUT), C.c_int], W.UINT),
            'SendMessageTimeoutW': ([W.HWND, W.UINT, W.WPARAM, W.LPARAM, W.UINT,
                                    W.UINT, C.POINTER(C.c_size_t)], W.LPARAM),
            'EnumWindows': ([self.callback, W.LPARAM], W.BOOL),
            'EnumChildWindows': ([W.HWND, self.callback, W.LPARAM], W.BOOL),
        }
        for name, (args, result) in signatures.items():
            method = getattr(self.u, name)
            method.argtypes, method.restype = args, result
        self.k.GetCurrentProcess.restype = W.HANDLE
        self.k.GetCurrentThreadId.restype = W.DWORD
        self.k.IsProcessInJob.argtypes = [W.HANDLE, W.HANDLE, C.POINTER(W.BOOL)]
        self.k.QueryInformationJobObject.argtypes = [W.HANDLE, C.c_int, C.c_void_p,
                                                    W.DWORD, C.c_void_p]
        self.k.ProcessIdToSessionId.argtypes = [W.DWORD, C.POINTER(W.DWORD)]
        inside, limits = W.BOOL(), EXTENDED()
        require(self.k.IsProcessInJob(self.k.GetCurrentProcess(), None, C.byref(inside))
                and inside.value, 'EXISTING_JOB_REQUIRED')
        require(self.k.QueryInformationJobObject(None, 9, C.byref(limits), C.sizeof(limits), None),
                'JOB_QUERY_FAILED')
        require(limits.basic.flags & 0x200 and 0 < limits.job <= JOB_LIMIT
                and limits.basic.flags & 0x100 and 0 < limits.process <= JOB_LIMIT,
                'JOB_MEMORY_BOUND_REQUIRED')
        current = W.DWORD()
        require(self.k.ProcessIdToSessionId(os.getpid(), C.byref(current)) and current.value > 0,
                'INTERACTIVE_SESSION_REQUIRED')
        self.session = current.value
        import room_reader
        room_reader.LIMIT_SECONDS = SOFT_SECONDS
        self.reader = room_reader.Reader()
        target = W.DWORD()
        require(self.k.ProcessIdToSessionId(self.reader.pid, C.byref(target)) and target.value == self.session,
                'SAME_INTERACTIVE_SESSION_REQUIRED')
        self.guard()

    def guard(self):
        require(time.monotonic() - self.started < SOFT_SECONDS, 'WORKER_TIME_LIMIT')
        private = self.reader.guard()
        require(private < APP_PRIVATE_STOP, 'APP_PRIVATE_STOP')
        require(self.reader.process_created(self.reader.handle) == self.reader.created_at_filetime,
                'PROCESS_IDENTITY_CHANGED')
        return private

    def owner(self, hwnd):
        pid = W.DWORD()
        self.u.GetWindowThreadProcessId(hwnd, C.byref(pid))
        return pid.value

    def cursor(self):
        point = W.POINT()
        require(self.u.GetCursorPos(C.byref(point)), 'CURSOR_READ_FAILED')
        return [point.x, point.y]

    def message(self, hwnd, msg, wp=0, lp=0):
        self.guard()
        self.messages += 1
        require(self.messages <= 180, 'NATIVE_READ_LIMIT')
        result = C.c_size_t()
        require(self.u.SendMessageTimeoutW(hwnd, msg, wp, lp, 2, 250, C.byref(result)),
                'NATIVE_READ_TIMEOUT')
        return result.value

    def text(self, hwnd, cap=128):
        length = self.message(hwnd, 14)
        require(length <= cap, 'TEXT_LENGTH_LIMIT')
        buf = C.create_unicode_buffer(cap + 1)
        self.message(hwnd, 13, len(buf), C.addressof(buf))
        value = buf.value
        C.memset(C.addressof(buf), 0, C.sizeof(buf))
        return value

    def metadata(self, hwnd):
        self.guard()
        rect, name = W.RECT(), C.create_unicode_buffer(128)
        require(self.u.GetWindowRect(hwnd, C.byref(rect)), 'RECT_UNAVAILABLE')
        require(self.u.GetClassNameW(hwnd, name, len(name)), 'CLASS_UNAVAILABLE')
        return {'hwnd': int(hwnd), 'parent': int(self.u.GetParent(hwnd) or 0),
                'class': name.value, 'control_id': self.u.GetDlgCtrlID(hwnd),
                'visible': bool(self.u.IsWindowVisible(hwnd)),
                'enabled': bool(self.u.IsWindowEnabled(hwnd)),
                'rect': [rect.left, rect.top, rect.right, rect.bottom]}

    def enumerate(self, parent=None, limit=2000):
        handles, failure = [], []

        @self.callback
        def each(hwnd, _):
            try:
                self.guard()
                if self.owner(hwnd) == self.reader.pid:
                    require(len(handles) < limit, 'WINDOW_ENUMERATION_LIMIT_' + str(limit))
                    handles.append(int(hwnd))
                return True
            except Exception as exc:
                failure.append(exc)
                return False

        if parent is None:
            self.u.EnumWindows(each, 0)
        else:
            self.u.EnumChildWindows(parent, each, 0)
        if failure:
            raise failure[0]
        return handles

    def tree(self):
        mains = []
        for hwnd in self.enumerate(limit=500):
            item = self.metadata(hwnd)
            if item['class'] == 'EVA_Window_Dblclk' and item['visible']:
                title = self.text(hwnd)
                if title in MAIN_TITLES:
                    item['title'] = title
                    mains.append(item)
        require(len(mains) == 1, 'MAIN_NOT_UNIQUE')
        main, children = mains[0], []
        for hwnd in self.enumerate(main['hwnd']):
            node = self.metadata(hwnd)
            # No RichEdit text or message-list contents are read here.
            if node['class'] in ('EVA_Window', 'EVA_Window_Dblclk', 'EVA_VH_ListControl_Dblclk'):
                title = structural_title(self.text(hwnd))
                if title is not None:
                    node['title'] = title
            children.append(node)
        require(not any(n['class'].upper() == 'RICHEDIT50W' and n['control_id'] == 1006
                        for n in children), 'MAIN_HAS_CHAT_INPUT')
        chat = [n for n in children if n.get('title') == 'ChatRoomListView']
        require(len(chat) == 1, 'CHAT_LIST_NOT_UNIQUE')
        edits = [n for n in children if n['class'] == 'Edit'
                 and self.u.IsChild(chat[0]['hwnd'], n['hwnd']) and n['visible']]
        lists = [n for n in children if n.get('title') == 'SearchListCtrl' and n['visible']]
        require(len(edits) <= 1 and len(lists) <= 1, 'SEARCH_CONTROLS_NOT_UNIQUE')
        return {'pid': self.reader.pid, 'created_at_filetime': str(self.reader.created_at_filetime),
                'captured_epoch': time.time(), 'main': main, 'chat_list': chat[0],
                'edit': edits[0] if edits else None, 'search_list': lists[0] if lists else None,
                'children': children}

    def foreground(self, hwnd):
        self.guard()
        require(self.owner(hwnd) == self.reader.pid, 'MAIN_OWNER_CHANGED')
        if self.u.IsIconic(hwnd):
            self.u.ShowWindowAsync(hwnd, 9)
        self.u.SetForegroundWindow(hwnd)
        time.sleep(.12)
        require(self.u.GetForegroundWindow() == hwnd, 'MAIN_FOREGROUND_REQUIRED')

    def restore_foreground(self, hwnd):
        """Restore the recorded window; detach every temporary input-queue link."""
        before = self.u.GetForegroundWindow()
        if before == hwnd:
            return
        self.no_modifiers()
        own, attached = self.k.GetCurrentThreadId(), []
        try:
            tids = {self.u.GetWindowThreadProcessId(before, None),
                    self.u.GetWindowThreadProcessId(hwnd, None)} - {own}
            for tid in sorted(tids):
                require(tid and self.u.AttachThreadInput(own, tid, True), 'RESTORE_ATTACH_FAILED')
                attached.append(tid)
            require(self.u.SetForegroundWindow(hwnd), 'RESTORE_FOREGROUND_FAILED')
        finally:
            detached = [bool(self.u.AttachThreadInput(own, tid, False)) for tid in reversed(attached)]
            require(all(detached), 'RESTORE_DETACH_FAILED')

    def focus(self, main, edit):
        self.guard()
        require(self.u.GetForegroundWindow() == main, 'MAIN_FOREGROUND_REQUIRED')
        tid = self.u.GetWindowThreadProcessId(main, None)
        own = self.k.GetCurrentThreadId()
        attached = own != tid
        if attached:
            require(self.u.AttachThreadInput(own, tid, True), 'FOCUS_ATTACH_FAILED')
        try:
            self.u.SetFocus(edit)
        finally:
            if attached:
                require(self.u.AttachThreadInput(own, tid, False), 'FOCUS_DETACH_FAILED')
        self.require_focus(main, edit)

    def require_focus(self, main, edit):
        self.guard()
        state = GUIINFO()
        state.cbSize = C.sizeof(state)
        tid = self.u.GetWindowThreadProcessId(main, None)
        require(self.u.GetForegroundWindow() == main
                and self.u.GetGUIThreadInfo(tid, C.byref(state)) and state.focus == edit,
                'SEARCH_FOCUS_REQUIRED')

    def send(self, events):
        self.guard()
        array = (INPUT * len(events))(*events)
        self.input_calls += 1
        count = self.u.SendInput(len(array), array, C.sizeof(INPUT))
        if count != len(array):
            # Release only down events successfully injected by this call.
            pressed = {}
            for event in events[:count]:
                if event.type == 1:
                    token = ('key', event.key.vk, event.key.scan, event.key.flags & 4)
                    if event.key.flags & 2:
                        pressed.pop(token, None)
                    else:
                        pressed[token] = self.key(event.key.vk, event.key.scan, event.key.flags | 2)
                elif event.mouse.flags & 2:
                    pressed[('mouse',)] = INPUT(type=0, mouse=MOUSE(0, 0, 0, 4, 0, 0))
                elif event.mouse.flags & 4:
                    pressed.pop(('mouse',), None)
            if pressed:
                release = (INPUT * len(pressed))(*reversed(list(pressed.values())))
                self.input_calls += 1
                require(self.u.SendInput(len(release), release, C.sizeof(INPUT)) == len(release),
                        'INPUT_RELEASE_FAILED')
            raise GuardError('INPUT_INCOMPLETE_RELEASED')

    @staticmethod
    def key(vk=0, scan=0, flags=0):
        return INPUT(type=1, key=KEY(vk, scan, flags, 0, 0))

    def no_modifiers(self):
        require(not any(self.u.GetAsyncKeyState(v) & 0x8000 for v in (16, 17, 18, 91, 92)),
                'USER_MODIFIER_PRESSED')

    def combo(self, vk):
        require(vk == 0x46, 'KEY_COMBINATION_NOT_ALLOWED')
        self.no_modifiers()
        self.send([self.key(17), self.key(vk), self.key(vk, flags=2), self.key(17, flags=2)])

    def search(self, request, before):
        main = before['main']['hwnd']
        require(before['main']['enabled'], 'MAIN_MODAL_ACTIVE')
        self.foreground(main)
        require(self.u.GetForegroundWindow() == main, 'MAIN_FOREGROUND_REQUIRED')
        if before.get('edit') is None:
            self.combo(0x46)
            time.sleep(.18)
        state = self.tree()
        require(state['edit'] is not None, 'SEARCH_EDIT_MISSING')
        edit = state['edit']['hwnd']
        prior_length = self.message(edit, 14)
        require(prior_length <= 1024, 'PRIOR_SEARCH_LENGTH_LIMIT')
        if prior_length and request.get('replace_existing_search') is not True:
            check_snapshot(request.get('expected'), state)
            require(self.text(edit, 100) == request['expected'].get('query'), 'UNOWNED_SEARCH_QUERY')
        # Address the observed main-window search Edit directly. Global Ctrl+A
        # caused Kakao to move focus; never route query text through that path.
        meta = self.metadata(edit)
        require(meta['class'] == 'Edit' and meta['control_id'] == 100
                and meta['enabled'] and meta['visible']
                and self.owner(edit) == self.reader.pid
                and self.u.IsChild(state['chat_list']['hwnd'], edit), 'SEARCH_WRITE_TARGET_INVALID')
        require(self.u.GetForegroundWindow() == main, 'MAIN_FOREGROUND_REQUIRED')
        query = C.create_unicode_buffer(request['target'])
        try:
            require(self.message(edit, 12, 0, C.addressof(query)), 'SEARCH_TEXT_WRITE_FAILED')
        finally:
            C.memset(C.addressof(query), 0, C.sizeof(query))
        time.sleep(.6)
        require(self.u.GetForegroundWindow() == main, 'MAIN_FOREGROUND_REQUIRED')
        require(self.text(edit, 100) == request['target'], 'SEARCH_QUERY_MISMATCH')
        state = self.tree()
        require(state['edit'] and state['edit']['hwnd'] == edit, 'SEARCH_EDIT_CHANGED')
        state['query'] = request['target']
        state['prior_query_length'] = prior_length
        state['query_replaced'] = prior_length > 0
        state['search_text_write_calls'] = 1
        return state

    def room(self, target):
        matches = []
        for hwnd in self.enumerate(limit=500):
            meta = self.metadata(hwnd)
            if not meta['visible'] or meta['class'] != 'EVA_Window_Dblclk' or self.text(hwnd) != target:
                continue
            # Match the existing read-only attachment probe's 2000-child cap.
            # Group chats can expose many rendered child controls.
            children = [self.metadata(h) for h in self.enumerate(hwnd, limit=2000)]
            inputs = [n for n in children if n['class'].upper() == 'RICHEDIT50W'
                      and n['control_id'] == 1006]
            lists = [n for n in children if n['class'] == 'EVA_VH_ListControl_Dblclk'
                     and n['control_id'] == 100]
            meta.update(title=target, input_count=len(inputs), message_list_count=len(lists))
            if len(inputs) == 1:
                length = self.message(inputs[0]['hwnd'], 14)
                placeholder = False
                if 0 < length <= 20:
                    placeholder = self.text(inputs[0]['hwnd'], 20) == '메시지 입력'
                meta.update(input=inputs[0], input_length=length, input_empty=length == 0,
                            input_placeholder=placeholder)
            if len(lists) == 1:
                meta['message_list'] = lists[0]
            matches.append(meta)
        require(len(matches) <= 1, 'TARGET_WINDOW_NOT_UNIQUE')
        return matches[0] if matches else None

    def capture_search(self, snapshot, path):
        """Copy only the visible, observed SearchListCtrl client DC, never desktop."""
        dc = memory = bitmap = old = None
        gdi, hwnd = None, None
        try:
            self.guard()
            require(snapshot.get('search_list') is not None, 'SEARCH_LIST_UNAVAILABLE')
            hwnd = snapshot['search_list']['hwnd']
            require(self.u.GetForegroundWindow() == snapshot['main']['hwnd'],
                    'CAPTURE_MAIN_NOT_FOREGROUND')
            require(self.u.IsWindowVisible(hwnd) and self.owner(hwnd) == self.reader.pid
                    and self.u.IsChild(snapshot['main']['hwnd'], hwnd), 'CAPTURE_CONTROL_CHANGED')
            require(self.metadata(hwnd)['rect'] == snapshot['search_list']['rect'],
                    'CAPTURE_RECT_CHANGED')
            require(self.text(snapshot['edit']['hwnd'], 100) == snapshot['query'],
                    'CAPTURE_QUERY_CHANGED')
            rect, origin = W.RECT(), W.POINT(0, 0)
            require(self.u.GetClientRect(hwnd, C.byref(rect))
                    and self.u.ClientToScreen(hwnd, C.byref(origin)), 'CAPTURE_BOUNDS_FAILED')
            client_width, client_height = rect.right - rect.left, rect.bottom - rect.top
            width, height = min(client_width, 1024), min(client_height, 768)
            _, size = capture_layout(width, height)
            bounds = [origin.x, origin.y, origin.x + width, origin.y + height]
            # Require this exact visible control at every sample. Occlusion fails closed.
            for x in (bounds[0], bounds[0] + width // 2, bounds[2] - 1):
                for y in (bounds[1], bounds[1] + height // 2, bounds[3] - 1):
                    hit = self.u.WindowFromPoint(W.POINT(x, y))
                    require(hit == hwnd or self.u.IsChild(hwnd, hit), 'CAPTURE_OCCLUDED')
            gdi = C.WinDLL('gdi32', use_last_error=True)
            signatures = {
                'CreateCompatibleDC': ([W.HDC], W.HDC),
                'CreateDIBSection': ([W.HDC, C.POINTER(BITMAPINFO), W.UINT,
                                      C.POINTER(C.c_void_p), W.HANDLE, W.DWORD], W.HANDLE),
                'SelectObject': ([W.HDC, W.HANDLE], W.HANDLE),
                'BitBlt': ([W.HDC, C.c_int, C.c_int, C.c_int, C.c_int,
                            W.HDC, C.c_int, C.c_int, W.DWORD], W.BOOL),
                'DeleteObject': ([W.HANDLE], W.BOOL), 'DeleteDC': ([W.HDC], W.BOOL),
                'GdiFlush': ([], W.BOOL),
            }
            for name, (args, result) in signatures.items():
                method = getattr(gdi, name)
                method.argtypes, method.restype = args, result
            dc = self.u.GetDC(hwnd)
            require(dc, 'CAPTURE_WINDOW_DC_FAILED')
            memory = gdi.CreateCompatibleDC(dc)
            require(memory, 'CAPTURE_MEMORY_DC_FAILED')
            info, pixels = BITMAPINFO(), C.c_void_p()
            info.header = BITMAPHEADER(C.sizeof(BITMAPHEADER), width, height, 1, 24,
                                       0, size, 0, 0, 0, 0)
            bitmap = gdi.CreateDIBSection(dc, C.byref(info), 0, C.byref(pixels), None, 0)
            require(bitmap and pixels.value, 'CAPTURE_BITMAP_FAILED')
            old = gdi.SelectObject(memory, bitmap)
            require(old and old != C.c_void_p(-1).value, 'CAPTURE_SELECT_FAILED')
            self.guard()
            require(self.u.GetForegroundWindow() == snapshot['main']['hwnd'],
                    'CAPTURE_MAIN_NOT_FOREGROUND')
            require(gdi.BitBlt(memory, 0, 0, width, height, dc, 0, 0, 0x00CC0020),
                    'CAPTURE_COPY_FAILED')
            require(gdi.GdiFlush(), 'CAPTURE_FLUSH_FAILED')
            payload = (struct.pack('<2sIHHI', b'BM', 54 + size, 0, 0, 54)
                       + struct.pack('<IiiHHIIiiII', 40, width, height, 1, 24, 0, size, 0, 0, 0, 0)
                       + C.string_at(pixels, size))
            require(len(payload) <= CAPTURE_LIMIT, 'CAPTURE_BYTE_LIMIT')
            if path is not None:
                with Path(path).open('xb') as stream:
                    require(stream.write(payload) == len(payload), 'CAPTURE_WRITE_INCOMPLETE')
            return {'status': 'CAPTURED', 'filename': Path(path).name if path else None,
                    'sha256': hashlib.sha256(payload).hexdigest(), 'width': width, 'height': height,
                    'bounds': bounds, 'bytes': len(payload), 'scope': 'SearchListCtrl_client',
                    'cropped': width != client_width or height != client_height}
        except GuardError as exc:
            return {'status': 'CAPTURE_UNAVAILABLE', 'reason': str(exc)}
        except Exception as exc:
            return {'status': 'CAPTURE_UNAVAILABLE', 'reason': type(exc).__name__}
        finally:
            if old and gdi and memory and old != C.c_void_p(-1).value:
                gdi.SelectObject(memory, old)
            if bitmap and gdi:
                gdi.DeleteObject(bitmap)
            if memory and gdi:
                gdi.DeleteDC(memory)
            if dc:
                self.u.ReleaseDC(hwnd, dc)

    def open(self, request, current):
        expected = request['expected']
        # A previous search restores an originally minimized main. Activate that
        # exact main only, then compare every visible control and rectangle again.
        require(expected.get('pid') == current['pid']
                and expected.get('created_at_filetime') == current['created_at_filetime'],
                'PROCESS_IDENTITY_CHANGED')
        old_main = expected.get('main')
        require(isinstance(old_main, dict) and all(old_main.get(k) == current['main'][k]
                for k in ('hwnd', 'class', 'control_id')), 'MAIN_IDENTITY_CHANGED')
        main = current['main']['hwnd']
        self.foreground(main)
        fresh = self.tree()
        check_snapshot(expected, fresh, request['target'])
        edit, search = (fresh[n]['hwnd'] for n in ('edit', 'search_list'))
        require(self.text(edit, 100) == request['target'], 'SEARCH_QUERY_MISMATCH')
        fresh['query'] = request['target']
        capture = self.capture_search(fresh, None)
        require(capture.get('status') == 'CAPTURED'
                and capture.get('sha256') == expected['capture']['sha256']
                and capture.get('bounds') == expected['capture']['bounds'],
                'SEARCH_RESULTS_CHANGED_REVIEW_AGAIN')
        point = request['row_point']
        require(point_in_rect(point, fresh['search_list']['rect']), 'POINT_OUTSIDE_SEARCH')
        require(self.text(edit, 100) == request['target'], 'SEARCH_QUERY_MISMATCH')
        self.no_modifiers()
        for _ in range(2):
            self.guard()
            require(self.u.GetForegroundWindow() == main, 'MAIN_FOREGROUND_REQUIRED')
            hit = self.u.WindowFromPoint(W.POINT(*point))
            require(hit == search or self.u.IsChild(search, hit), 'POINT_NOT_SEARCH_CONTROL')
            require(self.u.SetCursorPos(*point), 'CURSOR_MOVE_FAILED')
            require(self.cursor() == point and self.u.GetForegroundWindow() == main,
                    'POINTER_OR_FOREGROUND_CHANGED')
            self.send([INPUT(type=0, mouse=MOUSE(0, 0, 0, 2, 0, 0)),
                       INPUT(type=0, mouse=MOUSE(0, 0, 0, 4, 0, 0))])
            time.sleep(.06)
        found = None
        for _ in range(5):
            time.sleep(.15)
            found = self.room(request['target'])
            if found:
                break
        require(found is not None, 'EXACT_TARGET_WINDOW_NOT_FOUND')
        require(self.u.GetForegroundWindow() == found['hwnd'], 'EXACT_TARGET_NOT_FOREGROUND')
        require(found['input_count'] == 1 and found['message_list_count'] == 1,
                'ROOM_STRUCTURE_INCOMPLETE')
        return found


def preview_state(win):
    """Borrow this worker's exact Reader; never create a second process binding."""
    preview_root = Path(__file__).resolve().parents[1] / 'self-attachments'
    sys.path.insert(0, str(preview_root))
    import attachment_runtime_preview as preview

    class BorrowedReader:
        def __getattr__(self, name):
            return getattr(win.reader, name)

        @property
        def read_bytes(self):
            return win.reader.read_bytes

        @read_bytes.setter
        def read_bytes(self, value):
            win.reader.read_bytes = value

        def guard(self):
            return win.guard()

        def close(self):
            pass

    preview.Reader = BorrowedReader
    native = preview.inspect()
    require(native.get('status') == 'LIVE_PREVIEW_PREFERENCE_READ'
            and native.get('stable_double_read') is True
            and native.get('native_mode_check_performed') is True,
            'NATIVE_PREVIEW_NOT_VERIFIED')
    return {key: native[key] for key in (
        'status', 'value', 'preview_enabled', 'native_mode_check_performed',
        'saved_preference_applies', 'stable_double_read', 'metadata_reads',
        'process_bytes_read', 'settings_changed')}


def execute(request, capture_path=None):
    validate_request(request)
    started = time.monotonic()
    # Hard ceiling is independent of any native callback or Reader initialization.
    watchdog = threading.Timer(HARD_SECONDS, lambda: os._exit(124))
    watchdog.daemon = True
    watchdog.start()
    win, original, cursor, minimized = None, None, None, None
    result = {'action': request['action'], 'status': 'BLOCKED', 'send_ready': False,
              'chat_id_binding': False, 'clipboard_calls': 0, 'file_drop_calls': 0,
              'chat_input_write_calls': 0, 'raw_input_saved': False,
              'actual_send': 'NOT_RUN', 'actual_sends': 0, 'settings_changed': False}
    try:
        win = Windows(started)
        original, cursor = int(win.u.GetForegroundWindow() or 0), win.cursor()
        require(original and win.u.IsWindow(original), 'ORIGINAL_FOREGROUND_UNAVAILABLE')
        if request.get('expected_original_foreground') is not None:
            require(original == request['expected_original_foreground'], 'PRIOR_FOREGROUND_NOT_RESTORED')
        result.update(foreground_before=original, cursor_before=cursor,
                      app_private_before=win.guard(), session=win.session,
                      foreground_metadata=win.metadata(original), foreground_owner=win.owner(original))
        # A background room check needs no main/search window. It must still
        # work when the main window is hidden in the notification area.
        if request['action'] != 'surface':
            current = win.tree()
            minimized = bool(win.u.IsIconic(current['main']['hwnd']))
        if request['action'] == 'inspect':
            result.update(status='INSPECTED', snapshot=current)
        elif request['action'] == 'surface':
            result.update(status='ROOM_SURFACE_INSPECTED', room=win.room(request['target']))
        elif request['action'] == 'search':
            state = win.search(request, current)
            capture = win.capture_search(state, capture_path)
            state['capture'] = capture
            result.update(status='SEARCHED', snapshot=state, search_capture=capture,
                          prior_query_length=state['prior_query_length'],
                          query_replaced=state['query_replaced'])
            require(capture.get('status') == 'CAPTURED', 'SEARCH_CAPTURE_UNAVAILABLE')
        else:
            result.update(status='OPENED_EXACT_TITLE_STRUCTURE', room=win.open(request, current))
        if request['action'] == 'surface' and request.get('check') is True:
            room = result.get('room')
            require(room is not None, 'TARGET_WINDOW_NOT_FOUND')
            require(room.get('input_count') == 1 and room.get('message_list_count') == 1,
                    'ROOM_STRUCTURE_INCOMPLETE')
            require(room.get('input_empty') is True or room.get('input_placeholder') is True,
                    'ROOM_INPUT_NOT_EMPTY')
            require(room.get('visible') and room.get('enabled')
                    and not win.u.IsIconic(room['hwnd']), 'ROOM_NOT_VISIBLE_ENABLED_RESTORED')
            result['preview'] = preview_state(win) if request.get('check_preview') else {'status': 'NOT_REQUESTED'}
            result['status'] = 'PRE_SEND_SURFACE_CHECKED'
        result['app_private_after'] = win.guard()
    except GuardError as exc:
        result['error'] = str(exc)
        result['status'] = 'BLOCKED'
    except Exception as exc:
        result.update(status='BLOCKED', error='UNEXPECTED_' + type(exc).__name__)
    finally:
        if win is not None:
            try:
                if request['action'] in ('search', 'open') and original:
                    if minimized and 'current' in locals():
                        win.u.ShowWindowAsync(current['main']['hwnd'], 6)
                    if win.u.GetForegroundWindow() != original and win.u.IsWindow(original):
                        win.restore_foreground(original)
                    if cursor is not None:
                        win.u.SetCursorPos(*cursor)
                    restore_deadline = time.monotonic() + .8
                    while win.u.GetForegroundWindow() != original and time.monotonic() < restore_deadline:
                        time.sleep(.03)
                    time.sleep(.05)
                result.update(foreground_after=int(win.u.GetForegroundWindow() or 0),
                              cursor_after=win.cursor(), input_calls=win.input_calls)
                result['foreground_restored'] = result['foreground_after'] == original
                result['cursor_restored'] = result['cursor_after'] == cursor
                if not result['foreground_restored'] or not result['cursor_restored']:
                    result.update(status='BLOCKED', restore_error='FOREGROUND_OR_CURSOR_NOT_RESTORED')
            except Exception:
                result.update(status='BLOCKED', restore_error='RESTORE_CHECK_FAILED')
            finally:
                if win.reader is not None:
                    win.reader.close()
        result['elapsed_seconds'] = round(time.monotonic() - started, 3)
        watchdog.cancel()
    return result


def main():
    require(len(sys.argv) == 2, 'ONE_REQUEST_PATH_REQUIRED')
    path = Path(sys.argv[1]).resolve()
    require(path.is_file() and path.stat().st_size <= 32768, 'REQUEST_SIZE_INVALID')
    result = execute(json.loads(path.read_text(encoding='utf-8-sig')),
                     path.with_name(path.stem + '-search.bmp'))
    print(json.dumps(result, ensure_ascii=True), flush=True)
    return 2 if result['status'] == 'BLOCKED' else 0


if __name__ == '__main__':
    sys.exit(main())
