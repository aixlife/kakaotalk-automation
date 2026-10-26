"""Bounded, out-of-context observation of a single KakaoTalk process.

No input, focus, clipboard, settings or target-memory writes. Results describe
only the measured interval; they cannot prove that later UI will never appear.
Windows APIs are initialized only when entering WindowWatch.
"""
import hashlib
import os
import time


def classify_event(event, object_id, child_id, hwnd, root, owner_pid,
                   target_pid, visible, baseline):
    """Pure classifier. Only window objects at GA_ROOT count as top windows."""
    if owner_pid != target_pid or not hwnd:
        return None
    if event == 3:
        return 'app_foreground'
    if (event == 0x8002 and object_id == 0 and child_id == 0
            and root == hwnd and visible and hwnd not in baseline):
        return 'new_visible_app_top'
    return None


def bounded_seconds(seconds):
    if type(seconds) not in (float, int) or not 0 <= seconds <= 5:
        raise ValueError('WATCH_SECONDS_MUST_BE_0_TO_5')
    return float(seconds)


class WindowWatch:
    def __init__(self, pid, max_total_seconds=10, self_hwnd=None):
        if type(pid) is not int or pid <= 0:
            raise ValueError('WATCH_PID_REQUIRED')
        if type(max_total_seconds) is not int or not 10 <= max_total_seconds <= 45:
            raise ValueError('WATCH_TOTAL_SECONDS_MUST_BE_10_TO_45')
        self.max_total_seconds = max_total_seconds
        if self_hwnd is not None and (type(self_hwnd) is not int or self_hwnd<=0):
            raise ValueError('WATCH_VERIFIED_SELF_HWND_REQUIRED')
        self.self_hwnd=self_hwnd
        self.callback_limit=64
        self.message_limit=256
        self.pid = pid
        self.hooks = []
        self.handle = None
        self.entered = False
        self.finished = None
        self.errors = []
        self.overflow = False
        self.events = []
        self.callback_count = 0
        self.message_count = 0
        self.new_tops = set()
        self.foreground_events = 0
        self.new_top_details = {}
        self.unresolved_show_details = []

    def _init_api(self):
        if os.name != 'nt':
            raise RuntimeError('WINDOWS_REQUIRED')
        import ctypes as C
        from ctypes import wintypes as W
        self.C, self.W = C, W
        self.u = C.WinDLL('user32', use_last_error=True)
        self.k = C.WinDLL('kernel32', use_last_error=True)
        self.ps = C.WinDLL('psapi', use_last_error=True)
        self.k.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
        self.k.OpenProcess.restype = W.HANDLE
        self.k.CloseHandle.argtypes = [W.HANDLE]
        self.k.GetCurrentProcessId.restype = W.DWORD
        self.k.GetCurrentProcess.restype = W.HANDLE
        self.k.GetCurrentThreadId.restype = W.DWORD
        self.k.ProcessIdToSessionId.argtypes = [W.DWORD, C.POINTER(W.DWORD)]
        self.k.QueryFullProcessImageNameW.argtypes = [W.HANDLE, W.DWORD, W.LPWSTR, C.POINTER(W.DWORD)]
        self.k.GetProcessTimes.argtypes = [W.HANDLE] + [C.POINTER(W.FILETIME)] * 4
        self.k.GetExitCodeProcess.argtypes = [W.HANDLE, C.POINTER(W.DWORD)]
        self.u.GetForegroundWindow.restype = W.HWND
        self.u.GetCursorPos.argtypes = [C.POINTER(W.POINT)]
        self.u.GetWindowThreadProcessId.argtypes = [W.HWND, C.POINTER(W.DWORD)]
        self.u.GetAncestor.argtypes = [W.HWND, W.UINT]
        self.u.GetAncestor.restype = W.HWND
        self.u.IsWindowVisible.argtypes = [W.HWND]
        self.u.IsWindowEnabled.argtypes = [W.HWND]
        self.u.GetLastActivePopup.argtypes = [W.HWND]
        self.u.GetLastActivePopup.restype = W.HWND
        self.u.GetClassNameW.argtypes = [W.HWND, W.LPWSTR, C.c_int]
        self.u.GetWindowRect.argtypes = [W.HWND, C.POINTER(W.RECT)]
        self.u.GetWindowLongPtrW.argtypes = [W.HWND, C.c_int]
        self.u.GetWindowLongPtrW.restype = W.LPARAM
        self.u.GetWindow.argtypes = [W.HWND, W.UINT]
        self.u.GetWindow.restype = W.HWND
        self.u.GetWindowTextLengthW.argtypes = [W.HWND]
        self.u.MonitorFromWindow.argtypes = [W.HWND, W.DWORD]
        self.u.MonitorFromWindow.restype = W.HANDLE
        class MONITORINFO(C.Structure):
            _fields_ = [('cbSize', W.DWORD), ('monitor', W.RECT), ('work', W.RECT), ('flags', W.DWORD)]
        self.MONITORINFO = MONITORINFO
        self.u.GetMonitorInfoW.argtypes = [W.HANDLE, C.POINTER(MONITORINFO)]
        self.u.GetProcessWindowStation.restype = W.HANDLE
        self.u.GetThreadDesktop.argtypes = [W.DWORD]
        self.u.GetThreadDesktop.restype = W.HANDLE
        self.u.GetUserObjectInformationW.argtypes = [W.HANDLE, C.c_int, C.c_void_p, W.DWORD, C.POINTER(W.DWORD)]
        self.callback_type = C.WINFUNCTYPE(None, W.HANDLE, W.DWORD, W.HWND,
                                          C.c_long, C.c_long, W.DWORD, W.DWORD)
        self.enum_type = C.WINFUNCTYPE(W.BOOL, W.HWND, W.LPARAM)
        self.u.SetWinEventHook.argtypes = [W.DWORD, W.DWORD, W.HMODULE,
                                         self.callback_type, W.DWORD, W.DWORD, W.DWORD]
        self.u.SetWinEventHook.restype = W.HANDLE
        self.u.UnhookWinEvent.argtypes = [W.HANDLE]
        self.u.EnumWindows.argtypes = [self.enum_type, W.LPARAM]
        self.u.PeekMessageW.argtypes = [C.POINTER(W.MSG), W.HWND, W.UINT, W.UINT, W.UINT]
        self.u.TranslateMessage.argtypes = [C.POINTER(W.MSG)]
        self.u.DispatchMessageW.argtypes = [C.POINTER(W.MSG)]
        self.u.DispatchMessageW.restype = W.LPARAM
        class PM(C.Structure):
            _fields_ = [('cb', W.DWORD), ('fault', W.DWORD)] + [
                (n, C.c_size_t) for n in ('pws', 'ws', 'pp', 'p', 'pnp', 'np', 'pf', 'ppf', 'private')]
        self.PM = PM
        self.ps.GetProcessMemoryInfo.argtypes = [W.HANDLE, C.POINTER(PM), W.DWORD]

    def _owner(self, hwnd):
        pid = self.W.DWORD()
        self.u.GetWindowThreadProcessId(hwnd, self.C.byref(pid))
        return pid.value

    def _surface(self):
        point = self.W.POINT()
        hwnd = self.u.GetForegroundWindow()
        if not hwnd or not self.u.GetCursorPos(self.C.byref(point)):
            raise RuntimeError('WATCH_SURFACE_UNAVAILABLE')
        return int(hwnd), [point.x, point.y]

    def _window_metadata(self, hwnd):
        name = self.C.create_unicode_buffer(128); rect = self.W.RECT()
        named = self.u.GetClassNameW(hwnd, name, len(name))
        positioned = self.u.GetWindowRect(hwnd, self.C.byref(rect))
        chain=[];owner=self.u.GetWindow(hwnd, 4)
        while owner and len(chain)<12:
            if int(owner) in chain: break
            chain.append(int(owner)); owner=self.u.GetWindow(owner, 4)
        monitor=self.MONITORINFO();monitor.cbSize=self.C.sizeof(monitor)
        work=None
        if self.u.GetMonitorInfoW(self.u.MonitorFromWindow(hwnd, 2), self.C.byref(monitor)):
            work=[monitor.work.left,monitor.work.top,monitor.work.right,monitor.work.bottom]
        return {'hwnd':int(hwnd or 0),'class': name.value if named else None,
                'rect': [rect.left, rect.top, rect.right, rect.bottom] if positioned else None,
                'style': hex(self.u.GetWindowLongPtrW(hwnd, -16) & 0xffffffff),
                'exstyle': hex(self.u.GetWindowLongPtrW(hwnd, -20) & 0xffffffff),
                'owner_chain': chain,'owner_chain_complete':not owner,
                'title_length_only':self.u.GetWindowTextLengthW(hwnd),'monitor_work_rect':work}

    def _track_tops(self, tops):
        self.new_tops.update(tops-self.baseline)

    def _guard(self):
        if time.monotonic() - self.started > self.max_total_seconds:
            raise RuntimeError('WATCH_TOTAL_TIME_LIMIT')
        active = self.W.DWORD()
        if not self.k.GetExitCodeProcess(self.handle, self.C.byref(active)) or active.value != 259:
            raise RuntimeError('WATCH_APP_EXITED')
        mem = self.PM(); mem.cb = self.C.sizeof(mem)
        if not self.ps.GetProcessMemoryInfo(self.handle, self.C.byref(mem), mem.cb):
            raise RuntimeError('WATCH_MEMORY_UNAVAILABLE')
        if mem.private >= min(2147483648, 335675392 + 134217728):
            raise RuntimeError('WATCH_APP_MEMORY_LIMIT')
        self.last_private = mem.private
        if self.self_hwnd and (self._owner(self.self_hwnd)!=self.pid
                or not self.u.IsWindowEnabled(self.self_hwnd)
                or self.u.GetLastActivePopup(self.self_hwnd)!=self.self_hwnd):
            raise RuntimeError('WATCH_SELF_WINDOW_POPUP_OR_DISABLED')
        own = self.PM(); own.cb = self.C.sizeof(own)
        if (not self.ps.GetProcessMemoryInfo(self.k.GetCurrentProcess(), self.C.byref(own), own.cb)
                or own.private >= 268435456):
            raise RuntimeError('WATCH_OWN_MEMORY_LIMIT')

    def _visible_tops(self):
        found = set(); count = 0; failure = []
        @self.enum_type
        def each(hwnd, unused):
            nonlocal count
            try:
                count += 1
                if count > 500 or time.monotonic() - self.started > self.max_total_seconds:
                    raise RuntimeError('WATCH_WINDOW_ENUM_LIMIT')
                if (self._owner(hwnd) == self.pid and self.u.GetAncestor(hwnd, 2) == hwnd
                        and self.u.IsWindowVisible(hwnd)):
                    found.add(int(hwnd))
                return True
            except Exception as exc:
                failure.append(str(exc)); return False
        if not self.u.EnumWindows(each, 0) or failure:
            raise RuntimeError(failure[0] if failure else 'WATCH_WINDOW_ENUM_FAILED')
        return found

    def _object_name(self, handle):
        buf = self.C.create_unicode_buffer(128); needed = self.W.DWORD()
        if not handle or not self.u.GetUserObjectInformationW(handle, 2, buf, self.C.sizeof(buf), self.C.byref(needed)):
            raise RuntimeError('WATCH_DESKTOP_UNAVAILABLE')
        return buf.value

    def __enter__(self):
        if self.entered or self.finished is not None:
            raise RuntimeError('WATCH_SINGLE_USE')
        self.started = time.monotonic(); self.started_epoch = time.time()
        try:
            self._init_api()
            from room_reader import APP, EXPECTED
            with APP.open('rb') as stream:
                if hashlib.file_digest(stream, 'sha256').hexdigest() != EXPECTED:
                    raise RuntimeError('WATCH_INSTALLATION_CHANGED')
            self.handle = self.k.OpenProcess(0x1000, False, self.pid)
            if not self.handle: raise RuntimeError('WATCH_PROCESS_UNAVAILABLE')
            name = self.C.create_unicode_buffer(32768); size = self.W.DWORD(len(name))
            if (not self.k.QueryFullProcessImageNameW(self.handle, 0, name, self.C.byref(size))
                    or name.value.casefold() != str(APP).casefold()):
                raise RuntimeError('WATCH_PROCESS_IDENTITY_CHANGED')
            times = [self.W.FILETIME() for _ in range(4)]
            if not self.k.GetProcessTimes(self.handle, *[self.C.byref(t) for t in times]):
                raise RuntimeError('WATCH_PROCESS_TIMES_FAILED')
            self.created = times[0].dwHighDateTime << 32 | times[0].dwLowDateTime
            sessions = [self.W.DWORD(), self.W.DWORD()]
            for pid, value in zip((self.pid, self.k.GetCurrentProcessId()), sessions):
                if not self.k.ProcessIdToSessionId(pid, self.C.byref(value)):
                    raise RuntimeError('WATCH_SESSION_UNAVAILABLE')
            if sessions[0].value == 0 or sessions[0].value != sessions[1].value:
                raise RuntimeError('WATCH_INTERACTIVE_SESSION_REQUIRED')
            self.session = sessions[0].value
            if (self._object_name(self.u.GetProcessWindowStation()) != 'WinSta0'
                    or self._object_name(self.u.GetThreadDesktop(self.k.GetCurrentThreadId())) != 'Default'):
                raise RuntimeError('WATCH_INTERACTIVE_DESKTOP_REQUIRED')
            self._guard(); self.before_front, self.before_cursor = self._surface()
            self.baseline = self._visible_tops()
            self.callback = self.callback_type(self._event)
            self.hook_started = time.monotonic()
            for event, pid in ((0x8002, self.pid), (3, 0)):
                hook = self.u.SetWinEventHook(event, event, None, self.callback, pid, 0, 2)
                if not hook: raise RuntimeError('WATCH_HOOK_INSTALL_FAILED')
                self.hooks.append(hook)
            self.entered = True
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise

    def _event(self, hook, event, hwnd, object_id, child_id, thread_id, event_ms):
        try:
            self.callback_count += 1
            if self.callback_count > self.callback_limit:
                self.overflow = True; return
            self._guard()
            root = self.u.GetAncestor(hwnd, 2) if hwnd else None
            owner = self._owner(hwnd) if hwnd else 0
            # A queued SHOW can outlive its window. Do not silently treat an
            # unresolvable or already hidden top-window event as UI absence.
            if event == 0x8002 and object_id == 0 and child_id == 0:
                uncertain = not hwnd or not owner or not root
                hidden_top = (owner == self.pid and root == hwnd
                              and not self.u.IsWindowVisible(hwnd))
                if uncertain or hidden_top:
                    if len(self.unresolved_show_details) < 8:
                        self.unresolved_show_details.append({'hwnd': int(hwnd or 0),
                            'visible_at_delivery': bool(hwnd and self.u.IsWindowVisible(hwnd)),
                            'elapsed_sec': round(time.monotonic() - self.hook_started, 6),
                            **self._window_metadata(hwnd)})
                    if len(self.errors) < 8: self.errors.append('WATCH_SHOW_NOT_RESOLVABLE_AT_DELIVERY')
            kind = classify_event(event, object_id, child_id, int(hwnd or 0),
                                  int(root or 0), owner,
                                  self.pid, bool(hwnd and self.u.IsWindowVisible(hwnd)), self.baseline)
            if kind:
                entry = {'kind': kind, 'hwnd': int(hwnd),
                         'elapsed_sec': round(time.monotonic() - self.hook_started, 6)}
                if kind == 'new_visible_app_top':
                    self.new_tops.add(int(hwnd))
                    entry.update(self._window_metadata(hwnd))
                    self.new_top_details[int(hwnd)] = entry
                self.events.append(entry)
                if kind == 'app_foreground': self.foreground_events += 1
        except Exception as exc:
            if len(self.errors) < 8: self.errors.append(str(exc))

    def checkpoint(self):
        """Drain already queued events before a caller's irreversible step.

        This snapshot leaves hooks installed. It is not an atomic guarantee
        covering the target's later processing of an asynchronously queued drop.
        """
        if not self.entered or self.finished is not None:
            raise RuntimeError('WATCH_ACTIVE_CHECKPOINT_REQUIRED')
        after_front, after_cursor = None, None
        try:
            self._guard(); msg = self.W.MSG()
            while self.u.PeekMessageW(self.C.byref(msg), None, 0, 0, 1):
                self.message_count += 1
                if self.message_count > self.message_limit:
                    self.overflow = True; break
                if msg.message == 0x12: raise RuntimeError('WATCH_QUIT_RECEIVED')
                self.u.TranslateMessage(self.C.byref(msg)); self.u.DispatchMessageW(self.C.byref(msg))
                self._guard()
                if self.overflow or self.errors: break
            self._track_tops(self._visible_tops())
            after_front, after_cursor = self._surface()
        except Exception as exc:
            if len(self.errors) < 8: self.errors.append(str(exc))
        return {'complete': not self.errors and not self.overflow,
                'new_visible_app_top_count': len(self.new_tops),
                'app_foreground_events': self.foreground_events,
                'foreground_unchanged': self.before_front == after_front,
                'cursor_unchanged': self.before_cursor == after_cursor,
                'errors': list(self.errors), 'overflow': self.overflow}

    def finish(self, seconds=3.0):
        seconds = bounded_seconds(seconds)
        if self.finished is not None: return self.finished
        if not self.entered: raise RuntimeError('WATCH_NOT_ENTERED')
        deadline = time.monotonic() + seconds
        try:
            msg = self.W.MSG()
            while True:
                self._guard()
                while self.u.PeekMessageW(self.C.byref(msg), None, 0, 0, 1):
                    self.message_count += 1
                    if self.message_count > self.message_limit:
                        self.overflow = True; break
                    if msg.message == 0x12:
                        raise RuntimeError('WATCH_QUIT_RECEIVED')
                    self.u.TranslateMessage(self.C.byref(msg))
                    self.u.DispatchMessageW(self.C.byref(msg))
                    if self.overflow or self.errors or time.monotonic() >= deadline: break
                if self.overflow or self.errors or time.monotonic() >= deadline: break
                time.sleep(min(.01, max(0, deadline - time.monotonic())))
            if self.u.PeekMessageW(self.C.byref(msg), None, 0, 0, 0):
                self.errors.append('WATCH_PENDING_MESSAGES_AT_END')
            self._guard()
            tops = self._visible_tops()
            self._track_tops(tops)
            after_front, after_cursor = self._surface()
        except Exception as exc:
            if len(self.errors) < 8: self.errors.append(str(exc))
            after_front, after_cursor = None, None
        self.finished = {'observation_only': True, 'pid': self.pid, 'session': self.session,
            'created_at_filetime': str(self.created), 'started_epoch': self.started_epoch,
            'observed_sec': round(time.monotonic() - self.hook_started, 6),
            'requested_finish_sec': seconds, 'complete': not self.errors and not self.overflow,
            'overflow': self.overflow, 'errors': list(self.errors),
            'callback_count': self.callback_count, 'message_count': self.message_count,
            'baseline_visible_app_top_count': len(self.baseline),
            'new_visible_app_top_count': len(self.new_tops), 'app_foreground_events': self.foreground_events,
            'events': list(self.events), 'foreground_before': self.before_front,
            'new_top_details': list(self.new_top_details.values()),
            'unresolved_show_details': list(self.unresolved_show_details),
            'no_all_ui_absence_claim':True,
            'foreground_after': after_front, 'cursor_before': self.before_cursor,
            'cursor_after': after_cursor, 'foreground_unchanged': self.before_front == after_front,
            'cursor_unchanged': self.before_cursor == after_cursor,
            'app_private_after': self.last_private, 'input_calls': 0, 'focus_calls': 0,
            'clipboard_calls': 0, 'process_write_calls': 0,
            'later_ui_absence_proven': False}
        return self.finished

    def __exit__(self, exc_type, exc, tb):
        for hook in self.hooks:
            try:
                if not self.u.UnhookWinEvent(hook) and len(self.errors) < 8:
                    self.errors.append('WATCH_UNHOOK_FAILED')
            except Exception:
                if len(self.errors) < 8: self.errors.append('WATCH_UNHOOK_FAILED')
        self.hooks = []
        if self.handle:
            self.k.CloseHandle(self.handle); self.handle = None
        self.entered = False
        if self.finished is not None and self.errors:
            self.finished.update(complete=False, errors=list(self.errors))
        return False
