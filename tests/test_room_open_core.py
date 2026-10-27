"""Deterministic guards and AST checks; no Windows session or UI is touched."""
import ast
import copy
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'experimental/room-open/hybrid_ui_win.py'
SPEC = importlib.util.spec_from_file_location('hybrid_ui_win', SOURCE)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class Guards(unittest.TestCase):
    def snapshot(self):
        return dict(pid=12, created_at_filetime='123', captured_epoch=100, query='Target',
                    capture={'status': 'CAPTURED', 'bounds': [1, 2, 10, 20], 'sha256': 'a' * 64},
                    **{name: {'hwnd': n, 'rect': [1, 2, 10, 20], 'class': name, 'control_id': n}
                       for n, name in enumerate(('main', 'chat_list', 'edit', 'search_list'), 1)})

    def test_request(self):
        for action in ('inspect', 'search'):
            MODULE.validate_request({'action': action, 'target': '테스트', 'allow_ui': True})
        for target in ('', '\n', 'hello\rworld', 'x' * 101, 123):
            with self.assertRaises(MODULE.GuardError):
                MODULE.validate_request({'action': 'search', 'target': target, 'allow_ui': True})
        with self.assertRaises(MODULE.GuardError):
            MODULE.validate_request({'action': 'send', 'target': 'x'})
        MODULE.validate_request({'action': 'search', 'target': 'x', 'allow_ui': True, 'replace_existing_search': True})
        for action, value in (('search', 'true'), ('search', 1), ('inspect', True), ('open', True)):
            with self.assertRaises(MODULE.GuardError):
                MODULE.validate_request({'action': action, 'target': 'x', 'allow_ui': True, 'replace_existing_search': value})

    def test_open_requires_review_and_point(self):
        valid = {'action': 'open', 'target': 'Target', 'expected': self.snapshot(),
                 'row_point': [1, 2], 'row_verified': True, 'allow_ui': True}
        MODULE.validate_request(valid)
        for key, value in [('row_verified', False), ('row_point', [True, 2]), ('expected', None)]:
            with self.assertRaises(MODULE.GuardError):
                MODULE.validate_request(dict(valid, **{key: value}))
        for capture in (None, {'status': 'CAPTURE_UNAVAILABLE'},
                        {'status': 'CAPTURED', 'bounds': [3, 4, 10, 20]}):
            invalid = copy.deepcopy(valid)
            invalid['expected']['capture'] = capture
            with self.assertRaises(MODULE.GuardError):
                MODULE.validate_request(invalid)

    def test_snapshot_all_bindings(self):
        expected = self.snapshot()
        MODULE.check_snapshot(expected, expected, 'Target', now=110)
        for key in ('pid', 'created_at_filetime'):
            changed = copy.deepcopy(expected)
            changed[key] = 'different'
            with self.assertRaises(MODULE.GuardError):
                MODULE.check_snapshot(expected, changed, 'Target', now=110)
        for name in ('main', 'chat_list', 'edit', 'search_list'):
            for key in ('hwnd', 'rect', 'class', 'control_id'):
                changed = copy.deepcopy(expected)
                changed[name][key] = 'different'
                with self.assertRaises(MODULE.GuardError):
                    MODULE.check_snapshot(expected, changed, 'Target', now=110)

    def test_snapshot_freshness_query_and_completeness(self):
        expected = self.snapshot()
        MODULE.check_snapshot(expected, expected, 'Target', now=400)
        for now in (99, 401):
            with self.assertRaises(MODULE.GuardError):
                MODULE.check_snapshot(expected, expected, 'Target', now=now)
        with self.assertRaises(MODULE.GuardError):
            MODULE.check_snapshot(expected, expected, 'Other', now=110)
        current = dict(expected, edit=None)
        with self.assertRaises(MODULE.GuardError):
            MODULE.check_snapshot(current, current, now=110)

    def test_point_bounds(self):
        self.assertTrue(MODULE.point_in_rect([1, 2], [1, 2, 10, 20]))
        for point in ([0, 2], [10, 2], [1, 20], [1, 1]):
            self.assertFalse(MODULE.point_in_rect(point, [1, 2, 10, 20]))

    def test_capture_bounds_and_only_structural_titles(self):
        self.assertEqual(MODULE.capture_layout(1024, 768), (3072, 2359296))
        self.assertEqual(MODULE.capture_layout(1, 1), (4, 4))
        for pair in ((0, 1), (1, 0), (1025, 1), (1, 769), (True, 20)):
            with self.assertRaises(MODULE.GuardError):
                MODULE.capture_layout(*pair)
        self.assertIsNone(MODULE.structural_title('private other room title'))
        self.assertEqual(MODULE.structural_title('prefix ChatRoomListView private suffix'),
                         'ChatRoomListView')
        self.assertEqual(MODULE.structural_title('SearchListCtrl suffix'), 'SearchListCtrl')
        self.assertIsNone(MODULE.structural_title('ChatRoomListView SearchListCtrl'))

    def test_ast_no_external_effect_apis_or_enter(self):
        tree = ast.parse(SOURCE.read_text(encoding='utf8'))
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        forbidden = {'SendMessageW', 'PostMessageW', 'SetWindowTextW', 'OpenClipboard',
                     'SetClipboardData', 'ShellExecuteW', 'CreateProcessW', 'mouse_event',
                     'keybd_event', 'WriteProcessMemory'}
        names = {node.func.attr for node in calls if isinstance(node.func, ast.Attribute)}
        self.assertFalse(names & forbidden)
        for call in calls:
            if isinstance(call.func, ast.Attribute) and call.func.attr == 'key' and call.args:
                self.assertNotEqual(getattr(call.args[0], 'value', None), 13)
        self.assertLessEqual(MODULE.HARD_SECONDS, 15)
        self.assertEqual(MODULE.APP_PRIVATE_STOP, 469893120)
        self.assertEqual(MODULE.JOB_LIMIT, 268435456)
        self.assertNotIn('assert ', SOURCE.read_text(encoding='utf8'))

    def test_partial_input_releases_only_owned_down(self):
        class FakeUser:
            def __init__(self):
                self.calls = []

            def SendInput(self, count, events, size):
                self.calls.append([(event.type, event.key.vk, event.key.scan,
                                    event.key.flags, event.mouse.flags) for event in events])
                return 1 if len(self.calls) == 1 else count

        for kind in ('ctrl', 'unicode', 'mouse'):
            win = MODULE.Windows.__new__(MODULE.Windows)
            win.u, win.input_calls, win.guard = FakeUser(), 0, lambda: None
            if kind == 'ctrl':
                events = [win.key(17), win.key(65), win.key(65, flags=2), win.key(17, flags=2)]
            elif kind == 'unicode':
                events = [win.key(scan=123, flags=4), win.key(scan=123, flags=6)]
            else:
                events = [MODULE.INPUT(type=0, mouse=MODULE.MOUSE(0, 0, 0, 2, 0, 0)),
                          MODULE.INPUT(type=0, mouse=MODULE.MOUSE(0, 0, 0, 4, 0, 0))]
            with self.assertRaisesRegex(MODULE.GuardError, 'INPUT_INCOMPLETE_RELEASED'):
                win.send(events)
            self.assertEqual(len(win.u.calls), 2)
            self.assertEqual(len(win.u.calls[1]), 1)
            release = win.u.calls[1][0]
            if kind == 'mouse':
                self.assertEqual(release[4], 4)
            else:
                self.assertEqual(release[3], 2 if kind == 'ctrl' else 6)
                self.assertEqual(release[1], 17 if kind == 'ctrl' else 0)

    def test_zero_input_does_not_inject_releases(self):
        class FakeUser:
            def __init__(self):
                self.calls = 0

            def SendInput(self, count, events, size):
                self.calls += 1
                return 0

        win = MODULE.Windows.__new__(MODULE.Windows)
        win.u, win.input_calls, win.guard = FakeUser(), 0, lambda: None
        with self.assertRaises(MODULE.GuardError):
            win.send([win.key(17), win.key(17, flags=2)])
        self.assertEqual(win.u.calls, 1)

    def test_search_replacement_does_not_read_previous_text(self):
        snapshot = self.snapshot()
        snapshot['main']['enabled'] = True

        class FakeUser:
            def GetForegroundWindow(self):
                return snapshot['main']['hwnd']

            def IsChild(self, parent, hwnd):
                return parent == snapshot['chat_list']['hwnd'] and hwnd == snapshot['edit']['hwnd']

        win = MODULE.Windows.__new__(MODULE.Windows)
        win.u = FakeUser()
        win.foreground = lambda hwnd: None
        win.combo = lambda vk: None
        win.tree = lambda: copy.deepcopy(snapshot)
        win.message = lambda hwnd, msg, *args: 15 if msg == 14 else 1
        win.reader = type('Reader', (), {'pid': 12})()
        win.owner = lambda hwnd: 12
        win.metadata = lambda hwnd: {'class': 'Edit', 'control_id': 100, 'visible': True, 'enabled': True}
        win.focus = win.require_focus = lambda main, edit: None
        win.no_modifiers = lambda: None
        win.send = lambda events: None
        reads = []

        def text(hwnd, cap):
            reads.append(hwnd)
            return 'Target'

        win.text = text
        with patch.object(MODULE.time, 'sleep', return_value=None):
            result = win.search({'action': 'search', 'target': 'Target',
                                 'replace_existing_search': True}, snapshot)
        self.assertEqual(len(reads), 1)  # Target after exact search-control write only.
        self.assertEqual(result['prior_query_length'], 15)
        self.assertTrue(result['query_replaced'])
        reads.clear()
        with patch.object(MODULE.time, 'sleep', return_value=None):
            with self.assertRaisesRegex(MODULE.GuardError, 'SNAPSHOT_REQUIRED'):
                win.search({'action': 'search', 'target': 'Target'}, snapshot)
        self.assertEqual(reads, [])
        win.metadata = lambda hwnd: {'class': 'RICHEDIT50W', 'control_id': 1006}
        with self.assertRaisesRegex(MODULE.GuardError, 'SEARCH_WRITE_TARGET_INVALID'):
            win.search({'action': 'search', 'target': 'Target',
                        'replace_existing_search': True}, snapshot)


    def test_ui_actions_require_explicit_true(self):
        for action in ('search', 'open'):
            for consent in (None, False, 1, 'true'):
                request = {'action': action, 'target': 'Target',
                           'expected': self.snapshot(), 'row_point': [1, 2],
                           'row_verified': True}
                if consent is not None:
                    request['allow_ui'] = consent
                with self.assertRaises(MODULE.GuardError):
                    MODULE.validate_request(request)
        MODULE.validate_request({'action': 'inspect'})
        MODULE.validate_request({'action': 'surface', 'target': 'Target'})

    def test_ctrl_a_is_rejected_before_input(self):
        win = MODULE.Windows.__new__(MODULE.Windows)
        events = []
        win.no_modifiers = lambda: None
        win.send = events.append
        with self.assertRaises(MODULE.GuardError):
            win.combo(0x41)
        self.assertEqual(events, [])
        win.combo(0x46)
        self.assertEqual(len(events), 1)
        self.assertEqual([event.key.vk for event in events[0]], [17, 0x46, 0x46, 17])

    def test_capture_digest_required_for_open(self):
        valid = {'action': 'open', 'target': 'Target', 'expected': self.snapshot(),
                 'row_point': [1, 2], 'row_verified': True, 'allow_ui': True}
        MODULE.validate_request(valid)
        for digest in (None, '', 'a' * 63, 'g' * 64, 'a' * 65, 123):
            bad = copy.deepcopy(valid)
            bad['expected']['capture']['sha256'] = digest
            with self.assertRaises(MODULE.GuardError):
                MODULE.validate_request(bad)

    def test_restoration_failure_cannot_report_search_success(self):
        snapshot = self.snapshot()
        snapshot['main']['enabled'] = True

        class FakeWindows:
            def __init__(self, started):
                self.foreground = 9
                self.session = 2
                self.u = self
                self.reader = self
                self.input_calls = 0
                self.closed = False
                self.restore_attempted = False

            def GetForegroundWindow(self):
                return self.foreground

            def IsWindow(self, hwnd):
                return True

            def IsIconic(self, hwnd):
                return False

            def cursor(self):
                return [10, 20]

            def guard(self):
                return 1024

            def metadata(self, hwnd):
                return {'hwnd': hwnd}

            def owner(self, hwnd):
                return 12

            def tree(self):
                return copy.deepcopy(snapshot)

            def search(self, request, current):
                self.foreground = current['main']['hwnd']
                return dict(current, prior_query_length=0, query_replaced=False)

            def capture_search(self, state, path):
                return state['capture']

            def restore_foreground(self, hwnd):
                self.restore_attempted = True
                raise MODULE.GuardError('RESTORE_FOREGROUND_FAILED')

            def close(self):
                self.closed = True

        fake = FakeWindows(0)
        with patch.object(MODULE, 'Windows', return_value=fake), \
                patch.object(MODULE.time, 'sleep', return_value=None):
            result = MODULE.execute({'action': 'search', 'target': 'Target',
                                     'allow_ui': True}, capture_path='unused.bmp')
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertIn('restore_error', result)
        self.assertTrue(fake.restore_attempted)
        self.assertTrue(fake.closed)
        self.assertFalse(result['send_ready'])

    def static_window(self):
        fake = SimpleNamespace(session=2, input_calls=0, closed=False)
        fake.u = SimpleNamespace(GetForegroundWindow=lambda: 9,
                                 IsWindow=lambda hwnd: True,
                                 IsIconic=lambda hwnd: False,
                                 SetCursorPos=lambda x, y: True)
        fake.cursor = lambda: [10, 20]
        fake.guard = lambda: 1024
        fake.metadata = lambda hwnd: {'hwnd': hwnd}
        fake.owner = lambda hwnd: 12
        fake.reader = SimpleNamespace(close=lambda: setattr(fake, 'closed', True))
        return fake

    def test_background_check_does_not_require_main_window(self):
        fake = self.static_window()

        def forbidden_tree():
            raise AssertionError('Main window must not be queried during background check')

        fake.tree = forbidden_tree
        fake.room = lambda target: {'hwnd': 8, 'title': target, 'input_count': 1,
                                    'message_list_count': 1, 'input_empty': True,
                                    'visible': True, 'enabled': True}
        with patch.object(MODULE, 'Windows', return_value=fake):
            result = MODULE.execute({'action': 'surface', 'target': 'Target', 'check': True})
        self.assertEqual(result['status'], 'PRE_SEND_SURFACE_CHECKED')
        self.assertTrue(result['foreground_restored'])
        self.assertTrue(result['cursor_restored'])
        self.assertEqual(result['foreground_before'], result['foreground_after'])
        self.assertEqual(result['cursor_before'], result['cursor_after'])
        self.assertEqual(result['input_calls'], 0)
        self.assertTrue(fake.closed)
        self.assertFalse(result['send_ready'])

    def test_unavailable_search_capture_cannot_report_searched(self):
        fake = self.static_window()
        snapshot = self.snapshot()
        fake.tree = lambda: copy.deepcopy(snapshot)
        fake.search = lambda request, current: dict(current, prior_query_length=0,
                                                    query_replaced=False)
        fake.capture_search = lambda state, path: {'status': 'CAPTURE_UNAVAILABLE'}
        with patch.object(MODULE, 'Windows', return_value=fake), \
                patch.object(MODULE.time, 'sleep', return_value=None):
            result = MODULE.execute({'action': 'search', 'target': 'Target',
                                     'allow_ui': True}, capture_path='unused.bmp')
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertEqual(result['error'], 'SEARCH_CAPTURE_UNAVAILABLE')
        self.assertNotIn('restore_error', result)
        self.assertTrue(fake.closed)
        self.assertEqual(result['input_calls'], 0)

    def test_open_rechecks_capture_before_any_pointer_or_click(self):
        snapshot = self.snapshot()
        request = {'action': 'open', 'target': 'Target', 'expected': snapshot,
                   'row_point': [1, 2], 'row_verified': True, 'allow_ui': True}
        calls = []
        main = snapshot['main']['hwnd']
        search = snapshot['search_list']['hwnd']
        foreground = [main]
        cursor = [[0, 0]]

        class FakeUser:
            def GetForegroundWindow(self):
                return foreground[0]

            def WindowFromPoint(self, point):
                calls.append('hit')
                return search

            def SetCursorPos(self, x, y):
                calls.append('move')
                cursor[0] = [x, y]
                return True

        win = MODULE.Windows.__new__(MODULE.Windows)
        win.u = FakeUser()
        win.foreground = lambda hwnd: calls.append('foreground')
        win.tree = lambda: copy.deepcopy(snapshot)
        win.text = lambda hwnd, cap: 'Target'
        win.guard = lambda: None
        win.no_modifiers = lambda: None
        win.cursor = lambda: cursor[0]
        win.room = lambda target: {'hwnd': 8, 'input_count': 1, 'message_list_count': 1}

        def click(events):
            calls.append('click')
            if calls.count('click') == 2:
                foreground[0] = 8

        win.send = click
        for capture in ({'status': 'CAPTURE_UNAVAILABLE'},
                        dict(snapshot['capture'], sha256='b' * 64),
                        dict(snapshot['capture'], bounds=[0, 0, 9, 9])):
            calls.clear()
            win.capture_search = lambda state, path, captured=capture: calls.append('capture') or captured
            with patch.object(MODULE.time, 'time', return_value=110):
                with self.assertRaisesRegex(MODULE.GuardError, 'SEARCH_RESULTS_CHANGED_REVIEW_AGAIN'):
                    win.open(request, snapshot)
            self.assertEqual(calls, ['foreground', 'capture'])
        calls.clear()
        win.capture_search = lambda state, path: calls.append('capture') or snapshot['capture']
        with patch.object(MODULE.time, 'time', return_value=110), \
                patch.object(MODULE.time, 'sleep', return_value=None):
            result = win.open(request, snapshot)
        self.assertEqual(result['hwnd'], 8)
        self.assertEqual(calls[:2], ['foreground', 'capture'])
        self.assertEqual(calls.count('click'), 2)
        self.assertLess(calls.index('capture'), calls.index('move'))


if __name__ == '__main__':
    unittest.main()
