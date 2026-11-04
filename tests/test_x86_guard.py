"""Synthetic guard checks for the x86 candidate; no native app is read."""
import ctypes
import unittest
from unittest.mock import patch

import room_reader


class FakeKernel:
    def GetExitCodeProcess(self, handle, out):
        ctypes.cast(out, ctypes.POINTER(room_reader.W.DWORD)).contents.value = 259
        return True

    def GetCurrentProcess(self):
        return 0


class FakePsapi:
    def __init__(self, app_private):
        self.app_private = list(app_private)

    def GetProcessMemoryInfo(self, handle, out, size):
        value = ctypes.cast(out, ctypes.POINTER(room_reader.PM)).contents
        value.private = self.app_private.pop(0) if handle == 'app' else 1024
        return True


class FakeScope:
    def __init__(self):
        self.calls = 0

    def guard(self):
        self.calls += 1


def reader(architecture, app_private):
    value = room_reader.Reader.__new__(room_reader.Reader)
    value.started = 1000.0
    value.read_bytes = 0
    value.handle = 'app'
    value.target_architecture = architecture
    value.k = FakeKernel()
    value.ps = FakePsapi(app_private)
    value.files = FakeScope()
    return value


MIB = 1024 * 1024


class X86Guard(unittest.TestCase):
    def test_x86_memory_is_bounded_by_growth_from_first_observation(self):
        # 448.2 MiB at start is above the x64 fixed baseline allowance.
        start = 469987328
        value = reader('x86', [start, start + 127 * MIB, start + 128 * MIB])
        with patch.object(room_reader.time, 'monotonic', return_value=1001.0):
            self.assertEqual(value.guard(), start)
            value.guard()
            with self.assertRaisesRegex(AssertionError, 'APP_MEMORY_LIMIT'):
                value.guard()

    def test_x86_absolute_private_cap_is_unchanged(self):
        value = reader('x86', [2147483648])
        with patch.object(room_reader.time, 'monotonic', return_value=1001.0):
            with self.assertRaisesRegex(AssertionError, 'APP_MEMORY_LIMIT'):
                value.guard()

    def test_x64_keeps_fixed_baseline(self):
        value = reader('x64', [469987328])
        with patch.object(room_reader.time, 'monotonic', return_value=1001.0):
            with self.assertRaisesRegex(AssertionError, 'APP_MEMORY_LIMIT'):
                value.guard()

    def test_x86_scope_sweep_is_rate_limited(self):
        value = reader('x86', [400 * MIB] * 4)
        now = [1001.0]
        with patch.object(room_reader.time, 'monotonic', side_effect=lambda: now[0]):
            for moment in (1001.0, 1001.1, 1001.2, 1001.3):
                now[0] = moment
                value.guard()
        # 1001.0 full sweep, 1001.1/1001.2 skipped, 1001.3 full sweep.
        self.assertEqual(value.files.calls, 2)

    def test_x86_snapshot_scope_guard_is_rate_limited(self):
        value = reader('x86', [])
        now = [1001.0]
        with patch.object(room_reader.time, 'monotonic', side_effect=lambda: now[0]):
            for moment in (1001.0, 1001.1, 1001.4):
                now[0] = moment
                value.scope_guard()
        self.assertEqual(value.files.calls, 2)

    def test_x64_scope_sweep_runs_every_guard(self):
        value = reader('x64', [300 * MIB] * 3)
        with patch.object(room_reader.time, 'monotonic', return_value=1001.0):
            for _ in range(3):
                value.guard()
        self.assertEqual(value.files.calls, 3)

    def test_time_limit_is_unchanged(self):
        self.assertEqual(room_reader.LIMIT_SECONDS, 40)
        value = reader('x86', [400 * MIB])
        with patch.object(room_reader.time, 'monotonic', return_value=1040.0):
            with self.assertRaisesRegex(AssertionError, 'TIME_LIMIT'):
                value.guard()


if __name__ == '__main__':
    unittest.main()
