"""Fictional source-loader attacks; subprocesses never import the real reader."""
import ast
from contextlib import ExitStack, redirect_stdout
import hashlib
import importlib.machinery
import importlib.util
import json
import io
import marshal
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import reader_source


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / 'skills/kakaotalk-mac/scripts/windows'
SCRATCH = ROOT / 'work/.ai-scratch/reader-source-tests-20261102'
EVIL = 'FICTIONAL_UNVERIFIED_CODE_EXECUTED'
ENTRY = """import json
import sys
import fixture_dep

def main():
    print(json.dumps({'marker': fixture_dep.MARKER, 'args': sys.argv[1:],
                      'isolated': sys.flags.isolated,
                      'dont_write_bytecode': sys.dont_write_bytecode}))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
"""


class FictionalRuntime(unittest.TestCase):
    def setUp(self):
        SCRATCH.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix='fictional-', dir=SCRATCH)
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / 'runtime'
        self.root.mkdir()
        self.write('reader_source.py', Path(reader_source.__file__).read_bytes())
        self.write('fixture_dep.py', "MARKER = 'VERIFIED_DEPENDENCY'\n")
        self.write('room_reader.py', ENTRY)
        self.configure()

    def write(self, name, source):
        path = self.root / name
        path.write_bytes(source.encode('utf8') if isinstance(source, str) else source)
        return path

    def configure(self, names=None):
        if names is None:
            names = {p.name for p in self.root.glob('*.py')} | {'reader_config.py'}
        self.write('reader_config.py',
                   'from pathlib import Path\nROOT = Path(__file__).resolve().parent\n'
                   'SOURCE_NAMES = frozenset(' + repr(sorted(names)) + ')\n')
        return self.hashes()

    def hashes(self):
        return {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                for p in self.root.glob('*.py')}

    def argv(self, entry='room_reader.py', args=None, hashes=None):
        return reader_source.verified_argv(self.root, self.hashes() if hashes is None else hashes,
                                           entry, [] if args is None else args)

    def run_child(self, argv=None, env=None):
        return subprocess.run(self.argv() if argv is None else argv, cwd=self.base,
                              env=env, text=True, capture_output=True, timeout=10)

    def assert_child_blocked(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn(EVIL, result.stdout)

    def poison_cache(self, name):
        path = self.root / name
        cache = Path(importlib.util.cache_from_source(str(path)))
        cache.parent.mkdir(exist_ok=True)
        code = compile('print(' + repr(EVIL) + ')\nMARKER = ' + repr(EVIL), str(path), 'exec')
        metadata = path.stat()
        cache.write_bytes(importlib.util.MAGIC_NUMBER + struct.pack(
            '<III', 0, int(metadata.st_mtime) & 0xffffffff, metadata.st_size & 0xffffffff)
                          + marshal.dumps(code))
        ordinary = importlib.machinery.SourceFileLoader(path.stem, str(path)).get_code(path.stem)
        self.assertIn(EVIL, ordinary.co_consts, 'The attack must be valid for the normal loader')
        return cache

    def test_verified_subprocess_is_isolated_and_preserves_literal_arguments(self):
        args = ['messages', '--name', 'FICTIONAL room; $(never-run)', '--query', 'quote\"value']
        argv = self.argv(args=args)
        self.assertEqual(argv[:6], [sys.executable, '-I', '-B', '-X', 'utf8', '-c'])
        result = self.run_child(argv)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value['marker'], 'VERIFIED_DEPENDENCY')
        self.assertEqual(value['args'], args)
        self.assertEqual(value['isolated'], 1)
        self.assertTrue(value['dont_write_bytecode'])

    def test_redirected_unicode_json_uses_explicit_utf8_despite_encoding_environment(self):
        message = '가상 대화 내용과 한글 방 이름'
        self.write('room_reader.py',
                   'import json, sys\n'
                   'value = {"message": ' + repr(message) + ', "args": sys.argv[1:],\n'
                   '         "utf8_mode": sys.flags.utf8_mode, "isolated": sys.flags.isolated,\n'
                   '         "stdout_encoding": sys.stdout.encoding,\n'
                   '         "stderr_encoding": sys.stderr.encoding}\n'
                   'print(json.dumps(value, ensure_ascii=False))\n'
                   'print(json.dumps(value, ensure_ascii=False), file=sys.stderr)\n')
        args = ['--name', '가상 방']
        for encoding in ('cp949:strict', 'ascii:strict'):
            with self.subTest(encoding=encoding):
                env = dict(os.environ, PYTHONUTF8='0', PYTHONIOENCODING=encoding,
                           PYTHONCOERCECLOCALE='0', LC_ALL='C')
                result = subprocess.run(self.argv(args=args), cwd=self.base, env=env,
                                        capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0,
                                 result.stderr.decode('utf8', errors='replace'))
                for output in (result.stdout, result.stderr):
                    self.assertIn(message.encode('utf8'), output)
                    value = json.loads(output.decode('utf8', errors='strict'))
                    self.assertEqual(value['message'], message)
                    self.assertEqual(value['args'], args)
                    self.assertEqual(value['utf8_mode'], 1)
                    self.assertEqual(value['isolated'], 1)
                    for stream in ('stdout_encoding', 'stderr_encoding'):
                        self.assertEqual(value[stream].lower().replace('-', ''), 'utf8')

    def test_timestamp_valid_poisoned_dependency_helper_and_entry_caches_are_ignored(self):
        for name in ('fixture_dep.py', 'reader_source.py', 'room_reader.py'):
            with self.subTest(name=name):
                cache = self.poison_cache(name)
                try:
                    result = self.run_child()
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertNotIn(EVIL, result.stdout)
                    self.assertEqual(json.loads(result.stdout)['marker'], 'VERIFIED_DEPENDENCY')
                finally:
                    cache.unlink()

    def test_source_changed_after_argv_creation_is_rejected_before_execution(self):
        for name in ('fixture_dep.py', 'reader_source.py', 'reader_config.py', 'room_reader.py'):
            with self.subTest(name=name):
                path = self.root / name
                original = path.read_bytes()
                argv = self.argv()
                try:
                    path.write_text('print(' + repr(EVIL) + ')\n', encoding='utf8')
                    self.assert_child_blocked(self.run_child(argv))
                finally:
                    path.write_bytes(original)

    def test_dependency_changed_after_initial_validation_is_not_imported(self):
        self.write('room_reader.py',
                   'from pathlib import Path\n'
                   "Path(__file__).with_name('fixture_dep.py').write_text("
                   + repr('print(' + repr(EVIL) + ')\n') + ", encoding='utf8')\n"
                   'import fixture_dep\n')
        self.assert_child_blocked(self.run_child())

    def test_unpinned_local_module_added_during_main_cannot_execute(self):
        self.write('room_reader.py',
                   'from pathlib import Path\n'
                   "Path(__file__).with_name('fixture_unpinned.py').write_text("
                   + repr('print(' + repr(EVIL) + ')\n') + ", encoding='utf8')\n"
                   'import fixture_unpinned\n')
        self.assert_child_blocked(self.run_child())

    def test_already_imported_source_changed_before_exit_fails_final_check(self):
        self.write('room_reader.py',
                   'from pathlib import Path\nimport fixture_dep\n'
                   "Path(__file__).with_name('fixture_dep.py').write_text("
                   + repr("MARKER = 'MODIFIED_AFTER_IMPORT'\n") + ", encoding='utf8')\n"
                   "print('FICTIONAL_MAIN_RETURNED_ZERO')\nraise SystemExit(0)\n")
        result = self.run_child()
        self.assertIn('FICTIONAL_MAIN_RETURNED_ZERO', result.stdout)
        self.assert_child_blocked(result)

    def test_return_code_is_preserved_without_source_changes(self):
        self.write('room_reader.py', "raise SystemExit(7)\n")
        self.assertEqual(self.run_child().returncode, 7)

    def test_direct_cli_bootstrap_ignores_helper_and_dependency_bytecode(self):
        # Reuse only the production bootstrap statement with a fictional main;
        # no application reader or Windows native module is imported here.
        tree = ast.parse((RUNTIME / 'kakao_read_win.py').read_text())
        bootstraps = [node for node in tree.body if isinstance(node, ast.If)
                      and any(isinstance(item, ast.Call)
                              and isinstance(item.func, ast.Attribute)
                              and item.func.attr == 'bootstrap_current'
                              for item in ast.walk(node))]
        self.assertEqual(len(bootstraps), 1)
        prologue = 'import sys as _source_sys\n' + ast.unparse(bootstraps[0]) + '\n'
        self.write('room_reader.py', prologue + ENTRY)
        for name in ('reader_source.py', 'fixture_dep.py'):
            self.poison_cache(name)
        result = self.run_child([sys.executable, '-B', str(self.root / 'room_reader.py'),
                                 'FICTIONAL_DIRECT_ARGUMENT'])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn(EVIL, result.stdout)
        value = json.loads(result.stdout)
        self.assertEqual(value['marker'], 'VERIFIED_DEPENDENCY')
        self.assertEqual(value['args'], ['FICTIONAL_DIRECT_ARGUMENT'])
        self.assertTrue(value['dont_write_bytecode'])

    def test_manual_bootstrap_reconfigures_cp949_pipes_without_changing_utf8_mode(self):
        tree = ast.parse((RUNTIME / 'kakao_read_win.py').read_text())
        bootstrap = next(node for node in tree.body if isinstance(node, ast.If)
                         and any(isinstance(item, ast.Call)
                                 and isinstance(item.func, ast.Attribute)
                                 and item.func.attr == 'bootstrap_current'
                                 for item in ast.walk(node)))
        prologue = ('import sys as _source_sys\n'
                    'if not getattr(_source_sys, "_kakao_verified_source_bootstrap", None):\n'
                    '    _source_sys._fictional_initial_encoding = _source_sys.stdout.encoding\n'
                    + ast.unparse(bootstrap) + '\n')
        message = '직접 실행한 가상 한글 대화'
        self.write('room_reader.py', prologue +
                   'import json, sys\n'
                   'value = {"message": ' + repr(message) + ',\n'
                   '         "initial_encoding": sys._fictional_initial_encoding,\n'
                   '         "utf8_mode": sys.flags.utf8_mode,\n'
                   '         "stdout_encoding": sys.stdout.encoding,\n'
                   '         "stderr_encoding": sys.stderr.encoding}\n'
                   'print(json.dumps(value, ensure_ascii=False))\n'
                   'print(json.dumps(value, ensure_ascii=False), file=sys.stderr)\n')
        result = subprocess.run([sys.executable, '-B', '-X', 'utf8=0',
                                 str(self.root / 'room_reader.py')],
                                cwd=self.base, capture_output=True, timeout=10,
                                env=dict(os.environ, PYTHONUTF8='0',
                                         PYTHONIOENCODING='cp949:strict'))
        self.assertEqual(result.returncode, 0,
                         result.stderr.decode('utf8', errors='replace'))
        for output in (result.stdout, result.stderr):
            self.assertIn(message.encode('utf8'), output)
            value = json.loads(output.decode('utf8', errors='strict'))
            self.assertEqual(value['message'], message)
            self.assertEqual(value['initial_encoding'].lower(), 'cp949')
            self.assertEqual(value['utf8_mode'], 0)
            for stream in ('stdout_encoding', 'stderr_encoding'):
                self.assertEqual(value[stream].lower().replace('-', ''), 'utf8')

    def test_utf8_stdio_preserves_stringio_redirects(self):
        output, errors = io.StringIO(), io.StringIO()
        with patch.object(sys, 'stdout', output), patch.object(sys, 'stderr', errors):
            reader_source._utf8_stdio()
            print('가상 출력')
            print('가상 오류', file=sys.stderr)
        self.assertEqual(output.getvalue(), '가상 출력\n')
        self.assertEqual(errors.getvalue(), '가상 오류\n')

    def test_pythonpath_cannot_shadow_verified_dependency(self):
        shadow = self.base / 'shadow'
        shadow.mkdir()
        (shadow / 'fixture_dep.py').write_text('print(' + repr(EVIL) + ')\n')
        result = self.run_child(env=dict(os.environ, PYTHONPATH=str(shadow)))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn(EVIL, result.stdout)
        self.assertEqual(json.loads(result.stdout)['marker'], 'VERIFIED_DEPENDENCY')

    def test_each_allowlisted_entry_can_run(self):
        for entry in ('room_reader.py', 'reader_job.py', 'kakao_read_win.py'):
            with self.subTest(entry=entry):
                self.write(entry, ENTRY)
                self.configure()
                result = self.run_child(self.argv(entry=entry))
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_extra_source_added_after_argv_is_blocked(self):
        argv = self.argv()
        self.write('unexpected.py', 'pass\n')
        self.assert_child_blocked(self.run_child(argv))

    def test_config_source_names_must_equal_manifest(self):
        self.configure(names={'reader_source.py', 'reader_config.py', 'room_reader.py'})
        try:
            argv = self.argv()
        except RuntimeError:
            return
        self.assert_child_blocked(self.run_child(argv))

    def test_missing_helper_config_or_entry_is_rejected(self):
        for name in ('reader_source.py', 'reader_config.py', 'room_reader.py'):
            with self.subTest(name=name):
                hashes = self.hashes()
                del hashes[name]
                with self.assertRaises((RuntimeError, ValueError)):
                    self.argv(hashes=hashes)

    def test_unknown_absolute_and_traversal_entries_are_rejected(self):
        self.write('unapproved.py', 'print(' + repr(EVIL) + ')\n')
        self.configure()
        for entry in ('unapproved.py', '../room_reader.py', str(self.root / 'room_reader.py'),
                      'room_reader.py:stream', None, 1):
            with self.subTest(entry=entry):
                with self.assertRaises((RuntimeError, ValueError)):
                    self.argv(entry=entry)

    def test_malformed_manifests_are_rejected(self):
        good = self.hashes()
        cases = [None, [], {}, dict(good, **{'../outside.py': 'a' * 64}),
                 dict(good, **{'room_reader.py:stream': 'a' * 64})]
        for value in ('A' * 64, 'a' * 63, 'z' * 64, None, 123):
            cases.append(dict(good, **{'fixture_dep.py': value}))
        for hashes in cases:
            with self.subTest(hashes=repr(hashes)[:80]):
                with self.assertRaises((RuntimeError, ValueError)):
                    reader_source.verified_argv(self.root, hashes, 'room_reader.py', [])

    def test_malformed_argument_vectors_are_rejected(self):
        for args in ('messages', {'command': 'messages'}, [None], [1], ['nul\0value'],
                     ['x' * 16385], ['value'] * 100):
            with self.subTest(args=repr(args)[:80]):
                with self.assertRaises((RuntimeError, ValueError)):
                    reader_source.verified_argv(self.root, self.hashes(), 'room_reader.py', args)

    def test_more_than_32_source_files_are_rejected(self):
        for index in range(33):
            self.write('extra_' + str(index) + '.py', 'pass\n')
        self.configure()
        with self.assertRaises((RuntimeError, ValueError)):
            self.argv()

    def test_source_larger_than_one_mib_is_rejected(self):
        self.write('fixture_dep.py', b'#' + b'x' * (1024 * 1024))
        with self.assertRaises((RuntimeError, ValueError)):
            self.argv()

    def test_source_total_larger_than_eight_mib_is_rejected(self):
        for index in range(9):
            self.write('large_' + str(index) + '.py', b'#' + b'x' * (1024 * 1024 - 1))
        self.configure()
        with self.assertRaises((RuntimeError, ValueError)):
            self.argv()

    def test_symlinked_source_is_rejected(self):
        source = self.root / 'fixture_dep.py'
        outside = self.base / 'outside.py'
        source.rename(outside)
        try:
            source.symlink_to(outside)
        except (OSError, NotImplementedError) as exc:
            self.skipTest('File symlinks unavailable: ' + type(exc).__name__)
        with self.assertRaises((RuntimeError, ValueError)):
            self.argv()

    def test_symlinked_root_is_rejected(self):
        alias = self.base / 'alias'
        try:
            alias.symlink_to(self.root, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest('Directory symlinks unavailable: ' + type(exc).__name__)
        with self.assertRaises((RuntimeError, ValueError)):
            reader_source.verified_argv(alias, self.hashes(), 'room_reader.py', [])

    def test_source_replaced_by_same_bytes_symlink_after_argv_is_rejected(self):
        argv = self.argv()
        source = self.root / 'fixture_dep.py'
        outside = self.base / 'outside.py'
        source.rename(outside)
        try:
            source.symlink_to(outside)
        except (OSError, NotImplementedError) as exc:
            self.skipTest('File symlinks unavailable: ' + type(exc).__name__)
        self.assert_child_blocked(self.run_child(argv))

    def test_windows_reparse_source_or_root_is_rejected(self):
        original = Path.lstat
        for target in (self.root, self.root / 'fixture_dep.py'):
            with self.subTest(target=target.name):
                def reparse(path):
                    info = original(path)
                    if path == target:
                        fields = {name: getattr(info, name) for name in dir(info)
                                  if name.startswith('st_')}
                        return SimpleNamespace(**dict(fields, st_file_attributes=0x400))
                    return info
                with patch.object(Path, 'lstat', reparse):
                    with self.assertRaises((RuntimeError, ValueError)):
                        self.argv()


class ExistingJobBoundaries(unittest.TestCase):
    @staticmethod
    def integer_expression(node):
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value
        if isinstance(node, ast.BinOp):
            left = ExistingJobBoundaries.integer_expression(node.left)
            right = ExistingJobBoundaries.integer_expression(node.right)
            if isinstance(node.op, ast.Mult):
                return left * right
            if isinstance(node.op, ast.BitOr):
                return left | right
        raise AssertionError('Expected a constant integer expression')

    def test_job_memory_limits_and_suspended_start_are_preserved(self):
        config = ast.parse((RUNTIME / 'reader_config.py').read_text())
        memory = [node.value for node in config.body if isinstance(node, ast.Assign)
                  and any(isinstance(target, ast.Name) and target.id == 'MEMORY_LIMIT'
                          for target in node.targets)]
        self.assertEqual(len(memory), 1)
        self.assertEqual(self.integer_expression(memory[0]), 268435456)
        tree = ast.parse((RUNTIME / 'reader_job.py').read_text())
        run = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                   and node.name == 'run')
        assignments = [node for node in ast.walk(run) if isinstance(node, ast.Assign)]
        flags = [node.value for node in assignments
                 if any(isinstance(target, ast.Attribute) and target.attr == 'flags'
                        for target in node.targets)]
        self.assertEqual(len(flags), 1)
        self.assertEqual(self.integer_expression(flags[0]), 0x2300)
        memory_targets = {target.attr for node in assignments
                          if isinstance(node.value, ast.Name) and node.value.id == 'LIMIT'
                          for target in node.targets if isinstance(target, ast.Attribute)}
        self.assertTrue({'process', 'job'} <= memory_targets)
        calls = [node for node in ast.walk(run) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute)]
        popen = next(node for node in calls if node.func.attr == 'Popen')
        creation = next(keyword.value for keyword in popen.keywords
                        if keyword.arg == 'creationflags')
        self.assertEqual(self.integer_expression(creation), 0x08000004)
        assign = next(node for node in calls if node.func.attr == 'AssignProcessToJobObject')
        resume = next(node for node in calls if node.func.attr == 'NtResumeProcess')
        self.assertLess(popen.lineno, assign.lineno)
        self.assertLess(assign.lineno, resume.lineno)
        assertions = [node for node in ast.walk(run) if isinstance(node, ast.Assert)]
        for guarded in (assign, resume):
            self.assertTrue(any(guarded in ast.walk(node.test) for node in assertions))

    def test_outer_and_inner_job_timeouts_remain_50_and_45_seconds(self):
        for filename, entry, timeout in (('reader_rpc.py', 'reader_job.py', 50),
                                         ('reader_job.py', 'room_reader.py', 45)):
            tree = ast.parse((RUNTIME / filename).read_text())
            calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                     and isinstance(node.func, ast.Name) and node.func.id == 'run'
                     and node.args and isinstance(node.args[-1], ast.Constant)
                     and node.args[-1].value == timeout]
            with self.subTest(filename=filename):
                self.assertEqual(len(calls), 1)
                command = calls[0].args[0]
                self.assertIsInstance(command, ast.Call)
                name = command.func.id if isinstance(command.func, ast.Name) else command.func.attr
                self.assertEqual(name, 'verified_argv')
                self.assertTrue(any(isinstance(arg, ast.Constant) and arg.value == entry
                                    for arg in command.args))


class ReaderRequestBinding(unittest.TestCase):
    def setUp(self):
        import reader_job
        self.job = reader_job
        temporary = tempfile.TemporaryDirectory(prefix='fictional-request-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source = self.root / 'source'; self.source.mkdir()
        self.state = self.root / 'receipts'; self.state.mkdir()
        for name in ('room_reader.py', 'reader_config.py'):
            (self.source / name).write_text('# fictional source only\n')
        (self.source / 'reader_source.py').write_bytes(Path(reader_source.__file__).read_bytes())
        self.hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                       for path in self.source.iterdir()}
        self.request = {'source_hashes': self.hashes,
                        'source_sha256': self.hashes['room_reader.py'],
                        'args': ['messages', '--name', 'FICTIONAL_ROOM']}
        self.name = 'reader-' + 'a' * 32 + '.json'
        self.raw = json.dumps(self.request).encode()
        (self.state / self.name).write_bytes(self.raw)
        self.digest = hashlib.sha256(self.raw).hexdigest()
        self.runner = Mock(return_value={'exit': 0, 'timeout': False})
        stack = ExitStack(); self.addCleanup(stack.close)
        stack.enter_context(patch.object(reader_job, 'ROOT', self.source))
        stack.enter_context(patch.object(reader_job, 'SOURCE_NAMES', frozenset(self.hashes)))
        stack.enter_context(patch.object(reader_job, 'state_root', return_value=self.state))
        stack.enter_context(patch.object(reader_job, 'run', self.runner))
        stack.enter_context(patch.object(sys, '_kakao_verified_source_bootstrap',
            reader_source.manifest_sha256(self.hashes), create=True))

    def run_main(self, digest=None):
        with patch.object(sys, 'argv', ['reader_job.py', self.name, digest or self.digest]), \
             redirect_stdout(io.StringIO()):
            return self.job.main()

    def test_changed_request_bytes_never_start_a_child(self):
        changed = dict(self.request, args=['messages', '--name', 'DIFFERENT_FICTIONAL_ROOM'])
        (self.state / self.name).write_text(json.dumps(changed))
        with self.assertRaisesRegex(AssertionError, 'REQUEST_CHANGED'):
            self.run_main()
        self.runner.assert_not_called()

    def test_source_manifest_in_request_cannot_replace_bootstrap_manifest(self):
        changed = dict(self.request, source_hashes=dict(self.hashes, reader_config='0' * 64))
        raw = json.dumps(changed).encode(); (self.state / self.name).write_bytes(raw)
        with self.assertRaisesRegex(AssertionError, 'REQUEST_SOURCE_BINDING_CHANGED'):
            self.run_main(hashlib.sha256(raw).hexdigest())
        self.runner.assert_not_called()

    def test_unchanged_request_launches_verified_inner_child_and_records_source_binding(self):
        self.assertEqual(self.run_main(), 0)
        argv, output, timeout = self.runner.call_args.args
        self.assertEqual(argv[:6], [sys.executable, '-I', '-B', '-X', 'utf8', '-c'])
        self.assertEqual(timeout, 45)
        receipt = json.loads((self.state / self.name.replace('.json', '-receipt.json')).read_text())
        self.assertEqual(receipt['source_execution'], 'verified-source-bytes')
        self.assertEqual(receipt['source_manifest_sha256'], reader_source.manifest_sha256(self.hashes))


if __name__ == '__main__':
    unittest.main()
