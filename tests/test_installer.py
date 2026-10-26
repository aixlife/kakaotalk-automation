"""Pure filesystem installation checks; no app data or dependency installation."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location('project_skill_installer',
    Path(__file__).resolve().parents[1] / 'tools' / 'install.py')
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.source = self.base / 'source'
        self.source.mkdir()
        (self.source / 'SKILL.md').write_text('synthetic skill\n')
        (self.source / 'scripts').mkdir()
        (self.source / 'scripts' / 'reader.py').write_text('print("fixture")\n')
        self.project = self.base / 'project'
        self.project.mkdir()

    def run_install(self, agent='codex', apply=False):
        return installer.install(self.source, self.project, agent, apply)

    def test_default_inspection_does_not_create_files(self):
        result = self.run_install()
        self.assertEqual(result['status'], 'READY')
        self.assertEqual(list(self.project.iterdir()), [])

    def test_real_copy_matches_manifest_and_same_install_is_noop(self):
        result = self.run_install(apply=True)
        target = Path(result['target'])
        self.assertEqual(result['status'], 'INSTALLED')
        self.assertEqual(installer.manifest(target), installer.manifest(self.source))
        modified = (target / 'SKILL.md').stat().st_mtime_ns
        self.assertEqual(self.run_install(apply=True)['status'], 'UNCHANGED')
        self.assertEqual((target / 'SKILL.md').stat().st_mtime_ns, modified)

    def add_generated_files(self, root):
        cache = root / 'scripts' / '__pycache__'
        cache.mkdir()
        (cache / 'reader.cpython-test.pyc').write_bytes(b'private filename in bytecode')
        (root / 'scripts' / 'old.pyc').write_bytes(b'generated pyc')
        (root / 'scripts' / 'old.pyo').write_bytes(b'generated pyo')
        (root / '.DS_Store').write_bytes(b'generated metadata')

    def test_generated_source_files_are_not_copied(self):
        original = installer.manifest(self.source)
        self.add_generated_files(self.source)
        self.assertEqual(installer.manifest(self.source), original)
        target = Path(self.run_install(apply=True)['target'])
        self.assertFalse((target / 'scripts' / '__pycache__').exists())
        self.assertFalse((target / 'scripts' / 'old.pyc').exists())
        self.assertFalse((target / 'scripts' / 'old.pyo').exists())
        self.assertFalse((target / '.DS_Store').exists())

    def test_generated_source_and_target_files_keep_reinstall_unchanged(self):
        first = self.run_install(apply=True)
        target = Path(first['target'])
        self.add_generated_files(self.source)
        self.add_generated_files(target)
        before = {p: p.read_bytes() for p in target.rglob('*') if p.is_file()}
        repeated = self.run_install(apply=True)
        self.assertEqual(repeated['status'], 'UNCHANGED')
        self.assertEqual(repeated['manifest_sha256'], first['manifest_sha256'])
        self.assertEqual({p: p.read_bytes() for p in target.rglob('*') if p.is_file()}, before)

    def test_binary_lf_crlf_and_control_bytes_copy_exactly(self):
        payload = b'line one\nline two\r\n\x00\x1a\xff\n'
        (self.source / 'scripts' / 'bytes.dat').write_bytes(payload)
        target = Path(self.run_install(apply=True)['target'])
        self.assertEqual((target / 'scripts' / 'bytes.dat').read_bytes(), payload)

    def test_copy_requests_binary_mode_when_available(self):
        binary_flag = 1 << 30
        real_open = installer.os.open
        real_binary_flag = getattr(installer.os, 'O_BINARY', 0)
        observed = []
        def capture_open(path, flags, mode):
            observed.append(flags)
            return real_open(path, (flags & ~binary_flag) | real_binary_flag, mode)
        with patch.object(installer.os, 'O_BINARY', binary_flag, create=True):
            with patch.object(installer.os, 'open', side_effect=capture_open):
                self.run_install(apply=True)
        self.assertTrue(observed)
        self.assertTrue(all(flags & binary_flag for flags in observed))

    def test_generated_name_symlink_is_rejected_before_ignoring(self):
        link = self.source / '__pycache__'
        try:
            link.symlink_to(self.project, target_is_directory=True)
        except OSError as exc:
            self.skipTest(str(exc))
        with self.assertRaises(installer.InstallError):
            self.run_install(apply=True)

    def test_ignored_cache_children_are_not_traversed(self):
        cache = self.source / '__pycache__'
        cache.mkdir()
        try:
            (cache / 'unread').symlink_to(self.base / 'missing')
        except OSError as exc:
            self.skipTest(str(exc))
        self.assertEqual(self.run_install(apply=True)['status'], 'INSTALLED')

    def test_claude_destination(self):
        result = self.run_install('claude', True)
        self.assertEqual(Path(result['target']), self.project / '.claude/skills/kakaotalk-mac')

    def test_conflict_preserves_existing_content(self):
        target = Path(self.run_install(apply=True)['target'])
        (target / 'SKILL.md').write_text('user custom rules\n')
        with self.assertRaises(installer.InstallError):
            self.run_install(apply=True)
        self.assertEqual((target / 'SKILL.md').read_text(), 'user custom rules\n')

    def test_extra_target_file_is_a_conflict(self):
        target = Path(self.run_install(apply=True)['target'])
        (target / 'keep.txt').write_text('owned by user')
        with self.assertRaises(installer.InstallError):
            self.run_install()
        self.assertTrue((target / 'keep.txt').exists())

    def test_source_file_and_directory_links_are_rejected(self):
        for name, destination in (('linked', self.project), ('linked.txt', self.source / 'SKILL.md')):
            link = self.source / name
            try:
                link.symlink_to(destination, target_is_directory=destination.is_dir())
            except OSError as exc:
                self.skipTest(str(exc))
            try:
                with self.assertRaises(installer.InstallError):
                    self.run_install(apply=True)
            finally:
                link.unlink()
        self.assertEqual(list(self.project.iterdir()), [])

    def test_target_parent_link_is_rejected(self):
        link = self.project / '.agents'
        try:
            link.symlink_to(self.source, target_is_directory=True)
        except OSError as exc:
            self.skipTest(str(exc))
        with self.assertRaises(installer.InstallError):
            self.run_install(apply=True)
        self.assertTrue(link.is_symlink())

    def test_parent_traversal_is_rejected(self):
        with self.assertRaises(installer.InstallError):
            installer.install(self.source, self.project / '..' / 'project', 'codex', True)

    def test_source_root_link_is_rejected(self):
        link = self.base / 'source-link'
        try:
            link.symlink_to(self.source, target_is_directory=True)
        except OSError as exc:
            self.skipTest(str(exc))
        with self.assertRaises(installer.InstallError):
            installer.install(link, self.project, 'codex', True)

    def test_source_change_during_copy_rolls_back(self):
        original = installer.copy_file
        def mutate_source(source, target, expected, created):
            source.write_text('changed while copying')
            original(source, target, expected, created)
        with patch.object(installer, 'copy_file', side_effect=mutate_source):
            with self.assertRaises(installer.InstallError):
                self.run_install(apply=True)
        self.assertEqual(list(self.project.iterdir()), [])

    def test_root_and_home_are_not_project_installations(self):
        for project in (Path(self.project.anchor), Path.home()):
            with self.assertRaises(installer.InstallError):
                installer.install(self.source, project, 'codex', True)

    def test_rollback_removes_only_attempt_files(self):
        (self.project / 'user.txt').write_text('keep')
        original = installer.copy_file
        count = 0
        def fail_second(*args):
            nonlocal count
            count += 1
            if count == 2:
                raise OSError('synthetic write failure')
            original(*args)
        with patch.object(installer, 'copy_file', side_effect=fail_second):
            with self.assertRaises(installer.InstallError):
                self.run_install(apply=True)
        self.assertEqual([p.name for p in self.project.iterdir()], ['user.txt'])

    def test_rollback_preserves_modified_file_and_foreign_files(self):
        folder = self.project / 'owned'
        folder.mkdir()
        owned = folder / 'owned.txt'
        owned.write_text('initial')
        created = [(folder, installer.identity(folder), None),
                   (owned, installer.identity(owned), hashlib.sha256(b'initial').hexdigest())]
        owned.write_text('changed by user')
        (folder / 'foreign.txt').write_text('keep')
        self.assertTrue(installer.rollback(created))
        self.assertEqual(owned.read_text(), 'changed by user')
        self.assertEqual((folder / 'foreign.txt').read_text(), 'keep')


if __name__ == '__main__':
    unittest.main()
