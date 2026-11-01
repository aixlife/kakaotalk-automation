"""No network/app access: synthetic release transport plus real crash processes."""
import copy
import contextlib
import hashlib
import io
import json
import importlib.util
import os
from pathlib import Path, PureWindowsPath
import stat
import py_compile
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
import reader_manager as manager
import release_manifest as manifest_api
from test_release_manifest import qa_fixture

APP = {'architecture':'x64','sha256':'a'*64}


def release(sequence=1, *, app=None, supported_app=None, marker=None,
            requirements='cryptography==47.0.0\n', executable_fixture=False):
    marker = str(sequence) if marker is None else marker
    bodies = {'SKILL.md':b'Synthetic updater test skill.\n', 'LICENSE':b'Test fixture\n',
              'scripts/windows/requirements.txt':requirements.encode()}
    for name in manifest_api.RUNTIME:
        bodies['scripts/windows/'+name] = ('# Synthetic '+name+' '+marker+'\n').encode()
    app = app or APP
    supported_app = supported_app or app
    bodies['scripts/windows/room_reader.py'] = (bodies['scripts/windows/room_reader.py']+
        ('EXPECTED='+repr(supported_app['sha256'])+'\nREADER_SUPPORTED={EXPECTED:"26.9.0.0"}\n'
         'X86_CANDIDATES={'+repr('b'*64)+':"26.9.0.0"}\n').encode())
    if executable_fixture:
        # Only the generic source loader is real. This entry never imports the
        # native reader and performs no app, account, DB, UI or network access.
        bodies['scripts/windows/reader_source.py'] = (ROOT/
            'skills/kakaotalk-mac/scripts/windows/reader_source.py').read_bytes()
        bodies['scripts/windows/reader_config.py'] = (
            'from pathlib import Path\nROOT=Path(__file__).parent\nSOURCE_NAMES=frozenset('+
            repr(sorted(manifest_api.RUNTIME))+')\n').encode()
        bodies['scripts/windows/kakao_read_win.py'] = (
            'import json,sys\nprint(json.dumps({"fixture":"safe", "command":sys.argv[1]}))\n').encode()
    hashes = {name:hashlib.sha256(body).hexdigest() for name,body in bodies.items()}
    report = b'# Synthetic QA fixture; no live validation claim.\n'
    value = {'schema':1,'manager_revision':1,'channel':'stable','sequence':sequence,
        'tag':'v0.4.'+str(sequence), 'commit':str(sequence)*40, 'capability':'reader-only',
        'files':hashes,'manifest_sha256':manifest_api.file_manifest_sha(hashes),
        'report':{'path':'docs/fixture-qa.md','sha256':hashlib.sha256(report).hexdigest()},
        'compatible_apps':[{'architecture':app['architecture'],'app_sha256':app['sha256'],
            'version':'26.9.0.0'}]}
    application = value['compatible_apps'][0]
    sources = {name.rsplit('/',1)[1]:digest for name,digest in hashes.items() if name.endswith('.py')}
    application['qa'] = qa_fixture(sources,application,value['report']['sha256'])
    return manifest_api.validate_manifest(value), bodies, report


def archive(value, bodies, extra=None):
    stream = io.BytesIO()
    prefix = 'kakaotalk-automation-'+value['commit']+'/'
    with zipfile.ZipFile(stream,'w',zipfile.ZIP_DEFLATED) as zipped:
        for name,body in bodies.items():
            zipped.writestr(prefix+'skills/kakaotalk-mac/'+name,body)
        if extra:
            name,body = extra
            if isinstance(name,zipfile.ZipInfo):
                zipped.writestr(name,body)
            else:
                zipped.writestr(prefix+name,body)
    return stream.getvalue()


class FakeTransport:
    def __init__(self, value, bodies, report):
        self.calls = []
        asset = 'https://github.com/'+manager.REPO+'/releases/download/'+value['tag']+'/'+manager.ASSET
        self.responses = {
            manager.API+'/releases/latest':manifest_api.canonical_bytes({
                'tag_name':value['tag'],'draft':False,'prerelease':False,
                'assets':[{'name':manager.ASSET,'browser_download_url':asset}]}),
            asset:manifest_api.canonical_bytes(value),
            manager.API+'/git/ref/tags/'+value['tag']:manifest_api.canonical_bytes(
                {'object':{'type':'commit','sha':value['commit']}}),
            manager.RAW+'/'+value['commit']+'/'+value['report']['path']:report,
            'https://codeload.github.com/'+manager.REPO+'/zip/'+value['commit']:archive(value,bodies)}

    def get(self,url,maximum,deadline):
        self.calls.append(url)
        manager.deadline_check(deadline)
        body = self.responses[url]
        if isinstance(body,Exception):
            raise body
        if len(body)>maximum:
            raise manager.UpdateError('DOWNLOAD_SIZE_LIMIT')
        return body


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.project = Path(self.temporary.name).resolve()/'project'
        self.project.mkdir()
        self.dependencies = patch.object(manager.importlib.metadata,'version',
            side_effect=lambda name:{'cryptography':'47.0.0','apsw':'3.54.1.0'}[name])
        self.dependencies.start()
        self.addCleanup(self.dependencies.stop)
        manager.enable(self.project,'codex')
        self.subject = manager.Manager(self.project,'codex')
        self.first = release()

    def install(self, fixture=None, **kwargs):
        fixture = fixture or self.first
        transport = FakeTransport(*fixture)
        result = self.subject.check(APP,transport=transport,now=100,**kwargs)
        return result,transport

    def test_opt_in_and_agent_isolation_no_schedule_or_skill_write(self):
        self.assertTrue(self.subject.config()['enabled'])
        self.assertFalse((self.project/'.agents').exists())
        self.assertFalse(self.subject.active_path.exists())
        self.assertFalse((self.subject.root/'state/claude').exists())
        manager.disable(self.project,'codex')
        fake = FakeTransport(*self.first)
        with self.assertRaisesRegex(manager.UpdateError,'AUTO_UPDATES_DISABLED'):
            self.subject.check(APP,transport=fake)
        self.assertEqual(fake.calls,[])

    def test_install_cache_then_complete_update_preserves_previous(self):
        result,transport = self.install()
        self.assertEqual(result['status'],'UPDATED')
        first = self.subject.active()
        self.assertEqual(len(transport.calls),5)
        cached = FakeTransport(*self.first)
        self.assertEqual(self.subject.check(APP,transport=cached,now=101)['checked'],'cached')
        self.assertEqual(cached.calls,[])
        second = release(2)
        self.subject.check(APP,transport=FakeTransport(*second),now=3701)
        pointer = self.subject.active()
        self.assertEqual(pointer['previous'],first['current'])
        self.assertEqual(pointer['highest_sequence'],2)
        self.assertEqual(manager.verify_package(self.subject.package(first['current'])),self.first[0])
        self.assertEqual(manager.load_json(self.subject.state/'active.previous.json'),first)

    def test_metadata_only_release_is_separate_immutable_version(self):
        self.install()
        second = release(2,marker='1')
        self.assertEqual(second[0]['manifest_sha256'],self.first[0]['manifest_sha256'])
        self.subject.check(APP,force=True,transport=FakeTransport(*second),now=101)
        self.assertNotEqual(self.subject.active()['current'],self.subject.active()['previous'])

    def test_app_hash_change_forces_check_and_unknown_stays_blocked(self):
        self.install()
        before = self.subject.active_path.read_bytes()
        changed = {'architecture':'x64','sha256':'b'*64}
        fake = FakeTransport(*self.first)
        with self.assertRaisesRegex(manager.UpdateError,'NO_VERIFIED_UPDATE'):
            self.subject.check(changed,transport=fake,now=101)
        self.assertGreater(len(fake.calls),0)
        self.assertEqual(before,self.subject.active_path.read_bytes())

    def test_candidate_x86_cannot_promote_by_forging_probe_candidate_flag(self):
        self.install()
        before = self.subject.active_path.read_bytes()
        candidate = {'architecture':'x86','sha256':'b'*64}
        fixture = release(2,app=candidate,supported_app=APP)
        fake = FakeTransport(*fixture)
        with self.assertRaises(manifest_api.ManifestError):
            self.subject.check(candidate,transport=fake,now=101)
        self.assertEqual(before,self.subject.active_path.read_bytes())

    def test_future_x86_requires_stable_source_profile_and_complete_qa(self):
        self.install()
        future = {'architecture':'x86','sha256':'c'*64}
        fixture = release(2,app=future)
        result = self.subject.check(future,transport=FakeTransport(*fixture),now=101)
        self.assertEqual(result['status'],'UPDATED')
        self.assertTrue(self.subject.reader_path(future).is_file())

    def test_network_failure_only_falls_back_to_compatible_intact_payload(self):
        fake = FakeTransport(*self.first)
        fake.responses[manager.API+'/releases/latest'] = manager.NetworkUnavailable('OFFLINE')
        with self.assertRaises(manager.NetworkUnavailable):
            self.subject.check(APP,transport=fake,now=100)
        self.install(force=True)
        self.assertEqual(self.subject.check(APP,force=True,transport=fake,now=101)['status'],'CURRENT_OFFLINE')
        with self.assertRaises(manager.NetworkUnavailable):
            self.subject.check({'architecture':'x64','sha256':'b'*64},transport=fake,now=102)
        source = self.subject.reader_path(APP)
        source.write_text('modified')
        with self.assertRaisesRegex(manager.UpdateError,'LOCAL_PAYLOAD_MODIFIED'):
            self.subject.check(APP,force=True,transport=fake,now=103)

    def test_archive_network_failure_preserves_verified_current_reader(self):
        self.install()
        before = self.subject.active_path.read_bytes()
        fixture = release(2)
        fake = FakeTransport(*fixture)
        fake.responses['https://codeload.github.com/'+manager.REPO+'/zip/'+fixture[0]['commit']] = (
            manager.NetworkUnavailable('OFFLINE'))
        result = self.subject.check(APP,force=True,transport=fake,now=101)
        self.assertEqual(result['status'],'CURRENT_OFFLINE')
        self.assertEqual(before,self.subject.active_path.read_bytes())

    def test_stable_metadata_and_report_identity_fail_closed(self):
        self.install()
        before = self.subject.active_path.read_bytes()
        for change,reason in [('prerelease','STABLE_RELEASE_REQUIRED'),
                              ('asset','VERIFIED_MANIFEST_MISSING'),
                              ('commit','TAG_COMMIT_MISMATCH'),
                              ('report','QA_REPORT_HASH_MISMATCH')]:
            with self.subTest(change=change):
                fixture = release(2)
                fake = FakeTransport(*fixture)
                url = manager.API+'/releases/latest'
                metadata = json.loads(fake.responses[url])
                if change=='prerelease':
                    metadata['prerelease'] = True
                elif change=='asset':
                    metadata['assets'][0]['browser_download_url']='https://example.com/evil.json'
                elif change=='commit':
                    fake.responses[manager.API+'/git/ref/tags/'+fixture[0]['tag']] = b'{"object":{"type":"commit","sha":"0000000000000000000000000000000000000000"}}'
                else:
                    fake.responses[manager.RAW+'/'+fixture[0]['commit']+'/'+fixture[0]['report']['path']]=b'changed'
                fake.responses[url] = json.dumps(metadata).encode()
                with self.assertRaisesRegex(manager.UpdateError,reason):
                    self.subject.check(APP,force=True,transport=fake,now=101)
                self.assertEqual(before,self.subject.active_path.read_bytes())

    def test_failed_fresh_check_cannot_reuse_old_success_cache(self):
        self.install()
        second = release(2,app={'architecture':'x64','sha256':'b'*64})
        for forced in (True,False):
            with self.assertRaisesRegex(manager.UpdateError,'NO_VERIFIED_UPDATE'):
                self.subject.check(APP,force=forced,transport=FakeTransport(*second),now=101)

    def test_unknown_check_state_is_preserved_and_blocked(self):
        self.install()
        path = self.subject.state/'check.json'
        path.write_text('["user-data"]')
        with self.assertRaisesRegex(manager.UpdateError,'CHECK_STATE_INVALID'):
            self.subject.check(APP,force=True,transport=FakeTransport(*self.first),now=101)
        self.assertEqual(path.read_text(),'["user-data"]')

    def test_sequence_rollback_and_reuse_fail_unchanged(self):
        self.install(release(2))
        before = self.subject.active_path.read_bytes()
        for fixture,reason in [(release(1),'UPDATE_ROLLBACK_REJECTED'),
                               (release(2,marker='different'),'RELEASE_SEQUENCE_REUSED')]:
            with self.assertRaisesRegex(manager.UpdateError,reason):
                self.subject.check(APP,force=True,transport=FakeTransport(*fixture),now=101)
            self.assertEqual(before,self.subject.active_path.read_bytes())

    def test_dependency_missing_never_activates_or_runs_installer(self):
        self.install()
        before = self.subject.active_path.read_bytes()
        fixture = release(2,requirements='cryptography==99.0.0\n')
        with patch.object(manager.subprocess,'Popen',side_effect=AssertionError('installer ran')):
            with self.assertRaisesRegex(manager.UpdateError,'DEPENDENCY_MISSING'):
                self.subject.check(APP,force=True,transport=FakeTransport(*fixture),now=101)
        self.assertEqual(before,self.subject.active_path.read_bytes())

    def test_local_extra_directory_and_oversized_metadata_block_before_read(self):
        self.install()
        package = self.subject.package(self.subject.active()['current'])
        (package/'custom').mkdir()
        with self.assertRaisesRegex(manager.UpdateError,'LOCAL_PAYLOAD_MODIFIED'):
            manager.verify_package(package)
        (package/'custom').rmdir()
        with (package/'release.json').open('wb') as stream:
            stream.truncate(262145)
        with self.assertRaisesRegex(manager.UpdateError,'PAYLOAD_METADATA_SIZE_LIMIT'):
            manager.verify_package(package)

    def test_package_directory_comparison_uses_windows_portable_names(self):
        self.install()
        package = self.subject.package(self.subject.active()['current'])
        def windows_relative_paths(value):
            if isinstance(value,str) and value in self.first[0]['files']:
                return PureWindowsPath(value)
            return Path(value)
        with patch.object(manager,'Path',side_effect=windows_relative_paths):
            self.assertEqual(manager.verify_package(package),self.first[0])

    def test_archive_hostile_paths_links_duplicates_and_expansion(self):
        value,bodies,_ = self.first
        for name in ('../escape','a/./b','a//b','CON.txt','com¹.txt','conout$',
                     'skills/kakaotalk-mac/extra.py','skills/KAKAOTALK-mac/other'):
            with self.subTest(name=name):
                with self.assertRaises((manager.UpdateError,manifest_api.ManifestError)):
                    manager.stage_package(self.subject.root,value,archive(value,bodies,(name,b'x')),time.monotonic()+10)
        info = zipfile.ZipInfo('kakaotalk-automation-'+value['commit']+'/link')
        info.create_system=3
        info.external_attr=(stat.S_IFLNK|0o777)<<16
        with self.assertRaisesRegex(manager.UpdateError,'ARCHIVE_LINK_OR_ENCRYPTION'):
            manager.stage_package(self.subject.root,value,archive(value,bodies,(info,b'target')),time.monotonic()+10)
        with self.assertRaisesRegex(manager.UpdateError,'ARCHIVE_MEMBER_INVALID'):
            manager.stage_package(self.subject.root,value,archive(value,bodies,('huge',b'0'*(manager.MAX_FILE+1))),time.monotonic()+10)
        with self.assertWarns(UserWarning):
            duplicate = archive(value,bodies,('skills/kakaotalk-mac/SKILL.md',b'duplicate'))
        with self.assertRaisesRegex(manager.UpdateError,'ARCHIVE_DUPLICATE_MEMBER'):
            manager.stage_package(self.subject.root,value,duplicate,time.monotonic()+10)
        self.assertIsNone(self.subject.active())

    def test_archive_incomplete_or_source_mutation_never_activates(self):
        value,bodies,_ = self.first
        changed = dict(bodies)
        changed['SKILL.md']=b'changed'
        with self.assertRaisesRegex(manager.UpdateError,'ARCHIVE_FILE_HASH_MISMATCH'):
            manager.stage_package(self.subject.root,value,archive(value,changed),time.monotonic()+10)
        del changed['SKILL.md']
        with self.assertRaisesRegex(manager.UpdateError,'ARCHIVE_PAYLOAD_INCOMPLETE'):
            manager.stage_package(self.subject.root,value,archive(value,changed),time.monotonic()+10)

    def test_bootstrap_is_never_overwritten_and_invalid_agent_writes_nothing(self):
        path = self.subject.root/'reader_manager.py'
        path.write_text('custom bootstrap')
        with self.assertRaisesRegex(manager.UpdateError,'BOOTSTRAP_MODIFIED'):
            manager.enable(self.project,'codex')
        self.assertEqual(path.read_text(),'custom bootstrap')
        other = self.project/'another'
        other.mkdir()
        with self.assertRaisesRegex(manager.UpdateError,'AGENT_INVALID'):
            manager.enable(other,'other')
        self.assertEqual(list(other.iterdir()),[])

    def test_read_argument_allowlist_excludes_candidate_and_execution_flags(self):
        self.assertEqual(manager.reader_arguments(['accounts']),['accounts'])
        manager.reader_arguments(['messages','--account-token','a'*64,'--name','room'])
        for argv in (['probe'],['send'],['messages','--candidate-x86'],
                     ['messages','--python','evil.py'],['messages','--account-token','A'*64],
                     ['messages','--limit','10000']):
            with self.subTest(argv=argv),self.assertRaises(manager.UpdateError):
                manager.reader_arguments(argv)

    def test_real_launch_compiles_manifest_bound_source_and_ignores_poisoned_pyc(self):
        self.install(release(executable_fixture=True))
        command = self.subject.reader_command(APP,['accounts'])
        source = self.subject.reader_path(APP)
        marker = self.project/'poison-executed'
        poison = self.project/'poison.py'
        poison.write_text('from pathlib import Path\nPath('+repr(str(marker))+').write_text("bad")\n')
        # A cache prefix mirrors the complete source path below itself. Keep
        # this synthetic prefix short on Windows without enabling long paths.
        cache_root = self.project.parent/'c'
        command[3:3] = ['-X','pycache_prefix='+str(cache_root)]
        for file in (source,source.parent/'reader_source.py',source.parent/'reader_config.py'):
            with patch.object(sys,'pycache_prefix',str(cache_root)):
                cached = Path(importlib.util.cache_from_source(str(file)))
            cached.parent.mkdir(parents=True,exist_ok=True)
            py_compile.compile(str(poison),cfile=str(cached),
                invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,doraise=True)
        completed = subprocess.run(command,capture_output=True,text=True,timeout=5)
        self.assertEqual(completed.returncode,0,completed.stderr)
        self.assertEqual(json.loads(completed.stdout),{'fixture':'safe','command':'accounts'})
        self.assertFalse(marker.exists())

    def test_real_launch_rejects_edit_after_selection_before_any_payload_execution(self):
        self.install(release(executable_fixture=True))
        command = self.subject.reader_command(APP,['accounts'])
        source = self.subject.reader_path(APP)
        marker = self.project/'changed-executed'
        source.write_text('from pathlib import Path\nPath('+repr(str(marker))+').write_text("bad")\n')
        completed = subprocess.run(command,capture_output=True,text=True,timeout=5)
        self.assertNotEqual(completed.returncode,0)
        self.assertIn('READER_SOURCE_CHANGED',completed.stderr)
        self.assertFalse(marker.exists())

    def test_real_cli_bootstrap_derives_project_and_preserves_user_files(self):
        command = [sys.executable,'-B',str(self.subject.root/'reader_manager.py'),'status','--agent','codex']
        completed = subprocess.run(command,capture_output=True,text=True,timeout=5)
        self.assertEqual(completed.returncode,0,completed.stderr)
        self.assertEqual(json.loads(completed.stdout)['status'],'ENABLED')
        completed = subprocess.run(command[:-3]+['disable','--agent','codex'],capture_output=True,text=True,timeout=5)
        self.assertEqual(completed.returncode,0,completed.stderr)
        self.assertFalse(self.subject.config()['enabled'])

    def test_cli_utf8_json_and_stderr_override_legacy_pipe_encoding(self):
        project = self.project/'학생 작업'
        project.mkdir()
        code = '''import sys
sys.path.insert(0,sys.argv[1])
import reader_manager as manager
result=manager.main(['enable','--project',sys.argv[2],'--agent','codex'])
print('한글 진단',file=sys.stderr)
raise SystemExit(result)
'''
        environment = dict(os.environ,PYTHONIOENCODING='cp1252')
        completed = subprocess.run([sys.executable,'-B','-c',code,str(ROOT/'tools'),str(project)],
                                  env=environment,capture_output=True,timeout=5)
        self.assertEqual(completed.returncode,0,completed.stderr)
        output = json.loads(completed.stdout.decode('utf8'))
        self.assertEqual(output['status'],'ENABLED')
        self.assertEqual(output['launcher'],str(project/manager.ROOT_NAME/'reader_manager.py'))
        self.assertIn('학생 작업'.encode('utf8'),completed.stdout)
        self.assertEqual(completed.stderr.decode('utf8').strip(),'한글 진단')

    def test_cli_keeps_stringio_redirects_usable(self):
        output,error = io.StringIO(),io.StringIO()
        with contextlib.redirect_stdout(output),contextlib.redirect_stderr(error):
            result = manager.main(['status','--project',str(self.project),'--agent','codex'])
            self.assertIs(sys.stdout,output)
            self.assertIs(sys.stderr,error)
        self.assertEqual(result,0)
        self.assertEqual(json.loads(output.getvalue())['status'],'ENABLED')
        self.assertEqual(error.getvalue(),'')

    def test_real_process_crash_before_and_after_atomic_pointer_recovers(self):
        self.install()
        before = self.subject.active()
        second = release(2)
        manager.stage_package(self.subject.root,second[0],archive(second[0],second[1]),time.monotonic()+10)
        for phase in ('before_active','after_active'):
            with self.subTest(phase=phase):
                manager.write_json(self.subject.active_path,before)
                code = '''import os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import reader_manager as m
subject=m.Manager(Path(sys.argv[2]),'codex')
value=m.verify_package(subject.package(sys.argv[3]))
original=m.write_json
def crash(path,value,**kwargs):
    if Path(path).name=='active.json' and sys.argv[4]=='before_active': os._exit(91)
    original(path,value,**kwargs)
    if Path(path).name=='active.json' and sys.argv[4]=='after_active': os._exit(92)
m.write_json=crash
with m.manager_lock(subject.root): subject.activate(value)
'''
                completed = subprocess.run([sys.executable,'-B','-c',code,str(ROOT/'tools'),str(self.project),
                    manager.release_id(second[0]),phase],capture_output=True,timeout=10)
                self.assertIn(completed.returncode,(91,92),completed.stderr)
                with manager.manager_lock(self.subject.root):
                    self.subject.recover()
                actual = self.subject.active()
                self.assertEqual(actual['highest_sequence'],1 if phase=='before_active' else 2)
                self.subject.validate_pointer(actual)
                self.assertEqual(manager.load_json(self.subject.state/'transaction.json')['phase'],
                                 'ROLLED_BACK' if phase=='before_active' else 'COMMITTED')

    def test_real_os_lock_contention_and_crash_release(self):
        code = '''import os,sys,time
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import reader_manager as m
with m.manager_lock(Path(sys.argv[2])):
 print('locked',flush=True)
 time.sleep(20)
'''
        child = subprocess.Popen([sys.executable,'-B','-c',code,str(ROOT/'tools'),str(self.subject.root)],
                                 stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(),'locked')
            with self.assertRaisesRegex(manager.UpdateError,'UPDATE_BUSY'):
                with manager.manager_lock(self.subject.root):
                    self.fail('second writer acquired held lock')
        finally:
            child.kill()
            child.communicate(timeout=5)
        with manager.manager_lock(self.subject.root):
            self.assertTrue((self.subject.root/'manager.lock').exists())

    def test_real_network_worker_timeout_is_killed_without_network_access(self):
        original = subprocess.Popen
        children = []
        def sleeping_child(*args,**kwargs):
            child = original([sys.executable,'-c','import time; time.sleep(20)'],**kwargs)
            children.append(child)
            return child
        with patch.object(manager.subprocess,'Popen',side_effect=sleeping_child):
            with self.assertRaisesRegex(manager.NetworkUnavailable,'UPDATE_NETWORK_TIMEOUT'):
                manager.HttpTransport().get(manager.API+'/releases/latest',100,time.monotonic()+.1)
        self.assertIsNotNone(children[0].poll())

    def test_trusted_urls_reject_auth_plaintext_and_unknown_hosts(self):
        for url in ('http://github.com/a','https://user:pass@github.com/a',
                    'https://github.com.evil.invalid/a','https://github.com:444/a'):
            with self.assertRaises(manager.UpdateError):
                manager.trusted_url(url)


if __name__=='__main__':
    unittest.main()
