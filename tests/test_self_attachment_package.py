"""Portable QA packaging checks. No Windows API, app, network or send is executed."""
import ast
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
from contextlib import redirect_stdout

PACKAGE=Path(__file__).resolve().parents[1]/'experimental/self-attachments'
sys.path.insert(0,str(PACKAGE))
spec=importlib.util.spec_from_file_location('portable_self_qa',PACKAGE/'self_qa.py')
qa=importlib.util.module_from_spec(spec);spec.loader.exec_module(qa)

class PortableAttachmentTests(unittest.TestCase):
    def test_sources_parse_without_executing_windows_modules(self):
        files=list(PACKAGE.glob('*.py'))
        self.assertEqual(len(files),10)
        for path in files:ast.parse(path.read_text(),filename=path.name)

    def test_no_personal_machine_paths(self):
        for path in PACKAGE.glob('*.py'):
            text=path.read_text()
            self.assertNotIn('C:\\Users\\',text)
            self.assertNotIn('/Users/',text)
            self.assertNotIn('Python314',text)

    def test_source_and_state_separated(self):
        self.assertEqual(qa.READER_ROOT,PACKAGE.parents[1]/'skills/kakaotalk-mac/scripts/windows')
        job=(PACKAGE/'attachment_no_ui_job_win.py').read_text()
        self.assertIn('(SOURCE_ROOT/filename).read_bytes()',job)
        self.assertIn("str(SOURCE_ROOT/'no_ui_observer_win.py')",job)
        self.assertIn("str(SOURCE_ROOT/'attachment_receipt_win.py')",job)
        self.assertIn("READER_ROOT/'kakao_read_win.py'",job)
        self.assertNotIn("str(ROOT/'",job)

    def test_plan_return_precedes_drop_code(self):
        tree=ast.parse((PACKAGE/'attachment_send_win.py').read_text())
        fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='run')
        gate=next(n for n in fn.body if isinstance(n,ast.If) and ast.unparse(n.test)=="not request['execute']")
        self.assertIsInstance(gate.body[0],ast.Return)
        drop=next(n for n in ast.walk(fn) if isinstance(n,ast.Attribute) and n.attr=='PostMessageW')
        self.assertLess(gate.lineno,drop.lineno)
        job=(PACKAGE/'attachment_no_ui_job_win.py').read_text()
        self.assertIn("send(dict(request,execute=False))",job)

    def test_fixed_fixture_bytes_and_types(self):
        self.assertEqual([len(x[2]) for x in qa.FIXTURES],[70,5931])
        self.assertEqual(hashlib.sha256(qa.TXT).hexdigest(),'c83792175f3ee3314d65ad2a11055fb2e24a278f54c40de0b120d7d483543518')
        self.assertEqual(hashlib.sha256(qa.PNG).hexdigest(),'3d37577ad5ba46bff4f9f5bcf17e7107d5c51a87e28d02d89ee4338569497949')

    def test_plan_never_dispatches_send_action(self):
        bundle={'id':'a'*32,'requests':[{'kind':'file'},{'kind':'image'}]}
        with mock.patch.object(qa,'new_bundle',return_value=bundle),mock.patch.object(qa,'write'),mock.patch.object(qa,'run_job',return_value={'status':'PREFLIGHT_RETURNED','plan':{'status':'PREFLIGHT_READY_NOT_EXECUTED'},'send_attempted':False}) as run:
            result=qa.plan()
        self.assertEqual(result['status'],'PLAN_READY_NO_SEND')
        self.assertFalse(result['send_attempted'])
        self.assertEqual([c.args[2] for c in run.call_args_list],['plan','plan'])

    def test_plan_stops_after_failed_preflight(self):
        bundle={'id':'a'*32,'requests':[{'kind':'file'},{'kind':'image'}]}
        with mock.patch.object(qa,'new_bundle',return_value=bundle),mock.patch.object(qa,'write'),mock.patch.object(qa,'run_job',return_value={'status':'BLOCKED_BEFORE_SEND','send_attempted':False}) as run:
            result=qa.plan()
        self.assertEqual(run.call_count,1)
        self.assertEqual(result['status'],'PLAN_BLOCKED_NO_SEND')

    def test_second_inner_plan_failure_cannot_be_ready(self):
        bundle={'id':'a'*32,'requests':[{'kind':'file'},{'kind':'image'}]}
        results=[{'status':'PREFLIGHT_RETURNED','plan':{'status':'PREFLIGHT_READY_NOT_EXECUTED'},'send_attempted':False},
                 {'status':'PREFLIGHT_RETURNED','plan':{'status':'BLOCKED'},'send_attempted':False}]
        with mock.patch.object(qa,'new_bundle',return_value=bundle),mock.patch.object(qa,'write'),mock.patch.object(qa,'run_job',side_effect=results):
            result=qa.plan()
        self.assertEqual(result['status'],'PLAN_BLOCKED_NO_SEND')
        self.assertEqual(result['results'][1]['plan_status'],'BLOCKED')

    def test_plan_requires_explicit_no_send_result(self):
        bundle={'id':'a'*32,'requests':[{'kind':'file'},{'kind':'image'}]}
        for attempted in (True,None,'unknown'):
            with self.subTest(attempted=attempted),mock.patch.object(qa,'new_bundle',return_value=bundle),mock.patch.object(qa,'write'),mock.patch.object(qa,'run_job',return_value={'status':'PREFLIGHT_RETURNED','plan':{'status':'PREFLIGHT_READY_NOT_EXECUTED'},'send_attempted':attempted}) as run:
                result=qa.plan()
            self.assertEqual(result['status'],'PLAN_BLOCKED_NO_SEND')
            self.assertEqual(run.call_count,1)

    def test_plan_artifacts_have_no_execute_authority(self):
        with tempfile.TemporaryDirectory() as folder,mock.patch.object(qa,'ROOT',Path(folder)),mock.patch.object(qa,'require_windows'),mock.patch.object(qa,'current_hashes',return_value=({},{})):
            bundle=qa.new_bundle()
            manifest=qa.load(Path(folder)/bundle['manifest'])
            self.assertIs(manifest['owner_authorized_no_ui_fixtures'],False)
            for item in bundle['requests']:
                request=qa.load(Path(folder)/('attachment-send-'+item['request_id']+'.json'))
                self.assertIs(request['execute'],False)
                self.assertIs(request['owner_authorized_self_qa'],False)

    def test_direct_sender_validates_explicit_approval(self):
        tree=ast.parse((PACKAGE/'attachment_send_win.py').read_text())
        fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='validate_request')
        namespace={'re':re}
        exec(compile(ast.Module(body=[fn],type_ignores=[]),'sender-request-check','exec'),namespace)
        request={'request_id':'a'*32,'execute':True,'kind':'file','destination':'SELF_CHAT_ONLY',
                 'file_sha256':'b'*64,'file_name':'attachment-qa-123456789abc.txt','require_no_ui':True,
                 'owner_approved_preview_ui':False}
        with self.assertRaisesRegex(ValueError,'EXPLICIT_SELF_QA_APPROVAL_REQUIRED'):namespace['validate_request'](request)
        request['owner_authorized_self_qa']=False
        with self.assertRaisesRegex(ValueError,'EXPLICIT_SELF_QA_APPROVAL_REQUIRED'):namespace['validate_request'](request)
        request['owner_authorized_self_qa']=True
        namespace['validate_request'](request)

    def test_execute_requires_approval(self):
        with mock.patch.object(qa,'require_windows'),mock.patch.object(qa,'new_bundle') as create:
            with self.assertRaisesRegex(RuntimeError,'EXPLICIT_SELF_TXT_PNG_APPROVAL_REQUIRED'):qa.execute('a'*32,False)
        create.assert_not_called()

    def test_changed_source_blocks_execution(self):
        with mock.patch.object(qa,'require_windows'),mock.patch.object(qa,'ROOT',Path('/unused')), \
             mock.patch.object(qa,'load',side_effect=[{'owner_approved':False,'source_hashes':{},'reader_source_hashes':{}},{'status':'PLAN_READY_NO_SEND'}]), \
             mock.patch.object(qa,'current_hashes',return_value=({'changed':'x'},{})),mock.patch.object(qa,'write') as write:
            with self.assertRaisesRegex(RuntimeError,'SOURCE_CHANGED_AFTER_PLAN'):qa.execute('a'*32,True)
        write.assert_not_called()

    def test_claim_prevents_reexecution_even_when_incomplete(self):
        with tempfile.TemporaryDirectory() as folder,mock.patch.object(qa,'ROOT',Path(folder)),mock.patch.object(qa,'require_windows'),mock.patch.object(qa,'current_hashes',return_value=({},{})),mock.patch.object(qa,'new_bundle',return_value={'id':'b'*32,'requests':[]}):
            qa.write('bundle-'+'a'*32+'.json',{'owner_approved':False,'source_hashes':{},'reader_source_hashes':{}})
            qa.write('plan-'+'a'*32+'-summary.json',{'status':'PLAN_READY_NO_SEND'})
            first=qa.execute('a'*32,True)
            self.assertEqual(first['status'],'INCOMPLETE_NO_RETRY')
            with self.assertRaises(FileExistsError):qa.execute('a'*32,True)

    def test_missing_receipt_cannot_pass(self):
        self.assertFalse(qa.verified_receipt({'status':'HEADLESS_SELF_ATTACHMENT_E2E_PASS'},{'kind':'file','request_id':'a'*32}))

    def _saved_fixture_receipt(self,root):
        rid='a'*32;sha=hashlib.sha256(qa.TXT).hexdigest();name='attachment-qa-8a73e2e535e7.txt'
        request={'file_sha256':sha,'file_bytes':len(qa.TXT),'file_name':name}
        request_path=qa.write('attachment-send-'+rid+'.json',request)
        copy_name='attachment-received-'+rid+'.txt';(root/copy_name).write_bytes(qa.TXT)
        item={'kind':'file','request_id':rid,'request_sha256':qa.digest(request_path)}
        result={'status':'HEADLESS_SELF_ATTACHMENT_E2E_PASS','send_attempted':True,'request_id':rid,
                'send':{'request_id':rid,'kind':'file','file_sha256':sha},
                'receipt':{'request_id':rid,'kind':'file','received_sha256':sha,'fixture_name':name,
                           'downloaded_bytes':len(qa.TXT),'download_http_status':200,'matching_rows':1,'type':18,
                           'author_is_self':True,'new_after_preflight':True,'original_sha256_matches':True,
                           'received_qa_copy_name':copy_name},
                'observer_exited':True,'observer':{'complete':True,'stop_reason':'STOP_FILE','errors':[],
                    'observed_start_epoch':1,'observed_end_epoch':4,'observation':{'complete':True,
                    'errors':[],'overflow':False,'new_visible_app_top_count':0,'app_foreground_events':0,
                    'foreground_unchanged':True,'cursor_unchanged':True}},
                'send_started_epoch':2,'receipt_confirmed_epoch':3,'peak_job_commit_bytes':1000000,
                'job_memory_limit':268435456,'elapsed_sec':12}
        return result,item,request_path

    def test_receipt_requires_unchanged_request_bytes(self):
        with tempfile.TemporaryDirectory() as folder,mock.patch.object(qa,'ROOT',Path(folder)):
            result,item,path=self._saved_fixture_receipt(Path(folder))
            self.assertTrue(qa.verified_receipt(result,item))
            path.write_text(path.read_text()+'\n')
            self.assertFalse(qa.verified_receipt(result,item))

    def test_receipt_cannot_pass_after_time_limit(self):
        with tempfile.TemporaryDirectory() as folder,mock.patch.object(qa,'ROOT',Path(folder)):
            result,item,_=self._saved_fixture_receipt(Path(folder))
            self.assertTrue(qa.verified_receipt(result,item))
            for elapsed in (50.001,-1,True,None,'12'):
                with self.subTest(elapsed=elapsed):
                    result['elapsed_sec']=elapsed
                    self.assertFalse(qa.verified_receipt(result,item))

    def test_main_redacts_non_runtime_exception_text(self):
        output=io.StringIO()
        with mock.patch.object(qa.sys,'argv',['self_qa.py','plan']),mock.patch.object(qa,'require_windows',side_effect=OSError('private-sensitive-path')),redirect_stdout(output):
            self.assertEqual(qa.main(),2)
        self.assertEqual(json.loads(output.getvalue())['reason'],'OSError')
        self.assertNotIn('private-sensitive-path',output.getvalue())

    def test_private_state_junction_attribute_is_rejected(self):
        tree=ast.parse((PACKAGE/'selfqa_config.py').read_text())
        fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='require_windows')
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            namespace={'os':SimpleNamespace(name='nt'),'struct':SimpleNamespace(calcsize=lambda _:8),
                       'sys':SimpleNamespace(version_info=(3,11)),'ROOT':root,
                       'SOURCE_ROOT':PACKAGE,'READER_ROOT':qa.READER_ROOT}
            exec(compile(ast.Module(body=[fn],type_ignores=[]),'private-state-check','exec'),namespace)
            original=Path.lstat
            def fake_lstat(path):
                stat=original(path)
                return SimpleNamespace(st_mode=stat.st_mode,st_file_attributes=0x400) if path==root else stat
            with mock.patch.object(Path,'lstat',fake_lstat):
                with self.assertRaisesRegex(RuntimeError,'PRIVATE_STATE_REPARSE_POINT'):namespace['require_windows']()

if __name__=='__main__':unittest.main()
