"""One self-fixture QA in the existing desktop session. No focus/clipboard/UI.

The owner authorized exactly a TXT and a PNG fixture with ordinary preview OFF.
The observer runs independently through receipt/download, inside our bounded
Job. Sending is once-only; receipt checks may poll without re-sending.
"""
import ctypes as C
import ctypes.wintypes as W
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time

from selfqa_config import ROOT, SOURCE_ROOT, READER_ROOT, PYTHON
SOURCES = {'attachment_send_win.py','attachment_receipt_win.py','attachment_runtime_preview.py',
           'attachment_window_probe.py','no_ui_window_watch.py','no_ui_observer_win.py',
           'attachment_no_ui_job_win.py','selfqa_config.py','self_qa.py','fixture_data.py'}


def read(path, maximum=16384):
    assert path.parent == ROOT and not path.is_symlink() and 0 < path.stat().st_size <= maximum
    return json.loads(path.read_text(encoding='utf-8-sig'))


def finish_verdict(send, receipt, observer, started, confirmed):
    photo_type = 2 if send.get('kind') == 'image' else 18
    return (send.get('send_attempted') is True
            and send.get('status') == 'DROP_QUEUED_RECEIPT_UNVERIFIED'
            and receipt.get('status') == 'QA_ATTACHMENT_DOWNLOADED_HASH_EXACT'
            and receipt.get('type') == photo_type
            and receipt.get('author_is_self') is True
            and receipt.get('new_after_preflight') is True
            and receipt.get('original_sha256_matches') is True
            and observer.get('complete') is True and observer.get('stop_reason') == 'STOP_FILE'
            and type(observer.get('observed_start_epoch')) in (int,float)
            and observer['observed_start_epoch'] <= started
            and confirmed is not None and observer.get('observed_end_epoch',0) >= confirmed)


def run(name):
    from reader_job import EXTENDED, LIMIT, run as bounded
    from room_reader import Reader
    assert re.fullmatch(r'attachment-no-ui-job-[a-f0-9]{32}\.json', name)
    job_request = read(ROOT/name)
    assert job_request['action'] in ('plan','send-and-verify')
    assert set(job_request['source_hashes']) == SOURCES
    for filename,digest in job_request['source_hashes'].items():
        assert hashlib.sha256((SOURCE_ROOT/filename).read_bytes()).hexdigest() == digest, 'QA_SOURCE_CHANGED'
    from reader_config import SOURCE_NAMES as READER_NAMES
    assert set(job_request['reader_source_hashes'])==READER_NAMES
    for filename,digest in job_request['reader_source_hashes'].items():
        assert hashlib.sha256((READER_ROOT/filename).read_bytes()).hexdigest()==digest,'READER_SOURCE_CHANGED'
    assert re.fullmatch(r'attachment-no-ui-manifest-[a-f0-9]{32}\.json',job_request['manifest'])
    manifest_path=ROOT/job_request['manifest']
    assert hashlib.sha256(manifest_path.read_bytes()).hexdigest()==job_request['manifest_sha256']
    manifest=read(manifest_path)
    assert manifest['destination']=='SELF_CHAT_ONLY' and (job_request['action']=='plan' or manifest['owner_authorized_no_ui_fixtures'] is True)
    assert len(manifest['requests'])==2 and {i['kind'] for i in manifest['requests']}=={'file','image'}
    qid=job_request['qa_request_id'];assert re.fullmatch('[a-f0-9]{32}',qid)
    item=next(i for i in manifest['requests'] if i['request_id']==qid)
    request_path=ROOT/('attachment-send-'+qid+'.json')
    assert hashlib.sha256(request_path.read_bytes()).hexdigest()==item['request_sha256']
    request=read(request_path)
    assert request['request_id']==qid and request['kind']==item['kind']
    assert request['execute'] is (job_request['action']=='send-and-verify')
    assert request.get('owner_authorized_self_qa') is (job_request['action']=='send-and-verify')
    assert request['require_no_ui'] is True
    assert request.get('owner_approved_preview_ui') is False
    assert request['destination']=='SELF_CHAT_ONLY'
    job_id=name.removeprefix('attachment-no-ui-job-').removesuffix('.json')
    assert request['observer_stem']=='headless-observer-'+job_id
    destination=ROOT/(name[:-5]+'-'+job_request['action']+'-result.json');assert not destination.exists()
    k=C.WinDLL('kernel32',use_last_error=True)
    k.GetCurrentProcess.restype=W.HANDLE;k.CreateJobObjectW.restype=W.HANDLE
    k.SetInformationJobObject.argtypes=[W.HANDLE,C.c_int,C.c_void_p,W.DWORD]
    k.AssignProcessToJobObject.argtypes=[W.HANDLE,W.HANDLE]
    k.QueryInformationJobObject.argtypes=[W.HANDLE,C.c_int,C.c_void_p,W.DWORD,C.c_void_p]
    job=k.CreateJobObjectW(None,None);assert job
    limit=EXTENDED();limit.basic.flags=0x2000|0x200|0x100;limit.process=limit.job=LIMIT
    assert k.SetInformationJobObject(job,9,C.byref(limit),C.sizeof(limit))
    assert k.AssignProcessToJobObject(job,k.GetCurrentProcess())
    timer=threading.Timer(50,lambda:os._exit(124));timer.daemon=True;timer.start()
    started=time.monotonic();observer=None;observer_log=None;reader=None;confirmed=None
    result={'status':'BLOCKED_BEFORE_SEND','request_id':qid,'action':job_request['action'],
            'kind':request['kind'],'send_attempted':False,'automatic_retry_allowed':False,
            'focus_calls':0,'clipboard_calls':0,'settings_changed':False,
            'job_memory_limit':LIMIT,'timeout_sec':50}
    obs_stem=request['observer_stem'];send_started=None
    try:
        from attachment_send_win import run as send, preview_gate
        from attachment_runtime_preview import inspect as preview
        from no_ui_observer_win import clean
        reader=Reader();result['app_private_before']=reader.guard()
        preview_gate(request,preview())
        if job_request['action']=='plan':
            result.update(status='PREFLIGHT_RETURNED',plan=send(dict(request,execute=False)))
        else:
            baseline=ROOT/('observer-self-'+job_id+'.json')
            cli=READER_ROOT/'kakao_read_win.py'
            e=bounded([PYTHON,str(cli),'self','--limit','3'],baseline,20)
            assert e['exit']==0 and not e['timeout'],'OBSERVER_SELF_IDENTITY_FAILED'
            own=read(baseline,131072)['result']
            assert own['status']=='MESSAGES_READ' and own['room']['type']=='MemoChat' and own['messages']
            assert all(m['author_is_self'] for m in own['messages'])
            from attachment_window_probe import inspect as window_state
            from attachment_send_win import validate_window
            target=validate_window(window_state({'title':own['room']['title'],'room_type':'MemoChat','all_author_self':True}),True)
            obs_request={'pid':reader.pid,'created_at_filetime':str(reader.created_at_filetime),
                         'source_sha256':job_request['source_hashes']['no_ui_window_watch.py'],'seconds':35,
                         'self_hwnd':target['hwnd']}
            with (ROOT/(obs_stem+'.json')).open('x',encoding='utf8') as f:json.dump(obs_request,f)
            observer_log=(ROOT/(obs_stem+'-log.txt')).open('xb')
            observer=subprocess.Popen([PYTHON,str(SOURCE_ROOT/'no_ui_observer_win.py'),obs_stem+'.json'],
                cwd=ROOT,stdout=observer_log,stderr=subprocess.STDOUT,creationflags=0x08000000)
            k.IsProcessInJob.argtypes=[W.HANDLE,W.HANDLE,C.POINTER(W.BOOL)]
            inherited=W.BOOL()
            assert k.IsProcessInJob(W.HANDLE(int(observer._handle)),job,C.byref(inherited)) and inherited.value,'OBSERVER_NOT_IN_MEMORY_JOB'
            ready_path=ROOT/(obs_stem+'-ready.json');deadline=time.monotonic()+6
            while not ready_path.exists() and time.monotonic()<deadline and observer.poll() is None:time.sleep(.03)
            ready=read(ready_path)
            assert ready.get('status')=='READY' and clean(ready.get('observation') or {}),'CONTINUOUS_OBSERVER_NOT_READY'
            state_path=ROOT/(obs_stem+'-state.json');deadline=time.monotonic()+1
            while not state_path.exists() and time.monotonic()<deadline:time.sleep(.02)
            assert state_path.exists(),'CONTINUOUS_OBSERVER_NO_HEARTBEAT'
            send_started=time.time()
            result['send']=send(request)
            result['send_attempted']=result['send']['send_attempted']
            deadline=time.monotonic()+18;attempts=[]
            for attempt in range(3):
                if time.monotonic()+10>deadline:break
                out=ROOT/('attachment-no-ui-receipt-'+job_id+'-'+str(attempt)+'.json')
                execution=bounded([PYTHON,str(SOURCE_ROOT/'attachment_receipt_win.py'),qid,'--download-qa'],out,10)
                receipt=read(out,131072) if execution['exit']==0 and not execution['timeout'] else {'status':'RECEIPT_HELPER_FAILED'}
                attempts.append({'execution':execution,'result':receipt})
                result['receipt']=receipt
                if receipt.get('status')!='RECEIPT_NOT_FOUND':break
                time.sleep(.4)
            result['receipt_attempts']=attempts
            if result.get('receipt',{}).get('original_sha256_matches') is True:confirmed=time.time()
            with (ROOT/(obs_stem+'-stop.json')).open('x',encoding='utf8') as f:json.dump({'reason':'RECEIPT_CHECK_ENDED'},f)
            observer.wait(timeout=4)
            result['observer']=read(ROOT/(obs_stem+'-result.json'),131072)
            result['send_started_epoch']=send_started;result['receipt_confirmed_epoch']=confirmed
            result['status']='HEADLESS_SELF_ATTACHMENT_E2E_PASS' if finish_verdict(
                result['send'],result.get('receipt',{}),result['observer'],send_started,confirmed) else 'SELF_ATTACHMENT_QA_INCOMPLETE_NO_RETRY'
        result['app_private_after']=reader.guard()
    except Exception as error:
        result['status']='BLOCKED_BEFORE_SEND'
        result['reason']=str(error) if isinstance(error,(AssertionError,RuntimeError)) else type(error).__name__
        ledger=ROOT/('attachment-send-'+qid+'-ledger.json')
        if ledger.exists():result.update(status='UNCERTAIN_INSPECT_SAME_LEDGER_NO_RETRY',send_attempted='unknown')
    finally:
        if observer:
            stop=ROOT/(obs_stem+'-stop.json')
            if not stop.exists():
                with stop.open('x',encoding='utf8') as f:json.dump({'reason':'PARENT_CLEANUP'},f)
            try:observer.wait(timeout=4)
            except subprocess.TimeoutExpired:observer.kill();observer.wait(timeout=2);result['observer_forced_stop']=True
            obs_result=ROOT/(obs_stem+'-result.json')
            if obs_result.exists() and 'observer' not in result:result['observer']=read(obs_result,131072)
            result['observer_exited']=observer.poll() is not None
        if observer_log:observer_log.close()
        if reader:reader.close()
        peak=EXTENDED();assert k.QueryInformationJobObject(job,9,C.byref(peak),C.sizeof(peak),None)
        result.update(peak_job_commit_bytes=peak.peakjob,elapsed_sec=round(time.monotonic()-started,3))
        with destination.open('x',encoding='utf8') as f:json.dump(result,f)
        timer.cancel()


if __name__=='__main__':
    assert len(sys.argv)==2
    run(sys.argv[1])
