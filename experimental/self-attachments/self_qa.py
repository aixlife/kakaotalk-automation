#!/usr/bin/env python3
"""Experimental fixed self-chat TXT/PNG QA. plan never sends; execute is explicit."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import uuid
from selfqa_config import ROOT,SOURCE_ROOT,READER_ROOT,PYTHON,require_windows
from fixture_data import TXT,PNG

SOURCE_NAMES=frozenset(('attachment_send_win.py','attachment_receipt_win.py',
    'attachment_runtime_preview.py','attachment_window_probe.py','no_ui_window_watch.py',
    'no_ui_observer_win.py','attachment_no_ui_job_win.py','selfqa_config.py','self_qa.py','fixture_data.py'))
FIXTURES=(('file','attachment-qa-8a73e2e535e7.txt',TXT),
          ('image','attachment-qa-8a73e2e535e7.png',PNG))

@contextmanager
def serial_lock():
    import msvcrt
    path=ROOT/'serial.lock'
    if path.is_symlink():raise RuntimeError('PRIVATE_LOCK_SYMLINK')
    with path.open('a+b') as stream:
        stream.seek(0,2)
        if stream.tell()==0:stream.write(b'0');stream.flush()
        stream.seek(0)
        try:msvcrt.locking(stream.fileno(),msvcrt.LK_NBLCK,1)
        except OSError:raise RuntimeError('ANOTHER_SELF_QA_RUNNING')
        try:yield
        finally:
            stream.seek(0);msvcrt.locking(stream.fileno(),msvcrt.LK_UNLCK,1)

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def load(path,maximum=262144):
    if path.parent!=ROOT or path.is_symlink() or not 0<path.stat().st_size<=maximum:
        raise RuntimeError('PRIVATE_RECORD_INVALID')
    return json.loads(path.read_text(encoding='utf8'))

def write(name,value):
    path=ROOT/name
    if path.parent!=ROOT or path.is_symlink():raise RuntimeError('PRIVATE_RECORD_PATH_INVALID')
    with path.open('x',encoding='utf8') as stream:
        json.dump(value,stream,ensure_ascii=True,indent=2)
    return path

def current_hashes():
    from reader_config import SOURCE_NAMES as READER_NAMES
    return ({n:digest(SOURCE_ROOT/n) for n in SOURCE_NAMES},
            {n:digest(READER_ROOT/n) for n in READER_NAMES})

def new_bundle(approved=False,parent_plan=None):
    if type(approved) is not bool:raise RuntimeError('APPROVAL_MUST_BE_BOOLEAN')
    require_windows()
    own,reader=current_hashes();ident=uuid.uuid4().hex;items=[]
    for kind,name,body in FIXTURES:
        target=ROOT/name
        if target.exists():
            if target.is_symlink() or target.read_bytes()!=body:raise RuntimeError('FIXED_FIXTURE_CHANGED')
        else:
            with target.open('xb') as stream:stream.write(body)
        sha=hashlib.sha256(body).hexdigest()
        if approved and (ROOT/('attachment-content-'+sha+'-once.json')).exists():
            raise RuntimeError('CONTENT_ALREADY_CLAIMED_NO_RETRY')
        rid=uuid.uuid4().hex;job=uuid.uuid4().hex
        req={'request_id':rid,'execute':approved,'owner_authorized_self_qa':approved,
             'kind':kind,'destination':'SELF_CHAT_ONLY',
             'file_name':name,'file_sha256':sha,'file_bytes':len(body),
             'require_no_ui':True,'owner_approved_preview_ui':False,
             'observer_stem':'headless-observer-'+job}
        if kind=='image':req.update(image_width=733,image_height=419)
        path=write('attachment-send-'+rid+'.json',req)
        items.append({'kind':kind,'request_id':rid,'job_id':job,'request_sha256':digest(path)})
    manifest={'run_id':ident,'destination':'SELF_CHAT_ONLY',
              'owner_authorized_no_ui_fixtures':approved,'requests':items,
              'parent_plan_id':parent_plan,'source_hashes':own,'reader_source_hashes':reader}
    path=write('attachment-no-ui-manifest-'+ident+'.json',manifest)
    bundle={'id':ident,'manifest':path.name,'manifest_sha256':digest(path),
            'source_hashes':own,'reader_source_hashes':reader,'requests':items,
            'owner_approved':approved,'parent_plan_id':parent_plan,'automatic_retry_allowed':False}
    write('bundle-'+ident+'.json',bundle)
    return bundle

def run_job(bundle,item,action):
    if current_hashes()!=(bundle['source_hashes'],bundle['reader_source_hashes']):
        raise RuntimeError('SOURCE_CHANGED_AFTER_PLAN')
    name='attachment-no-ui-job-'+item['job_id']+'.json'
    write(name,{'action':action,'source_hashes':bundle['source_hashes'],
                'reader_source_hashes':bundle['reader_source_hashes'],
                'manifest':bundle['manifest'],'manifest_sha256':bundle['manifest_sha256'],
                'qa_request_id':item['request_id']})
    result_path=ROOT/(name[:-5]+'-'+action+'-result.json')
    if result_path.exists():raise RuntimeError('RESULT_EXISTS_NO_RELAUNCH')
    # The child owns its complete 256MiB/50s Job, including observer/reader children.
    # A unique job file is the launch claim; timeouts never relaunch it.
    log=ROOT/(name[:-5]+'-launch.log')
    with log.open('xb') as output:
        child=subprocess.Popen([PYTHON,str(SOURCE_ROOT/'attachment_no_ui_job_win.py'),name],
            cwd=ROOT,stdout=output,stderr=subprocess.STDOUT,creationflags=0x08000000)
        try:child.wait(timeout=58)
        except subprocess.TimeoutExpired:
            child.kill();child.wait(timeout=3)
            raise RuntimeError('JOB_TIMEOUT_INSPECT_SAME_RESULT_NO_RETRY')
    if not result_path.exists():raise RuntimeError('RESULT_MISSING_INSPECT_SAME_JOB_NO_RETRY')
    return load(result_path)

def verified_receipt(result,item):
    """Independent final predicate binds request, downloaded bytes and observation."""
    try:
        send,a,o=result['send'],result['receipt'],result['observer'];z=o['observation']
        kind=item['kind'];rid=item['request_id']
        request_path=ROOT/('attachment-send-'+rid+'.json')
        if digest(request_path)!=item['request_sha256']:return False
        req=load(request_path)
        if not (result['status']=='HEADLESS_SELF_ATTACHMENT_E2E_PASS' and result['send_attempted'] is True
            and result['request_id']==send['request_id']==a['request_id']==rid
            and send['kind']==a['kind']==kind and send['file_sha256']==a['received_sha256']==req['file_sha256']
            and a['fixture_name']==req['file_name'] and a['downloaded_bytes']==req['file_bytes']
            and a['download_http_status']==200 and a['matching_rows']==1
            and a['type']==(18 if kind=='file' else 2) and a['author_is_self'] is True
            and a['new_after_preflight'] is True and a['original_sha256_matches'] is True
            and result['observer_exited'] is True and not result.get('observer_forced_stop')
            and o['complete'] is True and o['stop_reason']=='STOP_FILE' and not o['errors']
            and o['observed_start_epoch']<=result['send_started_epoch']<=result['receipt_confirmed_epoch']<=o['observed_end_epoch']
            and z['complete'] is True and not z['errors'] and not z['overflow']
            and z['new_visible_app_top_count']==z['app_foreground_events']==0
            and z['foreground_unchanged'] is True and z['cursor_unchanged'] is True
            and result['peak_job_commit_bytes']<result['job_memory_limit']==268435456
            and type(result['elapsed_sec']) in (int,float) and 0<=result['elapsed_sec']<=50):return False
        name='attachment-received-'+rid+('.txt' if kind=='file' else '.png')
        copy=ROOT/name
        return (a['received_qa_copy_name']==name and not copy.is_symlink()
                and copy.stat().st_size==req['file_bytes'] and digest(copy)==req['file_sha256'])
    except (KeyError,TypeError,ValueError,OSError):return False

def summarize(result):
    return {k:result[k] for k in ('status','reason','send_attempted','elapsed_sec',
        'peak_job_commit_bytes','observer_exited') if k in result}

def plan():
    bundle=new_bundle();rows=[]
    for item in bundle['requests']:
        result=run_job(bundle,item,'plan')
        rows.append({'kind':item['kind'],'plan_status':result.get('plan',{}).get('status'),**summarize(result)})
        if (result.get('status')!='PREFLIGHT_RETURNED'
                or rows[-1]['plan_status']!='PREFLIGHT_READY_NOT_EXECUTED'
                or result.get('send_attempted') is not False):break
    ready=len(rows)==2 and all(x['status']=='PREFLIGHT_RETURNED'
        and x['plan_status']=='PREFLIGHT_READY_NOT_EXECUTED' and x.get('send_attempted') is False for x in rows)
    summary={'status':'PLAN_READY_NO_SEND' if ready else 'PLAN_BLOCKED_NO_SEND',
             'plan_id':bundle['id'],'send_attempted':False,'results':rows}
    write('plan-'+bundle['id']+'-summary.json',summary)
    return summary

def execute(plan_id,approved):
    require_windows()
    if approved is not True:raise RuntimeError('EXPLICIT_SELF_TXT_PNG_APPROVAL_REQUIRED')
    if not re.fullmatch('[a-f0-9]{32}',plan_id or ''):raise RuntimeError('PLAN_ID_REQUIRED')
    prior=load(ROOT/('bundle-'+plan_id+'.json'));summary=load(ROOT/('plan-'+plan_id+'-summary.json'))
    if prior['owner_approved'] or summary['status']!='PLAN_READY_NO_SEND':raise RuntimeError('SUCCESSFUL_UNEXECUTED_PLAN_REQUIRED')
    if current_hashes()!=(prior['source_hashes'],prior['reader_source_hashes']):raise RuntimeError('SOURCE_CHANGED_AFTER_PLAN')
    # This durable claim is intentionally never erased, even on a pre-send failure.
    write('plan-'+plan_id+'-execute-once.json',{'approved_self_txt_png':True,'automatic_retry_allowed':False})
    bundle=new_bundle(approved=True,parent_plan=plan_id);rows=[]
    for item in bundle['requests']:
        result=run_job(bundle,item,'send-and-verify')
        passed=verified_receipt(result,item)
        rows.append({'kind':item['kind'],'independent_receipt_pass':passed,**summarize(result)})
        if not passed:break
    summary={'status':'TWO_SELF_ATTACHMENTS_VERIFIED' if len(rows)==2 and all(x['independent_receipt_pass'] for x in rows) else 'INCOMPLETE_NO_RETRY',
             'execution_id':bundle['id'],'parent_plan_id':plan_id,'results':rows,'automatic_retry_allowed':False}
    write('execution-'+bundle['id']+'-summary.json',summary)
    return summary

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest='command',required=True)
    commands.add_parser('plan',help='Inspect only; never send or open a chat window')
    send=commands.add_parser('execute-self-qa',help='Adds exactly one fixed TXT and one fixed PNG to your self chat')
    send.add_argument('--plan-id',required=True)
    send.add_argument('--approve-self-chat-txt-and-png',action='store_true',required=True)
    show=commands.add_parser('show',help='Read an existing local summary only; never retry')
    show.add_argument('--id',required=True);show.add_argument('--execution',action='store_true')
    args=parser.parse_args()
    try:
        require_windows()
        with serial_lock():
            if args.command=='plan':result=plan()
            elif args.command=='execute-self-qa':result=execute(args.plan_id,args.approve_self_chat_txt_and_png)
            else:
                if not re.fullmatch('[a-f0-9]{32}',args.id):raise RuntimeError('ID_INVALID')
                result=load(ROOT/(('execution-' if args.execution else 'plan-')+args.id+'-summary.json'))
        print(json.dumps(result,ensure_ascii=True,indent=2))
        return 0 if result['status'] in ('PLAN_READY_NO_SEND','TWO_SELF_ATTACHMENTS_VERIFIED') else 2
    except Exception as exc:
        print(json.dumps({'status':'BLOCKED_OR_INCOMPLETE_NO_RETRY',
                          'reason':str(exc) if isinstance(exc,RuntimeError) else type(exc).__name__,
                          'automatic_retry_allowed':False},ensure_ascii=True))
        return 2

if __name__=='__main__':raise SystemExit(main())
