#!/usr/bin/env python3
"""Read one Windows KakaoTalk room without opening or controlling its window.

Run on Windows with the user's own logged-in KakaoTalk process.
Uses no SSH, interactive-session worker, daemon, clipboard or send operation.
"""
import sys as _source_sys
if __name__=='__main__' and not getattr(_source_sys,'_kakao_verified_source_bootstrap',None):
    if not getattr(_source_sys.flags,'safe_path',False):_source_sys.path=_source_sys.path[1:]
    import hashlib as _source_hashlib, pathlib as _source_pathlib, types as _source_types
    _source_script=_source_pathlib.Path(__file__).resolve()
    _source_helper=_source_script.with_name('reader_source.py')
    if not 0<_source_helper.stat().st_size<=1048576:raise RuntimeError('READER_SOURCE_BOOTSTRAP_INVALID')
    with _source_helper.open('rb') as _source_stream:_source_body=_source_stream.read(1048577)
    if len(_source_body)>1048576:raise RuntimeError('READER_SOURCE_BOOTSTRAP_INVALID')
    _source_module=_source_types.ModuleType('reader_source');_source_module.__file__=str(_source_helper)
    _source_module.__verified_source_sha256__=_source_hashlib.sha256(_source_body).hexdigest()
    _source_sys.modules['reader_source']=_source_module
    exec(compile(_source_body,str(_source_helper),'exec',dont_inherit=True,optimize=0),_source_module.__dict__)
    _source_module.bootstrap_current(_source_script,_source_sys.argv[1:])
    raise SystemExit(0)
import argparse
import hashlib
import json
import os
import platform
import struct
import sys
from pathlib import Path
import uuid

from reader_config import ROOT,SOURCE_NAMES,state_root,installation_report
from reader_queries import MAX_HOURS,query_spec

def read(args):
    from reader_rpc import process as rpc
    STATE=state_root()
    if args.command=='resume':
        transport=args.request_id
        assert transport and len(transport)==32 and all(x in '0123456789abcdef' for x in transport),'REQUEST_ID_REQUIRED'
        receipt=STATE/(transport+'.json')
        record=json.loads(receipt.read_text(encoding='utf8'))
        response=rpc({'action':'fetch','request_id':transport})
        assert response['request']==record['request'],'RESUME_REQUEST_MISMATCH'
        record.update(execution=response['execution'],outer_execution=response['outer_execution'],
                      result=response['result'],resumed_without_reexecution=True)
        save(receipt,record,replace=True)
        record['receipt_path']=str(receipt)
        return record
    source=ROOT/'room_reader.py'
    hashes={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in SOURCE_NAMES}
    argv=[args.command]
    if args.name is not None:argv+=['--name',args.name]
    argv+=['--hours',str(args.hours),'--limit',str(args.limit)]
    if args.after_id is not None:argv+=['--after-id',str(args.after_id)]
    for key in ('before_id','since','until','query','cursor'):
        value=getattr(args,key,None)
        if value is not None:argv+=['--'+key.replace('_','-'),str(value)]
    argv+=['--key-route',args.key_route]
    if getattr(args,'account_token',None):argv+=['--account-token',args.account_token]
    if getattr(args,'candidate_x86',False):argv+=['--candidate-x86']
    transport=uuid.uuid4().hex
    request={'source_sha256':hashes[source.name],'source_hashes':hashes,'args':argv}
    record={'request_id':transport,'request':request,'source_hashes':hashes,
            'execution':{},'result':{'status':'BLOCKED','reason':'RPC_RESULT_PENDING'}}
    STATE.mkdir(parents=True,exist_ok=True,mode=0o700)
    receipt=STATE/(transport+'.json')
    save(receipt,record)
    try:
        response=rpc({'action':'execute','request_id':transport,'request':request})
        assert response['request']==request,'RPC_REQUEST_MISMATCH'
        record.update(execution=response['execution'],outer_execution=response['outer_execution'],result=response['result'])
    except (RuntimeError,AssertionError) as exc:
        record['result']={'status':'BLOCKED','reason':str(exc),'resume_same_request_id':transport}
    save(receipt,record,replace=True)
    record['receipt_path']=str(receipt)
    return record

def save(path,record,replace=False):
    target=path.with_suffix('.pending') if replace else path
    with target.open('x',encoding='utf8') as f:
        os.chmod(target,0o600);json.dump(record,f,ensure_ascii=False,indent=2)
    if replace:target.replace(path)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['doctor','accounts','schema','rooms','self','messages','search','resume'])
    parser.add_argument('--request-id',help='resume: fetch an existing read result without re-execution')
    parser.add_argument('--account-token',help='Explicit opaque account token from accounts; never auto-select a backup')
    parser.add_argument('--candidate-x86',action='store_true',help='Explicit 26.9.1 x86 candidate probe; not stable support')
    parser.add_argument('--name',help='Room search text, or exact title for messages')
    parser.add_argument('--hours',type=int,default=24)
    parser.add_argument('--limit',type=int,default=20)
    parser.add_argument('--after-id',type=int)
    parser.add_argument('--before-id',type=int)
    parser.add_argument('--since',help='Inclusive date/time, KST when timezone omitted')
    parser.add_argument('--until',help='Exclusive date/time, KST when timezone omitted')
    parser.add_argument('--query',help='Literal text, including percent/underscore/backslash')
    parser.add_argument('--cursor',help='Continue same account, room and filters')
    parser.add_argument('--key-route',choices=['codec','envelope'],default='envelope',
                        help='envelope: validated v2 derivation; codec: live-codec diagnostic')
    args=parser.parse_args()
    if args.command=='accounts':
        try:
            if os.name!='nt':raise RuntimeError('WINDOWS_REQUIRED')
            from reader_accounts import inventory_accounts
            accounts=inventory_accounts(Path(os.environ['LOCALAPPDATA'])/'Kakao'/'KakaoTalk'/'users')
            print(json.dumps({'status':'ACCOUNT_METADATA_READ','accounts':accounts,'app_memory_read':False,
                'database_contents_read':False,'automatic_account_selection':False,'send_attempted':False}))
            return 0
        except Exception as exc:
            print(json.dumps({'status':'BLOCKED','reason':str(exc) if isinstance(exc,RuntimeError) else 'ACCOUNT_METADATA_UNAVAILABLE'}))
            return 2
    if args.command=='doctor':
        try:
            import importlib.metadata
            from room_reader import APP,EXPECTED,READER_SUPPORTED,X86_CANDIDATES,x86_app
            platform_ok=os.name=='nt' and struct.calcsize('P')==8 and sys.version_info>=(3,11)
            dependency=importlib.metadata.version('cryptography')
            alternate=Path(os.environ.get('ProgramFiles(x86)',r'C:\Program Files (x86)'))/'Kakao'/'KakaoTalk'/'KakaoTalk.exe'
            report=installation_report(APP,READER_SUPPORTED,EXPECTED,fallback=alternate)
            candidate_path=x86_app()
            candidate=installation_report(candidate_path,{},EXPECTED)
            candidate_ok=candidate['installation_sha256'] in X86_CANDIDATES and candidate['app_architecture']=='x86'
            report['candidate_probe_available']=candidate_ok
            if args.candidate_x86:
                report=candidate
                report.update(candidate_probe_available=candidate_ok,candidate_only=True,
                    reason=None if candidate_ok else 'CANDIDATE_INSTALLATION_CHANGED',
                    next_action='Run an owner-approved candidate probe; actual x86 reading is not yet established.',
                    matched_app_version=X86_CANDIDATES.get(candidate['installation_sha256']),
                    supported_installation=False,reader_supported=False,
                    room_open_supported=False,self_attachment_supported=False)
            if not platform_ok:
                report.update(reason='WINDOWS_X64_PYTHON_REQUIRED',
                    next_action='Run Python 3.11 or newer x64 on Windows.',
                    supported_installation=False,reader_supported=False,
                    room_open_supported=False,self_attachment_supported=False)
            ready=platform_ok and (candidate_ok if args.candidate_x86 else report['supported_installation'])
            print(json.dumps({'status':('CANDIDATE_READY' if args.candidate_x86 else 'READY') if ready else 'BLOCKED',
                'python':platform.python_version(),'windows_x64':platform_ok,
                'cryptography':dependency,'app_launched':False,
                'app_data_read':False,'settings_changed':False,'send_supported':False,**report}))
            return 0 if ready else 2
        except Exception:
            print(json.dumps({'status':'BLOCKED','reason':'READINESS_CHECK_FAILED','settings_changed':False}))
            return 2
    if not 1<=args.limit<=100 or not 1<=args.hours<=MAX_HOURS:parser.error('limit: 1..100; hours: 1..87600')
    if args.candidate_x86 and args.key_route!='envelope':parser.error('candidate x86 permits the envelope route only')
    if args.account_token and (len(args.account_token)!=64 or any(c not in '0123456789abcdef' for c in args.account_token)):parser.error('account token: 64 lowercase hexadecimal characters')
    try:query_spec(args)
    except AssertionError as exc:parser.error(str(exc))
    if args.command in ('rooms','messages','search') and not args.name:parser.error('--name is required')
    if args.command=='search' and not args.query:parser.error('search requires --query')
    if args.cursor and len(args.cursor)>2048:parser.error('cursor length limit')
    if args.name is not None and not 1<=len(args.name)<=100:parser.error('room name length: 1..100')
    if args.after_id is not None and args.after_id<=0:parser.error('--after-id must be positive')
    if args.command=='resume' and not args.request_id:parser.error('resume requires --request-id')
    try:
        if hasattr(sys.stdout,'reconfigure'):sys.stdout.reconfigure(encoding='utf8')
        record=read(args);print(json.dumps(record,ensure_ascii=False,indent=2))
        return 0 if record['execution'].get('exit')==0 and not record['execution'].get('timeout') and record['result'].get('status') in ('SCHEMA_READ','ROOMS_READ','MESSAGES_READ','SEARCH_READ') else 2
    except Exception as exc:
        print(json.dumps({'status':'BLOCKED','reason':str(exc),'send_attempted':False},ensure_ascii=False))
        return 2

if __name__=='__main__':raise SystemExit(main())
