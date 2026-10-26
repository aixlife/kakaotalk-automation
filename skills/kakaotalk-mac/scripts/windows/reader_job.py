"""Bounded Windows reader runner. No daemon, GUI or security changes."""
import ctypes as C
import ctypes.wintypes as W
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time

from reader_config import ROOT,SOURCE_NAMES,MEMORY_LIMIT,state_root
LIMIT=MEMORY_LIMIT

class BASIC(C.Structure):
    _fields_=[('a',C.c_longlong),('b',C.c_longlong),('flags',W.DWORD),
              ('min',C.c_size_t),('max',C.c_size_t),('active',W.DWORD),
              ('affinity',C.c_size_t),('priority',W.DWORD),('scheduling',W.DWORD)]
class IO(C.Structure):
    _fields_=[('counts',C.c_ulonglong*6)]
class EXTENDED(C.Structure):
    _fields_=[('basic',BASIC),('io',IO),('process',C.c_size_t),('job',C.c_size_t),
              ('peakprocess',C.c_size_t),('peakjob',C.c_size_t)]

def run(argv,output,timeout):
    k=C.WinDLL('kernel32',use_last_error=True)
    k.CreateJobObjectW.restype=W.HANDLE
    k.SetInformationJobObject.argtypes=[W.HANDLE,C.c_int,C.c_void_p,W.DWORD]
    k.AssignProcessToJobObject.argtypes=[W.HANDLE,W.HANDLE]
    k.CloseHandle.argtypes=[W.HANDLE]
    k.QueryInformationJobObject.argtypes=[W.HANDLE,C.c_int,C.c_void_p,W.DWORD,C.c_void_p]
    job=k.CreateJobObjectW(None,None);assert job,'JOB_CREATE_FAILED'
    child=None;started=time.monotonic();timed_out=False;peak=EXTENDED()
    try:
        limits=EXTENDED();limits.basic.flags=0x2000|0x200|0x100
        limits.process=limits.job=LIMIT
        assert k.SetInformationJobObject(job,9,C.byref(limits),C.sizeof(limits)),'JOB_LIMIT_FAILED'
        with output.open('xb') as stream:
            child=subprocess.Popen(argv,cwd=ROOT,stdout=stream,stderr=subprocess.STDOUT,
                                   creationflags=0x08000000|4)
            assert k.AssignProcessToJobObject(job,W.HANDLE(int(child._handle))),'JOB_ASSIGN_FAILED'
            nt=C.WinDLL('ntdll');nt.NtResumeProcess.argtypes=[W.HANDLE]
            assert nt.NtResumeProcess(W.HANDLE(int(child._handle)))==0,'OWN_CHILD_RESUME_FAILED'
            try:child.wait(timeout=timeout)
            except subprocess.TimeoutExpired:timed_out=True
            finally:k.QueryInformationJobObject(job,9,C.byref(peak),C.sizeof(peak),None)
    finally:
        k.CloseHandle(job)
        if child:
            try:child.wait(timeout=3)
            except subprocess.TimeoutExpired:child.kill();child.wait(timeout=3)
    return {'exit':child.returncode if child else None,'timeout':timed_out,
            'elapsed_sec':round(time.monotonic()-started,3),
            'job_memory_limit':LIMIT,'peak_job_commit_bytes':peak.peakjob}

def main():
    assert len(sys.argv)==2,'ONE_REQUEST_REQUIRED'
    name=sys.argv[1]
    if name in ('--test-memory','--test-timeout'):
        label=name.removeprefix('--test-');output=state_root()/('reader-guard-'+label+'.log')
        code='bytearray(300*1024*1024)' if label=='memory' else 'import time;time.sleep(10)'
        result=run([sys.executable,'-c',code],output,2)
        result['guard_test']=label
        result['passed']=(result['exit']!=0 and not result['timeout']) if label=='memory' else result['timeout']
        print(json.dumps(result));return 0 if result['passed'] else 2
    assert re.fullmatch(r'reader-[0-9a-f]{32}\.json',name),'INVALID_REQUEST_NAME'
    request_path=state_root()/name;assert request_path.stat().st_size<8192,'REQUEST_TOO_LARGE'
    request=json.loads(request_path.read_text(encoding='utf-8-sig'))
    source=ROOT/'room_reader.py'
    assert hashlib.sha256(source.read_bytes()).hexdigest()==request['source_sha256'],'READER_SOURCE_CHANGED'
    hashes=request.get('source_hashes',{})
    expected=SOURCE_NAMES
    assert set(hashes)==expected,'READER_DEPENDENCY_HASHES_REQUIRED'
    for name,digest in hashes.items():
        assert re.fullmatch('[0-9a-f]{64}',digest) and hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==digest,'READER_DEPENDENCY_CHANGED'
    args=request['args']
    assert isinstance(args,list) and 1<=len(args)<=26 and args[0] in ('schema','rooms','self','messages','search'),'ACTION_NOT_ALLOWED'
    assert all(isinstance(a,str) and len(a)<=2048 for a in args),'INVALID_ARGUMENTS'
    stem=request_path.stem;output=state_root()/(stem+'-output.json');receipt=state_root()/(stem+'-receipt.json')
    assert not output.exists() and not receipt.exists(),'REQUEST_ALREADY_EXECUTED'
    result=run([sys.executable,str(source)]+args,output,45)
    with receipt.open('x',encoding='utf8') as f:json.dump(result,f)
    print(json.dumps(result));return 0

if __name__=='__main__':raise SystemExit(main())
