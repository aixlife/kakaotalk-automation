"""One-shot Windows reader RPC. No daemon, GUI, send or security changes."""
import hashlib,json,re
from pathlib import Path
import sys
from reader_config import ROOT,SOURCE_NAMES,state_root
SOURCES=SOURCE_NAMES

def load(path):
    assert path.is_file() and 0<path.stat().st_size<=2097152,'RPC_RESPONSE_NOT_AVAILABLE'
    return json.loads(path.read_text(encoding='utf-8-sig'))

def process(payload):
    ident=payload['request_id'];assert re.fullmatch('[0-9a-f]{32}',ident),'RPC_REQUEST_ID'
    assert payload['action'] in ('execute','fetch'),'READ_ONLY_RPC_ACTION_REQUIRED'
    state=state_root();stem='reader-'+ident;request_path=state/(stem+'.json')
    if payload['action']=='execute':
        request=payload['request'];hashes=request['source_hashes']
        assert set(hashes)==SOURCES,'RPC_SOURCE_SET'
        for name,digest in hashes.items():
            assert re.fullmatch('[0-9a-f]{64}',digest) and hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==digest,'RPC_SOURCE_CHANGED'
        encoded=json.dumps(request);assert len(encoded.encode())<8192,'RPC_REQUEST_LIMIT'
        with request_path.open('x',encoding='utf8') as f:f.write(encoded)
        from reader_job import run
        # The full reader runner + decryptor tree shares this outer 256MiB Job.
        # Its inner reader Job and the 40-second source guard remain enabled.
        execution=run([sys.executable,str(ROOT/'reader_job.py'),request_path.name],
                      state/(stem+'-rpc-output.json'),50)
        with (state/(stem+'-rpc-receipt.json')).open('x') as f:json.dump(execution,f)
    request=load(request_path)
    outer_path=state/(stem+'-rpc-receipt.json');outer=load(outer_path) if outer_path.exists() else None
    if outer and (outer['timeout'] or outer['exit']!=0):
        return {'request_id':ident,'request':request,'outer_execution':outer,'execution':outer,
                'result':{'status':'BLOCKED','reason':'RPC_READER_JOB_FAILED'}}
    inner=load(state/(stem+'-receipt.json'))
    result=({'status':'BLOCKED','reason':'READER_TIMEOUT_NO_RESULT_ACCEPTED'} if inner['timeout']
            else load(state/(stem+'-output.json')))
    return {'request_id':ident,'request':request,'outer_execution':outer,'execution':inner,'result':result}
