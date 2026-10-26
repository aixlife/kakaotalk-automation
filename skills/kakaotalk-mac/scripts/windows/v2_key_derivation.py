"""Exact observed v2 mode-1 derivation; keys remain in this bounded child.

REA and synthetic x86 tracing identify HMAC-SHA256(binding, IKM ||
"entropy-bound-kek"), followed by HKDF-SHA256 with the stored salt and the
prefix plus normalized relative file path. A result is accepted only after
AES-KW integrity AND the selected database's SQLCipher page authentication.
No target function calls, process writes, or GUI access.
"""
import ctypes as C
import hashlib,hmac,struct
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap,InvalidUnwrap
from vendor_appstate import parse_file

DOMAIN=b'entropy-bound-kek'

def file_kek(ikm,binding,salt,prefix,relative):
    assert len(ikm)==len(binding)==len(salt)==32 and prefix==b'v2:','V2_INPUT_CONTRACT'
    assert (relative.startswith('chat_data\\') or relative=='TalkUserDB.edb') and '/' not in relative and '..' not in relative,'V2_PATH_CONTRACT'
    bound=hmac.new(binding,ikm+DOMAIN,hashlib.sha256).digest()
    return HKDF(algorithm=hashes.SHA256(),length=32,salt=salt,
                info=prefix+relative.encode('utf8')).derive(bound)

def typed_inputs(reader,state_base,stats):
    manager=state_base-0xe0
    raw=reader.memory(manager+0x48,32)
    binding=reader.memory(manager+0x68,32)
    span=reader.memory(manager+0x88,24)
    if raw is None or binding is None or span is None:return None
    begin,end,capacity=struct.unpack('<QQQ',span)
    if not (0<end-begin<=512 and end<=capacity and capacity-begin<=4096):return None
    identity=reader.memory(begin,end-begin)
    pointer,_,length,capacity=struct.unpack('<QQQQ',raw)
    if not (0<length<=512 and length<=capacity<=4096):return None
    wide=raw[:length*2] if capacity<=7 else reader.memory(pointer,length*2)
    if wide is None or identity is None:return None
    try:path=Path(wide.decode('utf-16-le')).resolve()
    except (ValueError,UnicodeError,OSError):return None
    if not path.is_relative_to(reader.data.parent.resolve()) or not path.is_file():return None
    if path.stat().st_size!=40:return None
    before=reader.file_hash(path);wrapped=path.read_bytes()
    assert before==reader.file_hash(path),'IKM_CONTAINER_CHANGED'
    try:ikm=aes_key_unwrap(hmac.new(binding,identity+b'ikm-wrap',hashlib.sha256).digest(),wrapped)
    except InvalidUnwrap:return None
    if len(ikm)!=32:return None
    stats.update(ikm_container_wrap_integrity=True,ikm_container_inside_selected_account=True)
    return ikm,binding

def recover(reader,target,first):
    reader.guard();state_path=reader.data.parent/'appstate.dat'
    assert 0<state_path.stat().st_size<=1024*1024,'ENVELOPE_SIZE_LIMIT'
    before=reader.file_hash(state_path);state=parse_file(str(state_path))
    assert before==reader.file_hash(state_path),'ENVELOPE_CHANGED_DURING_READ'
    assert state.info_prefix==b'v2:' and len(state.salt)==32,'ENVELOPE_VERSION_UNSUPPORTED'
    assert (target.parent==reader.data and target.name.endswith('.edb')) or (target.parent==reader.data.parent and target.name=='TalkUserDB.edb'),'SELECTED_DB_PATH_REQUIRED'
    relative=('chat_data\\' if target.parent==reader.data else '')+target.name;wrapped=state.wrapped_for(relative)
    assert wrapped and len(wrapped)==40,'SELECTED_WRAPPED_KEY_MISSING'
    stats={'version':'v2','native_kdf_mode':1,'implemented':True,'salt_matches':0,
           'matching_state_prefixes':0,'ikm_container_wrap_integrity':False,
           'target_wrap_integrity':False,'target_page_hmac':False}
    reader.envelope_stats=stats
    cached=getattr(reader,'envelope_inputs',None)
    if cached is not None and cached[:2]==(before,reader.account_scope):
        _,_,ikm,binding=cached
        try:key=aes_key_unwrap(file_kek(ikm,binding,state.salt,state.info_prefix,relative),wrapped)
        except InvalidUnwrap:raise RuntimeError('V2_CACHED_TARGET_WRAP_INVALID')
        assert len(key)==32 and reader.valid_page(first,key,1,first[:16]),'V2_CACHED_TARGET_PAGE_INVALID'
        stats.update(ikm_container_wrap_integrity=True,target_wrap_integrity=True,target_page_hmac=True,
                     selected_room_key_validated=True,request_memory_cache_hit=True,
                     derivation='bound-HMAC-SHA256_then_HKDF-SHA256')
        reader.validated_keys.append(key)
        return key
    address=0;carry=b'';last_end=None;seen=set();regions=0
    while address<0x7fffffffffff:
        reader.guard();m=reader.mbi_type()
        if not reader.k.VirtualQueryEx(reader.handle,address,C.byref(m),C.sizeof(m)):break
        regions+=1;assert regions<30000,'ENVELOPE_REGION_LIMIT'
        base=int(m.base or 0);end=base+m.size
        if end<=address:break
        if m.kind==0x20000 and m.state==0x1000 and m.protect in (2,4,8,32,64,128):
            position=base
            if last_end!=position:carry=b''
            while position<end:
                size=min(65536,end-position);chunk=reader.memory(position,size)
                if chunk is None:carry=b'';position+=size;continue
                data=carry+chunk;origin=position-len(carry);offset=0
                while True:
                    hit=data.find(state.salt,offset)
                    if hit<0:break
                    offset=hit+1;state_base=origin+hit-0x40
                    if state_base in seen:continue
                    seen.add(state_base);stats['salt_matches']+=1
                    assert len(seen)<=256,'ENVELOPE_SALT_MATCH_LIMIT'
                    prefix=reader.memory(state_base+0x20,32)
                    if prefix is None or prefix[:3]!=b'v2:':continue
                    length,capacity=struct.unpack_from('<QQ',prefix,16)
                    if length!=3 or not 3<=capacity<=15:continue
                    stats['matching_state_prefixes']+=1
                    inputs=typed_inputs(reader,state_base,stats)
                    if inputs is None:continue
                    ikm,binding=inputs;kek=file_kek(ikm,binding,state.salt,state.info_prefix,relative)
                    try:key=aes_key_unwrap(kek,wrapped)
                    except InvalidUnwrap:continue
                    stats['target_wrap_integrity']=True
                    if len(key)!=32 or not reader.valid_page(first,key,1,first[:16]):continue
                    stats.update(target_page_hmac=True,selected_room_key_validated=True,
                                 derivation='bound-HMAC-SHA256_then_HKDF-SHA256')
                    reader.validated_keys.append(key)
                    reader.envelope_inputs=(before,reader.account_scope,ikm,binding)
                    return key
                carry=data[-256:];last_end=position+size;position+=size
        else:carry=b'';last_end=None
        address=end
    raise RuntimeError('V2_SELECTED_DATABASE_KEY_NOT_VALIDATED')
