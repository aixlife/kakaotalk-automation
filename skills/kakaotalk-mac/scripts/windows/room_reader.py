"""Windows own-account KakaoTalk reader prototype. No GUI or app writes.

SQLCipher codec-context discovery informed by is-theo/kakao-cli-win,
revision 411d0dd1b472ea8a0cc8bf399e3351c0651748b6 (MIT).
Unlike that implementation, process bytes, keys and decrypted DBs are never
written to disk. Reads stream through 64KiB buffers with strict bounds.
64-bit pointers follow upstream SQLCipher codec_ctx/cipher_ctx layouts.
"""
import argparse
import reader_config
import ctypes as C
import ctypes.wintypes as W
import hashlib
import hmac
import json
import os
import re
from pathlib import Path
import sqlite3
import struct
import time
import traceback
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

APP=Path(os.environ.get('ProgramFiles',r'C:\Program Files'))/'Kakao'/'KakaoTalk'/'KakaoTalk.exe'
EXPECTED='abf66658c84c7a9a2f8300f9c3304a858bcacf8e3867bad33a79d769fd5321c1'
BASELINE=335675392
MAX_READ=384*1024*1024
LIMIT_SECONDS=40
PAGE=4096
RESERVE=80

class M(C.Structure):
    _fields_=[('base',C.c_void_p),('allocation',C.c_void_p),('ap',W.DWORD),
              ('partition',W.WORD),('size',C.c_size_t),('state',W.DWORD),
              ('protect',W.DWORD),('kind',W.DWORD)]

class PM(C.Structure):
    _fields_=[('cb',W.DWORD),('fault',W.DWORD)]+[(n,C.c_size_t) for n in
        ('pws','ws','pp','p','pnp','np','pf','ppf','private')]

class Reader:
    def __init__(self):
        self.started=time.monotonic();self.read_bytes=0;self.contexts=0
        self.mbi_type=M
        self.handle=None
        self.snapshots=[];self.validated_keys=[];self.snapshot_retries=0;self.literal_candidates=0;self.key_route='envelope';self.envelope_stats=None
        self.k=C.WinDLL('kernel32');self.ps=C.WinDLL('psapi')
        self.k.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD];self.k.OpenProcess.restype=W.HANDLE
        self.k.CloseHandle.argtypes=[W.HANDLE]
        self.k.GetCurrentProcess.restype=W.HANDLE
        self.k.VirtualQueryEx.argtypes=[W.HANDLE,C.c_void_p,C.POINTER(M),C.c_size_t]
        self.k.VirtualQueryEx.restype=C.c_size_t
        self.k.ReadProcessMemory.argtypes=[W.HANDLE,C.c_void_p,C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t)]
        self.k.QueryFullProcessImageNameW.argtypes=[W.HANDLE,W.DWORD,W.LPWSTR,C.POINTER(W.DWORD)]
        self.ps.GetProcessMemoryInfo.argtypes=[W.HANDLE,C.POINTER(PM),W.DWORD]
        self.ps.EnumProcesses.argtypes=[C.POINTER(W.DWORD),W.DWORD,C.POINTER(W.DWORD)]
        self.k.GetProcessTimes.argtypes=[W.HANDLE]+[C.POINTER(W.FILETIME)]*4
        self.k.GetExitCodeProcess.argtypes=[W.HANDLE,C.POINTER(W.DWORD)]
        assert reader_config.installation_matches(APP,EXPECTED),'INSTALLATION_CHANGED'
        candidates=(W.DWORD*4096)();needed=W.DWORD()
        assert self.ps.EnumProcesses(candidates,C.sizeof(candidates),C.byref(needed)) and needed.value<C.sizeof(candidates),'PROCESS_ENUMERATION_LIMIT'
        matches=[]
        for pid in candidates[:needed.value//C.sizeof(W.DWORD)]:
            if time.monotonic()-self.started>=LIMIT_SECONDS:raise RuntimeError('TIME_LIMIT')
            h=self.k.OpenProcess(0x1000,False,pid)
            if not h:continue
            try:
                if self.process_path(h)==str(APP).casefold():matches.append((pid,self.process_created(h)))
            finally:self.k.CloseHandle(h)
        from reader_queries import unique_process
        self.pid,self.created_at_filetime=unique_process(matches)
        self.handle=self.k.OpenProcess(0x1010,False,self.pid)
        assert self.handle,'PROCESS_READ_UNAVAILABLE'
        assert self.process_path(self.handle)==str(APP).casefold() and self.process_created(self.handle)==self.created_at_filetime,'PROCESS_IDENTITY_CHANGED'
        roots=list((Path(os.environ['LOCALAPPDATA'])/'Kakao'/'KakaoTalk'/'users').iterdir())
        accounts=[p for p in roots if p.is_dir() and (p/'chat_data'/'chatListInfo.edb').is_file()]
        assert len(accounts)==1,'ACCOUNT_NOT_UNIQUE'
        self.data=accounts[0]/'chat_data'
        self.account_scope=hashlib.sha256(str(accounts[0]).casefold().encode()).hexdigest()
        self.initial_private=self.guard()

    def process_path(self,handle):
        name=C.create_unicode_buffer(32768);length=W.DWORD(len(name))
        return name.value.casefold() if self.k.QueryFullProcessImageNameW(handle,0,name,C.byref(length)) else None

    def process_created(self,handle):
        values=[W.FILETIME() for _ in range(4)]
        assert self.k.GetProcessTimes(handle,*[C.byref(x) for x in values]),'PROCESS_TIMES_UNAVAILABLE'
        return values[0].dwHighDateTime<<32|values[0].dwLowDateTime

    def guard(self):
        assert time.monotonic()-self.started<LIMIT_SECONDS,'TIME_LIMIT'
        assert self.read_bytes<=MAX_READ,'PROCESS_READ_LIMIT'
        alive=W.DWORD()
        assert self.k.GetExitCodeProcess(self.handle,C.byref(alive)) and alive.value==259,'APP_EXITED_RETRY_READ'
        m=PM();m.cb=C.sizeof(m)
        assert self.ps.GetProcessMemoryInfo(self.handle,C.byref(m),m.cb),'APP_MEMORY_QUERY_FAILED'
        assert m.private<2147483648 and m.private-BASELINE<134217728,'APP_MEMORY_LIMIT'
        own=PM();own.cb=C.sizeof(own)
        assert self.ps.GetProcessMemoryInfo(self.k.GetCurrentProcess(),C.byref(own),own.cb) and own.private<268435456,'OWN_MEMORY_LIMIT'
        return m.private

    def memory(self,a,n):
        self.guard()
        assert self.read_bytes+n<=MAX_READ,'PROCESS_READ_LIMIT'
        if not (0x10000<=a<0x7fffffffffff and 0<n<=65536):return None
        m=M()
        if not self.k.VirtualQueryEx(self.handle,a,C.byref(m),C.sizeof(m)):return None
        if m.kind!=0x20000 or m.state!=0x1000 or m.protect not in (2,4,8,32,64,128) or a+n>m.base+m.size:return None
        b=C.create_string_buffer(n);got=C.c_size_t()
        if not self.k.ReadProcessMemory(self.handle,a,b,n,C.byref(got)) or got.value!=n:return None
        self.read_bytes+=n
        return b.raw

    @staticmethod
    def valid_page(page,key,pgno,salt):
        hk=hashlib.pbkdf2_hmac('sha512',key,bytes(b^0x3a for b in salt),2,dklen=32)
        offset=16 if pgno==1 else 0
        body=page[offset:PAGE-RESERVE+16]+struct.pack('<I',pgno)
        return hmac.compare_digest(hmac.new(hk,body,hashlib.sha512).digest(),page[PAGE-64:PAGE])

    def recover(self,first):
        for known in self.validated_keys:
            if self.valid_page(first,known,1,first[:16]):return known
        # Metadata signature only. Never retain region contents or candidate
        # credentials; only a DB-validated cipher key survives in this process.
        pattern=struct.pack('<7I',256000,2,16,32,16,16,4096)
        a=0;visited=0;seen=set();carry=b'';last_end=None
        while a<0x7fffffffffff:
            self.guard();m=M()
            if not self.k.VirtualQueryEx(self.handle,a,C.byref(m),C.sizeof(m)):break
            visited+=1;assert visited<30000,'REGION_LIMIT'
            region_base=int(m.base or 0);end=region_base+m.size
            if end<=a:break
            if m.kind==0x20000 and m.state==0x1000 and m.protect in (2,4,8,32,64,128):
                p=region_base
                if last_end!=p:carry=b''
                while p<end:
                    n=min(65536,end-p);chunk=self.memory(p,n)
                    if chunk is None:carry=b'';p+=n;continue
                    data=carry+chunk;origin=p-len(carry);pos=0
                    # SQLCipher's documented raw-key literal form. A closed
                    # DB may have no live codec but still have its own literal
                    # in an app-owned cache. Accept only a page-HMAC match;
                    # never print/save the literal or scan arbitrary passwords.
                    literals=[m.group(1) for m in re.finditer(rb"[xX]'([0-9a-fA-F]{96}|[0-9a-fA-F]{64})'",data)]
                    for match in re.finditer(rb"[xX]\x00'\x00((?:[0-9a-fA-F]\x00){96}|(?:[0-9a-fA-F]\x00){64})'\x00",data):
                        literals.append(match.group(1)[::2])
                    for literal in literals:
                        self.literal_candidates+=1;assert self.literal_candidates<=2048,'RAW_LITERAL_LIMIT'
                        material=bytes.fromhex(literal.decode('ascii'))
                        if len(material)==48 and material[32:]!=first[:16]:continue
                        candidate=material[:32]
                        if self.valid_page(first,candidate,1,first[:16]):
                            self.validated_keys.append(candidate);return candidate
                    while True:
                        pos=data.find(pattern,pos)
                        if pos<0:break
                        ctx=origin+pos-4;pos+=4
                        if ctx in seen or ctx%4:continue
                        seen.add(ctx);self.contexts+=1
                        assert self.contexts<=512,'CODEC_CONTEXT_LIMIT'
                        raw=self.memory(ctx,128)
                        if raw is None:continue
                        vals=struct.unpack_from('<15I',raw)
                        if not (vals[7]==4096 and 80 in vals[8:11] and 64 in vals[8:11]):continue
                        # x64: 15 uint32 fields, alignment padding, four ptrs,
                        # then read_ctx and write_ctx; cipher_ctx key is ptr+8.
                        for ctx_offset in (96,104):
                            cipher_ptr=struct.unpack_from('<Q',raw,ctx_offset)[0]
                            cipher=self.memory(cipher_ptr,32)
                            if cipher is None:continue
                            key_ptr=struct.unpack_from('<Q',cipher,8)[0]
                            key=self.memory(key_ptr,32)
                            if key and any(key) and self.valid_page(first,key,1,first[:16]):
                                self.validated_keys.append(key);return key
                    carry=data[-256:];last_end=p+n;p+=n
            else:carry=b'';last_end=None
            a=end
        raise RuntimeError('MATCHING_DATABASE_KEY_NOT_OBSERVED')

    @staticmethod
    def wal_pages(wal):
        if not wal:return {},None,0
        assert len(wal)>=32,'WAL_HEADER_INCOMPLETE'
        magic,version,pagesize=struct.unpack_from('>III',wal)
        assert magic in (0x377f0682,0x377f0683) and version==3007000 and pagesize==PAGE,'WAL_FORMAT_UNSUPPORTED'
        order='<' if magic==0x377f0682 else '>'
        def checksum(data,state=(0,0)):
            words=struct.unpack(order+str(len(data)//4)+'I',data);s0,s1=state
            for i in range(0,len(words),2):
                s0=(s0+words[i]+s1)&0xffffffff;s1=(s1+words[i+1]+s0)&0xffffffff
            return s0,s1
        state=checksum(wal[:24]);assert state==struct.unpack_from('>II',wal,24),'WAL_HEADER_CHECKSUM_FAILED'
        pending={};committed={};dbsize=None;committed_frames=0
        for index,off in enumerate(range(32,len(wal)-PAGE-23,PAGE+24),1):
            header=wal[off:off+24];pgno,size=struct.unpack_from('>II',header)
            if header[8:16]!=wal[16:24]:break
            new=checksum(header[:8]+wal[off+24:off+24+PAGE],state)
            if new!=struct.unpack_from('>II',header,16):break
            assert 0<pgno<=24*1024*1024//PAGE,'WAL_PAGE_LIMIT'
            state=new;pending[pgno]=off+24
            if size:
                assert size<=24*1024*1024//PAGE,'WAL_DATABASE_LIMIT'
                committed.update(pending);pending.clear();dbsize=size;committed_frames=index
        return {p:o for p,o in committed.items() if dbsize is not None and p<=dbsize},dbsize,committed_frames

    @staticmethod
    def file_hash(path):
        with path.open('rb') as f:return hashlib.file_digest(f,'sha256').digest()

    def capture_files(self,path):
        moving={'DB_CHANGED_DURING_READ','DB_DOUBLE_READ_MISMATCH','WAL_APPEARANCE_CHANGED','WAL_CHANGED_DURING_READ','WAL_DOUBLE_READ_MISMATCH'}
        for attempt in range(3):
            try:return self.capture_files_once(path)
            except AssertionError as exc:
                if str(exc) not in moving or attempt==2:raise
                self.snapshot_retries+=1;self.guard();time.sleep(.05)

    def capture_files_once(self,path):
        self.guard()
        before=path.stat();assert 4096<=before.st_size<=24*1024*1024 and before.st_size%4096==0,'DB_SIZE_LIMIT'
        wal_path=path.with_name(path.name+'-wal');wal_before=wal_path.stat() if wal_path.exists() else None
        if wal_before:assert wal_before.st_size<=24*1024*1024,'WAL_SIZE_LIMIT'
        encrypted=path.read_bytes();wal=wal_path.read_bytes() if wal_before else b'';after=path.stat()
        assert (before.st_size,before.st_mtime_ns)==(after.st_size,after.st_mtime_ns),'DB_CHANGED_DURING_READ'
        assert self.file_hash(path)==hashlib.sha256(encrypted).digest(),'DB_DOUBLE_READ_MISMATCH'
        assert wal_path.exists()==bool(wal_before),'WAL_APPEARANCE_CHANGED'
        if wal_before:
            wal_after=wal_path.stat()
            assert (wal_before.st_size,wal_before.st_mtime_ns)==(wal_after.st_size,wal_after.st_mtime_ns),'WAL_CHANGED_DURING_READ'
            assert self.file_hash(wal_path)==hashlib.sha256(wal).digest(),'WAL_DOUBLE_READ_MISMATCH'
        return encrypted,wal

    def database(self,path):
        self.guard();assert (path.parent==self.data and path.suffix=='.edb') or (path.parent==self.data.parent and path.name=='TalkUserDB.edb'),'DB_OUTSIDE_ACCOUNT'
        encrypted,wal=self.capture_files(path)
        frames,dbsize,committed_count=self.wal_pages(wal)
        if self.key_route=='envelope':
            from reader_envelope import recover
            key=recover(self,path,encrypted[:PAGE])
        else:key=self.recover(encrypted[:PAGE])
        plain=bytearray();salt=encrypted[:16];authenticated=0;zero_pages=0
        target_size=dbsize*PAGE if dbsize is not None else len(encrypted)
        for off in range(0,target_size,PAGE):
            if off%(1024*1024)==0:self.guard()
            pgno=off//PAGE+1
            page=wal[frames[pgno]:frames[pgno]+PAGE] if pgno in frames else encrypted[off:off+PAGE]
            assert len(page)==PAGE,'SNAPSHOT_PAGE_MISSING'
            if not any(page):plain.extend(page);zero_pages+=1;continue
            assert self.valid_page(page,key,pgno,salt),'PAGE_AUTHENTICATION_FAILED'
            authenticated+=1
            cipher=Cipher(algorithms.AES(key),modes.CBC(page[PAGE-RESERVE:PAGE-RESERVE+16])).decryptor()
            part=page[16:PAGE-RESERVE] if pgno==1 else page[:PAGE-RESERVE]
            decoded=cipher.update(part)+cipher.finalize()
            plain.extend((b'SQLite format 3\0' if pgno==1 else b'')+decoded+b'\0'*RESERVE)
        del key,encrypted,wal
        assert plain[:16]==b'SQLite format 3\0','DECRYPTED_HEADER_INVALID'
        # Only this independent in-memory copy changes its journal flags.
        plain[18]=plain[19]=1
        con=sqlite3.connect(':memory:');con.deserialize(bytes(plain));con.execute('PRAGMA query_only=ON');del plain
        con.set_progress_handler(lambda: int(time.monotonic()-self.started>=LIMIT_SECONDS),1000)
        assert con.execute('PRAGMA quick_check').fetchone()[0]=='ok','SNAPSHOT_INTEGRITY_FAILED'
        con.row_factory=sqlite3.Row
        self.snapshots.append({'kind':('room-list' if path.name=='chatListInfo.edb' else 'profiles' if path.name=='TalkUserDB.edb' else 'selected-messages'),
                               'committed_wal_frames':committed_count,'wal_pages_applied':len(frames),
                               'authenticated_pages':authenticated,'zero_pages':zero_pages,'snapshot_pages':target_size//PAGE,'double_read_verified':True,
                               'quick_check':'ok'})
        return con

    def close(self):
        self.validated_keys.clear()
        if hasattr(self,'envelope_inputs'):self.envelope_inputs=None
        if self.handle:self.k.CloseHandle(self.handle);self.handle=None

def text(value):
    if isinstance(value,bytes):return value.decode('utf-8',errors='replace')
    return '' if value is None else str(value)

def room_title(row):
    title=text(row['chatRoomTitle']).strip()
    if title:return title
    if row['type']=='MemoChat':return '나와의 채팅'
    try:
        members=json.loads(text(row['titleDisplayMembers']));names=[]
        def walk(item):
            if isinstance(item,dict):
                for key in ('nickName','nickname','name','displayName','userName'):
                    if isinstance(item.get(key),str) and item[key].strip():names.append(item[key].strip());return
                for val in item.values():walk(val)
            elif isinstance(item,list):
                for val in item:walk(val)
            elif isinstance(item,str) and item.strip() and not item.isdigit():names.append(item.strip())
        walk(members)
        if names:return ', '.join(dict.fromkeys(names[:8]))
    except (ValueError,TypeError):pass
    return 'chatId:'+str(row['chatId'])

def profile_names(reader,room,authors,index):
    profiles=reader.data.parent/'TalkUserDB.edb'
    if not profiles.is_file():return
    con=reader.database(profiles)
    try:
        slots=','.join('?' for _ in authors);ids=[int(x) for x in sorted(authors)]
        cols={r[1] for r in con.execute('PRAGMA table_info(talkUser)')}
        assert {'userId','nickName','friendNickName','linkId'}<=cols,'PROFILE_SCHEMA_UNSUPPORTED'
        link=room['linkId'] or 0
        where='userId IN ('+slots+') AND '+('linkId=?' if link else '(linkId=0 OR linkId IS NULL)')
        params=ids+([link] if link else [])
        for row in con.execute('SELECT userId,nickName,friendNickName FROM talkUser WHERE '+where,params):
            friend=text(row['friendNickName']).strip();nick=text(row['nickName']).strip()
            index.add_contact(row['userId'],friend,nick)
        if not link:
            cols={r[1] for r in con.execute('PRAGMA table_info(Profile)')}
            if {'userId','nickname'}<=cols:
                for row in con.execute('SELECT userId,nickname FROM Profile WHERE userId IN ('+slots+')',ids):
                    index.add(row['userId'],text(row['nickname']),'TalkUserDB.Profile.nickname',0)
    finally:con.close()

def sender_names(reader,metadata,room,authors):
    from reader_queries import NameIndex
    index=NameIndex()
    if not authors:return index
    assert len(authors)<=100 and all(re.fullmatch('[0-9]{1,20}',x) for x in authors),'AUTHOR_SCOPE_INVALID'
    profile_names(reader,room,authors,index)
    # Own-account identity only: inspect author IDs from its one MemoChat, not
    # its message bodies. A non-unique positive author set is never guessed.
    if authors:
        memos=metadata.execute("SELECT chatId FROM chatRoomList WHERE type='MemoChat' LIMIT 2").fetchall()
        if len(memos)==1:
            selfpath=reader.data/('chatLogs_'+str(int(memos[0]['chatId']))+'.edb')
            if selfpath.is_file():
                own=reader.database(selfpath);reader.snapshots[-1]['kind']='self-author-identity'
                try:
                    own_ids=[r[0] for r in own.execute('SELECT DISTINCT authorId FROM chatLogs WHERE authorId>0 LIMIT 2')]
                    if len(own_ids)==1 and str(own_ids[0]) in authors:index.mark_self(own_ids[0])
                finally:own.close()
    return index

def selected_messages(reader,room,args,metadata):
    from reader_queries import query_spec,scope_digest,query_window,select_page,snippet,timestamp_fields
    chat_id=int(room['chatId']);assert chat_id>0,'INVALID_CHAT_ID'
    con=reader.database(reader.data/('chatLogs_'+str(chat_id)+'.edb'))
    try:
        cols={r[1] for r in con.execute('PRAGMA table_info(chatLogs)')}
        ident=next((x for x in ('id','logId','_id') if x in cols),None)
        stamp=next((x for x in ('sendAt','createdAt','sentAt','created_at') if x in cols),None)
        assert ident and stamp and {'message','authorId','type'}<=cols,'MESSAGE_SCHEMA_UNSUPPORTED'
        maximum=con.execute('SELECT MAX('+stamp+') FROM chatLogs').fetchone()[0]
        minimum=con.execute('SELECT MIN('+stamp+') FROM chatLogs').fetchone()[0]
        scale=1000 if maximum and maximum>10**12 else 1
        assert not maximum or maximum<10**15,'TIMESTAMP_UNIT_UNSUPPORTED'
        spec=query_spec(args);scope=scope_digest(reader.account_scope,chat_id,spec)
        window=query_window(spec,scope,args.cursor)
        rows,truncated,cursor=select_page(con,cols,spec,window,args.limit,ident,stamp,scale,args.command=='search')
        index=sender_names(reader,metadata,room,{str(r['authorId']) for r in rows})
        result=[]
        for row in (rows if window['direction']=='ASC' else reversed(rows)):
            body=text(row['message']);is_search=args.command=='search'
            result.append({'log_id':str(row['log_id']),'author_id':str(row['authorId']),'type':row['type'],
                           **index.resolve(row['authorId']),
                           'text':snippet(body,args.query) if is_search else body,
                           'text_truncated':(row['full_length'] or 0)>4000,
                           'snippet_only':is_search,
                           **timestamp_fields(row['sent_at'],stamp,scale,row['sent_at_sqlite_type'])})
        return {'messages':result,'limit_reached':truncated,'hours':args.hours,
                'next_cursor':cursor,'next_before_id':str(min(int(r['log_id']) for r in result)) if result else None,
                'next_after_id':str(max((int(r['log_id']) for r in result),default=args.after_id)) if result or args.after_id is not None else None,
                'query':args.query,'since_inclusive_kst':datetime.fromtimestamp(window['start'],timezone(timedelta(hours=9))).isoformat(),
                'until_exclusive_kst':datetime.fromtimestamp(window['end'],timezone(timedelta(hours=9))).isoformat(),
                'messages_read_from_selected_room_only':True,'source':'windows-local-cache',
                'server_history_fetched':False,
                'sender_names_resolved':sum(r['author_name_status'] in ('resolved','self') for r in result),
                'sender_lookup_reads_message_bodies':False,
                'earliest_local_message_at_kst':datetime.fromtimestamp(minimum/scale,timezone(timedelta(hours=9))).isoformat() if minimum else None,
                'latest_local_message_at_kst':datetime.fromtimestamp(maximum/scale,timezone(timedelta(hours=9))).isoformat() if maximum else None}
    finally:con.close()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['schema','rooms','self','messages','search'])
    parser.add_argument('--name')
    parser.add_argument('--limit',type=int,default=20)
    parser.add_argument('--hours',type=int,default=24)
    parser.add_argument('--after-id',type=int)
    parser.add_argument('--before-id',type=int)
    parser.add_argument('--since')
    parser.add_argument('--until')
    parser.add_argument('--query')
    parser.add_argument('--cursor')
    parser.add_argument('--key-route',choices=['codec','envelope'],default='envelope')
    args=parser.parse_args();reader=None;out={'status':'BLOCKED','input_calls':0,'clipboard_calls':0,'process_dump_saved':False,'key_saved':False,'plaintext_db_saved':False}
    try:
        reader=Reader();reader.key_route=args.key_route;con=reader.database(reader.data/'chatListInfo.edb')
        try:
            from reader_queries import query_spec
            assert 1<=args.limit<=100,'QUERY_LIMIT_INVALID'
            query_spec(args)
            assert args.command!='search' or args.query,'SEARCH_QUERY_REQUIRED'
            if args.command=='schema':
                names=[r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' LIMIT 80")]
                columns=[r[1] for r in con.execute('PRAGMA table_info(chatRoomList)')]
                out.update(status='SCHEMA_READ',tables=names,room_columns=columns,
                           table_columns={n:[r[1] for r in con.execute('PRAGMA table_info("'+n.replace('"','""')+'")')] for n in names},
                           metadata_files=sorted(p.name for p in reader.data.glob('*.edb') if not p.name.startswith('chatLogs_')),
                           room_count=con.execute('SELECT COUNT(*) FROM chatRoomList').fetchone()[0],
                           memo_count=con.execute("SELECT COUNT(*) FROM chatRoomList WHERE type='MemoChat'").fetchone()[0])
                out['profile_columns']={}
                for basename in ('TalkUserDB.edb',):
                    profiles=reader.data.parent/basename
                    if profiles.is_file():
                        pc=reader.database(profiles)
                        try:
                            tables=[r[0] for r in pc.execute("SELECT name FROM sqlite_master WHERE type='table' LIMIT 30")]
                            out['profile_columns'][basename]={n:[r[1] for r in pc.execute('PRAGMA table_info("'+n.replace('"','""')+'")')] for n in tables}
                        finally:pc.close()
            else:
                assert args.command=='self' or (args.name and 1<=len(args.name)<=100),'ROOM_NAME_REQUIRED'
                sql='SELECT chatId,type,chatRoomTitle,titleDisplayMembers,lastUpdatedAt,directChatMemberId,linkId FROM chatRoomList'
                if args.command=='self':
                    rows=con.execute(sql+" WHERE type='MemoChat'").fetchall()
                else:
                    rows=[r for r in con.execute(sql) if args.name.casefold() in room_title(r).casefold()]
                    if args.command in ('messages','search'):
                        exact=[r for r in rows if room_title(r)==args.name]
                        assert exact or not rows,'EXACT_ROOM_NAME_REQUIRED'
                        rows=exact
                rooms=[{'chat_id':str(r['chatId']),'title':room_title(r),'type':r['type'],'last_updated_at':r['lastUpdatedAt']} for r in rows]
                if args.command=='rooms':out.update(status='ROOMS_READ',rooms=rooms[:args.limit],limit_reached=len(rooms)>args.limit)
                else:
                    assert len(rows)==1,'ROOM_NOT_UNIQUE_OR_NOT_FOUND'
                    out.update(status='SEARCH_READ' if args.command=='search' else 'MESSAGES_READ',room=rooms[0],**selected_messages(reader,rows[0],args,con))
        finally:con.close()
        out.update(connection={'pid':reader.pid,'created_at_filetime':str(reader.created_at_filetime),
                               'discovery':'fresh-process-enumeration','installation_sha256':EXPECTED,
                               'cached_pid_reused':False,'decryption_material_saved':False},
                   app_private_before=reader.initial_private,app_private_after=reader.guard(),
                   process_read_bytes=reader.read_bytes,codec_contexts=reader.contexts,raw_literal_candidates=reader.literal_candidates,
                   snapshots=reader.snapshots,snapshot_retries=reader.snapshot_retries,envelope=reader.envelope_stats,
                   elapsed_sec=round(time.monotonic()-reader.started,3))
    except Exception as exc:
        out.update(status='BLOCKED',error_type=type(exc).__name__,reason=str(exc) if isinstance(exc,(AssertionError,RuntimeError)) else 'DETAILS_WITHHELD')
        out['source_line']=traceback.extract_tb(exc.__traceback__)[-1].lineno
        if reader:out.update(process_read_bytes=reader.read_bytes,codec_contexts=reader.contexts,raw_literal_candidates=reader.literal_candidates)
        if reader and reader.envelope_stats is not None:out['envelope']=reader.envelope_stats
    finally:
        if reader:reader.close()
    print(json.dumps(out,ensure_ascii=True))
    return 0 if out['status'] in ('SCHEMA_READ','ROOMS_READ','MESSAGES_READ','SEARCH_READ') else 2

if __name__=='__main__':raise SystemExit(main())
