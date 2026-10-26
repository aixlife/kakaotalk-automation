"""Portable, bounded query/cursor and exact sender-identity helpers.

No app access or persistence. Cursors bind an account, room and filter; they
are consistency markers, not authentication credentials.
"""
import base64
from datetime import datetime, timezone, timedelta
import hashlib
import json
import math
import re
import time

KST=timezone(timedelta(hours=9))
MAX_HOURS=24*365*10

def timestamp_fields(raw,column,scale,sqlite_type):
    """Preserve the platform's saved value; never align it to another app."""
    assert column in ('sendAt','createdAt','sentAt','created_at') and scale in (1,1000),'TIMESTAMP_SOURCE_INVALID'
    assert sqlite_type in ('integer','real','null'),'TIMESTAMP_TYPE_UNSUPPORTED'
    assert raw is None or type(raw) in (int,float) and math.isfinite(raw),'TIMESTAMP_VALUE_INVALID'
    stamp=None if raw is None else raw/scale
    assert stamp is None or 0<=stamp<32503680000,'TIMESTAMP_VALUE_INVALID'
    return {'sent_at':stamp,'sent_at_kst':datetime.fromtimestamp(stamp,KST).isoformat() if stamp is not None else None,
            'sent_at_source':{'platform':'windows-local-cache','table':'chatLogs','column':column,
                              'raw_value':raw,'sqlite_type':sqlite_type,
                              'unit':'milliseconds' if scale==1000 else 'seconds','rounding_applied':'none'}}

def unique_process(matches):
    assert matches,'APP_NOT_RUNNING'
    assert len(matches)==1,'APP_PROCESS_NOT_UNIQUE'
    pid,created=matches[0]
    assert isinstance(pid,int) and pid>0 and isinstance(created,int) and created>0,'PROCESS_IDENTITY_INVALID'
    return pid,created

def date_epoch(value):
    assert isinstance(value,str) and 1<=len(value)<=40,'DATE_INVALID'
    try:
        stamp=datetime.fromisoformat(value.replace('Z','+00:00'))
        if stamp.tzinfo is None:stamp=stamp.replace(tzinfo=KST)
        result=stamp.timestamp()
    except (ValueError,OverflowError):raise AssertionError('DATE_INVALID')
    assert 0<=result<32503680000,'DATE_OUT_OF_RANGE'
    return result

def query_spec(args):
    spec={k:getattr(args,k,None) for k in ('hours','since','until','query','after_id','before_id')}
    assert isinstance(spec['hours'],int) and 1<=spec['hours']<=MAX_HOURS,'HOURS_LIMIT'
    assert not (spec['after_id'] is not None and spec['before_id'] is not None),'CURSOR_DIRECTION_CONFLICT'
    for key in ('after_id','before_id'):
        assert spec[key] is None or isinstance(spec[key],int) and 0<spec[key]<2**63,'MESSAGE_ID_INVALID'
    assert spec['query'] is None or isinstance(spec['query'],str) and 1<=len(spec['query'])<=200,'QUERY_LENGTH_INVALID'
    for key in ('since','until'):
        if spec[key] is not None:date_epoch(spec[key])
    return spec

def scope_digest(account,room,spec):
    return hashlib.sha256(json.dumps([account,str(room),spec],sort_keys=True,separators=(',',':')).encode()).hexdigest()

def query_window(spec,scope,cursor=None,now=None):
    if cursor:
        assert isinstance(cursor,str) and len(cursor)<=2048,'CURSOR_SIZE_LIMIT'
        try:
            raw=base64.b64decode(cursor.encode(),altchars=b'-_',validate=True)
            data=json.loads(raw)
        except (ValueError,UnicodeError):raise AssertionError('CURSOR_INVALID')
        assert isinstance(data,dict) and set(data)=={'v','scope','start','end','anchor','snapshot_max','direction'},'CURSOR_SCHEMA'
        assert data['v']==1 and data['scope']==scope,'CURSOR_SCOPE_MISMATCH'
        assert all(type(data[k]) is int for k in ('anchor','snapshot_max')) and 0<data['anchor']<=data['snapshot_max']<2**63,'CURSOR_ID_INVALID'
        assert all(type(data[k]) in (float,int) for k in ('start','end')) and 0<=data['start']<data['end']<32503680000,'CURSOR_WINDOW_INVALID'
        assert data['direction']==('ASC' if spec['after_id'] is not None else 'DESC'),'CURSOR_DIRECTION_MISMATCH'
        return data
    end=date_epoch(spec['until']) if spec['until'] else (time.time() if now is None else now)
    start=date_epoch(spec['since']) if spec['since'] else max(0,end-spec['hours']*3600)
    assert 0<=start<end,'DATE_RANGE_INVALID'
    return {'v':1,'scope':scope,'start':start,'end':end,'anchor':None,'snapshot_max':None,
            'direction':'ASC' if spec['after_id'] is not None else 'DESC'}

def page_cursor(window,anchor,snapshot_max):
    value=dict(window,anchor=int(anchor),snapshot_max=int(snapshot_max))
    return base64.urlsafe_b64encode(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).decode()

def select_page(con,cols,spec,window,limit,ident,stamp,scale,snippets_only=False):
    assert 1<=limit<=100,'QUERY_LIMIT_INVALID'
    assert ident in ('id','logId','_id') and stamp in ('sendAt','createdAt','sentAt','created_at'),'MESSAGE_SCHEMA_UNSUPPORTED'
    where=[stamp+'>=?',stamp+'<?'];params=[window['start']*scale,window['end']*scale]
    if 'deleted' in cols:where.append('(deleted=0 OR deleted IS NULL)')
    for key,op in (('after_id','>'),('before_id','<')):
        if spec[key] is not None:where.append(ident+op+'?');params.append(spec[key])
    if spec['query'] is not None:
        where.append("instr(lower(COALESCE(message,'')),lower(?))>0");params.append(spec['query'])
    if window['anchor'] is not None:
        where.extend([ident+('>?' if window['direction']=='ASC' else '<?'),ident+'<=?'])
        params.extend([window['anchor'],window['snapshot_max']])
    predicate=' AND '.join(where)
    snapshot_max=window['snapshot_max']
    if snapshot_max is None:snapshot_max=con.execute('SELECT MAX('+ident+') FROM chatLogs WHERE '+predicate,params).fetchone()[0]
    body='substr(message,1,4000)'
    prefix=[]
    if snippets_only:
        assert spec['query'],'SEARCH_QUERY_REQUIRED'
        size=max(180,len(spec['query'])+100)
        body="substr(message,max(1,instr(lower(COALESCE(message,'')),lower(?))-50),"+str(size)+")"
        prefix=[spec['query']]
    sql=('SELECT '+ident+' AS log_id,authorId,type,'+body+' AS message,'
         'length(message) AS full_length,'+stamp+' AS sent_at,typeof('+stamp+') AS sent_at_sqlite_type FROM chatLogs WHERE '+predicate+
         ' ORDER BY '+ident+' '+window['direction']+' LIMIT ?')
    rows=con.execute(sql,prefix+params+[limit+1]).fetchall();more=len(rows)>limit;rows=rows[:limit]
    cursor=page_cursor(window,rows[-1]['log_id'],snapshot_max) if more else None
    return rows,more,cursor

class NameIndex:
    def __init__(self):self.values={};self.self_id=None

    def mark_self(self,ident):
        assert re.fullmatch('[0-9]{1,20}',str(ident)) and int(ident)>0,'SELF_ID_INVALID'
        self.self_id=str(ident)

    def add_contact(self,ident,friend,nickname):
        if isinstance(friend,str) and friend.strip():self.add(ident,friend,'TalkUserDB.talkUser.friendNickName',2)
        elif isinstance(nickname,str) and nickname.strip():self.add(ident,nickname,'TalkUserDB.talkUser.nickName',1)

    def add(self,ident,name,source,priority=0):
        ident=str(ident)
        if not re.fullmatch('[0-9]{1,20}',ident) or int(ident)<=0:return
        if not isinstance(name,str) or not name.strip() or len(name)>200:return
        entries=self.values.setdefault(ident,[])
        item=(priority,name.strip(),source)
        if item not in entries:entries.append(item)

    def resolve(self,ident):
        if str(ident)==self.self_id:
            return {'author_name':'나','author_name_status':'self','author_name_source':'MemoChat.authorId','author_is_self':True}
        entries=self.values.get(str(ident),[])
        if not entries:return {'author_name':None,'author_name_status':'unresolved','author_name_source':None,'author_is_self':False}
        best=max(x[0] for x in entries);entries=[x for x in entries if x[0]==best]
        names={x[1] for x in entries}
        if len(names)!=1:return {'author_name':None,'author_name_status':'conflict','author_name_source':None,'author_is_self':False}
        return {'author_name':next(iter(names)),'author_name_status':'resolved',
                'author_name_source':','.join(sorted({x[2] for x in entries})),'author_is_self':False}

def snippet(body,query,size=180):
    size=max(size,len(query or '')+100)
    offset=body.lower().find(query.lower()) if query else 0
    start=max(0,offset-50);end=min(len(body),start+size)
    return ('…' if start else '')+body[start:end]+('…' if end<len(body) else '')
