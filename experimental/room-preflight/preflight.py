"""Inspect one exact room and existing window. No send, input or opening API."""
import argparse
import ctypes as C
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import re
import sys
import time
import uuid

HERE=Path(__file__).resolve().parent
READER=HERE.parents[1]/'skills/kakaotalk-mac/scripts/windows'
sys.path.insert(0,str(READER))

def select_exact(result,name,expected_id=None):
    if result.get('status')!='ROOMS_READ' or result.get('limit_reached'):
        raise RuntimeError('ROOM_LIST_INCOMPLETE')
    rooms=[r for r in result.get('rooms',[]) if r.get('title')==name]
    if len(rooms)!=1:raise RuntimeError('EXACT_ROOM_NOT_UNIQUE_OR_NOT_FOUND')
    room=rooms[0]
    if not re.fullmatch('[0-9]{1,20}',str(room.get('chat_id',''))):
        raise RuntimeError('ROOM_ID_INVALID')
    if expected_id is not None and str(room['chat_id'])!=expected_id:
        raise RuntimeError('CACHED_ROOM_ID_MISMATCH')
    return {key:room[key] for key in ('title','chat_id','type') if key in room}

def classify(windows,complete):
    if not complete:return 'WINDOW_INVENTORY_INCOMPLETE'
    if not windows:return 'TARGET_WINDOW_NOT_FOUND'
    if len(windows)!=1:return 'AMBIGUOUS_WINDOW_TITLE'
    return 'WINDOW_FOUND_CHAT_ID_BINDING_UNVERIFIED'

def inspect_windows(reader,title):
    u=C.WinDLL('user32',use_last_error=True)
    k=C.WinDLL('kernel32',use_last_error=True)
    callback=C.WINFUNCTYPE(W.BOOL,W.HWND,W.LPARAM)
    u.EnumWindows.argtypes=[callback,W.LPARAM]
    u.EnumChildWindows.argtypes=[W.HWND,callback,W.LPARAM]
    u.GetWindowThreadProcessId.argtypes=[W.HWND,C.POINTER(W.DWORD)]
    u.GetWindowTextW.argtypes=[W.HWND,W.LPWSTR,C.c_int]
    u.GetClassNameW.argtypes=[W.HWND,W.LPWSTR,C.c_int]
    u.GetDlgCtrlID.argtypes=[W.HWND]
    u.IsWindowVisible.argtypes=[W.HWND]
    u.IsWindowEnabled.argtypes=[W.HWND]
    u.IsIconic.argtypes=[W.HWND]
    u.GetForegroundWindow.restype=W.HWND
    u.GetCursorPos.argtypes=[C.POINTER(W.POINT)]
    k.ProcessIdToSessionId.argtypes=[W.DWORD,C.POINTER(W.DWORD)]
    current,target=W.DWORD(),W.DWORD()
    if not (k.ProcessIdToSessionId(k.GetCurrentProcessId(),C.byref(current)) and
            k.ProcessIdToSessionId(reader.pid,C.byref(target)) and current.value==target.value>0):
        raise RuntimeError('INTERACTIVE_SESSION_REQUIRED')
    started=time.monotonic();count=0;child_count=0;windows=[];errors=[]
    def owner(h):
        p=W.DWORD();u.GetWindowThreadProcessId(h,C.byref(p));return p.value
    def surface():
        p=W.POINT();f=u.GetForegroundWindow()
        if not f or not u.GetCursorPos(C.byref(p)):raise RuntimeError('SURFACE_UNAVAILABLE')
        return int(f),[p.x,p.y]
    before=surface()
    @callback
    def each(hwnd,_):
        nonlocal count,child_count
        try:
            count+=1
            if count>=500 or time.monotonic()-started>5:return False
            if owner(hwnd)!=reader.pid:return True
            text=C.create_unicode_buffer(256);u.GetWindowTextW(hwnd,text,len(text))
            if text.value!=title:return True
            classes=[]
            @callback
            def child(h,_):
                nonlocal child_count
                child_count+=1
                if child_count>=2000:return False
                b=C.create_unicode_buffer(128);u.GetClassNameW(h,b,len(b))
                classes.append((b.value.upper(),u.GetDlgCtrlID(h)));return True
            u.EnumChildWindows(hwnd,child,0)
            windows.append({'visible':bool(u.IsWindowVisible(hwnd)),
              'enabled':bool(u.IsWindowEnabled(hwnd)),'minimized':bool(u.IsIconic(hwnd)),
              'input_count':classes.count(('RICHEDIT50W',1006)),
              'message_list_count':classes.count(('EVA_VH_LISTCONTROL_DBLCLK',100))})
            return True
        except Exception:
            errors.append('WINDOW_ENUMERATION_FAILED');return False
    complete=bool(u.EnumWindows(each,0)) and count<500 and child_count<2000 and not errors
    after=surface()
    return {'status':classify(windows,complete),'window_candidates':windows,'complete':complete,
        'foreground_unchanged':before[0]==after[0],'cursor_unchanged':before[1]==after[1],
        'foreground_is_kakao':owner(before[0])==reader.pid,'session':current.value,
        'chat_id_hwnd_binding_verified':False,'input_content_read':False}

def worker(args):
    from reader_config import state_root
    from reader_job import run as bounded,EXTENDED
    from room_reader import Reader
    k=C.WinDLL('kernel32',use_last_error=True)
    k.QueryInformationJobObject.argtypes=[W.HANDLE,C.c_int,C.c_void_p,W.DWORD,C.POINTER(W.DWORD)]
    info=EXTENDED()
    if not k.QueryInformationJobObject(None,9,C.byref(info),C.sizeof(info),None):
        raise RuntimeError('BOUNDED_PARENT_JOB_REQUIRED')
    if not info.job or info.job>268435456:raise RuntimeError('JOB_LIMIT_REQUIRED')
    reader=Reader()
    try:
        before=reader.guard()
        if before>=args.app_stop_bytes:raise RuntimeError('APP_MEMORY_STOP')
        initial=(reader.pid,str(reader.created_at_filetime))
        output=state_root()/('preflight-room-'+uuid.uuid4().hex+'.json')
        command=[sys.executable,str(READER/'kakao_read_win.py'),'rooms','--name='+args.name,'--limit','10']
        execution=bounded(command,output,20)
        if execution['exit']!=0 or execution['timeout']:raise RuntimeError('ROOM_LOOKUP_FAILED')
        if not 0<output.stat().st_size<=2097152:raise RuntimeError('RECEIPT_SIZE_LIMIT')
        record=json.loads(output.read_text(encoding='utf-8-sig'))
        room=select_exact(record['result'],args.name,args.expected_chat_id)
        conn=record['result']['connection']
        if (conn['pid'],conn['created_at_filetime'])!=initial:raise RuntimeError('APP_IDENTITY_CHANGED')
        if reader.guard()>=args.app_stop_bytes:raise RuntimeError('APP_MEMORY_STOP')
        result=inspect_windows(reader,room['title'])
        after=reader.guard()
        if after>=args.app_stop_bytes:raise RuntimeError('APP_MEMORY_STOP')
        result.update(room=room,app_private_before=before,app_private_after=after,
          process_identity_verified=True,room_lookup_execution=execution,
          send_ready=False,automatic_open_supported=False,actual_sends=0,
          send_calls=0,input_calls=0,file_drop_calls=0,window_open_calls=0,clipboard_calls=0,
          settings_changed=False,security_changed=False,app_stop_bytes=args.app_stop_bytes,
          reason='No verified inactive-window opening or generic chat-ID-to-window send contract')
        return result
    finally:reader.close()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--name',required=True)
    p.add_argument('--expected-chat-id')
    p.add_argument('--app-stop-bytes',type=int,default=469893120)
    p.add_argument('--worker',action='store_true',help=argparse.SUPPRESS)
    args=p.parse_args()
    if os.name!='nt':p.error('Windows is required')
    if not 1<=len(args.name)<=100 or '\0' in args.name:p.error('Exact room name required')
    if args.expected_chat_id and not re.fullmatch('[0-9]{1,20}',args.expected_chat_id):p.error('Invalid room ID')
    if not 0<args.app_stop_bytes<=469893120:p.error('Stop line may only be lowered')
    try:
        if args.worker:result=worker(args)
        else:
            from reader_config import state_root
            from reader_job import run as bounded
            output=state_root()/('room-preflight-'+uuid.uuid4().hex+'.json')
            execution=bounded([sys.executable,str(Path(__file__).resolve()),*sys.argv[1:],'--worker'],output,40)
            result={'execution':execution,'receipt_path':str(output),'actual_sends':0}
            if execution['exit']==0 and not execution['timeout'] and output.stat().st_size<=2097152:
                result['result']=json.loads(output.read_text(encoding='utf-8-sig'))
            else:result['status']='PREFLIGHT_FAILED_NO_SEND'
        print(json.dumps(result,ensure_ascii=True));return 0
    except Exception as exc:
        print(json.dumps({'status':'BLOCKED','reason':str(exc) if isinstance(exc,(RuntimeError,AssertionError)) else type(exc).__name__,'actual_sends':0}));return 2

if __name__=='__main__':raise SystemExit(main())
