"""Deterministic edge cases using fictional in-memory messages only."""
import json
import sqlite3
from types import SimpleNamespace
import unittest

from reader_queries import (NameIndex,date_epoch,page_cursor,query_spec,
                            query_window,scope_digest,select_page,unique_process)

def options(**kw):
    return SimpleNamespace(**dict(dict(hours=24,since=None,until=None,query=None,
                                      after_id=None,before_id=None),**kw))

class Queries(unittest.TestCase):
    def setUp(self):
        self.con=sqlite3.connect(':memory:');self.con.row_factory=sqlite3.Row
        self.con.execute('CREATE TABLE chatLogs(id INTEGER,authorId INTEGER,type INTEGER,message TEXT,sendAt INTEGER,deleted INTEGER)')
        for ident in range(1,10):
            self.con.execute('INSERT INTO chatLogs VALUES(?,1,1,?,1000,0)',(ident,'가상 대화 '+str(ident)))
        self.cols={'id','authorId','type','message','sendAt','deleted'}
    def tearDown(self):self.con.close()
    def page(self,spec,window,limit=3,snips=False):
        return select_page(self.con,self.cols,spec,window,limit,'id','sendAt',1,snips)
    def test_past_three_pages_no_duplicates_after_new_arrival(self):
        spec=query_spec(options());scope=scope_digest('a','1',spec)
        window=query_window(spec,scope,now=2000);ids=[]
        for page in range(3):
            rows,more,cursor=self.page(spec,window);ids.extend(row['log_id'] for row in rows)
            if page==0:self.con.execute("INSERT INTO chatLogs VALUES(10,1,1,'later',1000,0)")
            if cursor:window=query_window(spec,scope,cursor,now=9999)
        self.assertEqual(ids,list(range(9,0,-1)));self.assertFalse(more);self.assertIsNone(cursor)
    def test_cursor_wrong_room_account_filter_rejected(self):
        spec=query_spec(options());scope=scope_digest('a','1',spec)
        window=query_window(spec,scope,now=2000);_,_,cursor=self.page(spec,window)
        for other in (scope_digest('b','1',spec),scope_digest('a','2',spec),scope_digest('a','1',query_spec(options(query='다른말')))):
            with self.assertRaisesRegex(AssertionError,'CURSOR_SCOPE'):query_window(spec,other,cursor)
    def test_literal_percent_underscore_backslash(self):
        for ident,body in enumerate(('100% 완료','파일_이름',r'C:\demo','1000 완료','파일A이름'),20):
            self.con.execute('INSERT INTO chatLogs VALUES(?,1,1,?,1000,0)',(ident,body))
        for needle,expected in (('%',[20]),('_',[21]),('\\',[22])):
            spec=query_spec(options(query=needle));window=query_window(spec,'x',now=2000)
            rows,_,_=self.page(spec,window,100)
            self.assertEqual([r['log_id'] for r in rows],expected)
    def test_forward_incremental_and_empty(self):
        spec=query_spec(options(after_id=4));window=query_window(spec,'x',now=2000)
        rows,more,cursor=self.page(spec,window)
        self.assertEqual([r['log_id'] for r in rows],[5,6,7]);self.assertTrue(more)
        rows,more,cursor=self.page(spec,query_window(spec,'x',cursor))
        self.assertEqual([r['log_id'] for r in rows],[8,9]);self.assertFalse(more)
        spec=query_spec(options(after_id=9));rows,more,cursor=self.page(spec,query_window(spec,'x',now=2000))
        self.assertFalse(rows);self.assertIsNone(cursor)
    def test_date_boundaries_and_deleted(self):
        self.con.execute('UPDATE chatLogs SET deleted=1 WHERE id=9')
        spec=query_spec(options(since='1970-01-01T00:16:40Z',until='1970-01-01T00:16:41Z'))
        rows,_,_=self.page(spec,query_window(spec,'x'),100);self.assertEqual(len(rows),8)
        spec=query_spec(options(since='1970-01-01T00:16:39Z',until='1970-01-01T00:16:40Z'))
        self.assertFalse(self.page(spec,query_window(spec,'x'),100)[0])
        self.assertEqual(date_epoch('2026-01-01'),date_epoch('2026-01-01T00:00:00+09:00'))
    def test_long_message_search_shows_actual_match(self):
        self.con.execute('INSERT INTO chatLogs VALUES(10,1,1,?,1000,0)',('x'*5000+'바늘'+'y'*1000,))
        spec=query_spec(options(query='바늘'));window=query_window(spec,'x',now=2000)
        rows,_,_=self.page(spec,window,3,True)
        self.assertIn('바늘',rows[0]['message']);self.assertLessEqual(len(rows[0]['message']),180)
    def test_long_literal_query_is_not_cut_out_of_snippet(self):
        needle='가'*200
        self.con.execute('INSERT INTO chatLogs VALUES(10,1,1,?,1000,0)',('x'*5000+needle+'y'*1000,))
        spec=query_spec(options(query=needle));window=query_window(spec,'x',now=2000)
        rows,_,_=self.page(spec,window,3,True)
        self.assertIn(needle,rows[0]['message']);self.assertLessEqual(len(rows[0]['message']),300)
    def test_bad_cursor_and_limits(self):
        spec=query_spec(options())
        for cursor in ('!','e30=','x'*2049):
            with self.assertRaises(AssertionError):query_window(spec,'x',cursor)
        for kw in ({'after_id':1,'before_id':2},{'hours':0},{'hours':87601},{'query':''},{'since':'bad'}):
            with self.assertRaises(AssertionError):query_spec(options(**kw))
    def test_author_ids_conflicts_and_priority(self):
        names=NameIndex();names.add(1,'가상 이름','members');names.add(2,'다른 이름','members')
        self.assertEqual(names.resolve(1)['author_name'],'가상 이름')
        self.assertIsNone(names.resolve(3)['author_name'])
        names.add(1,'충돌 이름','members');self.assertEqual(names.resolve(1)['author_name_status'],'conflict')
        names.add(1,'저장한 이름','contacts',1);self.assertEqual(names.resolve(1)['author_name'],'저장한 이름')
    def test_pid_changes_have_no_cached_dependency(self):
        self.assertEqual(unique_process([(11,100)]),(11,100))
        self.assertEqual(unique_process([(22,200)]),(22,200))
        for matches in ([],[(1,100),(2,200)]):
            with self.assertRaises(AssertionError):unique_process(matches)
    def test_confirmed_self_is_role_not_guessed_profile_name(self):
        names=NameIndex();names.mark_self(12)
        self.assertTrue(names.resolve(12)['author_is_self'])
        self.assertEqual(names.resolve(12)['author_name_status'],'self')
        self.assertEqual(names.resolve(12)['author_name'],'나')
        self.assertFalse(names.resolve(13)['author_is_self'])
    def test_actual_contact_feeder_prefers_saved_name(self):
        names=NameIndex();names.add_contact(1,'저장한 이름','기본 닉네임')
        names.add_contact(1,'','기본 닉네임')
        self.assertEqual(names.resolve(1)['author_name'],'저장한 이름')
        names.add_contact(1,'다른 저장명','기본 닉네임')
        self.assertEqual(names.resolve(1)['author_name_status'],'conflict')

class FinalGuard(unittest.TestCase):
    def test_self_role_even_if_own_profile_name_is_available(self):
        from pathlib import Path
        from unittest.mock import patch
        from room_reader import sender_names
        class Reader:
            data=Path('/fictional/chat_data')
            def __init__(self):self.snapshots=[]
            def database(self,path):
                con=sqlite3.connect(':memory:');con.row_factory=sqlite3.Row
                if path.name=='TalkUserDB.edb':
                    con.execute('CREATE TABLE talkUser(userId INTEGER,nickName TEXT,friendNickName TEXT,linkId INTEGER)')
                    con.execute("INSERT INTO talkUser VALUES(1,'가상 본인','',0)")
                    con.execute('CREATE TABLE Profile(userId INTEGER,nickname TEXT)')
                else:
                    con.execute('CREATE TABLE chatLogs(authorId INTEGER)');con.execute('INSERT INTO chatLogs VALUES(1)')
                self.snapshots.append({});return con
        meta=sqlite3.connect(':memory:');meta.row_factory=sqlite3.Row
        meta.execute('CREATE TABLE chatRoomList(chatId INTEGER,type TEXT)');meta.execute("INSERT INTO chatRoomList VALUES(99,'MemoChat')")
        try:
            for present in (True,False):
                with self.subTest(profile_present=present):
                    with patch.object(Path,'is_file',lambda path:present or path.name!='TalkUserDB.edb'):
                        index=sender_names(Reader(),meta,{'linkId':0},{'1'})
                    self.assertEqual(index.resolve(1)['author_name_status'],'self');self.assertTrue(index.resolve(1)['author_is_self'])
        finally:meta.close()
    def test_final_guard_failure_cannot_report_success(self):
        import contextlib,io
        from unittest.mock import patch
        import room_reader
        class Reader:
            def __init__(self):
                self.pid=1;self.created_at_filetime=1;self.initial_private=1
                self.read_bytes=0;self.contexts=0;self.literal_candidates=0;self.envelope_stats=None
            def database(self,path):
                con=sqlite3.connect(':memory:');con.row_factory=sqlite3.Row
                con.execute('CREATE TABLE chatRoomList(chatId INTEGER,type TEXT,chatRoomTitle TEXT,titleDisplayMembers TEXT,lastUpdatedAt INTEGER,directChatMemberId INTEGER,linkId INTEGER)')
                con.execute("INSERT INTO chatRoomList VALUES(1,'DirectChat','가상 방','0',1,2,0)")
                return con
            @property
            def data(self):
                from pathlib import Path
                return Path('/fictional/chat_data')
            def guard(self):raise AssertionError('APP_MEMORY_LIMIT')
            def close(self):pass
        stream=io.StringIO()
        with patch.object(room_reader,'Reader',Reader),patch('sys.argv',['room_reader.py','rooms','--name','가상 방']),contextlib.redirect_stdout(stream):
            code=room_reader.main()
        result=json.loads(stream.getvalue())
        self.assertEqual(code,2);self.assertEqual(result['status'],'BLOCKED')
        self.assertEqual(result['reason'],'APP_MEMORY_LIMIT')

if __name__=='__main__':unittest.main()
