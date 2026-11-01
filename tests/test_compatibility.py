"""Build compatibility and capability isolation; fictional PE files only."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import struct
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import reader_config
import room_reader
import kakao_read_win

OLD='abf66658c84c7a9a2f8300f9c3304a858bcacf8e3867bad33a79d769fd5321c1'
NEW='d7781cf275a6f4f23547e8e698005d0e8dbb78e205a34baa2eda3ea158fc64d1'


def fake_pe(machine=0x8664,magic=0x20b):
    data=bytearray(512);data[:2]=b'MZ';struct.pack_into('<I',data,0x3c,128)
    data[128:132]=b'PE\0\0';struct.pack_into('<H',data,132,machine)
    struct.pack_into('<H',data,148,64);struct.pack_into('<H',data,152,magic)
    return data


class Compatibility(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='kakao-fictional-pe-')
        self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name);self.app=self.root/'KakaoTalk.exe'
        self.app.write_bytes(fake_pe())

    def report(self,digest=NEW,primary=None,fallback=None):
        with patch.object(reader_config,'installation_digest',return_value=digest), \
             patch.object(reader_config,'file_version',return_value='26.9.1.5339'):
            return reader_config.installation_report(primary or self.app,
                room_reader.READER_SUPPORTED,OLD,fallback=fallback)

    def test_hash_boolean_contract_and_multiple_fixed_hashes(self):
        digest=hashlib.sha256(self.app.read_bytes()).hexdigest()
        self.assertIs(reader_config.installation_matches(self.app,digest),True)
        self.assertIs(reader_config.installation_matches(self.app,'0'*64),False)
        self.assertEqual(reader_config.matched_installation(self.app,{digest:'fictional'},architecture='x64'),digest)
        self.assertIsNone(reader_config.matched_installation(self.app,{digest},maximum_bytes=100))
        self.assertIsNone(reader_config.matched_installation(self.app,{digest},architecture='x86'))

    def test_new_build_is_reader_only_and_doctor_does_not_claim_read_success(self):
        report=self.report()
        self.assertTrue(report['reader_supported'])
        self.assertFalse(report['room_open_supported'])
        self.assertFalse(report['self_attachment_supported'])
        self.assertEqual(report['read_verification'],'NOT_RUN')
        self.assertEqual(report['installation_sha256'],NEW)
        self.assertEqual(report['matched_app_version'],'26.9.1.5339')

    def test_doctor_cli_only_checks_installation_and_preserves_capability_flags(self):
        output=io.StringIO()
        with patch.object(room_reader,'APP',self.app), \
             patch.object(reader_config,'installation_digest',return_value=NEW), \
             patch.object(reader_config,'file_version',return_value='26.9.1.5339'), \
             patch.object(kakao_read_win,'os',SimpleNamespace(name='nt',environ={})), \
             patch.object(kakao_read_win,'read') as read, \
             patch.object(room_reader.C,'WinDLL',create=True) as native, \
             patch('sys.argv',['kakao_read_win.py','doctor']),contextlib.redirect_stdout(output):
            self.assertEqual(kakao_read_win.main(),0)
        result=json.loads(output.getvalue())
        self.assertEqual(result['status'],'READY')
        self.assertEqual(result['read_verification'],'NOT_RUN')
        self.assertFalse(result['app_data_read'])
        self.assertFalse(result['app_launched'])
        self.assertFalse(result['self_attachment_supported'])
        self.assertFalse(result['room_open_supported'])
        read.assert_not_called();native.assert_not_called()

    def test_old_build_remains_eligible_for_existing_experiments(self):
        self.assertIsInstance(room_reader.EXPECTED,str)
        self.assertEqual(room_reader.EXPECTED,OLD)
        report=self.report(OLD)
        self.assertTrue(report['reader_supported'])
        self.assertTrue(report['room_open_supported'])
        self.assertTrue(report['self_attachment_supported'])

    def test_matching_version_and_unknown_hash_still_blocked(self):
        report=self.report('a'*64)
        self.assertEqual(report['app_version'],'26.9.1.5339')
        self.assertEqual(report['reason'],'INSTALLATION_NOT_REVIEWED')
        self.assertFalse(report['supported_installation'])

    def test_x86_is_blocked_even_if_hash_would_be_allowed(self):
        self.app.write_bytes(fake_pe(0x14c,0x10b))
        report=self.report()
        self.assertEqual(report['reason'],'APP_X86_UNSUPPORTED')
        self.assertEqual(report['app_architecture'],'x86')
        self.assertFalse(report['reader_supported'])
        self.assertIn('Do not replace',report['next_action'])

    def test_x86_standard_fallback_is_diagnosed_without_selecting_it(self):
        self.app.write_bytes(fake_pe(0x14c,0x10b))
        report=self.report(primary=self.root/'missing.exe',fallback=self.app)
        self.assertEqual(report['app_path'],str(self.app))
        self.assertEqual(report['reason'],'APP_X86_UNSUPPORTED')
        self.assertFalse(report['supported_installation'])

    def test_nonstandard_x64_fallback_does_not_pass_the_fixed_reader_path(self):
        report=self.report(primary=self.root/'missing.exe',fallback=self.app)
        self.assertEqual(report['reason'],'APP_INSTALLATION_PATH_UNSUPPORTED')
        self.assertFalse(report['supported_installation'])

    def test_invalid_pe_and_architecture_combinations_are_rejected(self):
        variants=[b'not an executable',fake_pe(0x14c,0x20b)]
        for offset in (0,0xffffffff):
            data=fake_pe();struct.pack_into('<I',data,0x3c,offset);variants.append(data)
        data=fake_pe();data[128:132]=b'NOPE';variants.append(data)
        data=fake_pe();struct.pack_into('<H',data,148,65535);variants.append(data)
        for data in variants:
            with self.subTest(data_length=len(data)):
                self.app.write_bytes(data)
                report=self.report()
                self.assertFalse(report['supported_installation'])
                self.assertIn(report['reason'],('INVALID_APP_EXECUTABLE','APP_ARCHITECTURE_UNSUPPORTED'))

    def test_missing_file_and_size_limit_have_specific_reasons(self):
        result=reader_config.installation_report(self.root/'missing.exe',room_reader.READER_SUPPORTED,OLD)
        self.assertEqual(result['reason'],'APP_NOT_FOUND')
        with patch.object(reader_config,'installation_digest',return_value=None):
            result=reader_config.installation_report(self.app,room_reader.READER_SUPPORTED,OLD)
        self.assertEqual(result['reason'],'APP_FILE_SIZE_LIMIT')

    def test_default_reader_rejects_new_build_before_native_access(self):
        with patch.object(room_reader,'APP',self.app), \
             patch.object(reader_config,'installation_digest',return_value=NEW), \
             patch.object(room_reader.C,'WinDLL',create=True) as native:
            with self.assertRaisesRegex(AssertionError,'INSTALLATION_CHANGED'):
                room_reader.Reader()
            native.assert_not_called()

    def test_explicit_reader_policy_accepts_new_build_without_changing_default(self):
        with patch.object(room_reader,'APP',self.app), \
             patch.object(reader_config,'installation_digest',return_value=NEW), \
             patch.object(room_reader.C,'WinDLL',side_effect=RuntimeError('NATIVE_BOUNDARY'),create=True):
            with self.assertRaisesRegex(RuntimeError,'NATIVE_BOUNDARY'):
                room_reader.Reader(allowed_installations=room_reader.READER_SUPPORTED)
        self.assertEqual(room_reader.EXPECTED,OLD)

    def test_environment_and_local_allowlist_cannot_enable_unknown_build(self):
        unknown='b'*64
        local=self.root/'KakaoReader';local.mkdir()
        (local/'verified_installs.json').write_text(json.dumps({unknown:{'version':'26.9.1.5339'}}))
        with patch.dict(os.environ,{'KAKAO_READER_PROBE_SHA256':unknown,'LOCALAPPDATA':str(self.root)}), \
             patch.object(reader_config,'installation_digest',return_value=unknown), \
             patch.object(room_reader,'APP',self.app), \
             patch.object(room_reader.C,'WinDLL',create=True) as native:
            with self.assertRaisesRegex(AssertionError,'INSTALLATION_CHANGED'):
                room_reader.Reader(allowed_installations=room_reader.READER_SUPPORTED)
            with self.assertRaisesRegex(AssertionError,'UNREVIEWED_INSTALLATION_POLICY'):
                room_reader.Reader(allowed_installations={unknown})
            native.assert_not_called()

    def test_read_cli_opts_in_and_receipt_reports_actual_matched_hash(self):
        connection=sqlite3.connect(':memory:');connection.row_factory=sqlite3.Row
        connection.execute('CREATE TABLE chatRoomList(chatId,type,chatRoomTitle,titleDisplayMembers,lastUpdatedAt,directChatMemberId,linkId)')
        connection.execute("INSERT INTO chatRoomList VALUES(1,'MemoChat','Fictional self','',1,1,0)")
        fake=SimpleNamespace(data=self.root,database=Mock(return_value=connection),
            installation=NEW,pid=123,created_at_filetime=456,initial_private=100,
            guard=lambda:100,read_bytes=0,contexts=0,literal_candidates=0,
            snapshots=[],snapshot_retries=0,envelope_stats=None,started=time.monotonic(),close=Mock())
        output=io.StringIO()
        with patch.object(room_reader,'Reader',return_value=fake) as constructor, \
             patch.object(room_reader,'selected_messages',return_value={'messages':[]}), \
             patch('sys.argv',['room_reader.py','self','--limit','1']), \
             contextlib.redirect_stdout(output):
            self.assertEqual(room_reader.main(),0)
        constructor.assert_called_once_with(allowed_installations=room_reader.READER_SUPPORTED)
        result=json.loads(output.getvalue())
        self.assertEqual(result['connection']['installation_sha256'],NEW)
        self.assertIsInstance(result['connection']['installation_sha256'],str)
        fake.close.assert_called_once()


if __name__=='__main__':unittest.main()
