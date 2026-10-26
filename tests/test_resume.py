"""Resume saved UTF-8 results without rerunning their producer."""
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
import unittest
import kakao_read_win
import reader_rpc

class Resume(unittest.TestCase):
    def test_korean_receipt_roundtrip_only_fetches(self):
        ident='a'*32
        record={'request_id':ident,'request':{'args':['messages','--name','가상 논의방']},
                'execution':{'exit':0,'timeout':False},'outer_execution':{'exit':0},
                'result':{'status':'MESSAGES_READ','messages':[{'text':'가상 한글 원문'}]}}
        seen=[]
        def fetch(payload):
            seen.append(payload)
            return record
        with tempfile.TemporaryDirectory(prefix='kakao-resume-fictional-') as tmp:
            state=Path(tmp);receipt=state/(ident+'.json')
            receipt.write_text(json.dumps(record,ensure_ascii=False),encoding='utf8')
            with patch.object(kakao_read_win,'state_root',lambda:state),patch.object(reader_rpc,'process',fetch):
                result=kakao_read_win.read(SimpleNamespace(command='resume',request_id=ident))
            self.assertEqual(seen,[{'action':'fetch','request_id':ident}])
            self.assertEqual(result['result'],record['result'])
            self.assertEqual(json.loads(receipt.read_text(encoding='utf8'))['result'],record['result'])
            self.assertTrue(result['resumed_without_reexecution'])

if __name__=='__main__':unittest.main()
