import importlib.util
import pathlib
import unittest
import ast

SOURCE=pathlib.Path(__file__).resolve().parents[1]/'experimental/room-preflight/preflight.py'
spec=importlib.util.spec_from_file_location('room_preflight',SOURCE)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class RoomPreflightTests(unittest.TestCase):
    def test_exact_unique_and_cached_id(self):
        r={'status':'ROOMS_READ','rooms':[{'title':'example','chat_id':'123'}],'limit_reached':False}
        self.assertEqual(module.select_exact(r,'example','123')['chat_id'],'123')
        for name,cid in [('exam',None),('example','456')]:
            with self.assertRaises(RuntimeError):module.select_exact(r,name,cid)
        r['rooms']*=2
        with self.assertRaises(RuntimeError):module.select_exact(r,'example')
    def test_only_allowlisted_room_metadata_is_returned(self):
        r={'status':'ROOMS_READ','rooms':[{'title':'example','chat_id':'123','type':'TestChat','unexpected':'not forwarded'}]}
        self.assertEqual(set(module.select_exact(r,'example')),{'title','chat_id','type'})
    def test_incomplete_and_missing(self):
        for r in ({'status':'BLOCKED'},{'status':'ROOMS_READ','limit_reached':True},{'status':'ROOMS_READ','rooms':[]}):
            with self.assertRaises(RuntimeError):module.select_exact(r,'example')
    def test_no_window_is_not_send_ready(self):
        self.assertEqual(module.classify([],True),'TARGET_WINDOW_NOT_FOUND')
        self.assertEqual(module.classify([{}],True),'WINDOW_FOUND_CHAT_ID_BINDING_UNVERIFIED')
        self.assertEqual(module.classify([{},{}],True),'AMBIGUOUS_WINDOW_TITLE')
        self.assertEqual(module.classify([],False),'WINDOW_INVENTORY_INCOMPLETE')
    def test_no_send_or_ui_mutation_api(self):
        tree=ast.parse(SOURCE.read_text())
        forbidden={'PostMessageW','SendMessageW','SendMessageTimeoutW','SendInput','SetWindowTextW','SetForegroundWindow','ShowWindow','SetClipboardData','WriteProcessMemory','ShellExecuteW','CreateRemoteThread'}
        attrs={n.attr for n in ast.walk(tree) if isinstance(n,ast.Attribute)}
        self.assertFalse(forbidden&attrs)
        self.assertNotIn('attachment_send',SOURCE.read_text())

if __name__=='__main__':unittest.main()
