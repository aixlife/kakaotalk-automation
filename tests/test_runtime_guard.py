"""Interpreter-level safety and standalone skill installation checks."""
from pathlib import Path
import subprocess
import sys
import tempfile
import shutil
import hashlib
import unittest
from reader_config import installation_matches

ROOT=Path(__file__).resolve().parents[1]
SKILL=ROOT/'skills/kakaotalk-mac'

class RuntimeGuard(unittest.TestCase):
    def test_installation_hash_is_streamed_and_oversize_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix='kakao-fictional-binary-') as temporary:
            sample=Path(temporary)/'sample';sample.write_bytes(b'fictional')
            digest=hashlib.sha256(b'fictional').hexdigest()
            self.assertTrue(installation_matches(sample,digest))
            self.assertFalse(installation_matches(sample,'0'*64))
            self.assertFalse(installation_matches(sample,digest,maximum_bytes=8))
            self.assertFalse(installation_matches(Path(temporary)/'absent',digest))

    def test_optimized_interpreter_cannot_disable_runtime_assertions(self):
        result=subprocess.run([sys.executable,'-O',str(SKILL/'scripts/windows/kakao_read_win.py'),'doctor'],capture_output=True,text=True,timeout=5)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('OPTIMIZED_PYTHON_UNSUPPORTED',result.stderr)

    def test_copied_skill_has_dependencies_license_and_working_entrypoint(self):
        with tempfile.TemporaryDirectory(prefix='kakao-synthetic-install-') as temporary:
            installed=Path(temporary)/'kakaotalk-mac'
            shutil.copytree(SKILL,installed,ignore=shutil.ignore_patterns('__pycache__'))
            self.assertTrue((installed/'LICENSE').is_file())
            self.assertEqual((installed/'scripts/windows/requirements.txt').read_text().strip(),'cryptography==47.0.0')
            result=subprocess.run([sys.executable,str(installed/'scripts/windows/kakao_read_win.py'),'--help'],capture_output=True,text=True,timeout=5)
            self.assertEqual(result.returncode,0)
            self.assertIn('doctor',result.stdout)
            self.assertNotIn('self-text',result.stdout)

if __name__=='__main__':unittest.main()
