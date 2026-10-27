"""Run synthetic tests and compile source without reading any app data."""
import ast
from pathlib import Path
import sys
import unittest

if sys.version_info < (3,11):
    raise SystemExit('Python 3.11 or newer is required; use the supported interpreter for checks.')

root=Path(__file__).resolve().parents[1]
runtime=root/'skills/kakaotalk-mac/scripts/windows'
sys.path.insert(0,str(runtime))
files=sorted(p for folder in ('skills','experimental','tools','tests')
             for p in (root/folder).rglob('*.py') if '__pycache__' not in p.parts)
for path in files:
    ast.parse(path.read_text(encoding='utf8'),filename=str(path.relative_to(root)))
suite=unittest.defaultTestLoader.discover(str(root/'tests'))
result=unittest.TextTestRunner(verbosity=2).run(suite)
print(f'Source parsed: {len(files)} modules; app data read: 0')
raise SystemExit(0 if result.wasSuccessful() else 2)
