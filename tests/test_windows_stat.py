"""Regression for observed Windows path-stat/fstat creation/mode differences."""
from types import SimpleNamespace
import stat
import unittest
from reader_image import _stat_identity
from reader_accounts import _identity
from reader_x86 import _stat_key


class WindowsStatIdentity(unittest.TestCase):
    def values(self, **changes):
        data=dict(st_dev=7,st_ino=11,st_size=40,st_mtime_ns=100,
                  st_ctime_ns=100,st_birthtime_ns=100,
                  st_mode=stat.S_IFREG|0o777,st_file_attributes=32,st_reparse_tag=0)
        data.update(changes)
        return SimpleNamespace(**data)

    def test_path_and_handle_metadata_for_same_file(self):
        path=self.values()
        handle=self.values(st_ctime_ns=220,st_mode=stat.S_IFREG|0o666)
        for identity in (_stat_identity,_identity,_stat_key):
            self.assertEqual(identity(path),identity(handle))

    def test_replaced_object_and_different_object_kind_still_rejected(self):
        original=self.values()
        for identity in (_stat_identity,_identity,_stat_key):
            self.assertNotEqual(identity(original),identity(self.values(st_ino=12)))
            self.assertNotEqual(identity(original),identity(self.values(st_dev=8)))
        for identity in (_identity,_stat_key):
            self.assertNotEqual(identity(original),identity(self.values(st_mode=stat.S_IFDIR|0o777)))

    def test_birthtime_and_content_metadata_remain_bound(self):
        original=self.values()
        for identity in (_stat_identity,_stat_key):
            for change in ({'st_birthtime_ns':101},{'st_mtime_ns':101},{'st_size':41}):
                self.assertNotEqual(identity(original),identity(self.values(**change)))

    def test_older_stat_without_birthtime_preserves_ctime(self):
        before=self.values();after=self.values(st_ctime_ns=101)
        del before.st_birthtime_ns;del after.st_birthtime_ns
        for identity in (_stat_identity,_stat_key):
            self.assertNotEqual(identity(before),identity(after))


if __name__=='__main__':unittest.main()
