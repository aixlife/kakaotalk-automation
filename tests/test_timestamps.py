"""Time integrity and date-boundary checks with fictional data only."""
from datetime import datetime,timezone
import unittest
from reader_queries import timestamp_fields

class TimestampIntegrity(unittest.TestCase):
    def test_preserve_saved_seconds_without_rounding(self):
        for raw,kind in ((1792335599,'integer'),(1792335599.875,'real')):
            row=timestamp_fields(raw,'sendAt',1,kind)
            self.assertEqual(row['sent_at'],raw)
            self.assertEqual(row['sent_at_source']['raw_value'],raw)
            self.assertEqual(row['sent_at_source']['rounding_applied'],'none')
            self.assertEqual(datetime.fromisoformat(row['sent_at_kst']).timestamp(),raw)

    def test_milliseconds_keep_fraction_across_kst_midnight(self):
        before=int(datetime(2026,1,1,14,59,59,tzinfo=timezone.utc).timestamp())
        a=timestamp_fields(before*1000+999,'sendAt',1000,'integer')
        b=timestamp_fields((before+1)*1000,'sendAt',1000,'integer')
        self.assertTrue(a['sent_at_kst'].startswith('2026-01-01T23:59:59.999'))
        self.assertTrue(b['sent_at_kst'].startswith('2026-01-02T00:00:00'))
        self.assertEqual(a['sent_at_source']['raw_value'],before*1000+999)

    def test_null_epoch_and_invalid_numbers(self):
        self.assertIsNone(timestamp_fields(None,'sendAt',1,'null')['sent_at'])
        self.assertEqual(timestamp_fields(0,'sendAt',1,'integer')['sent_at'],0)
        for raw in (float('nan'),float('inf'),-1,True,'1000'):
            with self.assertRaises(AssertionError):timestamp_fields(raw,'sendAt',1,'real')
        with self.assertRaises(AssertionError):timestamp_fields(1000,'sendAt',60,'integer')
        with self.assertRaises(AssertionError):timestamp_fields(1000,'sendAt',1,'text')

if __name__=='__main__':unittest.main()
