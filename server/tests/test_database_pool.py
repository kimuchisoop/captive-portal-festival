"""Connection reuse in database.transaction: same connection when clean, never carried state."""
import sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import database
from database import transaction,clear_pool
from mysql_fixture import new_database,root_execute

class ConnectionReuseTests(unittest.TestCase):
    def setUp(self):
        clear_pool();self.c=new_database()
    def tearDown(self):
        clear_pool()
    def connection_id(self,write=False):
        with transaction(self.c,write) as db:return db.execute('SELECT CONNECTION_ID() AS id').fetchone()['id']

    def test_clean_transactions_share_one_connection(self):
        first=self.connection_id(True)
        self.assertEqual(self.connection_id(),first);self.assertEqual(self.connection_id(True),first)

    def test_session_state_never_carries_over(self):
        with transaction(self.c,True) as db:
            db.execute("SET @carried=1, SESSION time_zone='+09:00', SESSION sql_mode='', NAMES latin1")
            db.execute('CREATE TEMPORARY TABLE carried (id INT)')
            db.execute("SELECT GET_LOCK('carried-lock',0)")
            first=db.execute('SELECT CONNECTION_ID() AS id').fetchone()['id']
        with transaction(self.c) as db:
            row=db.execute('SELECT CONNECTION_ID() AS id,@carried AS carried,@@session.time_zone=@@global.time_zone AS tz,'
                           '@@session.sql_mode=@@global.sql_mode AS mode,@@collation_connection AS collation,@@autocommit AS auto,'
                           "IS_USED_LOCK('carried-lock') AS used").fetchone()
            temporary=db.execute("SELECT COUNT(*) AS n FROM information_schema.INNODB_TEMP_TABLE_INFO WHERE NAME LIKE '%carried%'").fetchone()['n']
        self.assertEqual(row['id'],first)
        self.assertEqual((row['carried'],row['tz'],row['mode'],row['collation'],row['auto'],row['used']),(None,1,1,'utf8mb4_bin',0,None))
        self.assertEqual(temporary,0)

    def test_failed_transaction_connection_is_not_reused(self):
        first=self.connection_id()
        with self.assertRaises(RuntimeError):
            with transaction(self.c,True) as db:
                self.assertEqual(db.execute('SELECT CONNECTION_ID() AS id').fetchone()['id'],first)
                raise RuntimeError('application failure')
        self.assertNotEqual(self.connection_id(),first)
        lock='festival-wifi:'+__import__('hashlib').sha256(self.c['database'].encode()).hexdigest()[:32]
        with transaction(self.c) as db:self.assertIsNone(db.execute('SELECT IS_USED_LOCK(?) AS used',(lock,)).fetchone()['used'])

    def test_old_or_dropped_connections_are_replaced(self):
        first=self.connection_id()
        with patch.object(database,'POOL_MAX_AGE_SECONDS',0):second=self.connection_id()
        self.assertNotEqual(second,first)
        third=self.connection_id();self.assertNotEqual(third,second)  # the aged one was closed, not kept
        root_execute(['KILL '+str(third)])
        fourth=self.connection_id();self.assertNotEqual(fourth,third)

    def test_idle_connections_are_bounded_and_separate_per_target(self):
        other=new_database()
        with transaction(self.c) as a, transaction(other) as b:
            self.assertNotEqual(a.execute('SELECT DATABASE() AS d').fetchone()['d'],b.execute('SELECT DATABASE() AS d').fetchone()['d'])
        opened=[transaction(self.c) for _ in range(database.POOL_IDLE_LIMIT+3)]
        for t in opened:t.__enter__()
        for t in opened:t.__exit__(None,None,None)
        self.assertEqual(len(database._pool[database._pool_key(self.c)]),database.POOL_IDLE_LIMIT)

if __name__=='__main__':unittest.main()
