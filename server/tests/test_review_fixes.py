"""Prepared regression cases for docs7. Not executed during the test hold."""
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'.deps')]
import unittest
from unittest.mock import patch
import test_service as service_tests
from app import uid,utc
from jobs import notify
from operations import backup_inventory
from runtime_guard import owned_runtime
from capacity_policy import make_plan,apply_plan


class ReviewFixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):service_tests.Tests.setUpClass.__func__(cls)
    setUp=service_tests.Tests.setUp
    tearDown=service_tests.Tests.tearDown
    get=service_tests.Tests.get
    post=service_tests.Tests.post
    login=service_tests.Tests.login
    count=service_tests.Tests.count
    visitor=service_tests.Tests.visitor
    context=service_tests.Tests.context
    consent_data=service_tests.Tests.consent_data

    def test_saved_consent_replays_after_service_closes(self):
        data=self.consent_data();key=uid()
        first=self.post('/v1/consents',data,key)
        self.assertEqual(first.status_code,201,first.json)
        self.s.config['service_end_utc']=utc(self.s.now()-1)
        replay=self.post('/v1/consents',data,key)
        self.assertEqual((replay.status_code,replay.json),(first.status_code,first.json))
        self.assertEqual(self.count('consents'),1)
        self.assertEqual(self.post('/v1/consents',data,uid()).status_code,410)

    def test_saved_consent_replays_after_terms_change(self):
        data=self.consent_data();key=uid()
        first=self.post('/v1/consents',data,key)
        self.assertEqual(first.status_code,201,first.json)
        self.s.term_text['ja']+='\n新しい利用条件（専用QA用）'
        self.assertEqual(self.post('/v1/consents',data,key).json,first.json)
        self.assertEqual(self.post('/v1/consents',data,uid()).status_code,409)
        self.assertEqual(self.count('consents'),1)

    def test_saved_information_plan_replays_after_config_changes(self):
        self.login();info=self.get('/v1/admin/event-information').json
        data={'values':info['values'],'config_sha256':info['config_sha256']};key=uid()
        first=self.post('/v1/admin/event-information/plans',data,key)
        self.assertEqual(first.status_code,201,first.json)
        original=(self.home/'config.json').read_bytes()
        (self.home/'config.json').write_bytes(original+b'\n')
        replay=self.post('/v1/admin/event-information/plans',data,key)
        self.assertEqual((replay.status_code,replay.json),(first.status_code,first.json))
        self.assertEqual(self.post('/v1/admin/event-information/plans',data,uid()).status_code,409)
        self.assertEqual(len(list((self.home/'configuration-history').glob('event-info-plan-*.json'))),1)

    def notification(self):
        with self.s.db(True) as db:
            notify(db,self.s.now(),'docs7_regression','専用QAの通知')
            return dict(db.execute("SELECT * FROM notifications WHERE code='docs7_regression'").fetchone())

    def test_old_notification_screen_cannot_ack_reopened_generation(self):
        row=self.notification();self.login('operator')
        path='/v1/admin/notifications/'+row['id']+'/acknowledgements'
        headers={'X-Expected-Generation':str(row['generation'])};key=uid()
        first=self.post(path,key=key,headers=headers)
        self.assertEqual(first.status_code,200,first.json)
        with self.s.db(True) as db:
            notify(db,self.s.now(),'docs7_regression','専用QAの通知',False)
            notify(db,self.s.now(),'docs7_regression','専用QAの通知')
        self.assertEqual(self.post(path,headers=headers).status_code,409)
        # Exact retry returns the prior result, without acknowledging the new event.
        self.assertEqual(self.post(path,key=key,headers=headers).status_code,200)
        with self.s.db() as db:
            state=db.execute('SELECT state,acknowledged_by FROM notifications WHERE id=?',(row['id'],)).fetchone()
        self.assertEqual(state['state'],'open');self.assertIsNone(state['acknowledged_by'])
        newer={'X-Expected-Generation':str(row['generation']+1)}
        conflict=self.post(path,key=key,headers=newer)
        self.assertEqual(conflict.json['code'],'idempotency_conflict')
        self.assertEqual(self.post(path,headers=newer).status_code,200)

    def test_resolved_and_legacy_ack_requests_are_rejected(self):
        row=self.notification();self.login('operator')
        path='/v1/admin/notifications/'+row['id']+'/acknowledgements'
        self.assertEqual(self.post(path).status_code,409)
        with self.s.db(True) as db:notify(db,self.s.now(),'docs7_regression','専用QAの通知',False)
        response=self.post(path,headers={'X-Expected-Generation':str(row['generation'])})
        self.assertEqual(response.json['code'],'notification_resolved')

    def test_capacity_apply_rejects_direct_runtime_locks(self):
        plan=make_plan(self.s);original=(self.home/'config.json').read_bytes()
        for name in ('app','worker'):
            with self.subTest(runtime=name),owned_runtime(self.home,name):
                with self.assertRaises(ValueError):apply_plan(self.s,plan)
            self.assertEqual((self.home/'config.json').read_bytes(),original)

    def test_partial_and_other_files_are_counted_without_deletion(self):
        directory=self.home/'backups';directory.mkdir(exist_ok=True)
        base=f'backup-{self.s.now()}-{uid()}'
        completed=directory/(base+'.sffbackup');completed.write_bytes(b'a'*10)
        partial=directory/(base+'.sffbackup.partial');partial.write_bytes(b'b'*30)
        other=directory/'preserve.bin';other.write_bytes(b'c'*7)
        result=backup_inventory(self.s,limit=1)
        self.assertEqual(result['total_files'],1);self.assertEqual(result['partial_files'],1)
        self.assertEqual(result['total_bytes'],47);self.assertEqual(result['completed_bytes'],10)
        self.assertEqual(result['partial_bytes'],30);self.assertEqual(result['other_regular_bytes'],7)
        self.assertTrue(result['total_bytes_complete']);self.assertEqual(len(result['items']),1)
        self.assertEqual(partial.read_bytes(),b'b'*30);self.assertEqual(other.read_bytes(),b'c'*7)

    def test_filename_breaks_pagination_ties_at_the_same_time(self):
        directory=self.home/'backups';directory.mkdir(exist_ok=True)
        names={f'backup-{self.s.now()}-{uid()}.sffbackup' for _ in range(2)}
        for name in names:(directory/name).write_bytes(b'catalog fixture')
        first=backup_inventory(self.s,limit=1)
        second=backup_inventory(self.s,before=first['next_cursor'],limit=1)
        self.assertEqual({r['filename'] for r in first['items']+second['items']},names)
        self.assertIsNone(second['next_cursor'])

    def test_unreadable_directory_is_not_reported_as_zero_complete(self):
        (self.home/'backups').mkdir(exist_ok=True)
        with patch('operations.os.scandir',side_effect=PermissionError('QA only')):
            result=backup_inventory(self.s)
        self.assertFalse(result['total_bytes_complete']);self.assertFalse(result['directory_scan_complete'])


if __name__=='__main__':unittest.main()
