import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import json,unittest
from unittest.mock import patch
from app import uid,timestamp
from usage_summary import increment,summary,PREFIX,bucket
import test_service as service_tests

class ExperienceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): service_tests.Tests.setUpClass.__func__(cls)
    setUp=service_tests.Tests.setUp
    tearDown=service_tests.Tests.tearDown
    get=service_tests.Tests.get
    post=service_tests.Tests.post
    login=service_tests.Tests.login
    count=service_tests.Tests.count
    context=service_tests.Tests.context
    visitor=service_tests.Tests.visitor
    consent_data=service_tests.Tests.consent_data

    def test_summary_requires_auth_and_all_four_roles_can_read_aggregate(self):
        self.assertEqual(self.get('/v1/admin/usage-summary').status_code,401)
        for role in ('viewer','operator','records','settings'):
            self.login(role);r=self.get('/v1/admin/usage-summary?day=2026-10-20');self.assertEqual(r.status_code,200);self.assertEqual(len(r.json['hours']),24)
            self.assertNotIn('username',r.get_data(as_text=True));self.assertNotIn('password',r.get_data(as_text=True))

    def test_summary_rejects_invalid_duplicate_and_unknown_queries(self):
        self.login()
        for query in ('day=2026-02-30','day=2026-1-01','day=bad','day=2026-10-20&day=2026-10-21','other=1'):
            self.assertEqual(self.get('/v1/admin/usage-summary?'+query).status_code,400)

    def test_error_responses_count_without_raw_personal_data_and_admin_excluded(self):
        self.clock.value=timestamp('2026-10-19T15:00:00Z')
        self.get('/v1/public?lang=unavailable&private=DO-NOT-STORE')
        self.get('/v1/admin/unknown')
        r=summary(self.s,'2026-10-20');self.assertEqual(r['hours'][0]['client_errors'],1);self.assertEqual(r['total_errors'],1)
        with self.s.db() as db:
            values=json.dumps([dict(r) for r in db.execute('SELECT * FROM meta').fetchall()]);self.assertNotIn('DO-NOT-STORE',values)
        self.assertEqual(summary(self.s,'2026-10-19')['total_errors'],0)

    def test_counter_is_atomic_under_concurrent_errors(self):
        import concurrent.futures
        self.clock.value=timestamp('2026-10-20T03:00:00Z')
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool: list(pool.map(lambda _:increment(self.s,'client_error'),range(12)))
        self.assertEqual(summary(self.s,'2026-10-20')['hours'][12]['client_errors'],12)

    def test_counter_failure_does_not_replace_original_response(self):
        with patch('usage_summary.increment',side_effect=RuntimeError('PRIVATE-ERROR')):
            r=self.get('/v1/public?lang=invalid')
        self.assertEqual(r.status_code,400);self.assertEqual(self.s.unrecorded_usage_errors,1)
        self.assertNotIn('PRIVATE-ERROR',r.get_data(as_text=True))

    def test_consent_counts_jst_boundary_and_english_retry_does_not_duplicate(self):
        self.clock.value=timestamp('2026-10-19T15:00:00Z')
        # Reconfigure only this new QA home to cover the controlled clock.
        c=self.s.config;c['service_start_utc']='2026-10-19T00:00:00Z';c['service_end_utc']='2026-10-22T00:00:00Z'
        payload=self.consent_data();context=payload['context_id']
        english=self.get('/v1/contexts/'+context+'?lang=en').json['terms']
        payload.update(language='en',terms_sha256=english['sha256'])
        key=uid();first=self.post('/v1/consents',payload,key);again=self.post('/v1/consents',payload,key)
        self.assertEqual(first.status_code,201);self.assertEqual(first.json['consent_id'],again.json['consent_id']);self.assertEqual(self.count('consents'),1)
        current=summary(self.s,'2026-10-20');self.assertEqual(current['hours'][0]['consents'],1);self.assertEqual(summary(self.s,'2026-10-19')['total_consents'],0)

    def test_summary_read_does_not_mutate_audit_or_records(self):
        before=self.count('audit');summary(self.s,'2026-10-20');self.assertEqual(self.count('audit'),before)

    def test_aggregate_survives_application_restart_and_real_backup_restore(self):
        from app import create_app
        from stream_backup import backup_stream,restore_stream
        from manage import initialize
        from mysql_fixture import new_database
        self.clock.value=timestamp('2026-10-20T03:00:00Z');increment(self.s,'server_error')
        restarted=create_app(self.home,self.clock).extensions['service']
        self.assertEqual(summary(restarted,'2026-10-20')['hours'][12]['server_errors'],1)
        source=backup_stream(self.s);destination=self.home.parent/'restored-summary'
        restore_stream(source,self.home/'backup.key',destination,new_database())
        restored=initialize(destination,restored=True)
        self.assertEqual(summary(restored,'2026-10-20')['hours'][12]['server_errors'],1)

    def test_page_contains_language_help_and_labeled_accessibility_controls(self):
        r=self.get('/');text=r.get_data(as_text=True)
        for token in ('ja-easy','contrast-high','aria-labelledby="contrast-label"','portal-help-title','portal-copy.js','id="skip-link"'): self.assertIn(token,text)

class LocaleTests(unittest.TestCase):
    def test_windows_sid_is_independent_of_localized_account_encoding(self):
        from security import windows_sid
        from types import SimpleNamespace
        windows_sid.cache_clear()
        try:
            with patch('security.subprocess.run',return_value=SimpleNamespace(stdout=b'"\x93\xfa\x96\x7b","S-1-5-21-1-2-3-1001"\r\n')):
                self.assertEqual(windows_sid(),'S-1-5-21-1-2-3-1001')
        finally: windows_sid.cache_clear()

if __name__=='__main__': unittest.main()
