"""Prepared pure regression cases. Not executed while the user's test hold is active."""
import sys,json,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'.deps')]
from app import ApiError
from workflow_common import strict_json,encode_cursor,decode_cursor,policy,request_value
from workflow_backup import cell
from workflow_database import inspect_grants

class Example:
    key=b'fixture-only-not-a-runtime-secret'
    config={'workflow_policy':{'approved':True,'review_valid_seconds':86400,'cursor_valid_seconds':900,'export_row_limit':100000,'export_range_seconds':2678400,'owner_active_jobs':1,'heartbeat_seconds':10,'stale_after_seconds':30,'activation_grace_seconds':60}}
    clock=2000
    def now(self):return self.clock

class WorkflowContractTests(unittest.TestCase):
    def test_duplicate_json_keys_and_nonfinite_numbers_are_rejected(self):
        for raw in (b'{"a":1,"a":2}',b'{"a":NaN}',b'{"a":Infinity}'):
            with self.assertRaises(ValueError):strict_json(raw)

    def test_bigint_values_do_not_lose_precision(self):
        for codec,number in [('i64-decimal',-(2**63)),('i64-decimal',2**63-1),('u64-decimal',2**64-1)]:
            column={'codec':codec,'nullable':False,'name':'integer'}
            encoded=cell(column,number)
            self.assertIsInstance(encoded,str);self.assertEqual(cell(column,encoded,True),number)

    def test_noncanonical_integer_and_overflow_are_rejected(self):
        column={'codec':'u64-decimal','nullable':False,'name':'integer'}
        for value in ('01','-0','+1','1e3','-1',str(2**64)):
            with self.assertRaises(ValueError):cell(column,value,True)

    def test_sql_null_and_text_null_are_distinct(self):
        column={'codec':'utf8','nullable':True,'name':'text'}
        self.assertIsNone(cell(column,None));self.assertEqual(cell(column,'null'),'null');self.assertEqual(cell(column,''),'')
        with self.assertRaises(ValueError):cell({**column,'nullable':False},None)

    def test_json_cell_keeps_unicode_boolean_and_null(self):
        column={'codec':'json-object-v1','nullable':False,'name':'values_json'}
        value=dict(name_ja='学校祭',name_en=None,ssid=None,contact_ja=None,contact_en=None,period_confirmed=False,service_start_utc=None,service_end_utc=None)
        encoded=cell(column,value)
        self.assertEqual(json.loads(encoded),value);self.assertEqual(cell(column,encoded,True),encoded)

    def test_cursor_is_bound_to_owner_scope_and_filters(self):
        s=Example();cursor=encode_cursor(s,'search','owner-a',[1,2],{'event':'festival'})
        self.assertEqual(decode_cursor(s,cursor,'search','owner-a',{'event':'festival'})[0],[1,2])
        for scope,owner,context in [('content','owner-a',{'event':'festival'}),('search','owner-b',{'event':'festival'}),('search','owner-a',{'event':'other'})]:
            with self.assertRaises(ApiError):decode_cursor(s,cursor,scope,owner,context)
        with self.assertRaises(ApiError):decode_cursor(s,cursor[:-1]+('0' if cursor[-1]!='0' else '1'),'search','owner-a',{'event':'festival'})

    def test_expired_cursor_cannot_extend_its_deadline(self):
        s=Example();cursor=encode_cursor(s,'search','owner',1,None);s.clock+=901
        with self.assertRaises(ApiError) as error:decode_cursor(s,cursor,'search','owner',None)
        self.assertEqual(error.exception.code,'cursor_expired')

    def test_unapproved_policy_never_becomes_enabled_by_defaults(self):
        s=Example();s.config={'workflow_policy':{**Example.config['workflow_policy'],'approved':False}}
        with self.assertRaises(ApiError) as error:policy(s)
        self.assertEqual(error.exception.status,503)

    def test_review_body_rejects_unknown_fields_and_noncanonical_uuid(self):
        value=dict(expected_version=1,content_sha256='a'*64,note=None)
        self.assertEqual(request_value('recordEventInformationReview',value),value)
        with self.assertRaises(ApiError):request_value('recordEventInformationReview',{**value,'created_by':'forged'})
        with self.assertRaises(ApiError):request_value('commitLegacyEventPlanImport',dict(report_id='ABC',report_sha256='a'*64,expected_config_sha256='b'*64))

    def grants(self):
        rules=json.loads((ROOT/'workflow-privileges.json').read_text(encoding='utf-8'))
        result=[]
        for row in rules['runtime']:
            privileges=['SELECT','INSERT']
            if row['delete']:privileges.append('DELETE')
            if row['update_columns']:privileges.append('UPDATE ('+','.join('`'+c+'`' for c in row['update_columns'])+')')
            result.append('GRANT '+', '.join(privileges)+' ON `festival_db`.`'+row['table']+'` TO `fixture`@`localhost`')
        return result

    def test_table_and_multiple_column_grants_match_literal_underscore_database(self):
        result=inspect_grants(self.grants(),'festival_db','NONE')
        self.assertTrue(result['minimal'],result)

    def test_database_wildcard_and_inherited_role_are_not_reported_as_minimal(self):
        self.assertFalse(inspect_grants(['GRANT SELECT,INSERT,UPDATE,DELETE ON `festival_db`.* TO `fixture`@`localhost`'],'festival_db','NONE')['minimal'])
        self.assertFalse(inspect_grants(self.grants(),'festival_db','`extra_role`@`localhost`')['minimal'])

if __name__=='__main__':unittest.main()
