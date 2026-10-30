import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import io,json,struct,unittest
from unittest.mock import patch
from cryptography.fernet import Fernet,InvalidToken
from stream_encryption import Writer,open_reader,MAGIC
from stream_backup import backup_stream,inspect,compare_restored
from backup_review import decrypt_check,restore_check
from recovery_kit import create_kit,restore_kit,consume,safe_name
from preflight import inspect_home
from mysql_fixture import new_database
from manage import initialize
import test_service as service_tests

def encrypted(data,key):
    raw=io.BytesIO();writer=Writer(raw,key);writer.write(data);writer.finish();return raw.getvalue()
def decrypted(data,key):
    with open_reader(io.BytesIO(data),key) as reader: return reader.read()
class FrameTests(unittest.TestCase):
    def test_multiframe_and_empty_roundtrip(self):
        key=Fernet.generate_key()
        for data in (b'',b'a'*3_000_007): self.assertEqual(decrypted(encrypted(data,key),key),data)
    def test_wrong_key_and_tamper_rejected(self):
        key=Fernet.generate_key();blob=encrypted(b'hello',key)
        with self.assertRaises(InvalidToken): decrypted(blob,Fernet.generate_key())
        changed=bytearray(blob);changed[-9]^=1
        with self.assertRaises((ValueError,InvalidToken)): decrypted(changed,key)
    def test_truncated_and_appended_rejected(self):
        key=Fernet.generate_key();blob=encrypted(b'a'*1_100_000,key)
        for changed in (blob[:-1],blob[:-150],blob+b'anything'):
            with self.assertRaises((ValueError,InvalidToken)): decrypted(changed,key)
    def test_mix_reorder_and_duplicate_frames_rejected(self):
        key=Fernet.generate_key();one=encrypted(b'a'*3_000_000,key);two=encrypted(b'b'*3_000_000,key)
        def split(blob):
            offset=len(MAGIC);chunks=[]
            while offset<len(blob):
                n=struct.unpack('>I',blob[offset:offset+4])[0]+4;chunks.append(blob[offset:offset+n]);offset+=n
            return chunks
        a,b=split(one),split(two)
        for frames in ([a[0],a[2],a[1],*a[3:]],[a[0],b[1],*a[2:]],[a[0],a[1],a[1],*a[2:]]):
            with self.assertRaises((ValueError,InvalidToken)): decrypted(MAGIC+b''.join(frames),key)
    def test_oversized_length_and_unsafe_paths_refused(self):
        key=Fernet.generate_key()
        with self.assertRaises(ValueError): decrypted(MAGIC+struct.pack('>I',2**31),key)
        for path in ('../x','files/../../x','C:/x','files/a\\x','/files/x','other/x','files/a:stream'):
            with self.assertRaises(ValueError): safe_name(path)

class RecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): service_tests.Tests.setUpClass.__func__(cls)
    setUp=service_tests.Tests.setUp
    tearDown=service_tests.Tests.tearDown
    login=service_tests.Tests.login
    get=service_tests.Tests.get
    post=service_tests.Tests.post
    count=service_tests.Tests.count
    def test_stream_inventory_and_browser_check_permissions(self):
        source=backup_stream(self.s);self.login('records')
        items=self.get('/v1/admin/backups').json['items'];self.assertEqual(items[0]['filename'],source.name)
        self.assertEqual(self.post('/v1/admin/backups/'+source.name+'/checks').json['status'],'passed')
    def test_large_web_verification_redirects_to_cli_before_write_lock(self):
        source=backup_stream(self.s);self.login('records');before=self.count('backup_checks')
        with patch('backup_review.WEB_VERIFY_BYTES',1):
            result=self.post('/v1/admin/backups/'+source.name+'/checks')
        self.assertEqual(result.status_code,409);self.assertEqual(result.json['code'],'verify_at_terminal')
        self.assertEqual(self.count('backup_checks'),before)
    def test_stream_tamper_and_partial_are_not_successful(self):
        source=backup_stream(self.s);source.write_bytes(source.read_bytes()[:-1]);self.assertEqual(decrypt_check(self.s,source.name)['status'],'failed')
        self.login('records');self.assertNotEqual(self.get('/v1/admin/backups').json['items'][0]['verification'],'decrypt_checked')
    def test_stream_restore_existing_database_refused(self):
        source=backup_stream(self.s)
        from stream_backup import restore_stream
        with self.assertRaises(ValueError): restore_stream(source,self.home/'backup.key',Path(self.temp.name)/'refused',self.s.db_settings)
    def test_recovery_refuses_running_service_and_same_key_parent(self):
        archive=Path(self.temp.name)/'archives';archive.mkdir()
        with self.assertRaises(ValueError): create_kit(self.s,archive/'x',archive/'keys')
        runtime=self.home/'runtime';runtime.mkdir();(runtime/'current.json').write_text('{"state":"running"}')
        with self.assertRaises(ValueError): create_kit(self.s,archive/'x',Path(self.temp.name)/'keys')
    def test_preflight_collects_multiple_errors_and_is_safe(self):
        (self.home/'session.key').write_bytes(b'bad')
        c=self.s.config.copy();c['origin']='https://wrong.example.org';(self.home/'config.json').write_text(json.dumps(c))
        report=inspect_home(self.home,online=False,package_check=False)
        self.assertGreaterEqual(report['failed'],2);self.assertFalse(report['production_ready'])
        self.assertNotIn(self.s.db_settings['password'],json.dumps(report));self.assertFalse(report['mutation_performed'])
    def test_preflight_online_success_and_readonly(self):
        before=self.count('audit');report=inspect_home(self.home,online=True,package_check=False)
        self.assertEqual(report['failed'],0,report);self.assertEqual(self.count('audit'),before)
    def test_preflight_api_rbac_csrf_and_no_secret(self):
        self.login('viewer');self.assertEqual(self.post('/v1/admin/preflight').status_code,403)
        self.login('settings');self.assertEqual(self.post('/v1/admin/preflight',csrf='bad').status_code,403)
        report=self.post('/v1/admin/preflight');self.assertEqual(report.status_code,200);self.assertNotIn(self.s.db_settings['password'],report.get_data(as_text=True))

if __name__=='__main__': unittest.main()
