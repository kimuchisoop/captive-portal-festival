"""Schema-five backup, restore, release and recovery-kit paths (replace the retired schema-four tests)."""
import json,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import test_service as service_tests
from mysql_fixture import new_database,maintenance_file
from workflow_backup import backup_stream,inspect,restore
from workflow_generation import release_recovery
from recovery_kit import create_kit
from workflow_kit import restore_kit
from app import Service

class Schema5RecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): service_tests.Tests.setUpClass.__func__(cls)

    def count(self,s,table):
        with s.db() as db:return db.execute('SELECT count(*) FROM '+table).fetchone()[0]

    def restore_to_new(self,source,key_file,name='restored'):
        settings=new_database();destination=Path(self.temp.name)/name
        result=restore(source,key_file,destination,settings,maintenance_file(settings))
        return destination,result

    def test_backup_is_schema5_and_verifies(self):
        self.consent();path=backup_stream(self.s)
        summary=inspect(path,(self.home/'backup.key').read_bytes())
        self.assertEqual(summary['header']['format'],'festival-wifi-stream-backup-v2')
        self.assertEqual(len(summary['summaries']),31)
        self.assertEqual(summary['summaries']['consents']['rows'],'1')

    def test_restore_release_keeps_records_and_starts_closed(self):
        self.consent();consents=self.count(self.s,'consents');audit=self.count(self.s,'audit')
        path=backup_stream(self.s)
        destination,result=self.restore_to_new(path,self.home/'backup.key')
        self.assertTrue(result['restored']);self.assertTrue(result['requires_manual_release']);self.assertEqual(result['schema_version'],5)
        self.assertTrue((destination/'restore.incomplete').exists())
        released=release_recovery(destination)
        self.assertTrue(released['released']);self.assertTrue(released['records_preserved'])
        s=Service(destination)
        self.assertEqual(self.count(s,'consents'),consents);self.assertGreaterEqual(self.count(s,'audit'),audit)
        self.assertEqual(self.count(s,'sessions'),0)
        self.assertFalse(s.config['local_intake_enabled']);self.assertFalse(s.config['production_enabled'])
        self.assertNotEqual((destination/'session.key').read_bytes(),(self.home/'session.key').read_bytes())
        self.assertEqual(self.count(self.s,'consents'),consents)  # source is untouched
        self.assertFalse((destination/'restore.incomplete').exists())
        again=release_recovery(destination)  # a second run reports the finished release
        self.assertTrue(again['already_released']);self.assertEqual(again['generation'],released['generation'])
        with self.assertRaisesRegex(ValueError,'No restored data'):release_recovery(self.home)

    def test_restore_refuses_existing_destination_wrong_key_and_tampering(self):
        path=backup_stream(self.s)
        settings=new_database();existing=Path(self.temp.name)/'exists';existing.mkdir()
        with self.assertRaises(ValueError):restore(path,self.home/'backup.key',existing,settings,maintenance_file(settings))
        wrong=Path(self.temp.name)/'wrong.key';wrong.write_bytes(__import__('cryptography.fernet').fernet.Fernet.generate_key())
        with self.assertRaises(Exception):self.restore_to_new(path,wrong,'wrong-key')
        data=bytearray(path.read_bytes());data[len(data)//2]^=1
        tampered=Path(self.temp.name)/'tampered.sffbackup';tampered.write_bytes(bytes(data))
        with self.assertRaises(Exception):self.restore_to_new(tampered,self.home/'backup.key','tampered')
        self.assertTrue(path.exists())  # the original ciphertext is preserved

    def test_restore_requires_separate_maintenance_account(self):
        path=backup_stream(self.s);settings=new_database()
        same=Path(self.temp.name)/'same-account.json';same.write_text(json.dumps(settings),encoding='utf-8')
        with self.assertRaises(ValueError):restore(path,self.home/'backup.key',Path(self.temp.name)/'same',settings,same)

    def test_recovery_kit_round_trip(self):
        self.consent();consents=self.count(self.s,'consents')
        output=Path(self.temp.name)/'kit-out'/'festival.kit';output.parent.mkdir()
        keys=Path(self.temp.name)/'kit-keys'
        create_kit(self.s,output,keys)
        self.assertTrue(output.exists());self.assertTrue((keys/'recovery.key').exists())
        settings=new_database();destination=Path(self.temp.name)/'from-kit'
        result=restore_kit(output,keys/'recovery.key',destination,settings,maintenance_file(settings))
        self.assertTrue(result['restored']);self.assertTrue(release_recovery(destination)['released'])
        self.assertEqual(self.count(Service(destination),'consents'),consents)
        self.assertTrue(output.exists())

# Reuse the service fixture's setUp and request helpers without re-running its tests.
for _name,_value in vars(service_tests.Tests).items():
    if callable(_value) and not _name.startswith('test_') and _name not in ('setUpClass','count'):setattr(Schema5RecoveryTests,_name,_value)

if __name__=='__main__':unittest.main()
