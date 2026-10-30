import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import io,json,os,tarfile,unittest
from unittest.mock import patch
from cryptography.fernet import Fernet
from recovery_kit import safe_name,consume,source_files,restore_kit
from stream_encryption import Writer
from stream_backup import backup_stream,restore_stream
from backup_review import inspect_file
from migrations import upgrade_to_v4
from filesystem_guard import is_link
from mysql_fixture import new_database
import test_service as service_tests

class NameTests(unittest.TestCase):
    def test_windows_reserved_and_ambiguous_names_refused(self):
        for name in ('files/CON','files/aux.json','files/COM1.log','files/a.','files/a ','files/Nul.txt'):
            with self.assertRaises(ValueError): safe_name(name)
        safe_name('files/runtime/通常のログ.log')

class ValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): service_tests.Tests.setUpClass.__func__(cls)
    setUp=service_tests.Tests.setUp
    tearDown=service_tests.Tests.tearDown
    def archive(self,members,trailer=b''):
        data=io.BytesIO()
        with tarfile.open(fileobj=data,mode='w') as archive:
            for name,body in members:
                info=tarfile.TarInfo(name);info.size=len(body);archive.addfile(info,io.BytesIO(body))
        output=self.home/'unsafe.sffkit';key=Fernet.generate_key()
        with output.open('xb') as handle:
            writer=Writer(handle,key);writer.write(data.getvalue()+trailer);writer.finish()
        return output,key
    def test_authenticated_nonzero_tar_trailer_refused(self):
        path,key=self.archive([],b'EXTRA-AFTER-TAR')
        with self.assertRaisesRegex(ValueError,'tar EOF'): consume(path,key)
    def test_case_aliases_refused_before_extract(self):
        path,key=self.archive([('files/A.json',b'a'),('files/a.json',b'b')])
        with self.assertRaisesRegex(ValueError,'member'): consume(path,key)
    def test_inspect_proof_bound_before_decryption(self):
        source=backup_stream(self.s)
        from stream_backup import file_hash
        proofs=iter(['a','b'])
        def changed(path): return next(proofs) if Path(path)==source else file_hash(path)
        with patch('stream_backup.file_hash',side_effect=changed):
            with self.assertRaisesRegex(ValueError,'Source changed'): inspect_file(self.s,source.name)
    def test_upgrade_refuses_running_supervisor(self):
        runtime=self.home/'runtime';runtime.mkdir();(runtime/'current.json').write_text('{"state":"running"}')
        with self.assertRaisesRegex(ValueError,'Stop app'): upgrade_to_v4(self.s.db_settings,self.home)
    def test_windows_junction_is_refused_without_reading_external_files(self):
        if os.name!='nt': self.skipTest('Windows junction')
        import subprocess
        external=Path(self.temp.name)/'external';external.mkdir();(external/'sentinel.txt').write_text('not included')
        linked=self.home/'diagnostics'
        result=subprocess.run(['cmd','/c','mklink','/J',str(linked),str(external)],capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW)
        self.assertEqual(result.returncode,0);self.assertTrue(is_link(linked))
        with self.assertRaisesRegex(ValueError,'Linked'): source_files(self.home)
        self.assertEqual((external/'sentinel.txt').read_text(),'not included')

if __name__=='__main__': unittest.main()
