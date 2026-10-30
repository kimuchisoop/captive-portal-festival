"""Packaged CLI entry. Mutable records always live in the explicit --home directory."""
import sys,json,importlib
from pathlib import Path
VERSION='0.11.10-rc1'
def main():
    for stream in (sys.stdout,sys.stderr):
        if hasattr(stream,'reconfigure'):stream.reconfigure(encoding='utf-8')
    if sys.argv[1:]==['--version']:
        print(VERSION);return
    if sys.argv[1:]==['--self-check']:
        import app,manage,workflow_cli,workflow_backup,mfa,archive_exports
        import ssl
        ssl.create_default_context()
        from cryptography.fernet import Fernet
        key=Fernet.generate_key();cipher=Fernet(key);assert cipher.decrypt(cipher.encrypt(b'local-self-check'))==b'local-self-check'
        for module in ('mysql.connector.plugins.caching_sha2_password','mysql.connector.plugins.mysql_native_password','mysql.connector.locales.eng.client_error'):
            importlib.import_module(module)
        for filename in ('config.example.json','schema-v5.sql','templates/portal.html','templates/admin.html','static/portal.js','static/response-contracts.js'):
            assert (app.ROOT/filename).is_file(),filename
        print(json.dumps(dict(version=VERSION,imports=True,assets=True,crypto=True,database_connected=False)));return
    from manage import main as manage_main
    manage_main()
if __name__=='__main__':main()
