"""Run on each target OS in a venv with server/requirements.txt and PyInstaller 6.22.3.

Usage: python tools/build_binary.py --output /absolute/new/build-directory
No service data, keys or database settings are collected.
"""
from pathlib import Path
import argparse,hashlib,json,os,shutil,ssl,subprocess,sys
parser=argparse.ArgumentParser();parser.add_argument('--output',required=True,type=Path);args=parser.parse_args()
root=Path(__file__).resolve().parents[1];source=root/'server';out=args.output.resolve();out.mkdir(parents=True,exist_ok=False);stage=out/'input';stage.mkdir()
for p in source.iterdir():
    if p.is_file() and p.suffix in ('.py','.sql','.json','.txt') and p.name not in ('release-manifest.json','offline-manifest.json'):
        shutil.copy2(p,stage/p.name)
for name in ('static','templates'):shutil.copytree(source/name,stage/name)
# Preserve this Python distribution's trust configuration when it has one.
runtime_cert=Path(ssl.__file__).with_name('codex-rejected-cas.pem')
if runtime_cert.is_file():shutil.copy2(runtime_cert,stage/runtime_cert.name)
files={p.relative_to(stage).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in stage.rglob('*') if p.is_file()}
(stage/'release-manifest.json').write_text(json.dumps(dict(release='0.11.10-rc1',files=files),ensure_ascii=False,indent=2),encoding='utf-8')
command=[sys.executable,'-m','PyInstaller','--onedir','--name','festival-wifi','--distpath',str(out/'dist'),'--workpath',str(out/'build'),'--specpath',str(stage),'--add-data',str(stage)+os.pathsep+'.','--collect-submodules','mysql.connector.plugins','--collect-submodules','mysql.connector.locales']
for line in (source/'requirements.txt').read_text(encoding='utf-8').splitlines():command+=['--copy-metadata',line.split('==')[0]]
for p in stage.glob('*.py'):
    if p.stem!='binary_entry':command+=['--hidden-import',p.stem]
command+=[str(stage/'binary_entry.py')]
with (out/'build.log').open('xb') as log:subprocess.run(command,cwd=stage,stdout=log,stderr=log,check=True)
binary=out/'dist/festival-wifi'/('festival-wifi.exe' if os.name=='nt' else 'festival-wifi')
for option in ('--version','--self-check','--help'):subprocess.run([str(binary),option],check=True)
print(binary)
