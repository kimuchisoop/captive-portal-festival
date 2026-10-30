"""Owns only the two child processes it starts. Logs and data are never removed."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import uuid
from urllib.parse import urlsplit

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--home',type=Path,required=True)
    args=parser.parse_args();home=args.home.resolve()
    # Validate the service before spawning anything. Does not alter MySQL configuration.
    from app import Service
    from preflight import require_startable
    require_startable(home)
    service=Service(home)
    from filesystem_guard import is_link,regular
    runtime=home/'runtime'
    if is_link(runtime):raise ValueError('Linked runtime directory')
    runtime.mkdir(mode=0o700,exist_ok=True)
    from security import protect_directory
    protect_directory(runtime)
    lockfile=runtime/'supervisor.lock'
    if is_link(lockfile):raise ValueError('Linked supervisor lock')
    if lockfile.exists():regular(lockfile)
    lock=lockfile.open('a+b')
    if os.fstat(lock.fileno()).st_size==0:lock.write(b'1');lock.flush()
    lock.seek(0)
    try:
        if os.name=='nt':
            import msvcrt
            msvcrt.locking(lock.fileno(),msvcrt.LK_NBLCK,1)
        else:
            import fcntl
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except OSError:
        print('Another supervisor owns this data directory.',flush=True);return 2
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',urlsplit(service.config['origin']).port))
    token=uuid.uuid4().hex;children=[];handles=[];counts={'serve':0,'worker':0}
    statusfile=runtime/'current.json';events=(runtime/('events-'+token+'.log')).open('x',encoding='utf-8')
    def event(message):
        events.write(str(int(time.time()))+' '+message+'\n');events.flush()
    def save(state):
        data=dict(state=state,token=token,pid=os.getpid(),children={name:p.pid for name,p in children},
                  restart_counts=counts,updated_at=int(time.time()),production_enabled=False)
        temp=runtime/('status-'+uuid.uuid4().hex+'.json')
        temp.write_text(json.dumps(data),encoding='utf-8')
        # Windows readers can briefly hold a file without FILE_SHARE_DELETE.
        # A status read must never tear down the service being observed.
        for _ in range(50):
            try:
                os.replace(temp,statusfile);return
            except PermissionError: time.sleep(.02)
        event('status update delayed by file sharing; previous snapshot retained')
    def spawn(name):
        output=(runtime/(name+'-'+uuid.uuid4().hex+'.log')).open('xb')
        handles.append(output)
        process=subprocess.Popen([sys.executable,str(Path(__file__).parent/'manage.py'),'--home',str(home),name],
                                 stdout=output,stderr=subprocess.STDOUT,
                                 env={**os.environ,'PYTHONUNBUFFERED':'1'},
                                 creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
        event('started '+name+' pid='+str(process.pid));return process
    final_state='stopped'
    try:
        for name in ('serve','worker'): children.append((name,spawn(name)))
        save('running')
        while True:
            request=runtime/('stop-'+token+'.request')
            if request.exists(): event('stop requested');break
            if not (home/'config.json').exists(): event('configuration missing');break
            failed=False
            for index,(name,process) in enumerate(children):
                if process.poll() is not None:
                    event('exited '+name+' code='+str(process.returncode))
                    if counts[name]>=3:
                        event('restart limit reached '+name);failed=True;break
                    counts[name]+=1
                    children[index]=(name,spawn(name));save('running')
            if failed: final_state='failed';return 2
            save('running');time.sleep(2)
    except KeyboardInterrupt: event('keyboard stop')
    finally:
        for name,process in children:
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=10)
                except subprocess.TimeoutExpired: process.kill();process.wait(timeout=10)
                event('stopped owned '+name)
        save(final_state);events.close()
        for output in handles: output.close()
        lock.close()
    return 0

if __name__=='__main__':
    try: raise SystemExit(main())
    except Exception as error:
        print('Supervisor failed: '+type(error).__name__+'. Logs retained.',flush=True)
        raise SystemExit(1)
