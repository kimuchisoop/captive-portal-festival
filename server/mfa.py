"""RFC 6238 TOTP, one-use recovery codes, and terminal-only enrollment."""
import base64
import hashlib
import hmac
import re
import secrets
import struct
from cryptography.fernet import Fernet, InvalidToken
from flask import g, jsonify

def totp(secret, counter, digits=6, algorithm='sha1'):
    key=base64.b32decode(secret.upper()+'='*((-len(secret))%8))
    value=hmac.new(key,struct.pack('>Q',counter),algorithm).digest()
    offset=value[-1]&15
    number=(struct.unpack('>I',value[offset:offset+4])[0]&0x7fffffff)%(10**digits)
    return str(number).zfill(digits)

def matching_counter(secret, code, now, last=-1):
    if not isinstance(code,str) or not re.fullmatch(r'[0-9]{6}',code): return None
    for counter in (now//30,now//30-1,now//30+1):
        if counter>last and hmac.compare_digest(totp(secret,counter),code): return counter
    return None

def cipher(s):
    return Fernet((s.home/'mfa.key').read_bytes())

def enroll(s, username, secret, code):
    from app import uid,digest
    counter=matching_counter(secret,code,s.now())
    if counter is None: raise ValueError('Authenticator confirmation failed')
    encrypted=cipher(s).encrypt(secret.encode()).decode()
    generation=uid();codes=[secrets.token_hex(16) for _ in range(8)]
    with s.db(True) as db:
        a=db.execute('SELECT * FROM admins WHERE username=? AND enabled=1',(username,)).fetchone()
        if not a: raise ValueError('Unknown administrator')
        db.execute('INSERT INTO mfa_settings VALUES (?,?,?,1,0,?) ON DUPLICATE KEY UPDATE secret_ciphertext=VALUES(secret_ciphertext),generation=VALUES(generation),enabled=1,needs_reset=0,last_counter=VALUES(last_counter)',
                   (a['id'],encrypted,generation,counter))
        for code in codes: db.execute('INSERT INTO mfa_recovery VALUES (?,?,?,NULL)',(a['id'],generation,digest(code)))
        db.execute("DELETE FROM sessions WHERE kind LIKE 'admin%' AND owner_id=?",(a['id'],))
        s.audit(db,'local_cli','mfa_enrolled',a['id'])
    return codes

def reset(s, username):
    with s.db(True) as db:
        a=db.execute('SELECT id FROM admins WHERE username=?',(username,)).fetchone()
        if not a: raise ValueError('Unknown administrator')
        db.execute('UPDATE mfa_settings SET enabled=0,needs_reset=1 WHERE admin_id=?',(a['id'],))
        db.execute("DELETE FROM sessions WHERE kind LIKE 'admin%' AND owner_id=?",(a['id'],))
        s.audit(db,'local_cli','mfa_reset',a['id'])

def verify(s, db, administrator, code):
    from app import digest
    m=db.execute('SELECT * FROM mfa_settings WHERE admin_id=? AND enabled=1',(administrator,)).fetchone()
    if not m or m['needs_reset']: return False
    if not isinstance(code,str) or len(code)>64: return False
    if re.fullmatch(r'[0-9a-f]{32}',code):
        result=db.execute('UPDATE mfa_recovery SET used_at=? WHERE admin_id=? AND generation=? AND code_hash=? AND used_at IS NULL',
                          (s.now(),administrator,m['generation'],digest(code)))
        if result.rowcount:
            s.audit(db,administrator,'mfa_recovery_used',administrator)
            return True
        return False
    try: secret=cipher(s).decrypt(m['secret_ciphertext'].encode()).decode()
    except (InvalidToken,OSError,ValueError): return False
    counter=matching_counter(secret,code,s.now(),m['last_counter'])
    if counter is None: return False
    db.execute('UPDATE mfa_settings SET last_counter=? WHERE admin_id=?',(counter,administrator))
    return True

def register_mfa(app,s,body,cookie):
    from app import ApiError
    @app.post('/v1/admin/mfa')
    def challenge():
        session=s.get_session('admin')
        s.check_csrf(session)
        if session['kind']!='admin_mfa': raise ApiError('mfa_challenge_required',401)
        code=body(('code',))['code']
        limited=False;valid=False
        bucket=s.pseudonym('mfa:'+session['owner_id'])
        with s.db(True) as db:
            # Revalidate inside the serialized transaction: a parallel request cannot reuse this challenge.
            pending=db.execute("SELECT * FROM sessions WHERE token_hash=? AND kind='admin_mfa' AND expires_at>?",
                               (session['token_hash'],s.now())).fetchone()
            a=db.execute('SELECT * FROM admins WHERE id=? AND enabled=1',(session['owner_id'],)).fetchone()
            row=db.execute('SELECT * FROM login_limits WHERE bucket=?',(bucket,)).fetchone()
            limited=bool(row and row['expires_at']>s.now() and row['count']>=5)
            if not limited and pending and a:
                valid=verify(s,db,a['id'],code)
                if valid:
                    db.execute('DELETE FROM sessions WHERE token_hash=?',(session['token_hash'],))
                    raw=s.new_session(db,'admin',a['id'])
                    db.execute('DELETE FROM login_limits WHERE bucket=?',(bucket,))
                    s.audit(db,a['id'],'login')
                else:
                    if row and row['expires_at']<=s.now():
                        db.execute('UPDATE login_limits SET count=1,expires_at=? WHERE bucket=?',(s.now()+900,bucket))
                    else:
                        db.execute('INSERT INTO login_limits VALUES (?,1,?) ON DUPLICATE KEY UPDATE count=count+1',(bucket,s.now()+900))
                    s.audit(db,a['id'],'mfa_failed')
        if limited: raise ApiError('mfa_rate_limited',429,'追加認証の試行上限です。15分後にログインし直してください。')
        if not valid: raise ApiError('mfa_invalid',401,'認証コードを確認してください。期限切れの場合はログインし直してください。')
        return cookie(jsonify(authenticated=True,csrf_token=s.csrf(raw),user={'username':a['username'],'role':a['role']}),raw,'admin')

    @app.get('/v1/admin/mfa-status', endpoint='mfa_status')
    def status():
        session=s.get_session('admin')
        if not session or session['kind']!='admin': raise ApiError('authentication_required',401)
        with s.db() as db:
            m=db.execute('SELECT enabled,needs_reset,generation FROM mfa_settings WHERE admin_id=?',(session['owner_id'],)).fetchone()
            count=db.execute('SELECT count(*) FROM mfa_recovery WHERE admin_id=? AND generation=? AND used_at IS NULL',
                             (session['owner_id'],m['generation'])).fetchone()[0] if m else 0
        return jsonify(enabled=bool(m and m['enabled']),needs_reset=bool(m and m['needs_reset']),recovery_codes_remaining=count,
                       enrollment='terminal_only')
