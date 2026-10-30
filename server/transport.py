"""Strict single loopback proxy boundary for HTTPS preparation, with intake disabled."""
import ipaddress
import re
from urllib.parse import urlsplit
from werkzeug.wrappers import Response

FIELDS={'enabled','portal_origin','admin_origin','trusted_proxy'}

def validate_transport(config):
    data=config.get('https_transport',{'enabled':False,'portal_origin':None,'admin_origin':None,'trusted_proxy':None})
    if not isinstance(data,dict) or set(data)!=FIELDS or type(data['enabled']) is not bool:
        raise ValueError('Invalid HTTPS transport settings')
    if not data['enabled']: return data
    # Guests are only taken over HTTPS when core-rt actually releases them (vyos_portal); otherwise preparation only.
    portal=config.get('vyos_portal')
    if config.get('local_intake_enabled') is not False and not (isinstance(portal,dict) and portal.get('enabled') is True):
        raise ValueError('HTTPS preparation requires intake disabled')
    for name in ('portal_origin','admin_origin'):
        value=data[name]
        if not isinstance(value,str): raise ValueError('HTTPS origin required')
        parsed=urlsplit(value)
        if (parsed.scheme!='https' or parsed.netloc!=parsed.hostname or parsed.path or parsed.query or parsed.fragment
            or not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}',parsed.hostname or '')
            or len(parsed.hostname)>253): raise ValueError('Exact HTTPS origin required, default port only')
    if data['portal_origin']==data['admin_origin']: raise ValueError('Separate origins required')
    if data['trusted_proxy']!='127.0.0.1': raise ValueError('Only one loopback proxy is supported')
    return data

def admin_path(path):
    return path=='/admin' or path.startswith('/admin/') or path=='/v1/admin' or path.startswith('/v1/admin/') or path.startswith('/health/')

def request_origin(config,path):
    data=validate_transport(config)
    return data['admin_origin' if admin_path(path) else 'portal_origin'] if data['enabled'] else config['origin']

class HTTPSBoundary:
    """Validates raw peer/headers before changing WSGI fields; no proxy-count guessing."""
    def __init__(self,application,settings):
        self.application=application;self.settings=settings

    def __call__(self,environ,start_response):
        def reject():
            return Response('{"code":"https_proxy_boundary_rejected"}',status=400,content_type='application/json',
                            headers={'Cache-Control':'no-store'})(environ,start_response)
        if environ.get('REMOTE_ADDR')!=self.settings['trusted_proxy']: return reject()
        if environ.get('HTTP_X_FORWARDED_PROTO')!='https': return reject()
        if any(environ.get(key) for key in ('HTTP_FORWARDED','HTTP_X_FORWARDED_HOST','HTTP_X_FORWARDED_PORT','HTTP_X_FORWARDED_PREFIX')): return reject()
        if any(key.startswith('HTTP_X_FORWARDED_') and key not in ('HTTP_X_FORWARDED_PROTO','HTTP_X_FORWARDED_FOR') for key in environ): return reject()
        source=environ.get('HTTP_X_FORWARDED_FOR','')
        try: ipaddress.ip_address(source)
        except ValueError: return reject()
        path=environ.get('PATH_INFO','')
        host=environ.get('HTTP_HOST','')
        expected=self.settings['admin_origin' if admin_path(path) else 'portal_origin'][8:]
        # Static assets can be served on either host; all other routes are isolated.
        allowed={self.settings['admin_origin'][8:],self.settings['portal_origin'][8:]} if path.startswith('/static/') else {expected}
        if host not in allowed: return reject()
        environ['wsgi.url_scheme']='https';environ['SERVER_PORT']='443';environ['REMOTE_ADDR']=source
        for key in list(environ):
            if key=='HTTP_FORWARDED' or key.startswith('HTTP_X_FORWARDED_'): environ.pop(key)
        return self.application(environ,start_response)
