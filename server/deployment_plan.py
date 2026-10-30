"""Offline HTTPS planning only. It never enables the app or contacts a certificate issuer."""
import ipaddress
import json
from pathlib import Path
import re

FIELDS={'deployment_os','portal_hostname','admin_hostname','portal_certificate','portal_private_key',
        'admin_certificate','admin_private_key','management_networks'}

def inspect_plan(data):
    if not isinstance(data,dict) or set(data)!=FIELDS: raise ValueError('Invalid plan fields')
    missing=[];errors=[]
    for name in FIELDS-{'management_networks'}:
        value=data[name]
        if value is None or value=='': missing.append(name);continue
        if not isinstance(value,str): errors.append(name);continue
        if name=='deployment_os':
            if value!='linux': errors.append(name)
        elif name.endswith('hostname'):
            if len(value)>253 or not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}',value): errors.append(name)
        elif not re.fullmatch(r'/[A-Za-z0-9_./-]+',value) or '..' in value.split('/'): errors.append(name)
    if data['portal_hostname'] and data['portal_hostname']==data['admin_hostname']: errors.append('separate_admin_hostname_required')
    networks=data['management_networks']
    if not isinstance(networks,list) or len(networks)>20: errors.append('management_networks')
    elif not networks: missing.append('management_networks')
    else:
        for value in networks:
            try:
                if not isinstance(value,str): raise ValueError()
                network=ipaddress.ip_network(value,strict=True)
                if network.prefixlen==0: raise ValueError()
            except ValueError: errors.append('management_networks');break
    return dict(plan_complete=not missing and not errors,missing=sorted(missing),errors=sorted(set(errors)),
                production_ready=False,ap_verified=False,application_forwarding_enabled=False,
                blockers=['real_tls_proxy_certificate_and_access_tests_pending','ap_integration_pending','official_operational_approval_pending'],
                certificate_files_inspected=False,network_changes_performed=False)

def render_closed_config(data):
    status=inspect_plan(data)
    if not status['plan_complete']: raise ValueError('Complete the offline plan first')
    allows='\n'.join('    allow '+str(ipaddress.ip_network(value))+';' for value in data['management_networks'])
    return f'''# OFFLINE PREPARATION ONLY: no application traffic is forwarded.
# Dedicated Linux nginx http-context snippet. Not installed by this tool.
# Certificate paths are operator-supplied references; no key material is copied.
map $uri $festival_route {{
    default other;
    / portal;
    /admin admin;
    ~^/v1/admin/ admin_api;
    ~^/v1/ visitor_api;
    ~^/static/ static;
}}
log_format festival_safe '$time_iso8601 status=$status method=$request_method route=$festival_route request_id=$request_id';
server {{
    listen 80;
    listen [::]:80;
    server_name {data['portal_hostname']};
    access_log /var/log/nginx/festival-portal-access.log festival_safe;
    return 308 https://{data['portal_hostname']}$request_uri;
}}
server {{
    listen 80;
    listen [::]:80;
    server_name {data['admin_hostname']};
    access_log /var/log/nginx/festival-admin-access.log festival_safe;
    return 308 https://{data['admin_hostname']}$request_uri;
}}
server {{
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name {data['portal_hostname']};
    access_log /var/log/nginx/festival-portal-access.log festival_safe;
    ssl_certificate {data['portal_certificate']};
    ssl_certificate_key {data['portal_private_key']};
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 64k;
    add_header Cache-Control "no-store" always;
    location = /admin {{ return 404; }}
    location ^~ /admin/ {{ return 404; }}
    location ^~ /v1/admin/ {{ return 404; }}
    location / {{ return 503; }}
}}
server {{
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name {data['admin_hostname']};
    access_log /var/log/nginx/festival-admin-access.log festival_safe;
    ssl_certificate {data['admin_certificate']};
    ssl_certificate_key {data['admin_private_key']};
    ssl_protocols TLSv1.2 TLSv1.3;
{allows}
    deny all;
    add_header Cache-Control "no-store" always;
    # Create this as a NEW EMPTY directory during reviewed installation.
    # Access rules run before the content handler. A rewrite-phase return would bypass them.
    root /var/empty/festival-wifi-disabled;
    location / {{ try_files /__festival_wifi_maintenance_only__ =503; }}
}}
'''

def write_plan(input_path,output):
    from security import protect_directory
    from jobs import secure_new_file
    path=Path(input_path)
    if path.stat().st_size>32768: raise ValueError('Plan too large')
    data=json.loads(path.read_text(encoding='utf-8-sig'));status=inspect_plan(data)
    output=Path(output).resolve();output.mkdir(parents=False,exist_ok=False);protect_directory(output)
    secure_new_file(output/'https-readiness.json',json.dumps(status,ensure_ascii=False,indent=2).encode())
    if status['plan_complete']:
        secure_new_file(output/'nginx.closed.conf',render_closed_config(data).encode())
    return status
