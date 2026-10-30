"""Adds and removes visitor IPs in the core-rt (VyOS) PORTAL-AUTHED address group only (guide 16.4).

Not wired into the app yet; the AP adapter stays disconnected. The API key is passed in by the caller,
which reads it from a protected file. Certificate verification is always on.
"""
import ipaddress,json,socket,ssl
from urllib.error import HTTPError,URLError
from urllib.parse import urlencode,urlsplit
from urllib.request import Request,urlopen

GROUP='PORTAL-AUTHED'
BASE=['firewall','group','address-group',GROUP]
ANSWER_LIMIT=1048576

class GatewayError(Exception):pass
class GatewayRefused(GatewayError):"""Refused before contacting the router (bad input or settings)."""
class GatewayUnavailable(GatewayError):"""Router not reached, timed out, or answered with something unusable."""
class GatewayRejected(GatewayError):"""Router answered and refused the request."""

class VyosGateway:
    def __init__(self,origin,api_key,allowed_networks,ca_file=None,timeout=5,opener=urlopen):
        parts=urlsplit(origin) if isinstance(origin,str) else None
        if not parts or parts.scheme!='https' or not parts.hostname or parts.username or parts.password or parts.path not in ('','/') or parts.query or parts.fragment:
            raise GatewayRefused('VyOS API needs an https origin without path')
        if not isinstance(api_key,str) or not api_key.strip():raise GatewayRefused('VyOS API key missing')
        try:self.networks=[ipaddress.IPv4Network(n) for n in allowed_networks]
        except (TypeError,ValueError):raise GatewayRefused('Allowed networks must be IPv4 CIDR') from None
        if not self.networks:raise GatewayRefused('Allowed networks missing')
        if type(timeout) not in (int,float) or not 0<timeout<=30:raise GatewayRefused('Timeout must be 0-30 seconds')
        self.origin=origin.rstrip('/');self.key=api_key;self.timeout=timeout;self.opener=opener
        self.context=ssl.create_default_context(cafile=ca_file)

    def address(self,ip):
        try:value=ipaddress.IPv4Address(ip) if isinstance(ip,str) else None
        except ValueError:value=None
        if value is None:raise GatewayRefused('Not an IPv4 address')
        # Only guest addresses; a mistake must never open the router to a server or management address.
        if not any(value in n for n in self.networks):raise GatewayRefused('Address outside guest networks')
        return str(value)

    def call(self,endpoint,data):
        body=urlencode({'data':json.dumps(data),'key':self.key}).encode()
        request=Request(self.origin+endpoint,data=body,method='POST',headers={'Content-Type':'application/x-www-form-urlencoded'})
        try:
            with self.opener(request,timeout=self.timeout,context=self.context) as response:raw=response.read(ANSWER_LIMIT+1)
        except HTTPError as error:
            with error:raw=error.read(ANSWER_LIMIT+1) if error.code==400 else b''
            if error.code in (401,403):raise GatewayRejected('VyOS API key refused') from None
            if not raw:raise GatewayUnavailable('VyOS API HTTP '+str(error.code)) from None
        except (URLError,socket.timeout,TimeoutError,OSError):raise GatewayUnavailable('VyOS API not reached') from None
        if len(raw)>ANSWER_LIMIT:raise GatewayUnavailable('VyOS API answer too large')
        try:answer=json.loads(raw)
        except ValueError:raise GatewayUnavailable('VyOS API answer is not JSON') from None
        if not isinstance(answer,dict):raise GatewayUnavailable('VyOS API answer is not an object')
        if answer.get('success') is not True:raise GatewayRejected(str(answer.get('error') or 'refused')[:200])
        return answer.get('data')

    def authorized(self):
        try:data=self.call('/retrieve',{'op':'showConfig','path':BASE})
        except GatewayRejected as error:
            if 'empty' in str(error).lower():return []  # VyOS reports a group without members this way
            raise
        listed=(data or {}).get('address',[]) if isinstance(data,dict) else None
        if isinstance(listed,str):listed=[listed]
        if not isinstance(listed,list) or not all(isinstance(a,str) for a in listed):raise GatewayUnavailable('VyOS group answer has an unknown shape')
        return sorted(listed)

    def allow(self,ip):
        address=self.address(ip)
        self.call('/configure',{'op':'set','path':BASE+['address',address]})
        return address

    def revoke(self,ip):
        """Returns False when the address was not in the group. Existing connections may continue until conntrack expires."""
        address=self.address(ip)
        if address not in self.authorized():return False
        self.call('/configure',{'op':'delete','path':BASE+['address',address]})
        return True
