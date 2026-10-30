"""VyOS stage-2 and rollback command rendering (guide 16.3 / 16.6); no network, no MySQL."""
import sys,json,copy,io,unittest
from contextlib import redirect_stderr,redirect_stdout
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'deployment'/'vyos'))
from render_portal_config import check,render,main

EXAMPLE=ROOT/'deployment'/'vyos'/'portal-values.example.json'
FILLED={'guest_interfaces':['eth1.10','eth1.20'],'guest_networks':['192.0.2.0/24','198.51.100.0/24'],
        'portal_server':'203.0.113.11','portal_hostname':'wifi.example.test','dns_servers':['203.0.113.53'],'internal_networks':['203.0.113.0/24'],
        'firewall_rule_start':500,'nat_rule_start':100,'existing_firewall_rules':[10,20],'existing_nat_rules':[]}

def filled(**change):values=copy.deepcopy(FILLED);values.update(change);return values

class VyosRenderTests(unittest.TestCase):
    def test_example_is_not_rendered_until_decided(self):
        settings,problems=check(json.loads(EXAMPLE.read_text(encoding='utf-8')))
        self.assertIsNone(settings)
        self.assertEqual(len([p for p in problems if '要確認' in p]),8)

    def test_https_first(self):
        text=render(check(filled())[0]);lines=text.splitlines()
        # Only port 80 is ever redirected; 443 goes to the server untouched and is never translated.
        nat=[l for l in lines if l.startswith('set nat destination')]
        self.assertIn("set nat destination rule 100 destination port '80'",nat)
        self.assertFalse(any('443' in l for l in nat))
        self.assertIn('    return 302 https://wifi.example.test/;',lines)
        self.assertIn('    listen 80 default_server;',lines)
        capport=[l for l in lines if 'captive-portal' in l and 'set service' in l]
        self.assertEqual(len(capport),1);self.assertTrue(capport[0].startswith('# '))
        self.assertIn("'https://wifi.example.test/capport/api'",capport[0])
        self.assertFalse(any('http://wifi.example.test' in l for l in lines))
        for bad in ('203.0.113.11','Wifi.Example.Test','wifi','https://wifi.example.test','wifi.example.test/','-a.example.test'):
            settings,problems=check(filled(portal_hostname=bad))
            self.assertIsNone(settings,bad);self.assertTrue(any('portal_hostname' in p for p in problems))

    def test_rendered_commands(self):
        settings,problems=check(filled());self.assertEqual(problems,[])
        text=render(settings);lines=text.splitlines()
        self.assertIn('set firewall group address-group PORTAL-AUTHED',lines)
        self.assertIn('set firewall group network-group GUEST-NETS network 198.51.100.0/24',lines)
        self.assertIn("set firewall ipv4 forward filter rule 510 destination port '80,443'",lines)
        self.assertIn("set firewall ipv4 forward filter rule 520 destination address '203.0.113.53'",lines)
        self.assertIn("set firewall ipv4 forward filter rule 530 destination group network-group 'PORTAL-INTERNAL'",lines)
        self.assertIn("set firewall ipv4 forward filter rule 540 source group address-group 'PORTAL-AUTHED'",lines)
        self.assertIn("set firewall ipv4 forward filter rule 550 action 'drop'",lines)
        self.assertIn("set nat destination rule 101 inbound-interface name 'eth1.20'",lines)
        self.assertIn("set nat destination rule 100 source group address-group '!PORTAL-AUTHED'",lines)
        self.assertFalse(any('nat destination' in l and '443' in l for l in lines))
        # Internal drop comes before the authorized accept, and the final drop is last.
        self.assertLess(text.index('rule 530'),text.index('rule 540'))
        self.assertLess(text.index('commit-confirm 5'),text.index('confirm\n'))
        rollback=text.split('16.6')[1]
        self.assertIn('delete nat destination rule 100',rollback);self.assertIn('delete nat destination rule 101',rollback)
        self.assertIn("set firewall ipv4 forward filter rule 550 action 'accept'",rollback)
        self.assertNotIn('530',rollback)

    def test_one_group_type_per_nat_rule(self):
        text=render(check(filled())[0])
        for number in (100,101):
            rule=[l for l in text.splitlines() if l.startswith('set nat destination rule {} '.format(number))]
            self.assertFalse(any('network-group' in l for l in rule))

    def test_bad_values_listed(self):
        cases=[(dict(guest_interfaces=['eth1.10; rm']),'guest_interfaces'),(dict(guest_interfaces=['eth1.10','eth1.10']),'repeats'),
               (dict(guest_networks=['192.0.2.1/24']),'CIDR'),(dict(portal_server='192.0.2.5'),'inside guest_networks'),
               (dict(internal_networks=['192.0.0.0/16']),'overlaps'),(dict(dns_servers=['nope']),'IPv4'),
               (dict(firewall_rule_start='500'),'whole number'),(dict(nat_rule_start=0),'whole number'),
               (dict(existing_firewall_rules=[530]),'collide with existing: 530'),(dict(existing_nat_rules=[101]),'collide'),
               (dict(dns_servers=[]),'要確認'),(dict(portal_server=''),'要確認')]
        for change,message in cases:
            settings,problems=check(filled(**change))
            self.assertIsNone(settings,change);self.assertTrue(any(message in p for p in problems),(change,problems))
        values=filled();values['extra']=1;self.assertIn('Unknown: extra',check(values)[1])
        values=filled();del values['nat_rule_start'];self.assertIn('Missing: nat_rule_start',check(values)[1])
        values=filled();values['_note']='ignored';self.assertEqual(check(values)[1],[])

    def test_cli(self):
        err=io.StringIO()
        with redirect_stderr(err):self.assertEqual(main(['x',str(EXAMPLE)]),1)
        self.assertIn('Not rendered',err.getvalue())
        with redirect_stderr(io.StringIO()):self.assertEqual(main(['x']),2)

if __name__=='__main__':unittest.main()
