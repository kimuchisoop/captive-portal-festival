"""Prints the VyOS 1.4 commands for guide 16.3 (stage 2: block before consent) and 16.6 (rollback).

Usage: python render_portal_config.py <values.json>   (start from portal-values.example.json)
Stops and lists every problem while a value is missing, still 要確認, or collides with an existing rule.
Prints only; nothing is sent to the router.
"""
import ipaddress,json,re,sys

FIELDS={'guest_interfaces','guest_networks','portal_server','dns_servers','internal_networks',
        'firewall_rule_start','nat_rule_start','existing_firewall_rules','existing_nat_rules'}
INTERFACE=re.compile(r'[a-z]{2,8}[0-9]{1,3}(\.[0-9]{1,4})?')
STEP=10
CHAIN='firewall ipv4 forward filter'

def pending(value):return value is None or value=='' or value==[] or (isinstance(value,str) and '要確認' in value) or (isinstance(value,list) and any(pending(v) for v in value))

def check(values):
    """Returns (settings, problems); settings is None when anything is wrong."""
    if not isinstance(values,dict):return None,['Values must be a JSON object']
    keys={k for k in values if not k.startswith('_')};problems=[]
    problems+=['Missing: '+k for k in sorted(FIELDS-keys)]+['Unknown: '+k for k in sorted(keys-FIELDS)]
    if problems:return None,problems
    for key in sorted(FIELDS-{'existing_firewall_rules','existing_nat_rules'}):
        if pending(values[key]):problems.append('Not decided (要確認): '+key)
    if problems:return None,problems
    out={}
    def networks(key):
        try:return [ipaddress.IPv4Network(n) for n in values[key]] if isinstance(values[key],list) else problems.append(key+' must be a list')
        except (TypeError,ValueError):problems.append(key+' must be IPv4 CIDR (e.g. 192.0.2.0/24)')
    def addresses(key,single=False):
        items=[values[key]] if single else values[key]
        try:parsed=[ipaddress.IPv4Address(a) for a in items] if single or isinstance(items,list) else problems.append(key+' must be a list')
        except (TypeError,ValueError):return problems.append(key+' must be IPv4 addresses')
        return parsed[0] if single and parsed else parsed
    if not isinstance(values['guest_interfaces'],list) or not all(isinstance(i,str) and INTERFACE.fullmatch(i) for i in values['guest_interfaces']):
        problems.append('guest_interfaces must be names like eth1.10')
    elif len(set(values['guest_interfaces']))!=len(values['guest_interfaces']):problems.append('guest_interfaces repeats a name')
    out['guest_networks']=networks('guest_networks');out['internal_networks']=networks('internal_networks')
    out['portal_server']=addresses('portal_server',True);out['dns_servers']=addresses('dns_servers')
    for key in ('firewall_rule_start','nat_rule_start'):
        if type(values[key]) is not int or not 1<=values[key]<=9000:problems.append(key+' must be a whole number 1-9000')
    for key in ('existing_firewall_rules','existing_nat_rules'):
        if not isinstance(values[key],list) or not all(type(n) is int for n in values[key]):problems.append(key+' must be a list of rule numbers')
    if problems:return None,problems
    guests,internal=out['guest_networks'],out['internal_networks']
    if any(g.overlaps(i) for g in guests for i in internal):problems.append('internal_networks overlaps guest_networks')
    for address in [out['portal_server']]+out['dns_servers']:
        if any(address in g for g in guests):problems.append(str(address)+' is inside guest_networks')
    out['guest_interfaces']=values['guest_interfaces']
    out['firewall_rules']=[values['firewall_rule_start']+STEP*i for i in range(5+len(out['dns_servers']))]
    out['nat_rules']=[values['nat_rule_start']+i for i in range(len(out['guest_interfaces']))]
    for key,existing in (('firewall_rules','existing_firewall_rules'),('nat_rules','existing_nat_rules')):
        clash=sorted(set(out[key])&set(values[existing]))
        if clash:problems.append(key.replace('_',' ')+' collide with existing: '+', '.join(map(str,clash)))
    return (None if problems else out),problems

def render(c):
    fw=iter(c['firewall_rules']);lines=[]
    def rule(*parts):
        number=next(fw);lines.extend('set {} rule {} {}'.format(CHAIN,number,p) for p in parts);return number
    lines+=['# ===== 16.3 段階2：同意前は止める（VyOS 1.4）。configureの中で実行 =====',
            '# 先に段階1（16.2）：save /config/before-portal.boot',
            '','# 許可済み端末（最初は空。アプリが追加・削除する）','set firewall group address-group PORTAL-AUTHED']
    lines+=['set firewall group network-group GUEST-NETS network '+str(n) for n in c['guest_networks']]
    lines+=['set firewall group network-group PORTAL-INTERNAL network '+str(n) for n in c['internal_networks']]
    lines+=['','# 転送のルール（上から順に評価。番号は既存ルールとの順番を確認済みであること）',
            '# 戻りの通信（すでに既存ルールにあれば、この1件は不要）']
    rule("action 'accept'","state 'established'","state 'related'")
    lines.append('# ゲスト → 同意画面(80/443)')
    rule("action 'accept'","source group network-group 'GUEST-NETS'","destination address '{}'".format(c['portal_server']),"protocol 'tcp'","destination port '80,443'")
    lines.append('# ゲスト → DNS')
    for dns in c['dns_servers']:
        rule("action 'accept'","source group network-group 'GUEST-NETS'","destination address '{}'".format(dns),"protocol 'tcp_udp'","destination port '53'")
    lines.append('# ゲスト → 管理・内部ネットワーク：拒否（許可済みでも）')
    rule("action 'drop'","source group network-group 'GUEST-NETS'","destination group network-group 'PORTAL-INTERNAL'")
    lines.append('# 許可済み → インターネット')
    rule("action 'accept'","source group address-group 'PORTAL-AUTHED'")
    lines.append('# 未許可のゲスト → それ以外：拒否')
    last=rule("action 'drop'","source group network-group 'GUEST-NETS'")
    lines+=['','# 未許可端末のhttp(80)を同意画面へ向ける（httpsは向けない）',
            '# VyOSは1つのルールにaddress-groupとnetwork-groupを同時に書けないため、入口のインターフェースで絞る']
    for number,interface in zip(c['nat_rules'],c['guest_interfaces']):
        lines+=['set nat destination rule {} {}'.format(number,p) for p in (
            "inbound-interface name '{}'".format(interface),"protocol 'tcp'","destination port '80'",
            "source group address-group '!PORTAL-AUTHED'","translation address '{}'".format(c['portal_server']))]
    lines+=['','# 反映：5分以内にconfirmしないと自動で元に戻る','commit-confirm 5',
            '# 16.3の試験（端末1台）に通ったら：','confirm','save',
            '# DHCPはcore-rt自身（またはリレー）が扱うため、転送のルールには含めない',
            '# 許可を外しても、すでに張られた接続は切れるまで続く（すぐ止めるなら reset conntrack）',
            '','# ===== 16.6 切り戻し（予備案：ゲストを全員許可。内部への拒否は残す） =====']
    lines+=['delete nat destination rule '+str(n) for n in c['nat_rules']]
    lines+=["set {} rule {} action 'accept'".format(CHAIN,last),'commit','save',
            '# 段階1の状態に完全に戻す場合：load /config/before-portal.boot → commit → save',
            '# 掲示：当日資料/wifi-案内.html（Wi-Fi接続用QRだけの案内）']
    return '\n'.join(lines)+'\n'

def main(argv):
    if len(argv)!=2:print(__doc__.strip(),file=sys.stderr);return 2
    try:
        with open(argv[1],encoding='utf-8') as handle:values=json.load(handle)
    except (OSError,ValueError) as error:print('Cannot read values: '+str(error),file=sys.stderr);return 2
    settings,problems=check(values)
    if problems:print('Not rendered:\n'+'\n'.join('- '+p for p in problems),file=sys.stderr);return 1
    sys.stdout.reconfigure(encoding='utf-8')  # same bytes on Windows and FreeBSD when redirected to a file
    sys.stdout.write(render(settings));return 0

if __name__=='__main__':sys.exit(main(sys.argv))
