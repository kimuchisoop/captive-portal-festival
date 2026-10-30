"""AP inventory inspection only; it cannot enable networking or infer a live OS."""
import json
from pathlib import Path

SOURCES={
    'hardware':'https://arubanetworking.hpe.com/techdocs/hardware/aps/ap310/sug/AP-310_Startup_Guide_EN.pdf',
    'instant_example':'https://arubanetworking.hpe.com/techdocs/Archived/Instant-AOS-8/Instant_85_WebHelp/Content/instant-ug/captive-portal/conf-ext-cp.htm',
    'instant_readback':'https://arubanetworking.hpe.com/techdocs/CLI-Bank/Content/instant/sh-extern-cp.htm',
}
FIELDS={'product_model':'製品名','sku':'製品番号／SKU','os_family':'起動中のOS名','os_version':'OSバージョン',
        'management_mode':'管理方式','manager_address':'VCまたはコントローラーの管理先'}
CAPABILITIES={
    'launch_verification':'接続元をサーバーで照合する方法',
    'https_login':'HTTPSでの認証引き継ぎ',
    'radius_auth':'RADIUS認証と要求の検証',
    'absolute_deadline':'装置側の絶対時刻による利用期限',
    'session_observation':'対象端末の接続と許可ロールの観測',
    'targeted_disconnect':'対象セッションへの切断要求と結果確認',
    'ipv6_control':'IPv6を含む同等の利用制限',
}

def inspect_profile(path):
    p=Path(path)
    raw={};errors=[]
    if p.exists():
        try:
            if p.stat().st_size>32768: raise ValueError()
            raw=json.loads(p.read_text(encoding='utf-8'))
            if not isinstance(raw,dict): raise ValueError()
        except (OSError,ValueError): raw={};errors.append('確認情報ファイルを読み取れません。')
    facts={}
    for key,label in FIELDS.items():
        value=raw.get(key)
        if value is not None and (not isinstance(value,str) or len(value)>160):
            errors.append(label+'の形式を確認してください。');value=None
        facts[key]=value.strip() if value else None
    if facts['management_mode'] not in (None,'instant','controller'):
        errors.append('管理方式はinstantまたはcontrollerで確認してください。')
    missing=[{'id':k,'label':v} for k,v in FIELDS.items() if not facts[k]]
    mode=facts['management_mode']
    plan=('Instantの実機OSに合う外部ポータル・RADIUS仕様を確認する。' if mode=='instant' else
          'コントローラーの型番・OSと外部ポータル・RADIUS仕様を確認する。' if mode=='controller' else
          '製品ラベルと起動情報からInstant／コントローラー管理を判別する。')
    return dict(regulatory_model='APIN0315',regulatory_model_source='過去の引継ぎ記録',facts=facts,
                missing=missing,errors=errors,plan=plan,
                required_capabilities=[{'id':k,'label':v,'status':'not_verified'} for k,v in CAPABILITIES.items()],
                identity_complete=not missing and not errors,live_verified=False,adapter='disconnected',
                production_ready=False,sources=SOURCES,
                note='APIN0315はAP-315／IAP-315に共通する認証用型式です。実機の製品番号・OS・機能を確定した値ではありません。')
