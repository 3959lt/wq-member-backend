import json, ipaddress, re
from pathlib import Path

DEFAULT_RULES = json.loads(Path(__file__).with_name('routing-defaults.json').read_text())
CATEGORIES = sorted({r.split(',')[2] for r in DEFAULT_RULES if r.split(',')[0]!='MATCH' and r.split(',')[2] not in ('DIRECT','REJECT','服务节点')})
TARGETS = {'DIRECT','REJECT','服务节点',*CATEGORIES}

def ensure_routing(conn):
    conn.execute("CREATE TABLE IF NOT EXISTS routing_settings(id INTEGER PRIMARY KEY CHECK(id=1), custom TEXT NOT NULL DEFAULT '', baseline INTEGER NOT NULL DEFAULT 1, choices TEXT NOT NULL DEFAULT '{}')")
    conn.execute("INSERT OR IGNORE INTO routing_settings(id) VALUES(1)")
    conn.commit()

def validate_rules(text):
    rules=[]
    for number,line in enumerate(text.splitlines(),1):
        line=line.strip()
        if not line or line.startswith('#'): continue
        parts=[x.strip() for x in line.split(',')]
        if len(parts) not in (3,4) or parts[0] not in {'DOMAIN','DOMAIN-SUFFIX','DOMAIN-KEYWORD','IP-CIDR','IP-CIDR6','GEOIP','PROCESS-NAME'}:
            raise ValueError('第 %s 行：规则类型或字段数量不正确。'%number)
        kind,value,target=parts[:3]
        if not value or target not in TARGETS: raise ValueError('第 %s 行：值为空或目标策略不存在。'%number)
        if len(parts)==4 and (parts[3]!='no-resolve' or kind not in ('IP-CIDR','IP-CIDR6','GEOIP')):
            raise ValueError('第 %s 行：no-resolve 只能用于 IP / GEOIP 规则。'%number)
        if kind in ('DOMAIN','DOMAIN-SUFFIX') and (not re.fullmatch(r'[A-Za-z0-9_.-]+',value) or '/' in value):
            raise ValueError('第 %s 行：请填写域名，不要填写网址。'%number)
        if kind in ('IP-CIDR','IP-CIDR6'):
            try: network=ipaddress.ip_network(value,strict=False)
            except ValueError: raise ValueError('第 %s 行：IP 网段不正确。'%number)
            if network.version != (6 if kind=='IP-CIDR6' else 4): raise ValueError('第 %s 行：IP 版本与规则不匹配。'%number)
        rules.append(','.join(parts))
        if len(rules)>1000: raise ValueError('自定义规则最多 1000 条。')
    return rules

def routing_config(conn,proxies):
    settings=conn.execute('SELECT * FROM routing_settings WHERE id=1').fetchone()
    choices=json.loads(settings['choices'])
    groups=[{'name':'服务节点','type':'select','proxies':[p['name'] for p in proxies]}]
    for category in CATEGORIES:
        first=choices.get(category,'服务节点')
        options=[first]+[x for x in ('服务节点','DIRECT','REJECT') if x!=first]
        groups.append({'name':category,'type':'select','proxies':options})
    rules=validate_rules(settings['custom'])
    if settings['baseline']: rules += [r for r in DEFAULT_RULES if not r.startswith('MATCH,')]
    rules.append('MATCH,服务节点')
    return {'mode':'rule','log-level':'info','proxies':proxies,'proxy-groups':groups,'rules':rules}
