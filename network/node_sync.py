#!/usr/bin/env python3
import os,sys,json,time,sqlite3,subprocess,re,uuid,fcntl
from pathlib import Path
sys.path.insert(0,'/opt/wq-backend')
from network_state import allocate_credentials, eligible

BINARY='/usr/local/lib/wq-xray/xray'
CONFIG=Path('/etc/wq-xray/config.json')
DB='/var/lib/wq-backend/app.sqlite3'

def command(args):
    return subprocess.run(args,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=15).stdout

def stats(conn):
    pid=command(['systemctl','show','wq-xray','--property=MainPID','--value']).strip()
    if pid=='0': return
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()+':'+pid+':'+Path('/proc/'+pid+'/stat').read_text().split()[21]
    result=json.loads(command([BINARY,'api','statsquery','--server=127.0.0.1:10085','-pattern=user>>>']))
    conn.execute('BEGIN IMMEDIATE')
    for item in result.get('stat',[]):
        match=re.fullmatch(r'user>>>user-(\d+)>>>traffic>>>(uplink|downlink)',item.get('name',''))
        if not match: continue
        uid=int(match.group(1));direction=match.group(2);value=max(0,int(item.get('value',0)))
        old=conn.execute('SELECT * FROM net_counters WHERE user_id=? AND direction=?',(uid,direction)).fetchone()
        delta=max(0,value-old['value']) if old and old['boot']==boot else value
        column='up_bytes' if direction=='uplink' else 'down_bytes'
        conn.execute('UPDATE net_credentials SET '+column+'='+column+'+? WHERE user_id=?',(delta,uid))
        if conn.execute('SELECT 1 FROM net_credentials WHERE user_id=?',(uid,)).fetchone():
            conn.execute('INSERT INTO net_counters VALUES(?,?,?,?) ON CONFLICT(user_id,direction) DO UPDATE SET boot=excluded.boot,value=excluded.value',(uid,direction,boot,value))
    conn.commit()

def make_config(rows):
    clients=[{'id':str(uuid.UUID(r['uuid'])),'email':'user-'+str(r['user_id']),'level':0} for r in rows]
    return {'log':{'loglevel':'warning'},'api':{'tag':'api','listen':'127.0.0.1:10085','services':['StatsService']},
        'stats':{},'policy':{'levels':{'0':{'statsUserUplink':True,'statsUserDownlink':True,'connIdle':300}}},
        'inbounds':[{'tag':'members','listen':'0.0.0.0','port':443,'protocol':'vmess','settings':{'clients':clients},'streamSettings':{'network':'tcp'}}],
        'outbounds':[{'tag':'direct','protocol':'freedom','settings':{'domainStrategy':'UseIP'}},{'tag':'blocked','protocol':'blackhole'}],
        'routing':{'domainStrategy':'IPOnDemand','rules':[{'type':'field','ip':['0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.168.0.0/16','224.0.0.0/4','240.0.0.0/4','::/128','::1/128','fc00::/7','fe80::/10','ff00::/8'],'outboundTag':'blocked'}]}}

def sync():
    conn=sqlite3.connect(DB,timeout=15);conn.row_factory=sqlite3.Row;conn.execute('PRAGMA foreign_keys=ON')
    try:
        stats_error=False
        if subprocess.run(['systemctl','is-active','--quiet','wq-xray']).returncode==0:
            try: stats(conn)
            except (subprocess.SubprocessError,ValueError,OSError):
                conn.rollback();stats_error=True
        conn.execute('BEGIN IMMEDIATE');allocate_credentials(conn);conn.commit()
        setting=conn.execute('SELECT s.*,n.enabled AS node_enabled FROM net_settings s JOIN nodes n ON n.id=s.node_id WHERE s.id=1').fetchone()
        rows=conn.execute("SELECT c.*,u.enabled AS user_enabled,c.enabled AS credential_enabled,u.expires,s.enabled AS sub_enabled FROM net_credentials c JOIN users u ON u.id=c.user_id LEFT JOIN subscriptions s ON s.user_id=u.id ORDER BY c.user_id").fetchall()
        active=[r for r in rows if eligible(r,int(time.time()))] if setting and setting['enabled'] and setting['node_enabled'] else []
        content=json.dumps(make_config(active),sort_keys=True,indent=2)+'\n'
        changed=not CONFIG.exists() or CONFIG.read_text()!=content
        if changed:
            temp=CONFIG.with_suffix('.new');temp.write_text(content);os.chmod(temp,0o640)
            command([BINARY,'run','-test','-format=json','-config',str(temp)])
            temp.replace(CONFIG)
        if changed or subprocess.run(['systemctl','is-active','--quiet','wq-xray']).returncode!=0:
            command(['sudo','-n','/usr/bin/systemctl','restart','wq-xray'])
        ready=False
        for _ in range(15):
            import socket
            try:
                with socket.create_connection(('127.0.0.1',10085),timeout=1): pass
                ready=True;break
            except OSError: time.sleep(.2)
        if not ready: raise RuntimeError('node API unavailable')
        conn.execute("UPDATE net_runtime SET updated=?,ready=1,active_count=?,error=? WHERE id=1",(int(time.time()),len(active),'流量采集暂时失败，授权仍已同步' if stats_error else ''));conn.commit()
        print('node sync complete; authorized users='+str(len(active)))
    except Exception as e:
        conn.rollback()
        conn.execute('UPDATE net_runtime SET updated=?,ready=0,error=? WHERE id=1',(int(time.time()),type(e).__name__+': 节点同步失败，请查看服务日志'));conn.commit()
        raise
    finally: conn.close()

if __name__=='__main__':
    with open('/var/lib/wq-backend/node-sync.lock','w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        try: sync()
        except Exception:
            subprocess.run(['sudo','-n','/usr/bin/systemctl','stop','wq-xray'],timeout=15)
            raise
