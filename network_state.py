import uuid

SCHEMA='''
CREATE TABLE IF NOT EXISTS net_settings(id INTEGER PRIMARY KEY CHECK(id=1), host TEXT NOT NULL, port INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, node_id INTEGER REFERENCES nodes(id));
CREATE TABLE IF NOT EXISTS net_credentials(user_id INTEGER PRIMARY KEY REFERENCES users(id), uuid TEXT UNIQUE NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, quota_bytes INTEGER NOT NULL DEFAULT 0, up_bytes INTEGER NOT NULL DEFAULT 0, down_bytes INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS net_runtime(id INTEGER PRIMARY KEY CHECK(id=1), updated INTEGER NOT NULL DEFAULT 0, ready INTEGER NOT NULL DEFAULT 0, active_count INTEGER NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT '等待节点同步');
CREATE TABLE IF NOT EXISTS net_counters(user_id INTEGER NOT NULL REFERENCES users(id), direction TEXT NOT NULL, boot TEXT NOT NULL, value INTEGER NOT NULL, PRIMARY KEY(user_id,direction));
'''

def ensure_tables(conn):
    conn.executescript(SCHEMA)
    conn.execute("INSERT OR IGNORE INTO net_runtime(id) VALUES(1)")
    conn.commit()

def allocate_credentials(conn):
    for row in conn.execute("SELECT id FROM users WHERE role='user' AND id NOT IN (SELECT user_id FROM net_credentials)").fetchall():
        conn.execute('INSERT OR IGNORE INTO net_credentials(user_id,uuid) VALUES(?,?)',(row[0],str(uuid.uuid4())))

def proxy_config(settings, credential):
    return {'name':'WQ 自动节点','type':'vmess','server':settings['host'],'port':settings['port'],
            'uuid':credential['uuid'],'alterId':0,'cipher':'auto','network':'tcp','udp':True,'tls':False}

def eligible(row, now):
    return bool(row['user_enabled'] and row['credential_enabled'] and row['expires']>now and
                row['sub_enabled']!=0 and (not row['quota_bytes'] or row['up_bytes']+row['down_bytes']<row['quota_bytes']))

def network_user(conn, user_id):
    credential=conn.execute('SELECT * FROM net_credentials WHERE user_id=?',(user_id,)).fetchone()
    settings=conn.execute('SELECT * FROM net_settings WHERE id=1').fetchone()
    runtime=conn.execute('SELECT * FROM net_runtime WHERE id=1').fetchone()
    return {'credential':credential,'settings':settings,'runtime':runtime}
