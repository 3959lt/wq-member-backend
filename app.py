import os, sqlite3, secrets, functools, time, re, hashlib
import yaml
import uuid
from network_state import ensure_tables, allocate_credentials, network_user, proxy_config
from datetime import datetime, timezone, timedelta
from flask import Flask, render_template, request, session, redirect, url_for, flash, abort, g
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config.update(SECRET_KEY=os.environ['APP_SECRET'], SESSION_COOKIE_NAME='wq_member_session', SESSION_COOKIE_HTTPONLY=True,
 SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=os.getenv('COOKIE_SECURE')=='1',
 PERMANENT_SESSION_LIFETIME=timedelta(hours=8), MAX_CONTENT_LENGTH=16384)
DB=os.getenv('DATABASE_PATH', 'data/app.sqlite3')

def db():
    if 'db' not in g:
        g.db=sqlite3.connect(DB, timeout=15)
        g.db.row_factory=sqlite3.Row
        g.db.execute('PRAGMA foreign_keys=ON')
    return g.db

@app.teardown_appcontext
def close_db(error):
    if 'db' in g: g.db.close()

def initialize():
    os.makedirs(os.path.dirname(DB) or '.', exist_ok=True)
    with app.app_context():
        db().executescript('''
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', enabled INTEGER NOT NULL DEFAULT 1, expires INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL, auth_version INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS plans(id INTEGER PRIMARY KEY, name TEXT NOT NULL, cents INTEGER NOT NULL, days INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), plan_name TEXT NOT NULL, cents INTEGER NOT NULL, days INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending', created INTEGER NOT NULL, approved INTEGER);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, actor INTEGER REFERENCES users(id), action TEXT NOT NULL, target TEXT NOT NULL, created INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS nodes(id INTEGER PRIMARY KEY, name TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL, protocol TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, UNIQUE(host,port,protocol));
        CREATE TABLE IF NOT EXISTS subscriptions(user_id INTEGER PRIMARY KEY REFERENCES users(id), token_hash TEXT UNIQUE, config TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS attempts(key TEXT PRIMARY KEY, started INTEGER NOT NULL, count INTEGER NOT NULL);
        ''')
        db().execute("BEGIN IMMEDIATE")
        if "auth_version" not in [r[1] for r in db().execute("PRAGMA table_info(users)")]:
            db().execute("ALTER TABLE users ADD COLUMN auth_version INTEGER NOT NULL DEFAULT 1")
        if not db().execute("SELECT 1 FROM users WHERE role='admin'").fetchone():
            password=os.environ.get('ADMIN_PASSWORD')
            if not password: raise RuntimeError('ADMIN_PASSWORD required for initial setup')
            db().execute('INSERT INTO users(email,password,role,created) VALUES(?,?,?,?)',
                (os.getenv('ADMIN_EMAIL','admin@example.com'),generate_password_hash(password),'admin',int(time.time())))
        db().commit()
        ensure_tables(db())

@app.before_request
def security():
    g.user = db().execute('SELECT * FROM users WHERE id=?',(session.get('uid'),)).fetchone() if session.get('uid') else None
    if g.user and (not g.user['enabled'] or session.get('auth_version')!=g.user['auth_version']):
        session.clear(); g.user=None
    if 'csrf' not in session: session['csrf']=secrets.token_urlsafe(32)
    if request.method=='POST' and not secrets.compare_digest(session['csrf'],request.form.get('csrf','')):
        if request.endpoint in ('login', 'register'):
            session.pop('csrf', None)
            flash('登录或注册页面已失效，请在刷新后的页面重新填写。', 'error')
            return redirect(url_for(request.endpoint))
        abort(400, '表单已失效，请刷新页面后重试。')

@app.after_request
def headers(response):
    response.headers['Cache-Control']='no-store'
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['X-Frame-Options']='DENY'
    response.headers['Referrer-Policy']='same-origin'
    response.headers['Content-Security-Policy']="default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
    return response

def require(admin=False):
    def wrap(fn):
        @functools.wraps(fn)
        def inner(*args,**kwargs):
            if not g.user: return redirect(url_for('login'))
            if admin and g.user['role']!='admin': abort(403)
            return fn(*args,**kwargs)
        return inner
    return wrap

def audit(action,target):
    db().execute('INSERT INTO audit(actor,action,target,created) VALUES(?,?,?,?)',(g.user['id'],action,str(target),int(time.time())))

def throttle(scope='register', count=True):
    now=int(time.time())
    ip=request.remote_addr or 'unknown'
    email=request.form.get('email','').strip().lower()
    identity=hashlib.sha256((ip+'|'+email).encode()).hexdigest()
    keys=[(scope+':account:'+identity,30),(scope+':ip:'+ip,300)] if scope=='login' else [(scope+':ip:'+ip,30)]
    db().execute('BEGIN IMMEDIATE')
    db().execute('DELETE FROM attempts WHERE started<?',(now-900,))
    for key,limit in keys:
        row=db().execute('SELECT count,started FROM attempts WHERE key=?',(key,)).fetchone()
        if row and row['count']>=limit:
            retry=max(1,row['started']+900-now)
            db().commit()
            response=app.make_response((render_template('error.html',error=type('RateError',(),{'code':429,'description':'尝试次数过多，请稍后重试。'})()),429))
            response.headers['Retry-After']=str(retry)
            abort(response)
        if count:
            db().execute('INSERT INTO attempts(key,started,count) VALUES(?,?,1) ON CONFLICT(key) DO UPDATE SET count=count+1',(key,now))
    db().commit()

@app.template_filter('date')
def date(value):
    return datetime.fromtimestamp(value,timezone(timedelta(hours=8))).strftime('%Y-%m-%d %H:%M') if value else '未开通'

@app.context_processor
def context(): return {'now':int(time.time())}

@app.route('/')
def home(): return redirect(url_for('admin' if g.user and g.user['role']=='admin' else 'dashboard'))

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        throttle('login', count=False)
        user=db().execute('SELECT * FROM users WHERE email=?',(request.form.get('email','').strip().lower(),)).fetchone()
        if user and check_password_hash(user['password'],request.form.get('password','')) and user['enabled']:
            session.clear(); session['uid']=user['id']; session['auth_version']=user['auth_version']; session.permanent=True
            return redirect(url_for('home'))
        throttle('login')
        flash('账号或密码错误，或账号已被停用。请使用邮箱登录。','error')
    return render_template('auth.html',register=False)

@app.route('/register',methods=['GET','POST'])
def register():
    if request.method=='POST':
        throttle(); email=request.form.get('email','').strip().lower(); password=request.form.get('password','')
        if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',email) or len(email)>254 or not 12<=len(password)<=128:
            flash('请输入有效邮箱，密码长度为 12–128 位。','error')
        else:
            try:
                db().execute('INSERT INTO users(email,password,created) VALUES(?,?,?)',(email,generate_password_hash(password),int(time.time())))
                db().commit(); flash('注册完成，请登录。'); return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                db().rollback(); flash('无法使用该邮箱注册。','error')
    return render_template('auth.html',register=True)

@app.post('/logout')
def logout(): session.clear(); return redirect(url_for('login'))

@app.get('/dashboard')
@require()
def dashboard():
    return render_template('dashboard.html',network=network_user(db(),g.user['id']),plans=db().execute('SELECT * FROM plans WHERE enabled=1 ORDER BY cents').fetchall(),orders=db().execute('SELECT * FROM orders WHERE user_id=? ORDER BY id DESC',(g.user['id'],)).fetchall(),subscription=db().execute("SELECT 1 FROM subscriptions WHERE user_id=? AND config!=''",(g.user['id'],)).fetchone())

@app.post('/order')
@require()
def order():
    plan=db().execute('SELECT * FROM plans WHERE id=? AND enabled=1',(request.form.get('plan'),)).fetchone()
    if not plan: abort(400)
    db().execute('BEGIN IMMEDIATE')
    if db().execute("SELECT COUNT(*) FROM orders WHERE user_id=? AND status='pending'",(g.user['id'],)).fetchone()[0]>=3:
        db().rollback(); flash('最多保留 3 笔待确认订单，请先取消旧订单。','error')
    else:
        db().execute('INSERT INTO orders(user_id,plan_name,cents,days,created) VALUES(?,?,?,?,?)',(g.user['id'],plan['name'],plan['cents'],plan['days'],int(time.time())))
        audit('创建订单',plan['name']); db().commit(); flash('订单已创建，请联系管理员确认付款。网络服务尚未自动开通。')
    return redirect(url_for('dashboard'))

@app.post('/orders/<int:oid>/cancel')
@require()
def cancel(oid):
    cur=db().execute("UPDATE orders SET status='cancelled' WHERE id=? AND user_id=? AND status='pending'",(oid,g.user['id']))
    if cur.rowcount: audit('取消订单',oid)
    db().commit(); return redirect(url_for('dashboard'))

@app.get('/admin')
@require(True)
def admin():
    return render_template('admin.html',users=db().execute('SELECT id,email,role,enabled,expires,created FROM users ORDER BY id DESC').fetchall(),plans=db().execute('SELECT * FROM plans').fetchall(),orders=db().execute('SELECT o.*,u.email FROM orders o JOIN users u ON u.id=o.user_id ORDER BY o.id DESC LIMIT 100').fetchall(),logs=db().execute('SELECT a.*,u.email FROM audit a LEFT JOIN users u ON u.id=a.actor ORDER BY a.id DESC LIMIT 50').fetchall())

@app.post('/admin/plans')
@require(True)
def plan_add():
    try:
        from decimal import Decimal, InvalidOperation
        price=Decimal(request.form.get('price','')); cents=int(price*100); days=int(request.form.get('days',''))
        name=request.form.get('name','').strip()
        if not price.is_finite() or price*100!=cents or not 1<=cents<=100000000 or not 1<=days<=3650 or not 1<=len(name)<=80: raise ValueError()
    except (ValueError,InvalidOperation,OverflowError):
        flash('套餐名称、价格或天数不合法。','error'); return redirect(url_for('admin'))
    db().execute('INSERT INTO plans(name,cents,days) VALUES(?,?,?)',(name,cents,days)); audit('添加套餐',name); db().commit()
    flash('套餐已添加。'); return redirect(url_for('admin'))

@app.post('/admin/plans/<int:pid>/toggle')
@require(True)
def plan_toggle(pid):
    db().execute('UPDATE plans SET enabled=1-enabled WHERE id=?',(pid,)); audit('切换套餐上架状态',pid); db().commit(); return redirect(url_for('admin'))

@app.post('/admin/orders/<int:oid>/approve')
@require(True)
def approve(oid):
    db().execute('BEGIN IMMEDIATE')
    order=db().execute("SELECT * FROM orders WHERE id=? AND status='pending'",(oid,)).fetchone()
    if not order:
        db().rollback(); flash('订单已处理，不会重复开通。','error')
    else:
        now=int(time.time())
        db().execute("UPDATE orders SET status='paid',approved=? WHERE id=?",(now,oid))
        db().execute('UPDATE users SET expires=MAX(expires,?)+? WHERE id=?',(now,order['days']*86400,order['user_id']))
        audit('人工确认收款并延长会员',oid); db().commit(); flash('已记录收款并更新会员有效期。节点权限将由自动节点同步。')
    return redirect(url_for('admin'))

@app.post('/admin/users/<int:uid>/toggle')
@require(True)
def user_toggle(uid):
    user=db().execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone()
    if not user or user['role']=='admin': abort(400)
    db().execute('UPDATE users SET enabled=1-enabled,auth_version=auth_version+1 WHERE id=?',(uid,)); audit('切换账号状态',uid); db().commit(); return redirect(url_for('admin'))

@app.route('/password',methods=['GET','POST'])
@require()
def password():
    if request.method=='POST':
        new=request.form.get('new','')
        if not check_password_hash(g.user['password'],request.form.get('old','')) or not 12<=len(new)<=128:
            flash('当前密码错误，或新密码长度不符合要求。','error')
        else:
            db().execute('UPDATE users SET password=?,auth_version=auth_version+1 WHERE id=?',(generate_password_hash(new),g.user['id']))
            audit('修改密码',g.user['id']); db().commit(); session.clear(); flash('密码已修改，请重新登录。'); return redirect(url_for('login'))
    return render_template('password.html')

@app.get('/health')
def health(): db().execute('SELECT 1'); return {'status':'ok','service':'wq-member-backend','version':'0.3.0'}

@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(429)
def error(e): return render_template('error.html',error=e),e.code

@app.route('/admin/nodes',methods=['GET','POST'])
@require(True)
def nodes():
    if request.method=='POST':
        name=request.form.get('name','').strip(); host=request.form.get('host','').strip(); protocol=request.form.get('protocol','')
        try:
            port=int(request.form.get('port',''))
            if not 1<=port<=65535 or not 1<=len(name)<=80 or not re.fullmatch(r'[a-zA-Z0-9.:_-]{1,253}',host) or protocol not in ('ss','trojan','vmess','vless'): raise ValueError()
            db().execute('INSERT INTO nodes(name,host,port,protocol) VALUES(?,?,?,?)',(name,host,port,protocol)); audit('登记节点',name); db().commit(); flash('节点信息已保存，此操作不会安装节点程序。')
        except (ValueError,sqlite3.IntegrityError):
            db().rollback(); flash('节点信息不合法或记录重复。','error')
        return redirect(url_for('nodes'))
    return render_template('nodes.html',nodes=db().execute('SELECT * FROM nodes').fetchall(),users=db().execute("SELECT u.id,u.email,s.enabled AS sub_enabled,s.config FROM users u LEFT JOIN subscriptions s ON s.user_id=u.id WHERE u.role='user'").fetchall())

@app.post('/admin/nodes/<int:nid>/toggle')
@require(True)
def node_toggle(nid):
    db().execute('UPDATE nodes SET enabled=1-enabled WHERE id=?',(nid,)); audit('切换节点可分发状态',nid); db().commit(); return redirect(url_for('nodes'))

@app.post('/admin/subscriptions/<int:uid>')
@require(True)
def configure_subscription(uid):
    if not db().execute("SELECT 1 FROM users WHERE id=? AND role='user'",(uid,)).fetchone(): abort(404)
    text=request.form.get('config','')
    try:
        if len(text)>12000: raise ValueError()
        # Reject aliases to avoid recursive or expansion-heavy configuration input.
        if any(isinstance(t,(yaml.tokens.AliasToken,yaml.tokens.AnchorToken)) for t in yaml.scan(text)): raise ValueError()
        value=yaml.safe_load(text)
        proxies=value.get('proxies') if isinstance(value,dict) else None
        if not isinstance(proxies,list) or not 1<=len(proxies)<=30: raise ValueError()
        names=set()
        for p in proxies:
            if not isinstance(p,dict) or not isinstance(p.get('name'),str) or not p['name'] or p['name'] in names: raise ValueError()
            if not isinstance(p.get('port'),int) or not isinstance(p.get('server'),str) or not isinstance(p.get('type'),str): raise ValueError()
            if not db().execute('SELECT 1 FROM nodes WHERE host=? AND port=? AND protocol=?',(p['server'],p['port'],p['type'])).fetchone(): raise ValueError()
            names.add(p['name'])
        config=yaml.safe_dump({'proxies':proxies},allow_unicode=True)
    except (ValueError,TypeError,yaml.YAMLError,RecursionError):
        flash('配置无效：请提供 proxies 列表，名称不能重复，地址、端口和协议须对应已登记节点。不允许 YAML 锚点。','error'); return redirect(url_for('nodes'))
    db().execute('INSERT INTO subscriptions(user_id,config) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET config=excluded.config',(uid,config))
    audit('更新用户订阅配置',uid); db().commit(); flash('订阅配置已保存。请确保这些用户专属凭证已在节点端实际创建。'); return redirect(url_for('nodes'))

@app.post('/admin/subscriptions/<int:uid>/toggle')
@require(True)
def sub_toggle(uid):
    db().execute('UPDATE subscriptions SET enabled=1-enabled WHERE user_id=?',(uid,)); audit('切换订阅分发状态',uid); db().commit(); return redirect(url_for('nodes'))

@app.post('/subscription/reset')
@require()
def subscription_reset():
    token=secrets.token_urlsafe(32)
    db().execute('INSERT INTO subscriptions(user_id,token_hash) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET token_hash=excluded.token_hash',(g.user['id'],hashlib.sha256(token.encode()).hexdigest()))
    audit('重置订阅链接',g.user['id']); db().commit(); session['subscription_token']=token
    flash('新的订阅链接已生成，旧链接立即失效。'); return redirect(url_for('subscription_link'))

@app.get('/subscription-link')
@require()
def subscription_link():
    token=session.get('subscription_token')
    record=db().execute('SELECT token_hash FROM subscriptions WHERE user_id=?',(g.user['id'],)).fetchone()
    if not token or not record or record['token_hash']!=hashlib.sha256(token.encode()).hexdigest(): token=None
    return render_template('subscription.html',token=token)

@app.get('/sub/<token>')
def subscription_download(token):
    if len(token)>100: abort(404)
    record=db().execute('SELECT s.*,u.enabled AS user_enabled,u.expires FROM subscriptions s JOIN users u ON u.id=s.user_id WHERE token_hash=?',(hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
    if not record: abort(404)
    if not record['enabled'] or not record['user_enabled'] or record['expires']<=int(time.time()): abort(403)
    network=network_user(db(),record['user_id'])
    if network['credential'] and network['settings']:
        c=network['credential'];setting=network['settings']
        node=db().execute('SELECT enabled FROM nodes WHERE id=?',(setting['node_id'],)).fetchone()
        if not c['enabled'] or not setting['enabled'] or not node or not node['enabled']: abort(403)
        if c['quota_bytes'] and c['up_bytes']+c['down_bytes']>=c['quota_bytes']: abort(403)
        proxies=[proxy_config(setting,c)]
        config={'proxies':proxies,'proxy-groups':[{'name':'服务节点','type':'select','proxies':[p['name'] for p in proxies]}],'rules':['MATCH,服务节点']}
        response=app.response_class(yaml.safe_dump(config,allow_unicode=True),mimetype='text/yaml')
        response.headers['Content-Disposition']='attachment; filename="subscription.yaml"'
        return response
    if not record['config']: return '订阅尚未配置',503
    proxies=[]
    for p in yaml.safe_load(record['config'])['proxies']:
        if db().execute('SELECT 1 FROM nodes WHERE host=? AND port=? AND protocol=? AND enabled=1',(p['server'],p['port'],p['type'])).fetchone(): proxies.append(p)
    if not proxies: return '暂无可分发节点',503
    config={'proxies':proxies,'proxy-groups':[{'name':'服务节点','type':'select','proxies':[p['name'] for p in proxies]}],'rules':['MATCH,服务节点']}
    response=app.response_class(yaml.safe_dump(config,allow_unicode=True),mimetype='text/yaml')
    response.headers['Content-Disposition']='attachment; filename="subscription.yaml"'
    return response

@app.get('/admin/network')
@require(True)
def network_admin():
    return render_template('network.html',settings=db().execute('SELECT * FROM net_settings WHERE id=1').fetchone(),runtime=db().execute('SELECT * FROM net_runtime WHERE id=1').fetchone(),users=db().execute("SELECT u.id,u.email,u.enabled,u.expires,c.uuid,c.enabled AS credential_enabled,c.quota_bytes,c.up_bytes,c.down_bytes FROM users u LEFT JOIN net_credentials c ON c.user_id=u.id WHERE u.role='user' ORDER BY u.id").fetchall())

@app.post('/admin/network/users/<int:uid>/action')
@require(True)
def network_action(uid):
    if not db().execute("SELECT 1 FROM users WHERE id=? AND role='user'",(uid,)).fetchone(): abort(404)
    if not db().execute('SELECT 1 FROM net_settings WHERE id=1').fetchone(): abort(400)
    action=request.form.get('action')
    db().execute('BEGIN IMMEDIATE');allocate_credentials(db())
    if action=='grant':
        try:
            days=int(request.form.get('days',''))
            if not 1<=days<=3650: raise ValueError()
        except ValueError:
            db().rollback();flash('有效天数须为 1–3650。','error');return redirect(url_for('network_admin'))
        db().execute('UPDATE users SET expires=MAX(expires,?)+? WHERE id=?',(int(time.time()),days*86400,uid))
        db().execute('UPDATE net_credentials SET enabled=1 WHERE user_id=?',(uid,))
        db().execute('UPDATE subscriptions SET enabled=1 WHERE user_id=?',(uid,))
    elif action=='disable': db().execute('UPDATE net_credentials SET enabled=0 WHERE user_id=?',(uid,))
    elif action=='enable': db().execute('UPDATE net_credentials SET enabled=1 WHERE user_id=?',(uid,))
    elif action=='rotate': db().execute('UPDATE net_credentials SET uuid=? WHERE user_id=?',(str(uuid.uuid4()),uid))
    elif action=='quota':
        try:
            gib=int(request.form.get('gib',''))
            if not 0<=gib<=100000: raise ValueError()
        except ValueError:
            db().rollback();flash('流量额度须为 0–100000 GiB。','error');return redirect(url_for('network_admin'))
        db().execute('UPDATE net_credentials SET quota_bytes=? WHERE user_id=?',(gib*1024**3,uid))
    else: db().rollback();abort(400)
    audit('节点授权操作 '+action,uid);db().commit();flash('已保存，通常 15–30 秒内同步至节点。权限变化会短暂重启节点并断开现有连接。');return redirect(url_for('network_admin'))

@app.post('/admin/network/toggle')
@require(True)
def network_toggle():
    db().execute('UPDATE net_settings SET enabled=1-enabled WHERE id=1');audit('切换自动节点状态',1);db().commit();return redirect(url_for('network_admin'))

initialize()
