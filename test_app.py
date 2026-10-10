import os,tempfile,unittest,re,hashlib,time
folder=tempfile.TemporaryDirectory()
os.environ.update(APP_SECRET='test-secret-only',ADMIN_PASSWORD='test-admin-password',DATABASE_PATH=folder.name+'/test.sqlite3')
from app import app, db
app.config['TESTING']=True
class Flow(unittest.TestCase):
 def test_full(self):
  admin=app.test_client(); user=app.test_client(); outsider=app.test_client()
  def post(client,path,data=None):
   client.get('/login')
   with client.session_transaction() as s: csrf=s['csrf']
   return client.post(path,data={**(data or {}),'csrf':csrf})
  self.assertEqual(outsider.post('/login',data={}).status_code,302)
  self.assertEqual(post(user,'/register',{'email':'user@example.com','password':'user-test-password'}).status_code,302)
  post(user,'/login',{'email':'user@example.com','password':'user-test-password'})
  self.assertEqual(user.get('/admin').status_code,403)
  post(admin,'/login',{'email':'admin@example.com','password':'test-admin-password'})
  self.assertEqual(admin.get('/admin').status_code,200)
  post(admin,'/admin/plans',{'name':'测试套餐','price':'29.90','days':'30'})
  post(user,'/order',{'plan':'1'})
  post(admin,'/admin/nodes',{'name':'测试节点','host':'example.com','port':'443','protocol':'trojan'})
  config='proxies:\n  - name: 测试节点\n    type: trojan\n    server: example.com\n    port: 443\n    password: test-only-no-real-node\n'
  post(admin,'/admin/subscriptions/2',{'config':config})
  post(user,'/subscription/reset')
  with user.session_transaction() as s: token=s['subscription_token']
  self.assertEqual(outsider.get('/sub/'+token).status_code,403)
  post(admin,'/admin/orders/1/approve')
  with app.app_context(): expiry=db().execute('SELECT expires FROM users WHERE id=2').fetchone()[0]
  post(admin,'/admin/orders/1/approve')
  with app.app_context(): self.assertEqual(db().execute('SELECT expires FROM users WHERE id=2').fetchone()[0],expiry)
  response=outsider.get('/sub/'+token)
  self.assertEqual(response.status_code,200);self.assertIn('test-only-no-real-node',response.text)
  post(admin,'/admin/nodes/1/toggle');self.assertEqual(outsider.get('/sub/'+token).status_code,503)
  post(admin,'/admin/nodes/1/toggle')
  post(user,'/subscription/reset');self.assertEqual(outsider.get('/sub/'+token).status_code,404)
  with user.session_transaction() as s: token=s['subscription_token']
  post(admin,'/admin/users/2/toggle');self.assertEqual(outsider.get('/sub/'+token).status_code,403)
  post(admin,'/admin/users/2/toggle')
  self.assertEqual(user.get('/dashboard').status_code,302)
  post(user,'/login',{'email':'user@example.com','password':'user-test-password'})
  with app.app_context():
   db().execute('UPDATE users SET expires=? WHERE id=2',(int(time.time())-1,));db().commit()
  self.assertEqual(outsider.get('/sub/'+token).status_code,403)
  self.assertEqual(admin.get('/admin/nodes').status_code,200)
  self.assertEqual(user.get('/dashboard').status_code,200)
  post(user,'/password',{'old':'user-test-password','new':'changed-test-password'})
  post(user,'/login',{'email':'user@example.com','password':'changed-test-password'})
  self.assertEqual(user.get('/dashboard').status_code,200)
class LoginRegression(unittest.TestCase):
 def setUp(self):
  with app.app_context():
   db().execute('DELETE FROM attempts');db().commit()
 def submit(self,client,email='admin@example.com',password='test-admin-password'):
  client.get('/login')
  with client.session_transaction() as session: token=session['csrf']
  return client.post('/login',data={'csrf':token,'email':email,'password':password})
 def test_successful_logins_do_not_consume_failure_limit(self):
  client=app.test_client()
  for _ in range(35): self.assertEqual(self.submit(client).status_code,302)
  self.assertEqual(client.get('/admin').status_code,200)
  with app.app_context(): self.assertEqual(db().execute('SELECT COUNT(*) FROM attempts').fetchone()[0],0)
 def test_different_account_can_login_on_shared_tunnel(self):
  client=app.test_client()
  for _ in range(30): self.submit(client,email='wrong@example.com',password='wrong')
  self.assertEqual(self.submit(client,email='wrong@example.com',password='wrong').status_code,429)
  self.assertEqual(self.submit(client).status_code,302)
  self.assertEqual(client.get('/admin').status_code,200)
 def test_old_or_missing_csrf_recovers_without_logging_in(self):
  client=app.test_client()
  response=client.post('/login',data={'csrf':'old','email':'admin@example.com','password':'test-admin-password'})
  self.assertEqual(response.status_code,302)
  self.assertEqual(client.get('/admin').status_code,302)
  self.assertEqual(self.submit(client).status_code,302)
  self.assertEqual(client.get('/admin').status_code,200)
 def test_cookie_isolated_from_other_local_apps(self):
  response=app.test_client().get('/login')
  self.assertIn('wq_member_session=',response.headers['Set-Cookie'])
  self.assertNotIn(' session=',response.headers['Set-Cookie'])
class NetworkIntegration(unittest.TestCase):
 def test_automatic_subscription_and_authorization(self):
  from network_state import eligible
  with app.app_context():
   db().execute('DELETE FROM attempts')
   db().execute("INSERT INTO nodes(name,host,port,protocol) VALUES('自动测试','example.net',443,'vmess')")
   nid=db().execute("SELECT id FROM nodes WHERE host='example.net'").fetchone()[0]
   db().execute('INSERT INTO net_settings(id,host,port,node_id) VALUES(1,?,?,?)',('example.net',443,nid));db().commit()
  admin=app.test_client();user=app.test_client()
  def post(client,path,data=None):
   client.get('/login')
   with client.session_transaction() as session: token=session['csrf']
   return client.post(path,data={**(data or {}),'csrf':token})
  post(admin,'/login',{'email':'admin@example.com','password':'test-admin-password'})
  post(user,'/login',{'email':'user@example.com','password':'changed-test-password'})
  self.assertEqual(user.get('/admin/network').status_code,403)
  self.assertEqual(post(user,'/admin/network/users/2/action',{'action':'grant','days':'7'}).status_code,403)
  post(admin,'/admin/network/users/2/action',{'action':'grant','days':'7'})
  post(user,'/subscription/reset')
  with user.session_transaction() as session: token=session['subscription_token']
  response=user.get('/sub/'+token);self.assertEqual(response.status_code,200)
  import yaml
  first=yaml.safe_load(response.text)['proxies'][0]['uuid']
  post(admin,'/admin/network/users/2/action',{'action':'rotate'})
  second=yaml.safe_load(user.get('/sub/'+token).text)['proxies'][0]['uuid']
  self.assertNotEqual(first,second)
  post(admin,'/admin/network/users/2/action',{'action':'disable'})
  self.assertEqual(user.get('/sub/'+token).status_code,403)
  post(admin,'/admin/network/users/2/action',{'action':'enable'})
  self.assertEqual(user.get('/sub/'+token).status_code,200)
  post(admin,'/admin/network/users/2/action',{'action':'quota','gib':'1'})
  with app.app_context():
   db().execute('UPDATE net_credentials SET up_bytes=? WHERE user_id=2',(1024**3,));db().commit()
   row=db().execute('SELECT c.*,u.enabled AS user_enabled,c.enabled AS credential_enabled,u.expires,s.enabled AS sub_enabled FROM net_credentials c JOIN users u ON u.id=c.user_id LEFT JOIN subscriptions s ON s.user_id=u.id WHERE c.user_id=2').fetchone()
   self.assertFalse(eligible(row,int(time.time())))
  self.assertEqual(user.get('/sub/'+token).status_code,403)
  self.assertEqual(admin.get('/admin/network').status_code,200)
class PaymentFlow(unittest.TestCase):
 def test_manual_payment(self):
  import app as module,json
  old=module.PAYMENT_CONFIG
  with tempfile.TemporaryDirectory() as directory:
   from pathlib import Path
   Path(directory+'/alipay.jpg').write_bytes(b'test-image-only')
   Path(directory+'/config.json').write_text(json.dumps({'url':'https://qr.alipay.com/test-only'}))
   module.PAYMENT_CONFIG=directory+'/config.json'
   try:
    user=app.test_client();admin=app.test_client();outsider=app.test_client()
    def post(client,path,data=None):
     client.get('/login')
     with client.session_transaction() as session: csrf=session['csrf']
     return client.post(path,data={**(data or {}),'csrf':csrf})
    post(user,'/login',{'email':'user@example.com','password':'changed-test-password'})
    post(admin,'/login',{'email':'admin@example.com','password':'test-admin-password'})
    response=post(user,'/order',{'plan':'1'})
    self.assertEqual(response.status_code,302)
    path=response.headers['Location'];self.assertTrue(path.endswith('/pay'))
    oid=int(path.split('/')[2]);page=user.get(path)
    self.assertEqual(page.status_code,200)
    self.assertIn('https://qr.alipay.com/test-only',page.text)
    self.assertEqual(outsider.get(path).status_code,302)
    self.assertEqual(admin.get(path).status_code,404)
    self.assertEqual(user.get('/payments/alipay/image').status_code,200)
    self.assertEqual(outsider.get('/payments/alipay/image').status_code,302)
    with app.app_context():
     before=db().execute('SELECT expires FROM users WHERE id=2').fetchone()[0]
     self.assertEqual(db().execute('SELECT status FROM orders WHERE id=?',(oid,)).fetchone()[0],'pending')
    post(admin,'/admin/orders/'+str(oid)+'/approve')
    post(admin,'/admin/orders/'+str(oid)+'/approve')
    self.assertIn('会员有效期已更新',user.get(path).text)
    with app.app_context():
     self.assertGreaterEqual(db().execute('SELECT expires FROM users WHERE id=2').fetchone()[0],before+30*86400)
    response=post(user,'/order',{'plan':'1'});path=response.headers['Location'];oid=int(path.split('/')[2])
    post(user,'/orders/'+str(oid)+'/cancel')
    self.assertNotIn('https://qr.alipay.com/test-only',user.get(path).text)
    Path(directory+'/config.json').write_text(json.dumps({'url':'https://evil.example/test'}))
    self.assertIsNone(module.payment_config())
   finally: module.PAYMENT_CONFIG=old

class RoutingRules(unittest.TestCase):
 def test_rules_and_permissions(self):
  from routing import routing_config, validate_rules, CATEGORIES
  import yaml
  admin=app.test_client();visitor=app.test_client()
  self.assertEqual(visitor.get('/admin/routing').status_code,302)
  admin.get('/login')
  with admin.session_transaction() as session: csrf=session['csrf']
  admin.post('/login',data={'csrf':csrf,'email':'admin@example.com','password':'test-admin-password'})
  self.assertEqual(admin.get('/admin/routing').status_code,200)
  with admin.session_transaction() as session: csrf=session['csrf']
  rule='DOMAIN-SUFFIX,example.com,DIRECT'
  response=admin.post('/admin/routing',data={'csrf':csrf,'custom':rule,'baseline':'1','choice_ChatGPT':'REJECT'})
  self.assertEqual(response.status_code,302)
  with app.app_context():
   config=routing_config(db(),[{'name':'test-node'}])
   self.assertEqual(config['mode'],'rule')
   self.assertEqual(config['rules'][0],rule)
   self.assertEqual(config['rules'][1:4],['GEOSITE,cn,DIRECT','GEOSITE,apple,苹果服务','GEOSITE,microsoft,微软服务'])
   for name in ('苹果服务','微软服务','哔哩哔哩','抖音'):
    self.assertEqual(next(g for g in config['proxy-groups'] if g['name']==name)['proxies'][0],'DIRECT')
   self.assertEqual(config['rules'][-1],'MATCH,服务节点')
   self.assertGreater(len(config['rules']),3800)
   self.assertEqual(next(g for g in config['proxy-groups'] if g['name']=='ChatGPT')['proxies'][0],'REJECT')
   self.assertEqual(yaml.safe_load(yaml.safe_dump(config,allow_unicode=True)),config)
  for invalid in ['DOMAIN-SUFFIX,https://example.com,DIRECT','MATCH,DIRECT','IP-CIDR,wrong,DIRECT','DOMAIN,x.com,unknown','DOMAIN,x.com,DIRECT,no-resolve']:
   with self.assertRaises(ValueError): validate_rules(invalid)
   self.assertEqual(admin.post('/admin/routing',data={'csrf':csrf,'custom':invalid}).status_code,400)
  with app.app_context():
   self.assertEqual(db().execute('SELECT custom FROM routing_settings').fetchone()[0],rule)
   db().execute("UPDATE routing_settings SET custom='',baseline=1,choices='{}'");db().commit()
if __name__=='__main__': unittest.main()
