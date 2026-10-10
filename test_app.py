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
if __name__=='__main__': unittest.main()
