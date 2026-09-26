#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,math,os,queue,re,smtplib,socket,ssl,sqlite3,threading,time
from collections import Counter
from datetime import datetime,timedelta,timezone
from email.message import EmailMessage
from pathlib import Path
from flask import Flask,Response,abort,jsonify,request,send_from_directory
try:
 import paramiko; HAVE_PARAMIKO=True
except Exception: HAVE_PARAMIKO=False
BASE=Path(__file__).resolve().parent; DATA=Path(os.getenv('DATA_DIR',BASE/'data')); DB=Path(os.getenv('DB_PATH',DATA/'honeypot.db')); SAMPLES=Path(os.getenv('SAMPLES_DIR',DATA/'captured_samples')); KEY=Path(os.getenv('HOST_KEY_PATH',DATA/'honeypot_host_key')); STATIC=BASE/'static'
HTTP_PORT=int(os.getenv('HTTP_PORT','8080')); TELNET_PORT=int(os.getenv('TELNET_PORT','2323')); SSH_PORT=int(os.getenv('SSH_PORT','2222')); DASH_PORT=int(os.getenv('DASH_PORT','5000')); DASH_HOST=os.getenv('DASH_HOST','127.0.0.1'); DASH_TOKEN=os.getenv('DASH_TOKEN',''); MAX_BODY=int(os.getenv('MAX_BODY_BYTES','262144')); MAX_SAMPLE=int(os.getenv('MAX_SAMPLE_BYTES','1048576')); WINDOW=int(os.getenv('BRUTE_WINDOW_SECONDS','300')); THRESHOLD=int(os.getenv('BRUTE_THRESHOLD','5')); RETENTION=int(os.getenv('RETENTION_DAYS','90')); COOLDOWN=int(os.getenv('EMAIL_COOLDOWN_SECONDS','600'))
lock=threading.RLock(); subs=set(); sublock=threading.Lock(); stop=threading.Event()
SIGS=[('CVE-2021-44228','Log4Shell',re.compile(r'\$\{jndi:(?:ldap|rmi|dns|iiop):',re.I)),('CVE-2014-6271','Shellshock',re.compile(r'\(\)\s*\{\s*:\s*;\s*\}',re.I)),('CVE-2021-41773','Apache path traversal',re.compile(r'(?:%2e){2,}',re.I)),('CVE-2022-1388','F5 BIG-IP',re.compile(r'tmshCmd|X-F5-Auth-Token',re.I)),('CVE-2022-22965','Spring4Shell',re.compile(r'class\.module\.classLoader|class\.classLoader',re.I)),('CVE-2021-26855','ProxyLogon',re.compile(r'proxyLogon|owaAuth',re.I)),('CVE-2017-9841','PHPUnit eval-stdin',re.compile(r'/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin\.php',re.I))]
RECON={'/.env','/.git/config','/.git/HEAD','/wp-login.php','/wp-admin','/admin','/login','/administrator','/phpmyadmin','/server-status','/config.php','/config.json','/actuator/env','/debug','/backup.zip'}
CREDS={('root','root'),('root','toor'),('root','123456'),('root','password'),('admin','admin'),('admin','123456'),('admin','password'),('user','user'),('test','test'),('guest','guest'),('root','xc3511')}
ATT={'brute':('T1110','Brute Force'),'recon':('T1595','Active Scanning'),'exploit':('T1190','Exploit Public-Facing Application'),'cred':('T1078','Valid Accounts')}
def now(): return datetime.now(timezone.utc).isoformat(timespec='seconds')
def clean(x,n=500): return ''.join(c for c in str(x or '') if c.isprintable())[:n]
def conn():
 DATA.mkdir(parents=True,exist_ok=True); c=sqlite3.connect(DB,timeout=15,check_same_thread=False); c.row_factory=sqlite3.Row; c.execute('PRAGMA journal_mode=WAL'); c.execute('PRAGMA busy_timeout=15000'); return c
def init_db():
 DATA.mkdir(parents=True,exist_ok=True); SAMPLES.mkdir(parents=True,exist_ok=True)
 with lock:
  c=conn(); c.executescript('''CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,ts TEXT,service TEXT,src_ip TEXT,src_port INTEGER,kind TEXT,detail TEXT,score INTEGER,severity TEXT);CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY,ts TEXT,src_ip TEXT,alert_type TEXT,severity TEXT,score INTEGER,technique_id TEXT,technique_name TEXT,detail TEXT,email_sent INTEGER DEFAULT 0);CREATE TABLE IF NOT EXISTS attackers(ip TEXT PRIMARY KEY,first_seen TEXT,last_seen TEXT,total_events INTEGER,login_attempts INTEGER,recon_hits INTEGER,signature_hits INTEGER,services TEXT,techniques TEXT,threat_score INTEGER);CREATE TABLE IF NOT EXISTS credentials(id INTEGER PRIMARY KEY,ts TEXT,src_ip TEXT,service TEXT,username TEXT,password TEXT,UNIQUE(src_ip,service,username,password));CREATE TABLE IF NOT EXISTS samples(id INTEGER PRIMARY KEY,ts TEXT,sha256 TEXT UNIQUE,src_ip TEXT,filename TEXT,size INTEGER,entropy REAL);CREATE TABLE IF NOT EXISTS signatures(id INTEGER PRIMARY KEY,ts TEXT,src_ip TEXT,service TEXT,cve_id TEXT,name TEXT,snippet TEXT);CREATE TABLE IF NOT EXISTS cooldowns(k TEXT PRIMARY KEY,last REAL);CREATE INDEX IF NOT EXISTS e_ts ON events(ts);CREATE INDEX IF NOT EXISTS e_ip ON events(src_ip);CREATE INDEX IF NOT EXISTS a_ts ON alerts(ts);CREATE INDEX IF NOT EXISTS a_ip ON alerts(src_ip);'''); c.commit(); c.close()
def publish(t,d):
 m={'type':t,'ts':now(),**d}
 with sublock:
  for q in list(subs):
   try:q.put_nowait(m)
   except: subs.discard(q)
def stats_ip(ip):
 cut=(datetime.now(timezone.utc)-timedelta(seconds=WINDOW)).isoformat(timespec='seconds')
 with lock:
  c=conn(); log=c.execute("select count(*) n from events where src_ip=? and kind='login_attempt' and ts>=?",(ip,cut)).fetchone()['n']; paths=c.execute("select count(distinct json_extract(detail,'$.path')) n from events where src_ip=? and kind='http_request' and ts>=?",(ip,cut)).fetchone()['n']; sig=c.execute('select count(*) n from signatures where src_ip=?',(ip,)).fetchone()['n']; services=[r[0] for r in c.execute('select distinct service from events where src_ip=?',(ip,))]; total=c.execute('select count(*) n from events where src_ip=?',(ip,)).fetchone()['n']; c.close()
 score=min(100,log*10+max(0,paths-1)*12+max(0,len(services)-1)*8+sig*35); label='exploit' if sig else 'brute' if log>=THRESHOLD else 'recon' if paths>=3 else 'cred' if log else 'low'; sev='Critical' if score>=80 else 'High' if score>=50 else 'Medium' if score>=25 else 'Low'; return score,sev,label,total,log,paths,sig,services
def email_allowed(k):
 if os.getenv('ALERT_EMAIL_ENABLED','false').lower()!='true': return False
 with lock:
  c=conn(); r=c.execute('select last from cooldowns where k=?',(k,)).fetchone(); t=time.time()
  if r and t-r['last']<COOLDOWN:c.close();return False
  c.execute('insert into cooldowns(k,last) values(?,?) on conflict(k) do update set last=excluded.last',(k,t));c.commit();c.close();return True
def send_alert(a):
 if not email_allowed(a['src_ip']+'|'+a['alert_type']): return False
 h,u,p,to=os.getenv('SMTP_HOST'),os.getenv('SMTP_USER'),os.getenv('SMTP_PASS'),os.getenv('ALERT_TO'); port=int(os.getenv('SMTP_PORT','587'))
 if not all((h,u,p,to)): return False
 m=EmailMessage();m['Subject']=f"[Honeypot {a['severity']}] {a['alert_type']} from {a['src_ip']}";m['From']=u;m['To']=to;m.set_content(json.dumps(a,indent=2))
 try:
  with smtplib.SMTP(h,port,timeout=15) as s:s.starttls(context=ssl.create_default_context());s.login(u,p);s.send_message(m)
  return True
 except Exception as e: print('[email]',e);return False
def alert(ip,typ,sev,score,detail,key):
 tid,tname=ATT.get(key,('','')); a={'src_ip':ip,'alert_type':typ,'severity':sev,'score':score,'technique_id':tid,'technique_name':tname,'detail':detail}; sent=send_alert(a)
 with lock:
  c=conn();c.execute('insert into alerts(ts,src_ip,alert_type,severity,score,technique_id,technique_name,detail,email_sent) values(?,?,?,?,?,?,?,?,?)',(now(),ip,typ,sev,score,tid,tname,json.dumps(detail),int(sent)));c.commit();c.close()
 publish('alert',a)
def event(service,ip,port,kind,detail):
 with lock:
  c=conn();c.execute('insert into events(ts,service,src_ip,src_port,kind,detail,score,severity) values(?,?,?,?,?,?,0,"Low")',(now(),service,ip,port,kind,json.dumps(detail)));c.commit();c.close()
 score,sev,label,total,log,paths,sig,services=stats_ip(ip)
 with lock:
  c=conn();c.execute('update events set score=?,severity=? where id=(select max(id) from events)',(score,sev));tech=ATT.get(label,('', ''))[0];c.execute('''insert into attackers(ip,first_seen,last_seen,total_events,login_attempts,recon_hits,signature_hits,services,techniques,threat_score) values(?,?,?,?,?,?,?,?,?,?) on conflict(ip) do update set last_seen=excluded.last_seen,total_events=excluded.total_events,login_attempts=excluded.login_attempts,recon_hits=excluded.recon_hits,signature_hits=excluded.signature_hits,services=excluded.services,techniques=excluded.techniques,threat_score=excluded.threat_score''',(ip,now(),now(),total,log,paths,sig,','.join(services),tech,score));c.commit();c.close()
 publish('event',{'service':service,'src_ip':ip,'src_port':port,'kind':kind,'detail':detail,'score':score,'severity':sev})
 if label=='exploit':alert(ip,'Exploit signature detected',sev,score,detail,'exploit')
 elif label=='brute' and kind=='login_attempt':alert(ip,f'{service.upper()} brute force',sev,score,detail,'brute')
 elif label=='recon' and kind=='http_request':alert(ip,'Web reconnaissance',sev,score,detail,'recon')
 elif label=='cred' and kind=='login_attempt':alert(ip,'Credential probing',sev,score,detail,'cred')
def signatures(text,ip,service):
 for cve,name,rx in SIGS:
  if rx.search(text):
   sn=clean(text,400)
   with lock:
    c=conn();c.execute('insert into signatures(ts,src_ip,service,cve_id,name,snippet) values(?,?,?,?,?,?)',(now(),ip,service,cve,name,sn));c.commit();c.close()
   event(service,ip,0,'signature_hit',{'cve_id':cve,'name':name,'snippet':sn})
def entropy(b):
 if not b:return 0.0
 c=Counter(b);n=len(b);return round(-sum(v/n*math.log2(v/n) for v in c.values()),3)
def sample(data,ip,name):
 if not data or len(data)>MAX_SAMPLE:return None
 h=hashlib.sha256(data).hexdigest();p=SAMPLES/h
 if not p.exists():p.write_bytes(data)
 with lock:
  c=conn();c.execute('insert or ignore into samples(ts,sha256,src_ip,filename,size,entropy) values(?,?,?,?,?,?)',(now(),h,ip,clean(name,200),len(data),entropy(data)));c.commit();c.close()
 event('http',ip,0,'file_upload',{'sha256':h,'size':len(data),'filename':clean(name,200)});return h
LOGIN='''<!doctype html><html><body style="font-family:Arial;background:#111;color:#eee;display:grid;place-items:center;height:100vh"><form method="post" action="/admin/login" style="background:#20252d;padding:30px;width:320px"><h2>System Administration</h2><input name="username" placeholder="Username" style="width:100%;padding:10px"><br><br><input name="password" type="password" placeholder="Password" style="width:100%;padding:10px"><br><br><button style="width:100%;padding:10px">Sign in</button></form></body></html>'''
web=Flask('honeypot')
@web.before_request
def capture():
 ip=request.remote_addr or 'unknown';body=request.get_data(cache=True,as_text=False)[:MAX_BODY];headers={clean(k,80):clean(v,300) for k,v in request.headers.items()};path=request.path[:300];text='\n'.join((path,request.query_string.decode('utf8','replace')[:1000],body.decode('utf8','replace')[:4000],json.dumps(headers)[:3000]));kind='http_request';event('http',ip,int(request.environ.get('REMOTE_PORT',0)),kind,{'method':request.method,'path':path,'ua':headers.get('User-Agent',''),'recon':path in RECON})
 signatures(text,ip,'http')
 if request.method in ('POST','PUT') and body and (request.content_type or '').split(';')[0]!='application/x-www-form-urlencoded':sample(body,ip,Path(path).name or 'upload.bin')
@web.route('/')
def home():return '<h1>Acme Infrastructure Portal</h1><a href="/admin">Administrator sign-in</a>'
@web.route('/admin')
@web.route('/login')
def login():return LOGIN
@web.route('/admin/login',methods=['POST'])
@web.route('/login',methods=['POST'])
def loginpost():
 u=clean(request.form.get('username'));p=clean(request.form.get('password'));ip=request.remote_addr or 'unknown'
 with lock:
  c=conn();c.execute('insert or ignore into credentials(ts,src_ip,service,username,password) values(?,?,?,?,?)',(now(),ip,'http',u,p));c.commit();c.close()
 event('http',ip,int(request.environ.get('REMOTE_PORT',0)),'login_attempt',{'username':u,'password':p,'default_credential':(u,p) in CREDS});return Response('Invalid credentials',401)
@web.route('/.env')
def env():return Response('APP_ENV=production\nAPP_NAME=acme-portal\nDEBUG=false\n',mimetype='text/plain')
@web.route('/health')
def health():return jsonify(status='ok')
def line(s,n=128):
 b=b''
 while len(b)<n:
  x=s.recv(1)
  if not x or x==b'\n':break
  b+=x
 return b.decode('utf8','replace').strip()
def telclient(s,a):
 ip,port=a
 try:
  s.settimeout(20);event('telnet',ip,port,'connect',{});s.sendall(b'Ubuntu 20.04.6 LTS\r\nlogin: ');u=line(s);s.sendall(b'Password: ');p=line(s)
  with lock:c=conn();c.execute('insert or ignore into credentials(ts,src_ip,service,username,password) values(?,?,?,?,?)',(now(),ip,'telnet',u,p));c.commit();c.close()
  event('telnet',ip,port,'login_attempt',{'username':u,'password':p,'default_credential':(u,p) in CREDS});s.sendall(b'\r\nLogin incorrect\r\n')
 except:pass
 finally:s.close()
def telnet():
 s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',TELNET_PORT));s.listen(100);print('[+] Telnet',TELNET_PORT)
 while not stop.is_set():
  try:s.settimeout(1);c,a=s.accept();threading.Thread(target=telclient,args=(c,a),daemon=True).start()
  except socket.timeout:continue
  except:break
if HAVE_PARAMIKO:
 class SSH(paramiko.ServerInterface):
  def __init__(self,ip,port):self.ip,self.port=ip,port
  def get_allowed_auths(self,u):return 'password,publickey'
  def check_channel_request(self,k,i):return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
  def check_auth_password(self,u,p):
   u,p=clean(u,100),clean(p,200)
   with lock:c=conn();c.execute('insert or ignore into credentials(ts,src_ip,service,username,password) values(?,?,?,?,?)',(now(),self.ip,'ssh',u,p));c.commit();c.close()
   event('ssh',self.ip,self.port,'login_attempt',{'username':u,'password':p,'default_credential':(u,p) in CREDS});return paramiko.AUTH_FAILED
  def check_auth_publickey(self,u,k):event('ssh',self.ip,self.port,'login_attempt',{'username':clean(u),'auth':'publickey','key_fingerprint':k.get_fingerprint().hex()});return paramiko.AUTH_FAILED
def sshclient(c,a,key):
 ip,port=a
 try:
  event('ssh',ip,port,'connect',{});t=paramiko.Transport(c);t.local_version='SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6';t.add_server_key(key);t.start_server(server=SSH(ip,port));t.accept(15);t.close()
 except:pass
 finally:c.close()
def ssh():
 if not HAVE_PARAMIKO:print('[!] Paramiko missing; SSH disabled');return
 DATA.mkdir(parents=True,exist_ok=True)
 if not KEY.exists():paramiko.RSAKey.generate(2048).write_private_key_file(str(KEY))
 key=paramiko.RSAKey(filename=str(KEY));s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',SSH_PORT));s.listen(100);print('[+] SSH',SSH_PORT)
 while not stop.is_set():
  try:s.settimeout(1);c,a=s.accept();threading.Thread(target=sshclient,args=(c,a,key),daemon=True).start()
  except socket.timeout:continue
  except:break
dash=Flask('dashboard',static_folder=str(STATIC),static_url_path='')
def auth():
 if DASH_TOKEN and request.headers.get('X-Dashboard-Token')!=DASH_TOKEN:abort(401)
@dash.before_request
def protect():
 if request.path.startswith('/api/') or request.path in ('/events','/export.csv'):auth()
@dash.route('/')
def index():return send_from_directory(STATIC,'index.html')
def cutoff(r):
 sec={'15m':900,'1h':3600,'24h':86400,'7d':604800,'30d':2592000}.get(r)
 return (datetime.now(timezone.utc)-timedelta(seconds=sec)).isoformat(timespec='seconds') if sec else '1970-01-01T00:00:00'
@dash.route('/api/stats')
def stats():
 x=cutoff(request.args.get('range','24h'))
 with lock:
  c=conn();a=lambda q:c.execute(q,(x,)).fetchone()[0];out={'total_events':a('select count(*) from events where ts>=?'),'unique_ips':a('select count(distinct src_ip) from events where ts>=?'),'login_attempts':a("select count(*) from events where ts>=? and kind='login_attempt'"),'alerts':a('select count(*) from alerts where ts>=?'),'critical':a("select count(*) from alerts where ts>=? and severity='Critical'"),'samples':a('select count(*) from samples where ts>=?'),'signatures':a('select count(*) from signatures where ts>=?')};c.close()
 return jsonify(out)
@dash.route('/api/events')
def events():
 try:n=max(1,min(int(request.args.get('limit','60')),500))
 except:n=60
 with lock:c=conn();r=c.execute('select * from events order by id desc limit ?',(n,)).fetchall();c.close()
 return jsonify(events=[dict(x,detail=json.loads(x['detail'])) for x in r])
@dash.route('/api/alerts')
def alerts():
 with lock:c=conn();r=c.execute('select * from alerts order by id desc limit 100').fetchall();c.close()
 return jsonify(alerts=[dict(x,detail=json.loads(x['detail'])) for x in r])
@dash.route('/api/attackers')
def attackers():
 with lock:c=conn();r=c.execute('select * from attackers order by threat_score desc,last_seen desc limit 100').fetchall();c.close()
 return jsonify(attackers=[dict(x) for x in r])
@dash.route('/api/signatures')
def sigs():
 with lock:c=conn();r=c.execute('select cve_id,name,count(*) count,max(ts) last_seen from signatures group by cve_id,name order by count desc').fetchall();c.close()
 return jsonify(signatures=[dict(x) for x in r])
@dash.route('/api/chart')
def chart():
 x=cutoff(request.args.get('range','24h'))
 with lock:c=conn();r=c.execute("select substr(ts,1,13) h,count(*) n from events where ts>=? group by h order by h",(x,)).fetchall();c.close()
 return jsonify(labels=[z['h']+':00Z' for z in r],values=[z['n'] for z in r])
@dash.route('/api/credentials')
def creds():
 with lock:c=conn();r=c.execute('select username,password,count(*) count from credentials group by username,password order by count desc limit 30').fetchall();c.close()
 return jsonify(credentials=[{'username':z['username'],'password':'•'*min(12,max(4,len(z['password'] or ''))),'count':z['count']} for z in r])
@dash.route('/api/samples')
def samples():
 with lock:c=conn();r=c.execute('select * from samples order by id desc limit 100').fetchall();c.close();return jsonify(samples=[dict(z) for z in r])
@dash.route('/events')
def sse():
 q=queue.Queue(100)
 with sublock:subs.add(q)
 def gen():
  try:
   yield 'retry: 3000\n\n'
   while True:
    try:m=q.get(timeout=20);yield 'data: '+json.dumps(m,separators=(',',':'))+'\n\n'
    except queue.Empty:yield ': keepalive\n\n'
  finally:
   with sublock:subs.discard(q)
 return Response(gen(),mimetype='text/event-stream',headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no'})
@dash.route('/export.csv')
def export():
 with lock:c=conn();r=c.execute('select ts,service,src_ip,src_port,kind,detail,score,severity from events order by id').fetchall();c.close()
 o=io.StringIO();w=csv.writer(o);w.writerow(['ts','service','src_ip','src_port','kind','detail','score','severity']);w.writerows([list(x) for x in r]);return Response(o.getvalue(),mimetype='text/csv',headers={'Content-Disposition':'attachment; filename=honeypot_events.csv'})
def retention():
 while not stop.wait(86400):
  cut=(datetime.now(timezone.utc)-timedelta(days=RETENTION)).isoformat(timespec='seconds')
  with lock:c=conn();c.execute('delete from events where ts<?',(cut,));c.execute('delete from credentials where ts<?',(cut,));c.execute('delete from signatures where ts<?',(cut,));c.commit();c.close()
def main():
 init_db();p=argparse.ArgumentParser();p.add_argument('cmd',choices=['run','report'],nargs='?',default='run');a=p.parse_args()
 if a.cmd=='report':
  with lock:c=conn();print('Events:',c.execute('select count(*) from events').fetchone()[0]);print('Alerts:',c.execute('select count(*) from alerts').fetchone()[0]);print('Attackers:',c.execute('select count(*) from attackers').fetchone()[0]);c.close();return
 print(f'[+] Dashboard: http://{DASH_HOST}:{DASH_PORT}');print(f'[+] HTTP:{HTTP_PORT} Telnet:{TELNET_PORT} SSH:{SSH_PORT}')
 for f in (ssh,telnet,lambda:dash.run(host=DASH_HOST,port=DASH_PORT,threaded=True,use_reloader=False),lambda:web.run(host='0.0.0.0',port=HTTP_PORT,threaded=True,use_reloader=False),retention):threading.Thread(target=f,daemon=True).start()
 try:
  while True:time.sleep(1)
 except KeyboardInterrupt:stop.set()
if __name__=='__main__':main()
