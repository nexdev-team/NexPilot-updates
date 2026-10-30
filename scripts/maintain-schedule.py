"""Record bounded public service maintenance monthly so the scheduled service stays active."""
from datetime import date
import base64,json,os,urllib.request,urllib.error
REPOSITORY='nexdev-team/NexPilot-updates'
URL='https://api.github.com/repos/'+REPOSITORY+'/contents/distribution-maintenance.json'
PURPOSE='nexpilot-public-update-service'
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**k):return None

def next_record(existing,today):
 if existing is not None:
  if set(existing)!={'format','purpose','checked_at'} or existing['format']!=1 or existing['purpose']!=PURPOSE:raise ValueError('Unexpected maintenance record')
  age=(today-date.fromisoformat(existing['checked_at'])).days
  if age<0:raise ValueError('Future maintenance record')
  if age<30:return None
 return {'format':1,'purpose':PURPOSE,'checked_at':today.isoformat()}

def maintain(request,today):
 response=request('GET',None);sha=None;existing=None
 if response is not None:
  if response.get('path')!='distribution-maintenance.json' or response.get('type')!='file' or response.get('size',4097)>4096 or response.get('encoding')!='base64':raise ValueError('Unexpected maintenance file')
  sha=response['sha'];existing=json.loads(base64.b64decode(response['content']))
 record=next_record(existing,today)
 if record is None:return {'maintenance':'healthy','changed':False}
 identity={'name':'NexPilot distribution bot','email':'distribution@nexpilot.invalid'}
 payload={'message':'Record monthly signed-update service maintenance','content':base64.b64encode((json.dumps(record,sort_keys=True)+'\n').encode()).decode(),'branch':'main','author':identity,'committer':identity}
 if sha:payload['sha']=sha
 request('PUT',payload)
 return {'maintenance':'refreshed','changed':True}

def main():
 if os.environ.get('GITHUB_REPOSITORY')!=REPOSITORY or os.environ.get('GITHUB_REF')!='refs/heads/main':raise ValueError('Unexpected repository/ref')
 token=os.environ.get('GITHUB_TOKEN','')
 if not token or any(c.isspace() for c in token):raise ValueError('Missing service credential')
 opener=urllib.request.build_opener(NoRedirect)
 def request(method,data):
  body=None if data is None else json.dumps(data).encode()
  req=urllib.request.Request(URL,method=method,data=body,headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','Content-Type':'application/json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'NexPilot-public-service-maintenance'})
  try:response=opener.open(req,timeout=30)
  except urllib.error.HTTPError as error:
   if method=='GET' and error.code==404:return None
   raise ValueError('Maintenance API request rejected') from None
  with response:raw=response.read(32769)
  if len(raw)>32768:raise ValueError('Maintenance response exceeds limit')
  return json.loads(raw)
 print(json.dumps(maintain(request,date.today()),sort_keys=True))
if __name__=='__main__':
 try:main()
 except Exception:raise SystemExit('Public schedule maintenance failed; no credential values are logged.')
