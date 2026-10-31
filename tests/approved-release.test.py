from pathlib import Path
import importlib.util,tempfile,shutil,copy,unittest
root=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('approved',root/'scripts/approved-release.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Fake:
 def __init__(self):self.current={'id':1,'tag_name':'v1.0.3','draft':False,'assets':[]};self.releases=[];self.data={};self.next=100;self.publications=0
 def latest(self):return copy.deepcopy(self.current)
 def request(self,path,method='GET',data=None):
  if path=='/releases' and method=='GET':return copy.deepcopy(self.releases)
  if path=='/releases' and method=='POST':
   r={'id':2,'assets':[],**data};self.releases.append(r);return copy.deepcopy(r)
  if path=='/releases/2' and method=='PATCH':
   self.releases[0].update(data);self.current=copy.deepcopy(self.releases[0]);self.publications+=1;return copy.deepcopy(self.current)
  raise AssertionError('Unexpected API operation')
 def upload(self,rid,name,data):
  self.next+=1;a={'id':self.next,'name':name,'size':len(data)};self.releases[0]['assets'].append(a);self.data[a['id']]=data;return copy.deepcopy(a)
 def download(self,aid,limit):return self.data[aid]
class Tests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.candidate=max((root/'release-candidates').iterdir());cls.approved=m.authenticate(cls.candidate)
 def test_signature_and_tamper(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/self.candidate.name;shutil.copytree(self.candidate,p);(p/'request.json').write_text('{}')
   with self.assertRaises(RuntimeError):m.authenticate(p)
 def test_two_phase_and_immutable_replay(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/self.candidate.name;shutil.copytree(self.candidate,p);api=Fake();request={k:v for k,v in self.approved.items() if k!='update'}
   first=m.publish(api,p,request,'a'*40);self.assertFalse(first['published']);self.assertEqual(api.publications,0)
   again=m.publish(api,p,request,'a'*40);self.assertEqual(first['asset_id'],again['asset_id']);self.assertEqual(len(api.releases[0]['assets']),6)
   (p/'nexpilot-update.json').write_text('synthetic offline metadata')
   request['update']={'asset_id':first['asset_id']+1,'bytes':request['bytes'],'sha256':request['sha256']}
   with self.assertRaises(RuntimeError):m.publish(api,p,request,'a'*40)
   self.assertEqual(api.publications,0);request['update']['asset_id']=first['asset_id']
   result=m.publish(api,p,request,'a'*40);self.assertTrue(result['published']);self.assertEqual(api.publications,1)
   result=m.publish(api,p,request,'a'*40);self.assertEqual(result['state'],'already-published');self.assertEqual(api.publications,1)
 def test_downgrade_and_asset_substitution(self):
  api=Fake();api.current['tag_name']='v99.0.0'
  with self.assertRaises(RuntimeError):m.publish(api,self.candidate,self.approved,'a'*40)
  api=Fake();request={k:v for k,v in self.approved.items() if k!='update'};m.publish(api,self.candidate,request,'a'*40);api.data[next(iter(api.data))]=b'changed'
  with self.assertRaises(RuntimeError):m.publish(api,self.candidate,request,'a'*40)
if __name__=='__main__':unittest.main()
