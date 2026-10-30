from pathlib import Path
import importlib.util,unittest,base64,json
from datetime import date,timedelta
spec=importlib.util.spec_from_file_location('maintenance',Path(__file__).resolve().parents[1]/'scripts/maintain-schedule.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class MaintenanceTests(unittest.TestCase):
 def test_fresh_record_never_writes(self):
  calls=[];record={'format':1,'purpose':m.PURPOSE,'checked_at':'2026-10-30'}
  def request(method,data):
   calls.append(method);return {'path':'distribution-maintenance.json','type':'file','size':100,'encoding':'base64','sha':'fixture','content':base64.b64encode(json.dumps(record).encode()).decode()}
  self.assertFalse(m.maintain(request,date(2026,11,28))['changed']);self.assertEqual(calls,['GET'])
 def test_monthly_refresh_changes_only_fixed_public_record(self):
  calls=[];record={'format':1,'purpose':m.PURPOSE,'checked_at':'2026-10-30'}
  def request(method,data):
   calls.append((method,data));return {'path':'distribution-maintenance.json','type':'file','size':100,'encoding':'base64','sha':'conditional-fixture','content':base64.b64encode(json.dumps(record).encode()).decode()} if method=='GET' else {}
  self.assertTrue(m.maintain(request,date(2026,11,29))['changed']);payload=calls[-1][1];self.assertEqual(payload['sha'],'conditional-fixture');self.assertEqual(payload['branch'],'main');self.assertEqual(set(json.loads(base64.b64decode(payload['content']))),{'format','purpose','checked_at'})
 def test_initial_service_record_is_generic(self):
  self.assertEqual(m.next_record(None,date(2026,10,30)),{'format':1,'purpose':m.PURPOSE,'checked_at':'2026-10-30'})
 def test_unknown_or_future_data_never_overwritten(self):
  for record in [{'format':1,'purpose':'unrelated','checked_at':'2026-10-30'},{'format':1,'purpose':m.PURPOSE,'checked_at':'2027-01-01'}]:
   with self.assertRaises(ValueError):m.next_record(record,date(2026,10,30))
if __name__=='__main__':unittest.main()
