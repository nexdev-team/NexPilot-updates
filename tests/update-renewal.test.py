"""Synthetic security/recovery tests. No GitHub requests, real keys or site access."""
from pathlib import Path
import copy, importlib.util, io, json, subprocess, tempfile, unittest, urllib.error

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('renew_update',ROOT/'scripts/renew-update.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
NOW=1800000000

def envelope(expiry=NOW+100):
    return json.dumps({'format':2,'channel':'public','repository':module.REPOSITORY,'slug':'nexdev-site-connector','version':'1.0.2','tag':'v1.0.2','asset_id':11,'bytes':3,'sha256':'a'*64,'issued_at':NOW-100,'expires_at':expiry}).encode()
def inspect(raw,zip):
    if raw==b'tampered':raise module.RenewalError('Signature rejected')
    return json.loads(raw)
def sign(raw,zip):
    m=json.loads(raw);m.update(issued_at=NOW,expires_at=NOW+7*86400);return json.dumps(m).encode()

class FakeGitHub:
    def __init__(self,raw=None):
        self.release={'id':1,'tag_name':'v1.0.2','draft':False,'prerelease':False,'assets':[{'id':10,'name':module.CANONICAL,'size':100},{'id':11,'name':'nexdev-site-connector-1.0.2.zip','size':3}]}
        self.bytes={10:raw or envelope(),11:b'zip'};self.writes=[];self.fail_promote=False;self.race=False;self.latest_calls=0
    def latest(self):
        self.latest_calls+=1
        d=copy.deepcopy(self.release)
        if self.race and self.latest_calls>1:d['id']=2
        return d
    def download(self,id,limit):return self.bytes[id]
    def upload(self,rid,name,content):
        self.writes.append(('upload',99,name));self.release['assets'].append({'id':99,'name':name,'size':len(content)});self.bytes[99]=content;return self.release['assets'][-1]
    def rename(self,id,name):
        if self.fail_promote and id==99 and name==module.CANONICAL:self.fail_promote=False;raise module.RenewalError('Synthetic promotion failure')
        self.writes.append(('rename',id,name))
        next(a for a in self.release['assets'] if a['id']==id)['name']=name
    def delete(self,id):
        self.writes.append(('delete',id));self.release['assets']=[a for a in self.release['assets'] if a['id']!=id]

class RenewalTests(unittest.TestCase):
    def test_healthy_manifest_never_writes(self):
        api=FakeGitHub(envelope(NOW+3*86400));r=module.renew(api,inspect,sign,NOW)
        self.assertFalse(r['changed']);self.assertEqual(api.writes,[])
    def test_renewal_preserves_zip_and_original_backup(self):
        api=FakeGitHub();r=module.renew(api,inspect,sign,NOW)
        self.assertTrue(r['zip_unchanged']);self.assertEqual(api.bytes[11],b'zip')
        self.assertEqual(module.asset_by_name(api.latest(),module.CANONICAL)['id'],99)
        self.assertEqual(module.asset_by_name(api.latest(),'nexpilot-update.previous-10.json')['id'],10)
        self.assertTrue(all(w[1]!=11 for w in api.writes))
    def test_bad_signature_has_no_remote_mutation(self):
        api=FakeGitHub(b'tampered')
        with self.assertRaises(module.RenewalError):module.renew(api,inspect,sign,NOW)
        self.assertEqual(api.writes,[])
    def test_signer_cannot_change_asset_identity(self):
        api=FakeGitHub()
        def bad(raw,zip):
            m=json.loads(sign(raw,zip));m['asset_id']=12;return json.dumps(m).encode()
        with self.assertRaises(module.RenewalError):module.renew(api,inspect,bad,NOW)
        self.assertEqual(api.writes,[])
    def test_failed_promotion_restores_original_canonical(self):
        api=FakeGitHub();api.fail_promote=True
        with self.assertRaises(module.RenewalError):module.renew(api,inspect,sign,NOW)
        self.assertEqual(module.asset_by_name(api.latest(),module.CANONICAL)['id'],10)
        self.assertNotIn(99,[a['id'] for a in api.release['assets']])
    def test_concurrent_release_change_aborts_without_rename(self):
        api=FakeGitHub();api.race=True
        with self.assertRaises(module.RenewalError):module.renew(api,inspect,sign,NOW)
        self.assertFalse(any(w[0]=='rename' for w in api.writes))
    def test_interrupted_rename_recovers_authentic_previous(self):
        api=FakeGitHub();api.release['assets'][0]['name']='nexpilot-update.previous-10.json'
        self.assertTrue(module.renew(api,inspect,sign,NOW)['changed'])
        self.assertEqual(module.asset_by_name(api.latest(),module.CANONICAL)['id'],99)
    def test_unauthentic_recovery_candidate_never_promoted(self):
        api=FakeGitHub(b'tampered');api.release['assets'][0]['name']='nexpilot-update.previous-10.json'
        with self.assertRaises(module.RenewalError):module.renew(api,inspect,sign,NOW)
        self.assertEqual(api.writes,[])
    def test_prerelease_and_duplicate_names_rejected(self):
        for mode in ['prerelease','duplicate']:
            api=FakeGitHub()
            if mode=='prerelease':api.release['prerelease']=True
            else:api.release['assets'].append(copy.deepcopy(api.release['assets'][0]))
            with self.assertRaises(module.RenewalError):module.renew(api,inspect,sign,NOW)
            self.assertEqual(api.writes,[])
    def test_redirect_drops_github_credential(self):
        class Response(io.BytesIO):pass
        class Opener:
            def __init__(self,target):self.target=target;self.requests=[]
            def open(self,req,timeout):
                self.requests.append(req)
                if len(self.requests)==1:raise urllib.error.HTTPError(req.full_url,302,'redirect',{'Location':self.target},None)
                return Response(b'asset')
        api=module.GitHub('synthetic-unit-credential')
        api.opener=Opener('https://release-assets.githubusercontent.com/asset?temporary=fixture')
        self.assertEqual(api.download(1,100),b'asset')
        self.assertIsNone(api.opener.requests[1].get_header('Authorization'))
        api.opener=Opener('https://attacker.invalid/asset')
        with self.assertRaises(module.RenewalError):api.download(1,100)
        self.assertEqual(len(api.opener.requests),1)
    def test_php_actual_crypto_and_expired_metadata_recovery(self):
        private=ROOT/'.runtime/private';private.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(dir=private,prefix='renewal-unit-') as d:
            harness=Path(d)/'test.php'
            harness.write_text('''<?php
require $argv[1];
$pair=sodium_crypto_sign_keypair();$secret=sodium_crypto_sign_secretkey($pair);$public=base64_encode(sodium_crypto_sign_publickey($pair));$now=1800000000;
$zip=__DIR__.'/fixture.zip';file_put_contents($zip,'synthetic ZIP bytes');
$base=['format'=>2,'channel'=>'public','repository'=>'nexdev-team/NexPilot-updates','slug'=>'nexdev-site-connector','version'=>'1.0.2','tag'=>'v1.0.2','asset_id'=>71,'bytes'=>filesize($zip),'sha256'=>hash_file('sha256',$zip),'issued_at'=>$now-8*86400,'expires_at'=>$now-86400];
function seal($m,$s){$p=json_encode($m);return json_encode(['payload'=>$p,'signature'=>base64_encode(sodium_crypto_sign_detached($p,$s))]);}
$old=seal($base,$secret);$m=renewal_manifest($old,$zip,$public,$now);$new=renewal_envelope($m,$secret,$public,$now);$v=renewal_manifest($new,$zip,$public,$now);
if($v['sha256']!==$base['sha256']||$v['asset_id']!==71||$v['expires_at']!==$now+7*86400)throw new Exception('Identity changed');
$denied=0;
foreach([['repository'=>'other/repo'],['tag'=>'v1.0.3'],['issued_at'=>$now+500],['expires_at'=>$now+40*86400],['sha256'=>str_repeat('0',64)]] as $change){try{renewal_manifest(seal(array_replace($base,$change),$secret),$zip,$public,$now);}catch(Throwable $e){$denied++;}}
try{renewal_envelope($base,sodium_crypto_sign_secretkey(sodium_crypto_sign_keypair()),$public,$now);}catch(Throwable $e){$denied++;}
$broken=json_decode($old,true);$broken['payload'].=' ';try{renewal_manifest(json_encode($broken),$zip,$public,$now);}catch(Throwable $e){$denied++;}
if($denied!==7)throw new Exception('Negative cases failed');echo "8 actual cryptographic and identity checks passed.\\n";
''')
            r=subprocess.run(['php',str(harness),str(ROOT/'scripts/renew-update.php')],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stderr);self.assertIn('8 actual cryptographic',r.stdout)

if __name__=='__main__':unittest.main(verbosity=2)
