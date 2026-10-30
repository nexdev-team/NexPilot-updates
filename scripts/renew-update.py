"""Renew an already signed public GitHub release. No site access, builds or new releases."""
from pathlib import Path
import argparse, json, os, re, subprocess, tempfile, time, urllib.request, urllib.parse, urllib.error

REPOSITORY = 'nexdev-team/NexPilot-updates'
API = 'https://api.github.com/repos/' + REPOSITORY
CANONICAL = 'nexpilot-update.json'
MAX_ZIP = 16777216

class RenewalError(Exception): pass
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): return None

class GitHub:
    def __init__(self, token):
        if not token or re.search(r'\s', token): raise RenewalError('Credential unavailable')
        self.token = token
        self.opener = urllib.request.build_opener(NoRedirect)

    def request(self, route, method='GET', data=None, binary=False, limit=262144):
        if not re.fullmatch(r'/releases(?:/latest|/[1-9][0-9]*(?:/assets)?|/assets/[1-9][0-9]*)?', route):
            raise RenewalError('API route denied')
        headers = {'Authorization':'Bearer '+self.token, 'Accept':'application/octet-stream' if binary else 'application/vnd.github+json', 'X-GitHub-Api-Version':'2022-11-28', 'User-Agent':'NexPilot-metadata-renewal'}
        payload = json.dumps(data).encode() if data is not None else None
        if payload is not None: headers['Content-Type']='application/json'
        try:
            response = self.opener.open(urllib.request.Request(API+route, data=payload, headers=headers, method=method), timeout=60)
        except urllib.error.HTTPError as error:
            if not binary or method!='GET' or error.code!=302: raise RenewalError('GitHub request rejected') from None
            target = error.headers.get('Location',''); parsed=urllib.parse.urlsplit(target)
            if parsed.scheme!='https' or parsed.hostname!='release-assets.githubusercontent.com' or parsed.username or parsed.password or parsed.port or parsed.fragment:
                raise RenewalError('Asset redirect denied')
            # New request: no Authorization header, no redirect following.
            response=self.opener.open(urllib.request.Request(target,headers={'User-Agent':'NexPilot-metadata-renewal'}),timeout=60)
        with response:
            raw=response.read(limit+1)
        if len(raw)>limit: raise RenewalError('Response exceeds limit')
        return raw if binary else json.loads(raw) if raw else None

    def latest(self): return self.request('/releases/latest')
    def download(self, asset, limit): return self.request('/releases/assets/'+str(asset),binary=True,limit=limit)
    def rename(self, asset, name): return self.request('/releases/assets/'+str(asset),'PATCH',{'name':name})
    def delete(self, asset): return self.request('/releases/assets/'+str(asset),'DELETE')
    def upload(self, release, name, content):
        route='https://uploads.github.com/repos/'+REPOSITORY+'/releases/'+str(release)+'/assets?name='+urllib.parse.quote(name,safe='')
        with self.opener.open(urllib.request.Request(route,data=content,method='POST',headers={'Authorization':'Bearer '+self.token,'Content-Type':'application/json','Accept':'application/vnd.github+json','User-Agent':'NexPilot-metadata-renewal'}),timeout=60) as response:
            raw=response.read(262145)
        if len(raw)>262144: raise RenewalError('Upload response exceeds limit')
        return json.loads(raw)

def identity(release):
    if release.get('draft') or release.get('prerelease') or not re.fullmatch(r'v[1-9][0-9]*\.[0-9]+\.[0-9]+',release.get('tag_name','')):
        raise RenewalError('Published Stable release required')
    if type(release.get('id')) is not int or release['id']<1: raise RenewalError('Invalid release identity')
    assets=release.get('assets',[])
    if len(assets)>100 or len({a['name'] for a in assets})!=len(assets): raise RenewalError('Ambiguous asset set')
    return release['id'],release['tag_name']

def asset_by_name(release,name):
    assets=[a for a in release['assets'] if a['name']==name]
    if len(assets)!=1 or type(assets[0].get('id')) is not int or assets[0]['id']<1: raise RenewalError('Expected release asset missing')
    return assets[0]

def renew(api, inspect, sign, now, force=False):
    release=api.latest(); rid,tag=identity(release)
    zip_asset=asset_by_name(release,'nexdev-site-connector-'+tag[1:]+'.zip')
    if not 0<zip_asset['size']<=MAX_ZIP: raise RenewalError('ZIP exceeds limit')
    archive=api.download(zip_asset['id'],MAX_ZIP)
    if not any(a['name']==CANONICAL for a in release['assets']):
        # Recover an interrupted rename using only authentic same-release metadata.
        valid=[]
        for a in release['assets']:
            if re.fullmatch(r'nexpilot-update\.previous-[1-9][0-9]*\.json',a['name']):
                try:
                    m=inspect(api.download(a['id'],32768),archive)
                    if (m['tag'],m['asset_id'],m['bytes'])==(tag,zip_asset['id'],zip_asset['size']):valid.append((m['issued_at'],a))
                except Exception:pass
        if not valid:raise RenewalError('No authentic metadata available for recovery')
        recovered=max(valid,key=lambda item:item[0])[1]
        if identity(api.latest())!=(rid,tag):raise RenewalError('Release changed during recovery')
        api.rename(recovered['id'],CANONICAL)
        release=api.latest()
        if identity(release)!=(rid,tag):raise RenewalError('Release changed during recovery')
    original=asset_by_name(release,CANONICAL)
    envelope=api.download(original['id'],32768)
    manifest=inspect(envelope,archive)
    if manifest['tag']!=tag or manifest['asset_id']!=zip_asset['id'] or manifest['bytes']!=zip_asset['size']:
        raise RenewalError('Signed release identity differs from GitHub')
    if not force and manifest['expires_at']-now>2*86400:
        return {'state':'healthy','version':tag[1:],'expires_at':manifest['expires_at'],'changed':False}
    renewed=sign(envelope,archive)
    new=inspect(renewed,archive)
    if {k:v for k,v in manifest.items() if k not in ('issued_at','expires_at')}!={k:v for k,v in new.items() if k not in ('issued_at','expires_at')}:
        raise RenewalError('Renewal changed code identity')
    if not now-300<=new['issued_at']<=now+300 or new['expires_at']-now<6*86400: raise RenewalError('Renewal window rejected')
    stage_name='nexpilot-update.staged-'+str(original['id'])+'-'+str(now)+'.json'
    stage=api.upload(rid,stage_name,renewed); old_renamed=False; promoted=False
    try:
        if api.download(stage['id'],32768)!=renewed: raise RenewalError('Staged upload differs')
        current=api.latest()
        if identity(current)!=(rid,tag) or asset_by_name(current,CANONICAL)['id']!=original['id'] or asset_by_name(current,zip_asset['name'])['id']!=zip_asset['id']:
            raise RenewalError('Release changed during renewal')
        api.rename(original['id'],'nexpilot-update.previous-'+str(original['id'])+'.json'); old_renamed=True
        api.rename(stage['id'],CANONICAL); promoted=True
        if api.download(stage['id'],32768)!=renewed: raise RenewalError('Published metadata differs')
    except Exception:
        # A failed promotion never deliberately removes the last authentic metadata.
        if old_renamed:
            if promoted: api.rename(stage['id'],stage_name)
            api.rename(original['id'],CANONICAL)
        api.delete(stage['id'])
        raise
    # Retain the previous authentic envelope for recovery; replace it only next cycle.
    # Remove older backup/staging assets only when owned by this renewal naming scheme.
    for a in release['assets']:
        if re.fullmatch(r'nexpilot-update\.(?:previous-[1-9][0-9]*|staged-[1-9][0-9]*-[0-9]+)\.json',a['name']):api.delete(a['id'])
    return {'state':'renewed','version':tag[1:],'expires_at':new['expires_at'],'changed':True,'zip_unchanged':True,'previous_metadata_asset':original['id']}

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--force',action='store_true');args=parser.parse_args()
    if os.environ.get('GITHUB_REPOSITORY')!=REPOSITORY: raise RenewalError('Unexpected repository')
    root=Path(__file__).resolve().parent
    temp_root=Path(os.environ.get('RUNNER_TEMP') or root.parent/'.runtime/private');temp_root.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='nexpilot-renew-',dir=temp_root) as tmp:
        private=Path(tmp);private.chmod(0o700);counter=0
        def php(mode,envelope,archive):
            nonlocal counter;counter+=1
            source=private/'source.json';zipfile=private/'release.zip';out=private/('result-'+str(counter)+'.json')
            source.write_bytes(envelope);zipfile.write_bytes(archive)
            result=subprocess.run(['php',str(root/'renew-update.php'),mode,str(source),str(zipfile),str(out)],capture_output=True)
            if result.returncode:raise RenewalError('Signature, identity or ZIP validation failed')
            return out.read_bytes()
        api=GitHub(os.environ.get('GITHUB_TOKEN',''))
        result=renew(api,lambda e,z:json.loads(php('inspect',e,z)),lambda e,z:php('renew',e,z),int(time.time()),args.force)
        print(json.dumps(result,sort_keys=True))
        summary=os.environ.get('GITHUB_STEP_SUMMARY')
        if summary:
            with open(summary,'a') as f:f.write('NexPilot metadata: '+result['state']+'; Stable '+result['version']+'. No plugin ZIP or site was changed.\n')

if __name__=='__main__':
    try:main()
    except Exception:raise SystemExit('NexPilot metadata renewal failed. Existing release requires review; credentials are never printed.')
