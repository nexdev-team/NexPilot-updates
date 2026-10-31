"""Publish only an offline-owner-approved immutable package; never signs code or accesses WordPress."""
from pathlib import Path
import importlib.util, json, os, re, subprocess, sys, zipfile, hashlib
root=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('renew',root/'scripts/renew-update.py')
renew=importlib.util.module_from_spec(spec);spec.loader.exec_module(renew)

def authenticate(directory):
    result=subprocess.run(['php',str(root/'scripts/approved-release.php'),str(directory)],capture_output=True,text=True)
    if result.returncode:raise RuntimeError('Offline owner authorization or artifact signature rejected')
    request=json.loads(result.stdout);version=request['version'];name='nexdev-site-connector-'+version+'.zip'
    allowed={name,name+'.manifest.json',name+'.sig',name+'.sha256','release-signing.pub','NexPilot-installation.txt','request.json','request.json.sig','nexpilot-update.json'}
    if directory.name!='v'+version or any(p.name not in allowed or p.is_symlink() or not p.is_file() for p in directory.iterdir()):raise RuntimeError('Unapproved candidate contents')
    with zipfile.ZipFile(directory/name) as archive:
        names=archive.namelist()
        if len(names)>400 or len(names)!=len(set(n.lower() for n in names)) or sum(i.file_size for i in archive.infolist())>64*1024*1024:raise RuntimeError('Invalid archive inventory')
        for info in archive.infolist():
            n=info.filename
            if not n.startswith('nexdev-site-connector/') or '\\' in n or any(p.startswith('.') for p in n.split('/')) or '..' in n.split('/') or n.endswith(('.key','.token','.sql','.pem','.mcpb')) or ((info.external_attr>>16)&0o170000)==0o120000:raise RuntimeError('Private or unsafe archive path')
        header=archive.read('nexdev-site-connector/nexdev-site-connector.php').decode()
        if not re.search(r'^ \* Version: '+re.escape(version)+r'$',header,re.M):raise RuntimeError('Archive version mismatch')
    return request

def publish(api,directory,request,commit):
    version=request['version'];tag='v'+version;name='nexdev-site-connector-'+version+'.zip'
    latest=api.latest()
    existing=[r for r in api.request('/releases') if r['tag_name']==tag]
    if len(existing)>1:raise RuntimeError('Ambiguous release identity')
    if tuple(map(int,latest['tag_name'][1:].split('.')))>tuple(map(int,version.split('.'))):raise RuntimeError('Refusing downgrade')
    release=existing[0] if existing else None
    if release and not release['draft']:
        if latest['id']!=release['id'] or 'update' not in request:raise RuntimeError('Published release is immutable')
        a=renew.asset_by_name(release,name)
        if a['id']!=request['update']['asset_id'] or hashlib.sha256(api.download(a['id'],renew.MAX_ZIP)).hexdigest()!=request['sha256']:raise RuntimeError('Published identity mismatch')
        return {'published':True,'release_id':release['id'],'asset_id':a['id'],'version':version,'state':'already-published'}
    if not release:release=api.request('/releases','POST',{'tag_name':tag,'target_commitish':commit,'name':'NexPilot '+version+' Stable','body':request['notes'],'draft':True,'prerelease':False})
    expected=[name,name+'.manifest.json',name+'.sig',name+'.sha256','release-signing.pub','NexPilot-installation.txt']
    for filename in expected:
        data=(directory/filename).read_bytes();assets=[a for a in release['assets'] if a['name']==filename]
        if len(assets)>1:raise RuntimeError('Ambiguous asset identity')
        if assets:
            a=assets[0]
            if api.download(a['id'],renew.MAX_ZIP if filename==name else 32768)!=data:raise RuntimeError('Existing asset differs; never overwrite')
        else:
            a=api.upload(release['id'],filename,data);release['assets'].append(a)
    archive=renew.asset_by_name(release,name)
    if 'update' not in request:return {'published':False,'release_id':release['id'],'asset_id':archive['id'],'version':version,'state':'draft-awaiting-offline-metadata'}
    m=request['update']
    if (m['asset_id'],m['bytes'],m['sha256'])!=(archive['id'],archive['size'],request['sha256']):raise RuntimeError('Signed update bound to another asset')
    metadata=[a for a in release['assets'] if a['name']=='nexpilot-update.json'];data=(directory/'nexpilot-update.json').read_bytes()
    if metadata:
        if len(metadata)!=1 or api.download(metadata[0]['id'],32768)!=data:raise RuntimeError('Existing signed metadata differs')
    else:api.upload(release['id'],'nexpilot-update.json',data)
    latest_now=api.latest()
    if latest_now['id']!=latest['id']:raise RuntimeError('Latest release changed during preparation')
    result=api.request('/releases/'+str(release['id']),'PATCH',{'draft':False,'prerelease':False,'make_latest':'true'})
    if result['draft'] or api.latest()['id']!=release['id']:raise RuntimeError('Publication verification failed')
    return {'published':True,'release_id':release['id'],'asset_id':archive['id'],'version':version,'state':'published'}

if __name__=='__main__':
    if os.environ.get('GITHUB_REPOSITORY')!=renew.REPOSITORY or os.environ.get('GITHUB_REF')!='refs/heads/main':raise SystemExit('Unexpected release destination')
    candidates=[p for p in (root/'release-candidates').iterdir() if p.is_dir() and re.fullmatch(r'v[1-9][0-9]*\.[0-9]+\.[0-9]+',p.name)]
    if not candidates:raise SystemExit('No approved release candidate')
    directory=max(candidates,key=lambda p:tuple(map(int,p.name[1:].split('.'))))
    request=authenticate(directory);api=renew.GitHub(os.environ.get('GITHUB_TOKEN',''))
    result=publish(api,directory,request,os.environ['GITHUB_SHA']);print(json.dumps(result))
    with open(os.environ['GITHUB_OUTPUT'],'a') as out:out.write('published='+str(result['published']).lower()+'\n')
