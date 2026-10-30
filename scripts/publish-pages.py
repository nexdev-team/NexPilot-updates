"""Assemble only authenticated public release files, never source trees or credentials."""
from pathlib import Path
import importlib.util,json,os,re,subprocess,tempfile,zipfile,io
root=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('renew',root/'scripts/renew-update.py');renew=importlib.util.module_from_spec(spec);spec.loader.exec_module(renew)
if os.environ.get('GITHUB_REPOSITORY')!=renew.REPOSITORY:raise SystemExit('Unexpected public repository')
api=renew.GitHub(os.environ.get('GITHUB_TOKEN',''));release=api.latest();rid,tag=renew.identity(release);version=tag[1:]
envelope=api.download(renew.asset_by_name(release,'nexpilot-update.json')['id'],32768)
name='nexdev-site-connector-'+version+'.zip';asset=renew.asset_by_name(release,name);archive=api.download(asset['id'],renew.MAX_ZIP)
with tempfile.TemporaryDirectory(dir=os.environ['RUNNER_TEMP']) as t:
 p=Path(t);(p/'envelope.json').write_bytes(envelope);(p/'archive.zip').write_bytes(archive)
 result=subprocess.run(['php',str(root/'scripts/renew-update.php'),'inspect',str(p/'envelope.json'),str(p/'archive.zip'),str(p/'manifest.json')],capture_output=True)
 if result.returncode:raise SystemExit('Public release authentication failed')
 manifest=json.loads((p/'manifest.json').read_text())
 if (manifest['tag'],manifest['asset_id'],manifest['bytes'])!=(tag,asset['id'],asset['size']):raise SystemExit('Public release identity mismatch')
with zipfile.ZipFile(io.BytesIO(archive)) as z:
 names=z.namelist()
 if sum(i.file_size for i in z.infolist())>64*1024*1024 or any(((i.external_attr>>16)&0o170000)==0o120000 for i in z.infolist()):raise SystemExit('Oversized or linked plugin archive')
 if len(names)>400 or len(names)!=len(set(n.lower() for n in names)) or any(not n.startswith('nexdev-site-connector/') or '..' in n.split('/') or '\\' in n or n.endswith(('.key','.token','.sql','.pem')) for n in names):raise SystemExit('Unsafe public plugin archive')
 header=z.read('nexdev-site-connector/nexdev-site-connector.php').decode()
 if not re.search(r'^ \* Version: '+re.escape(version)+r'$',header,re.M):raise SystemExit('Archive version mismatch')
out=root/'_site';out.mkdir(exist_ok=False)
(out/'nexpilot-update.json').write_bytes(envelope);(out/name).write_bytes(archive);(out/'update-signing.pub').write_bytes((root/'update-signing.pub').read_bytes())
for suffix,limit in [('.sha256',4096),('.sig',4096),('.manifest.json',4096)]:
 a=renew.asset_by_name(release,name+suffix);(out/(name+suffix)).write_bytes(api.download(a['id'],limit))
a=renew.asset_by_name(release,'release-signing.pub');(out/'release-signing.pub').write_bytes(api.download(a['id'],4096))
guide=[a for a in release['assets'] if a['name']=='NexPilot-installation.txt']
if guide:(out/'NexPilot-installation.txt').write_bytes(api.download(guide[0]['id'],32768))
guide_link='<p><a href="NexPilot-installation.txt">Οδηγίες εγκατάστασης και σύνδεσης στα Ελληνικά</a></p>' if guide else ''
(out/'.nojekyll').write_text('')
(out/'index.html').write_text('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>NexPilot downloads</title><body style="font:18px/1.6 system-ui;max-width:760px;margin:60px auto;padding:24px"><h1>NexPilot '+version+'</h1><p>Signed WordPress plugin. No GitHub account or update key needed with version 1.0.3 and later.</p><p><a href="'+name+'">Download installable plugin ZIP</a></p><p>WordPress → Plugins → Add New → Upload Plugin → Activate. Then Tools → NexPilot to create your own AI connection. Start with read-only access.</p><p>To install updates unattended, enable auto-updates for NexPilot on the WordPress Plugins screen. Otherwise use Update now when offered. Version 1.0.2 needs a one-time manual ZIP upgrade unless its legacy updater is already configured.</p>'+guide_link+'<p>Each AI connection belongs to its site and owner. No connection key is included in the download.</p><p>SHA256: <code>'+manifest['sha256']+'</code></p><p><a href="nexpilot-update.json">Signed update metadata</a></p><p>GPL-2.0-or-later. Single-site scope; internal review. No independent certification or WordPress.org listing is claimed.</p></body></html>')
print('Authenticated public distribution assembled: Stable '+version+', fixed file allowlist, no credentials.')
