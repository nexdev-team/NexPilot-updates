<?php
// Verify an owner-signed release request and artifact. No signing secret or site access.
require __DIR__.'/renew-update.php';
if(count($argv)!==2)exit(1);
$d=$argv[1];$raw=file_get_contents($d.'/request.json');$sig=base64_decode(trim(file_get_contents($d.'/request.json.sig')),true);
if(strlen($raw)>32768||$sig===false||strlen($sig)!==64||!sodium_crypto_sign_verify_detached($sig,$raw,base64_decode(RENEW_PUBLIC)))throw new RuntimeException('Owner release authorization rejected.');
$r=json_decode($raw,true,16,JSON_THROW_ON_ERROR);
if(array_diff(array_keys($r),['version','sha256','bytes','source_commit','ci_run','notes'])||!preg_match('/^[1-9][0-9]*\.[0-9]+\.[0-9]+$/D',$r['version']??'')||!preg_match('/^[a-f0-9]{64}$/D',$r['sha256']??'')||!is_int($r['bytes']??null)||$r['bytes']<1||$r['bytes']>16777216||!preg_match('/^[a-f0-9]{40}$/D',$r['source_commit']??'')||!is_int($r['ci_run']??null)||$r['ci_run']<1||!is_string($r['notes']??null)||strlen($r['notes'])>16000)throw new RuntimeException('Invalid approved request.');
$name='nexdev-site-connector-'.$r['version'].'.zip';$zip=$d.'/'.$name;
if(filesize($zip)!==$r['bytes']||!hash_equals($r['sha256'],hash_file('sha256',$zip)))throw new RuntimeException('Approved artifact mismatch.');
$public=base64_decode(trim(file_get_contents($d.'/release-signing.pub')),true);
if($public===false||!hash_equals('be10f57ceb80d70554a1e39eb8610088c0df79c62acc87d1dae48511c16ef375',hash('sha256',$public)))throw new RuntimeException('Artifact trust identity mismatch.');
$manifest=file_get_contents($zip.'.manifest.json');$s=base64_decode(trim(file_get_contents($zip.'.sig')),true);
if($s===false||strlen($s)!==64||!sodium_crypto_sign_verify_detached($s,$manifest,$public))throw new RuntimeException('Artifact signature rejected.');
$m=json_decode($manifest,true,16,JSON_THROW_ON_ERROR);
if(($m['format']??null)!==1||($m['artifact']??null)!==$name||($m['sha256']??null)!==$r['sha256']||($m['bytes']??null)!==$r['bytes']||explode(' ',trim(file_get_contents($zip.'.sha256')))[0]!==$r['sha256'])throw new RuntimeException('Artifact sidecar mismatch.');
if(is_file($d.'/nexpilot-update.json')){
 $update=renewal_manifest(file_get_contents($d.'/nexpilot-update.json'),$zip,RENEW_PUBLIC,time());
 if($update['version']!==$r['version']||$update['expires_at']<=time()+3600)throw new RuntimeException('Update identity or lifetime rejected.');
 $r['update']=$update;
}
echo json_encode($r,JSON_THROW_ON_ERROR);
