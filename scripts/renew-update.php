<?php
// Authenticate an existing release and renew only its time window. Never sign new code.
if(PHP_SAPI!=='cli')exit(1);
const RENEW_PUBLIC='CmAqjjgK/id809anjXzMqTIKLD7XxmGdtuY3v0guM1E=';
function renewal_manifest(string $envelope,string $archive,string $public,int $now): array {
 $e=json_decode($envelope,true,16,JSON_THROW_ON_ERROR);
 $payload=$e['payload']??null;$sig=base64_decode($e['signature']??'',true);$key=base64_decode($public,true);
 if(!is_string($payload)||strlen($payload)>16384||$sig===false||strlen($sig)!==64||$key===false||strlen($key)!==32||!sodium_crypto_sign_verify_detached($sig,$payload,$key))throw new RuntimeException('Existing release signature rejected.');
 $m=json_decode($payload,true,16,JSON_THROW_ON_ERROR);
 if(($m['format']??null)!==2||($m['channel']??null)!=='public'||($m['repository']??null)!=='nexdev-team/NexPilot-updates'||($m['slug']??null)!=='nexdev-site-connector'||!is_string($m['version']??null)||!preg_match('/^[1-9][0-9]*\.[0-9]+\.[0-9]+$/D',$m['version'])||($m['tag']??null)!=='v'.$m['version']||!is_int($m['asset_id']??null)||$m['asset_id']<1||!is_int($m['bytes']??null)||$m['bytes']<1||$m['bytes']>16777216||!is_string($m['sha256']??null)||!preg_match('/^[a-f0-9]{64}$/D',$m['sha256'])||!is_int($m['issued_at']??null)||!is_int($m['expires_at']??null)||$m['issued_at']>$now+300||$m['expires_at']<=$m['issued_at']||$m['expires_at']-$m['issued_at']>30*86400)throw new RuntimeException('Existing release identity or time window rejected.');
 // Expired but authentic metadata may be recovered; the signed code identity cannot change.
 if(filesize($archive)!==$m['bytes']||!hash_equals($m['sha256'],hash_file('sha256',$archive)))throw new RuntimeException('Existing signed ZIP integrity rejected.');
 return $m;
}
function renewal_envelope(array $manifest,string $secret,string $public,int $now): string {
 if(strlen($secret)!==64||!hash_equals(base64_decode($public,true),sodium_crypto_sign_publickey_from_secretkey($secret)))throw new RuntimeException('Signing identity rejected.');
 $manifest['issued_at']=$now;$manifest['expires_at']=$now+7*86400;
 $payload=json_encode($manifest,JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);
 return json_encode(['payload'=>$payload,'signature'=>base64_encode(sodium_crypto_sign_detached($payload,$secret))],JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR)."\n";
}
if(realpath($_SERVER['SCRIPT_FILENAME']??'')===__FILE__){
 try{
  if(count($argv)!==5||!in_array($argv[1],['inspect','renew'],true))throw new RuntimeException('Use inspect|renew ENVELOPE ZIP OUTPUT.');
  [$script,$mode,$input,$zip,$out]=$argv;$now=time();
  if(filesize($input)>32768)throw new RuntimeException('Metadata exceeds limit.');
  $manifest=renewal_manifest(file_get_contents($input),$zip,RENEW_PUBLIC,$now);
  if(file_exists($out)||is_link($out))throw new RuntimeException('Output already exists.');
  if($mode==='inspect')$bytes=json_encode($manifest,JSON_THROW_ON_ERROR)."\n";
  else{
   $secret=base64_decode(getenv('NEXPILOT_SIGNING_KEY_B64')?:'',true);
   try{if($secret===false)throw new RuntimeException('Signing identity unavailable.');$bytes=renewal_envelope($manifest,$secret,RENEW_PUBLIC,$now);}finally{if(is_string($secret))sodium_memzero($secret);}
  }
  $f=fopen($out,'x');if(!$f)throw new RuntimeException('Cannot create output.');chmod($out,0600);fwrite($f,$bytes);fclose($f);
  echo $mode==='inspect'?"Existing signed release verified.\n":"Existing release time window renewed.\n";
 }catch(Throwable $e){fwrite(STDERR,"Release metadata verification/renewal failed. No credential values are logged.\n");exit(1);}
}
