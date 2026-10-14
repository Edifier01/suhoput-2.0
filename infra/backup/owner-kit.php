<?php
declare(strict_types=1);
namespace SuhoputBackup;

// Portable encrypted kit. No Windows/DPAPI/SSH API exists in this module.
final class OwnerKitError extends \RuntimeException {}
const OWNER_RESTIC_SHA='20d4142678d0d95ec11a4759def1b73fd9190abc9ca19e4b62d067c0b387e639';
function kitNeed(bool $condition,string $code='invalid-evidence'): void { if(!$condition) throw new OwnerKitError($code); }
function ownerPassword(mixed $value): string {
 kitNeed(is_string($value) && strlen($value)<=4096 && !str_contains($value,"\0") && !str_contains($value,"\n") && !str_contains($value,"\r"));
 kitNeed(preg_match_all('/./us',$value)>=16);return $value;
}
function validateOwnerConfig(array $config): void {
 kitNeed(($config['format']??null)===1 && preg_match('/^[a-f0-9]{32}$/D',$config['generation']??'')===1
         && preg_match('/^[a-f0-9]{40}$/D',$config['preparation_code_sha']??'')===1);
 $s3=$config['s3']??null;kitNeed(is_array($s3));$url=parse_url($s3['endpoint']??'');
 kitNeed(is_array($url) && ($url['scheme']??'')==='https' && isset($url['host'])
         && !isset($url['user'],$url['pass']) && !isset($url['user']) && !isset($url['pass'])
         && !isset($url['query']) && !isset($url['fragment']) && in_array($url['path']??'',['','/'],true));
 kitNeed(preg_match('/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/D',$s3['bucket']??'')===1
         && preg_match('/^[a-z0-9-]{1,32}$/D',$s3['region']??'')===1
         && ($s3['prefix']??'')==='suhoput2/stage-b/');
 foreach(['access_key','secret_key'] as $field)kitNeed(is_string($s3[$field]??null) && strlen($s3[$field])>=8
     && strlen($s3[$field])<=4096 && preg_match('/[\x00\r\n]/',$s3[$field])!==1);
 kitNeed(preg_match('/^[a-f0-9]{64}$/D',$config['repository_password']??'')===1);
 $root='s3:'.rtrim($s3['endpoint'],'/').'/'.$s3['bucket'].'/'.$s3['prefix'];
 foreach(['base','binlog'] as $lane)kitNeed(($config['repositories'][$lane]??null)===$root.'repositories/'.$lane);
 $control=$config['control']??null;kitNeed(is_array($control));
 kitNeed(preg_match('~^'.preg_quote($root.'archive-control/','~').'[a-f0-9]{32}$~D',$control['repository']??'')===1
         && preg_match('/^[a-f0-9]{64}$/D',$control['snapshot_id']??'')===1);
}
function kitRun(array $args,array $env,string $label,bool $required=true): array {
 kitNeed(preg_match('/^[a-z0-9-]+$/D',$label)===1);
 $process=proc_open(array_merge(['/control/work/restic'],$args),
  [0=>['file','/dev/null','r'],1=>['file','/control/work/'.$label.'.out','w'],2=>['file','/control/work/'.$label.'.err','w']],
  $pipes,'/control/work',$env,['bypass_shell'=>true]);
 kitNeed(is_resource($process));$exit=proc_close($process);
 if($required && $exit!==0)throw new OwnerKitError('Native operation failed');
 return [$exit,file_get_contents('/control/work/'.$label.'.out'),file_get_contents('/control/work/'.$label.'.err')];
}
function ownerKitMain(array $input): array {
 umask(0077);$phase='input';$result=['started_at_utc'=>gmdate('c'),'dpapi'=>'absent','ssh'=>'absent','stage_restore'=>'not_run'];
 try {
  kitNeed(is_dir('/control/input') && !is_link('/control/input') && !file_exists('/control/work'),'bootstrap-boundary');
  $mode=$input['mode']??null;kitNeed(in_array($mode,['build','recover'],true),'mode');
  $password=ownerPassword($input['owner_password']??null);
  kitNeed(hash_file('sha256','/control/input/restic')===OWNER_RESTIC_SHA,'restic-binary-sha');
  mkdir('/control/work',0700);copy('/control/input/restic','/control/work/restic');chmod('/control/work/restic',0700);
  file_put_contents('/control/work/kit-password',$password."\n");unset($password);
  $env=['PATH'=>'/usr/local/bin:/usr/bin:/bin','HOME'=>'/control/work','TMPDIR'=>'/control/work',
        'RESTIC_CACHE_DIR'=>'/control/work/cache','RESTIC_PASSWORD_FILE'=>'/control/work/kit-password'];
  if($mode==='build') {
   $config=$input['config']??null;kitNeed(is_array($config));validateOwnerConfig($config);
   kitNeed(!file_exists('/control/export'));mkdir('/control/export',0700);mkdir('/control/work/source',0700);
   $raw=json_encode($config,JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);file_put_contents('/control/work/source/recovery.json',$raw);
   $manifest=['format'=>1,'generation'=>$config['generation'],'preparation_code_sha'=>$config['preparation_code_sha'],
     'recovery_sha256'=>hash('sha256',$raw),'restic_version'=>'0.19.1','restic_sha256'=>OWNER_RESTIC_SHA];
   file_put_contents('/control/work/source/manifest.json',json_encode($manifest,JSON_THROW_ON_ERROR));unset($raw,$config);
   $env['RESTIC_REPOSITORY']='/control/export/repository';
   $phase='init';kitRun(['init','--repository-version','2'],$env,'init');
   $phase='backup';[, $out]=kitRun(['backup','/control/work/source','--json','--host','task047-owner-kit','--tag','task047-owner-kit'],$env,'backup');
   $rows=array_map(fn($line)=>json_decode($line,true,32,JSON_THROW_ON_ERROR),array_filter(explode("\n",trim($out))));
   $summary=array_values(array_filter($rows,fn($r)=>($r['message_type']??'')==='summary'));
   kitNeed(count($summary)===1 && preg_match('/^[a-f0-9]{64}$/D',$summary[0]['snapshot_id']??'')===1);
   $result['snapshot_id']=$summary[0]['snapshot_id'];
   $phase='check';kitRun(['check','--read-data'],$env,'check');$result['encrypted_local_integrity']=true;
   copy('/control/input/restic','/control/export/restic-linux-amd64');
   copy('/control/input/owner-kit.php','/control/export/owner-kit.php');
   file_put_contents('/control/export/SHA256SUMS',OWNER_RESTIC_SHA."  restic-linux-amd64\n".hash_file('sha256','/control/input/owner-kit.php')."  owner-kit.php\n");
   file_put_contents('/control/export/RESTORE-OWNER.txt',"Encrypted restic repository format2. Keep the owner password independently. Linux restic0.19.1 is included; verify SHA256SUMS before use.\nTo recover without Windows/DPAPI/VPS: read the owner password privately into a0700 tmpfs/password file0600; run restic --repo <kit>/repository --password-file <tmpfs>/password --no-lock check --read-data and restore <exact kit snapshot> --target <tmpfs>/restored --verify.\nRecovered recovery.json contains the S3-B credential/repository password and scopes; never print it. Runtime repositories may be uninitialized until stage installation. The control repository is synthetic evidence only.\n");
  } else {
   $sid=$input['snapshot_id']??null;kitNeed(is_string($sid) && preg_match('/^[a-f0-9]{64}$/D',$sid)===1);
   $env['RESTIC_REPOSITORY']='/control/kit/repository';$phase='check';
   kitRun(['--no-lock','check','--read-data'],$env,'check');
   $phase='restore';kitRun(['--no-lock','restore',$sid,'--target','/control/work/restored','--verify'],$env,'restore');
   $root='/control/work/restored/control/work/source/';
   $raw=file_get_contents($root.'recovery.json');$manifest=json_decode(file_get_contents($root.'manifest.json'),true,32,JSON_THROW_ON_ERROR);
   kitNeed(hash('sha256',$raw)===($manifest['recovery_sha256']??null));$config=json_decode($raw,true,32,JSON_THROW_ON_ERROR);
   validateOwnerConfig($config);kitNeed($manifest['generation']===$config['generation'] && $manifest['preparation_code_sha']===$config['preparation_code_sha'] && $manifest['restic_sha256']===OWNER_RESTIC_SHA);
   $result['portable_decryption']=true;$result['manifest_integrity']=true;$result['generation']=$config['generation'];
   $phase='wrong-password';file_put_contents('/control/work/wrong-password',bin2hex(random_bytes(32))."\n");
   [$exit,$out,$err]=kitRun(['--password-file','/control/work/wrong-password','--no-lock','snapshots'],$env,'wrong',false);
   kitNeed($exit!==0 && preg_match('/wrong password|no key found/i',$out.$err)===1);$result['wrong_password_denied']=true;
   if(($input['verify_s3']??true)!==false) {
    $s3=$config['s3'];file_put_contents('/control/work/archive-password',$config['repository_password']."\n");
    $env['RESTIC_REPOSITORY']=$config['control']['repository'];$env['RESTIC_PASSWORD_FILE']='/control/work/archive-password';
    $env['AWS_ACCESS_KEY_ID']=$s3['access_key'];$env['AWS_SECRET_ACCESS_KEY']=$s3['secret_key'];$env['AWS_DEFAULT_REGION']=$s3['region'];
    $sid=$config['control']['snapshot_id'];$opts=['--no-lock','-o','s3.bucket-lookup=path','-o','s3.connections=1'];
    $phase='s3-check';kitRun(array_merge($opts,['check','--read-data']),$env,'s3-check');
    $phase='s3-snapshot';[, $out]=kitRun(array_merge($opts,['cat','snapshot',$sid]),$env,'s3-snapshot');
    $row=json_decode($out,true,32,JSON_THROW_ON_ERROR);kitNeed(($row['paths']??null)===['/control/payload'] && in_array('synthetic-local-mariadb',$row['tags']??[],true));
    $phase='s3-dump';[, $out]=kitRun(array_merge($opts,['dump',$sid,'/control/payload/coordinates']),$env,'s3-dump');
    kitNeed(preg_match('/^binlog\.000001 [0-9]+\nbinlog\.000002 [0-9]+\n$/D',$out)===1);
    $result['s3_read_integrity']=true;$result['s3_exact_snapshot']=true;$result['s3_coordinates_sha256']=hash('sha256',$out);
   } else $result['s3_read_integrity']='not_run';
  }
  $result['result']='PASS';
 }catch(\Throwable $error){$result['result']='FAIL';$result['failed_phase']=$phase;$result['error_type']=get_class($error);if($error instanceof OwnerKitError)$result['error_code']=$error->getMessage();}
 $result['finished_at_utc']=gmdate('c');return $result;
}
