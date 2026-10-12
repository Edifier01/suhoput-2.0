<?php
declare(strict_types=1);
namespace SuhoputBackup;
require_once __DIR__.'/owner-kit.php';
require_once __DIR__.'/media.php';
require_once __DIR__.'/database.php';

// Independent Linux recovery. Credentials come only from the decrypted owner
// kit. This module reads archives and prepares artifacts; it never imports SQL,
// invokes Docker, reads the source machine, or writes an S3 object.
final class OwnerFullError extends \RuntimeException {}
function fullNeed(bool $ok,string $code='invalid-owner-full-evidence'): void {if(!$ok)throw new OwnerFullError($code);}
function fullHex(mixed $value,int $length): string {
 fullNeed(is_string($value)&&preg_match('/^[a-f0-9]{'.$length.'}$/D',$value)===1);return $value;
}
function fullRelative(mixed $path): string {
 fullNeed(is_string($path)&&$path!==''&&$path[0]!=='/'&&!str_contains($path,'\\')&&!str_contains($path,':')&&preg_match('/[\x00-\x1f\x7f]/',$path)!==1);
 foreach(explode('/',$path) as $part)fullNeed($part!==''&&$part!=='.'&&$part!=='..');return $path;
}
function fullSource(string $stage,string $generation): array {
 fullNeed(preg_match('~^/srv/suhoput2-stage-20[0-9]{6}$~D',$stage)===1);
 $project=basename($stage);return ['root'=>$stage,'project'=>$project,'schema'=>'suhoput2_stage','generation'=>fullHex($generation,32),
  'db_container'=>$project.'-db-1','wordpress_container'=>$project.'-wordpress-1','db_volume'=>$project.'_db','wordpress_volume'=>$project.'_wordpress'];
}
function fullJson(string $body): array {
 fullNeed(strlen($body)<=64*1024*1024);try{$value=json_decode($body,true,64,JSON_THROW_ON_ERROR);}catch(\JsonException $e){throw new OwnerFullError('invalid-json');}
 fullNeed(is_array($value));return $value;
}
function fullFileRows(mixed $rows): array {
 fullNeed(is_array($rows)&&array_is_list($rows));$seen=[];
 foreach($rows as $row){fullNeed(is_array($row)&&count($row)===3&&isset($row['path'],$row['bytes'],$row['sha256']));
  $path=fullRelative($row['path']);fullNeed($path!=='manifest.json'&&!isset($seen[$path]));$seen[$path]=true;
  fullNeed(is_int($row['bytes'])&&$row['bytes']>=0);fullHex($row['sha256'],64);
 }return $rows;
}
/** Authenticate the exact archived bytes returned by restic dump, not flags. */
function authOwnerFullManifest(array $snapshot,string $body,string $scope,string $generation,array $source): array {
 fullNeed(($snapshot['paths']??null)===[$scope]);$tags=$snapshot['tags']??null;fullNeed(is_array($tags)&&array_is_list($tags)&&count($tags)===count(array_unique($tags,SORT_STRING)));
 foreach($tags as $tag)fullNeed(is_string($tag));fullNeed(in_array('task047',$tags,true));
 $tagValue=static function(string $prefix)use($tags):string{$values=[];foreach($tags as $tag)if(str_starts_with($tag,$prefix))$values[]=substr($tag,strlen($prefix));fullNeed(count($values)===1);return $values[0];};
 fullNeed($tagValue('generation:')===fullHex($generation,32));$token=fullHex($tagValue('token:'),32);$digest=fullHex($tagValue('manifest-sha:'),64);
 fullNeed(hash_equals($digest,hash('sha256',$body)),'manifest-sha');$manifest=fullJson($body);
 fullNeed(($manifest['format']??null)===1&&($manifest['generation']??null)===$generation&&($manifest['source']??null)==$source,'manifest-source');
 fullNeed($source==fullSource($source['root']??'',$generation));fullFileRows($manifest['files']??null);
 return ['manifest'=>$manifest,'manifest_sha256'=>$digest,'token'=>$token];
}
/** No links/devices/hard links or unstable files in the restored plaintext. */
function ownerFullTree(string $root): array {
 fullNeed(is_dir($root)&&!is_link($root));$real=realpath($root);fullNeed($real!==false);$rows=[];
 $iterator=new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($real,\FilesystemIterator::SKIP_DOTS),\RecursiveIteratorIterator::SELF_FIRST);
 foreach($iterator as $entry){$path=$entry->getPathname();fullNeed(!is_link($path),'archive-link');
  if($entry->isDir())continue;$before=lstat($path);fullNeed(is_array($before)&&($before['mode']&0170000)===0100000&&$before['nlink']===1,'archive-file-type');
  $digest=hash_file('sha256',$path);clearstatcache(true,$path);$after=lstat($path);fullNeed($before['ino']===$after['ino']&&$before['size']===$after['size']&&$before['mtime']===$after['mtime']&&is_string($digest),'archive-file-drift');
  $rows[]=['path'=>str_replace(DIRECTORY_SEPARATOR,'/',substr($path,strlen($real)+1)),'bytes'=>$after['size'],'sha256'=>$digest];
 }usort($rows,static fn(array $a,array $b):int=>strcmp($a['path'],$b['path']));return $rows;
}
function verifyOwnerFullPayload(string $root,array $proof): void {
 fullNeed(isset($proof['manifest'],$proof['manifest_sha256']));$rows=ownerFullTree($root);$expected=fullFileRows($proof['manifest']['files']??null);$manifest=[];
 foreach($rows as $row)if($row['path']==='manifest.json')$manifest[]=$row;
 fullNeed(count($manifest)===1&&hash_equals(fullHex($proof['manifest_sha256'],64),$manifest[0]['sha256']),'restored-manifest-sha');
 // Raw manifest bytes were authenticated above. Worker inventories use pathlib
 // component sorting; compare complete validated path maps without changing
 // archived manifest ordering or weakening duplicate/path/SHA/size validation.
 $actualFiles=[];$expectedFiles=[];
 foreach($rows as $row)if($row['path']!=='manifest.json')$actualFiles[$row['path']]=['bytes'=>$row['bytes'],'sha256'=>$row['sha256']];
 foreach($expected as $row)$expectedFiles[$row['path']]=['bytes'=>$row['bytes'],'sha256'=>$row['sha256']];
 fullNeed($actualFiles==$expectedFiles,'restored-file-tree');
}
function fullLogNumber(mixed $name): int {
 fullNeed(is_string($name)&&preg_match('/^suhoput2-binlog\.([0-9]{6})$/D',$name,$match)===1&&(int)$match[1]>0);return (int)$match[1];
}
function fullLogs(mixed $logs): array {
 fullNeed(is_array($logs)&&array_is_list($logs)&&$logs!==[]);$last=0;
 foreach($logs as $row){fullNeed(is_array($row)&&count($row)===3);$number=fullLogNumber($row['file']??null);fullNeed($number>$last&&is_int($row['size']??null)&&$row['size']>=4);fullHex($row['sha256']??null,64);$last=$number;}return $logs;
}
/** Derive a complete 1..last closed chain from authenticated manifests. */
function validateOwnerFullSelection(array $base,array $full,array $chains,array $tip): array {
 fullHex($base['id']??null,64);fullHex($full['id']??null,64);$b=$base['manifest']??[];$f=$full['manifest']??[];
 fullNeed(in_array($b['kind']??null,['full','pre-update','hourly'],true)&&in_array($f['kind']??null,['full','pre-update'],true));
 fullNeed(($b['kind']==='hourly'&&($b['full_id']??null)===$full['id'])||($b['kind']!=='hourly'&&$base['id']===$full['id']),'full-id-binding');
 foreach(['generation','source','stage_app_sha','application_sha256','configuration_sha256'] as $key)fullNeed(isset($b[$key],$f[$key])&&$b[$key]==$f[$key],'full-application-binding');
 fullHex($b['stage_app_sha'],40);fullHex($b['application_sha256'],64);fullHex($b['configuration_sha256'],64);
 $logs=[];$seen=[];$ids=[];fullNeed($chains!==[]&&array_is_list($chains));
 foreach($chains as $proof){$id=fullHex($proof['id']??null,64);fullNeed(!isset($ids[$id]));$ids[$id]=true;$m=$proof['manifest']??[];
  fullNeed(($m['kind']??null)==='binlog'&&($m['previous_count']??null)===count($logs),'chain-prefix');$fresh=fullLogs($m['logs']??null);
  fullNeed(($m['first_log']??null)===fullLogNumber($fresh[0]['file'])&&($m['last_log']??null)===fullLogNumber($fresh[count($fresh)-1]['file']));
  foreach($fresh as $row){fullNeed(fullLogNumber($row['file'])===count($logs)+1&&!isset($seen[$row['file']]),'chain-gap');$seen[$row['file']]=true;$logs[]=$row;}
  fullNeed(fullLogNumber($m['active_file']??null)===count($logs)+1,'closed-log-boundary');
 }
 $last=$logs[count($logs)-1];fullNeed(count($tip)===2&&($tip['file']??null)===$last['file']&&($tip['position']??null)===$last['size'],'closed-chain-tip');
 $coords=$b['coordinates']??[];$start=fullLogNumber($coords['file']??null);fullNeed(count($coords)===2&&is_int($coords['position']??null)&&$coords['position']>=4&&$start<=count($logs)&&$coords['position']<=$logs[$start-1]['size'],'base-coordinate-range');
 return array_slice($logs,$start-1);
}
function fullIdentityDigest(array $rows): string {
 usort($rows,static fn(array $a,array $b):int=>strcmp($a['path'],$b['path']));$ordered=[];
 foreach($rows as $row)$ordered[]=['bytes'=>$row['bytes'],'path'=>$row['path'],'sha256'=>$row['sha256']];
 return hash('sha256',json_encode($ordered,JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR));
}
function verifyOwnerFullIdentity(string $payload,array $manifest): array {
 $app=array_values(array_filter(ownerFullTree($payload.'/wordpress'),static fn(array $r):bool=>!str_starts_with($r['path'],'wp-content/uploads/')));$config=[];
 foreach(['.env','infra/staging/compose.yaml','infra/staging/backup.override.yaml','infra/staging/safety.php','infra/staging/proxy.conf'] as $name){$file=$payload.'/configuration/'.$name;fullNeed(is_file($file)&&!is_link($file));$config[]=['path'=>$name,'bytes'=>filesize($file),'sha256'=>hash_file('sha256',$file)];}
 $identity=['application_sha256'=>fullIdentityDigest($app),'configuration_sha256'=>fullIdentityDigest($config)];
 foreach($identity as $key=>$value)fullNeed(hash_equals(fullHex($manifest[$key]??null,64),$value),'captured-identity-sha');return $identity;
}
function fullPrivate(string $path,bool $directory=false): void {
 fullNeed(str_starts_with($path,'/control/')&&!str_contains($path,'//')&&!str_contains($path,'/../')&&!str_contains($path,'/./'));
 $current='';foreach(explode('/',ltrim($path,'/')) as $part){$current.='/'.$part;fullNeed(!is_link($current));}
 $stat=lstat($path);fullNeed(is_array($stat)&&$stat['uid']===0&&($stat['mode']&0777)===($directory?0700:0600)&&($directory?is_dir($path):(is_file($path)&&$stat['nlink']===1)),'private-owner-mode');
}
function fullProtectTree(string $root): void {
 ownerFullTree($root);chmod($root,0700);$iterator=new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root,\FilesystemIterator::SKIP_DOTS),\RecursiveIteratorIterator::SELF_FIRST);
 foreach($iterator as $entry){fullNeed(chmod($entry->getPathname(),$entry->isDir()?0700:0600));fullPrivate($entry->getPathname(),$entry->isDir());}
}
function fullNative(array $args,array $env,string $work,bool $required=true): array {
 fullPrivate($work,true);fullNeed(hash_file('sha256','/control/work/restic')===OWNER_RESTIC_SHA,'restic-binary-sha');
 fullNeed(in_array($args[0]??null,['check','cat','dump','ls','restore','snapshots'],true),'restic-read-only-command');
 $label=bin2hex(random_bytes(12));$out=$work.'/'.$label.'.out';$err=$work.'/'.$label.'.err';
 $process=proc_open(array_merge(['/control/work/restic','--no-lock','-o','s3.bucket-lookup=path','-o','s3.connections=1'],$args),
 [0=>['file','/dev/null','r'],1=>['file',$out,'x'],2=>['file',$err,'x']],$pipes,$work,$env,['bypass_shell'=>true]);fullNeed(is_resource($process));$exit=proc_close($process);
 fullPrivate($out);fullPrivate($err);fullNeed(filesize($out)<=64*1024*1024&&filesize($err)<=16*1024*1024,'native-output-limit');
 $output=file_get_contents($out);$error=file_get_contents($err);unlink($out);unlink($err);fullNeed(is_string($output)&&is_string($error));
 if($required)fullNeed($exit===0,'restic-read-failed');return [$exit,$output,$error];
}
function fullArchive(array $env,string $work,string $lane,string $id,string $stage,string $generation,array $source): array {
 $scope=$stage.'/backup/spool/'.$lane.'-payload';[, $raw]=fullNative(['cat','snapshot',$id],$env,$work);$snapshot=fullJson($raw);
 [, $body]=fullNative(['dump',$id,$scope.'/manifest.json'],$env,$work);$proof=authOwnerFullManifest($snapshot,$body,$scope,$generation,$source);$proof['id']=$id;
 [, $listing]=fullNative(['ls','--json','--recursive',$id,$scope],$env,$work);$actual=[];$headers=[];$expected=[$scope.'/manifest.json'=>strlen($body)];
 foreach($proof['manifest']['files'] as $row)$expected[$scope.'/'.$row['path']]=$row['bytes'];
 foreach(array_filter(explode("\n",trim($listing))) as $line){$row=fullJson($line);if(($row['message_type']??null)==='snapshot'){$headers[]=$row;continue;}
  fullNeed(($row['message_type']??null)==='node'&&in_array($row['type']??null,['file','dir'],true)&&is_string($row['path']??null));$path=$row['path'];fullNeed($path===$scope||str_starts_with($path,$scope.'/'));if($path!==$scope)fullRelative(substr($path,strlen($scope)+1));
  if($row['type']==='file'){fullNeed(!isset($actual[$path])&&is_int($row['size']??null));$actual[$path]=$row['size'];}
 }fullNeed(count($headers)===1&&($headers[0]['id']??null)===$id&&$actual==$expected,'authenticated-tree-incomplete');
 $target=$work.'/snapshots/'.$id;fullNeed(!file_exists($target)&&!is_link($target));
 fullNative(['restore',$id,'--target',$target,'--verify'],$env,$work);fullProtectTree($target);$payload=$target.$scope;
 verifyOwnerFullPayload($payload,$proof);$outer=ownerFullTree($target);fullNeed(count($outer)===count($expected),'snapshot-outside-scope');
 $proof['path']=$payload;return $proof;
}
/** Returns only protected artifact paths/hashes. SQL and replay require offline
 * dump_records/ROW-event guards before import into a new isolated MariaDB. */
function prepareOwnerFull(array $input): array {
 $allowed=['recovery_root','token','stage_root','stage_app_sha','base_id','full_id','binlog_ids','closedchain_tip'];
 fullNeed(array_diff(array_keys($input),$allowed)===[]&&count($input)===count($allowed),'owner-input-boundary');
 fullNeed(($input['recovery_root']??null)==='/control/work/restored/control/work/source','sealed-recovery-path');
 $token=fullHex($input['token']??null,32);$stage=$input['stage_root']??null;fullNeed(is_string($stage));$app=fullHex($input['stage_app_sha']??null,40);
 $baseId=fullHex($input['base_id']??null,64);$fullId=fullHex($input['full_id']??null,64);$ids=$input['binlog_ids']??null;
 fullNeed(is_array($ids)&&array_is_list($ids)&&$ids!==[]&&count($ids)===count(array_unique($ids,SORT_STRING)));foreach($ids as $id)fullHex($id,64);
 $recovery=$input['recovery_root'];fullPrivate($recovery,true);foreach(['recovery.json','manifest.json'] as $name)fullPrivate($recovery.'/'.$name);
 $raw=file_get_contents($recovery.'/recovery.json');$kit=fullJson(file_get_contents($recovery.'/manifest.json'));$config=fullJson($raw);validateOwnerConfig($config);
 fullNeed(($kit['format']??null)===1&&($kit['generation']??null)===$config['generation']&&($kit['preparation_code_sha']??null)===$config['preparation_code_sha']&&($kit['restic_sha256']??null)===OWNER_RESTIC_SHA&&($kit['recovery_sha256']??null)===hash('sha256',$raw),'sealed-recovery-manifest');
 $generation=$config['generation'];$source=fullSource($stage,$generation);$work='/control/owner-full-'.$token;fullNeed(!file_exists($work)&&!is_link($work),'owner-target-collision');umask(0077);fullNeed(mkdir($work,0700));fullNeed(mkdir($work.'/snapshots',0700));fullNeed(mkdir($work.'/cache',0700));fullNeed(mkdir($work.'/logs',0700));
 file_put_contents($work.'/repository-password',$config['repository_password']."\n");fullPrivate($work.'/repository-password');$s3=$config['s3'];
 $env=['PATH'=>'/usr/local/bin:/usr/bin:/bin','HOME'=>$work,'TMPDIR'=>$work,'RESTIC_CACHE_DIR'=>$work.'/cache','RESTIC_PASSWORD_FILE'=>$work.'/repository-password',
 'AWS_ACCESS_KEY_ID'=>$s3['access_key'],'AWS_SECRET_ACCESS_KEY'=>$s3['secret_key'],'AWS_DEFAULT_REGION'=>$s3['region']];$repositories=$config['repositories'];unset($config,$s3,$raw);
 foreach(['base','binlog'] as $lane){$env['RESTIC_REPOSITORY']=$repositories[$lane];fullNative(['check','--read-data'],$env,$work);}
 file_put_contents($work.'/wrong-password',bin2hex(random_bytes(32))."\n");$bad=$env;$bad['RESTIC_PASSWORD_FILE']=$work.'/wrong-password';
 [$exit,$output,$error]=fullNative(['snapshots','--json'],$bad,$work,false);fullNeed($exit!==0&&preg_match('/wrong password|no key found/i',$output.$error)===1,'wrong-repository-key-accepted');unset($bad,$output,$error);unlink($work.'/wrong-password');
 $env['RESTIC_REPOSITORY']=$repositories['base'];$base=fullArchive($env,$work,'base',$baseId,$stage,$generation,$source);$full=$baseId===$fullId?$base:fullArchive($env,$work,'base',$fullId,$stage,$generation,$source);
 fullNeed(($base['manifest']['stage_app_sha']??null)===$app,'expected-stage-application');$identity=verifyOwnerFullIdentity($full['path'],$full['manifest']);
 $env['RESTIC_REPOSITORY']=$repositories['binlog'];$chains=[];foreach($ids as $id)$chains[]=fullArchive($env,$work,'binlog',$id,$stage,$generation,$source);unset($env);
 $logs=validateOwnerFullSelection($base,$full,$chains,$input['closedchain_tip']);$archived=[];
 foreach($chains as $proof)foreach($proof['manifest']['logs'] as $row){$file=$proof['path'].'/logs/'.$row['file'];$head=file_get_contents($file,false,null,0,4);fullNeed(filesize($file)===$row['size']&&hash_file('sha256',$file)===$row['sha256']&&$head==="\xfebin",'binlog-file-sha');$archived[$row['file']]=$file;}
 foreach($logs as $row){$dest=$work.'/logs/'.$row['file'];fullNeed(isset($archived[$row['file']])&&copy($archived[$row['file']],$dest));chmod($dest,0600);fullPrivate($dest);}
 $media=fullJson(file_get_contents($base['path'].'/media.json'));fullNeed(isset($media['inventory'])&&is_array($media['inventory']));verifyMedia($base['path'].'/uploads',normalizeOwnerMediaRows($media['inventory']));
 $artifacts=['db.sql'=>$base['path'].'/db.sql','media.json'=>$base['path'].'/media.json'];$hashes=[];foreach($artifacts as $name=>$path){fullPrivate($path);$hashes[$name]=hash_file('sha256',$path);}
 $result=['format'=>1,'generation'=>$generation,'token'=>$token,'source'=>$source,'stage_app_sha'=>$app,'base_id'=>$baseId,'full_id'=>$fullId,
 'base_manifest_sha256'=>$base['manifest_sha256'],'full_manifest_sha256'=>$full['manifest_sha256'],'application_sha256'=>$identity['application_sha256'],'configuration_sha256'=>$identity['configuration_sha256'],
 'base_path'=>$base['path'],'full_path'=>$full['path'],'artifacts'=>$artifacts,'artifact_sha256'=>$hashes,'coordinates'=>$base['manifest']['coordinates'],'closedchain_tip'=>$input['closedchain_tip'],
 'logs'=>$logs,'logs_path'=>$work.'/logs','binlog_snapshots'=>array_map(static fn(array $p):array=>['id'=>$p['id'],'manifest_sha256'=>$p['manifest_sha256']],$chains),
 'full_files'=>count($full['manifest']['files']),'base_files'=>count($base['manifest']['files']),'archive_reads'=>'authenticated-restic-check-restore-sha','sql_import'=>'not_run','source_reads'=>0,'s3_writes'=>0];
 file_put_contents($work.'/prepared.json',json_encode($result,JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR));fullPrivate($work.'/prepared.json');return $result;
}
/** Authenticated Python JSON sorts object keys. Reconstruct the native PHP
 * media shape only after strict field/type/path validation; no unknown fields,
 * duplicate references or changed byte/hash values disappear in normalization. */
function normalizeOwnerMediaRows(array $inventory): array {
 fullNeed(array_is_list($inventory),'media-list');$rows=[];$seen=[];
 foreach($inventory as $row){fullNeed(is_array($row),'media-row');$keys=array_keys($row);sort($keys,SORT_STRING);
  $path=$row['path']??null;fullNeed(is_string($path)&&!isset($seen[$path]),'media-path-duplicate');$seen[$path]=true;
  if(array_key_exists('kind',$row)){
   fullNeed($keys===['kind','path']&&$row['kind']==='directory'&&str_ends_with($path,'/'),'media-directory-fields');fullRelative(substr($path,0,-1));
   $rows[]=['path'=>$path,'kind'=>'directory'];
  }else{
   fullNeed($keys===['bytes','path','sha256']&&is_int($row['bytes'])&&$row['bytes']>=0,'media-file-fields');fullRelative($path);fullHex($row['sha256'],64);
   $rows[]=['path'=>$path,'bytes'=>$row['bytes'],'sha256'=>$row['sha256']];
  }
 }usort($rows,static fn(array $a,array $b):int=>strcmp($a['path'],$b['path']));return $rows;
}
function verifyOwnerFullMedia(callable $query,string $uploads,array $expected): array {
 $normalized=normalizeOwnerMediaRows($expected);$result=databaseMedia($query,'suhoput2_stage','wp_',$uploads);fullNeed(normalizeOwnerMediaRows($result['inventory'])===$normalized,'complete-db-media-mismatch');return $result;
}
/** Socket-only read-only DB/media proof after the external guarded import/replay.
 * The imported original schema is intentionally retained: ROW events bind it. */
function verifyOwnerFull(string $work,string $passwordPath,string $socket='/dbsock/mysqld.sock'): array {
 fullNeed(preg_match('~^/control/owner-full-[a-f0-9]{32}$~D',$work)===1&&$socket==='/dbsock/mysqld.sock');fullPrivate($work,true);fullPrivate($work.'/prepared.json');fullPrivate($passwordPath);
 $prepared=fullJson(file_get_contents($work.'/prepared.json'));
 foreach($prepared['artifacts'] as $name=>$path){fullPrivate($path);fullNeed(str_starts_with($path,$work.'/snapshots/')&&hash_file('sha256',$path)===$prepared['artifact_sha256'][$name],'prepared-artifact-drift');}
 $base=fullJson(file_get_contents($prepared['base_path'].'/manifest.json'));$full=fullJson(file_get_contents($prepared['full_path'].'/manifest.json'));
 verifyOwnerFullPayload($prepared['base_path'],['manifest'=>$base,'manifest_sha256'=>$prepared['base_manifest_sha256']]);verifyOwnerFullPayload($prepared['full_path'],['manifest'=>$full,'manifest_sha256'=>$prepared['full_manifest_sha256']]);verifyOwnerFullIdentity($prepared['full_path'],$full);
 $password=rtrim(file_get_contents($passwordPath),"\r\n");fullNeed($password!==''&&!str_contains($password,"\0"));\mysqli_report(MYSQLI_REPORT_ERROR|MYSQLI_REPORT_STRICT);
 $connection=new \mysqli('localhost','root',$password,'suhoput2_stage',3306,$socket);unset($password);
 try{$connection->set_charset('utf8mb4');$query=static function(string $sql)use($connection):array{$result=$connection->query($sql);if(!$result instanceof \mysqli_result)return [];try{return $result->fetch_all(MYSQLI_ASSOC);}finally{$result->free();}};
  $settings=$query('SELECT @@global.skip_networking AS skip_networking,@@global.event_scheduler AS event_scheduler');fullNeed(count($settings)===1&&(string)$settings[0]['skip_networking']==='1'&&$settings[0]['event_scheduler']==='OFF','isolated-database-settings');
  $media=fullJson(file_get_contents($prepared['artifacts']['media.json']));return verifyOwnerFullMedia($query,$prepared['base_path'].'/uploads',$media['inventory']);
 }finally{$connection->close();}
}
