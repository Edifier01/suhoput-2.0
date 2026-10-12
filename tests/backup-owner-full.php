<?php
declare(strict_types=1);
// Synthetic bytes and SQL callbacks only; no network, credentials or Docker.
$module=__DIR__.'/../infra/backup/owner-full.php';
if(!is_file($module))$module='/input/owner-full.php';
if(!is_file($module)) {fwrite(STDERR,"FAIL owner full preparation missing\n");exit(1);}
require $module;
function must(bool $ok): void {if(!$ok)throw new RuntimeException('owner full assertion failed');}
function denied(callable $call): void {
 try{$call();}catch(SuhoputBackup\OwnerFullError|SuhoputBackup\OwnerKitError|SuhoputBackup\DatabaseError|SuhoputBackup\MediaError $e){return;}
 throw new RuntimeException('unsafe owner full evidence accepted');
}
umask(0077);
$root=sys_get_temp_dir().'/owner-full-test-'.bin2hex(random_bytes(8));mkdir($root,0700);
$generation=str_repeat('a',32);$stage='/srv/suhoput2-stage-20261010';$project=basename($stage);
$source=['root'=>$stage,'project'=>$project,'schema'=>'suhoput2_stage','generation'=>$generation,
 'db_container'=>$project.'-db-1','wordpress_container'=>$project.'-wordpress-1','db_volume'=>$project.'_db','wordpress_volume'=>$project.'_wordpress'];
$sid=str_repeat('1',64);$token=str_repeat('b',32);$scope=$stage.'/backup/spool/base-payload';
$manifest=['format'=>1,'generation'=>$generation,'source'=>$source,'kind'=>'full','stage_app_sha'=>str_repeat('c',40),
 'application_sha256'=>str_repeat('d',64),'configuration_sha256'=>str_repeat('e',64),
 'coordinates'=>['file'=>'suhoput2-binlog.000001','position'=>4],'files'=>[['path'=>'db.sql','bytes'=>3,'sha256'=>hash('sha256','SQL')]]];
$body=json_encode($manifest,JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);
$snapshot=['paths'=>[$scope],'tags'=>['task047','generation:'.$generation,'token:'.$token,'manifest-sha:'.hash('sha256',$body)]];
$proof=SuhoputBackup\authOwnerFullManifest($snapshot,$body,$scope,$generation,$source);
must($proof['manifest']===$manifest&&$proof['token']===$token);
denied(fn()=>SuhoputBackup\authOwnerFullManifest($snapshot,$body.' ',$scope,$generation,$source));
$bad=$snapshot;$bad['tags'][]='token:'.str_repeat('f',32);denied(fn()=>SuhoputBackup\authOwnerFullManifest($bad,$body,$scope,$generation,$source));
$bad=$snapshot;$bad['paths']=[$stage.'/backup/spool/binlog-payload'];denied(fn()=>SuhoputBackup\authOwnerFullManifest($bad,$body,$scope,$generation,$source));
denied(fn()=>SuhoputBackup\authOwnerFullManifest($snapshot,$body,$scope,str_repeat('f',32),$source));
$badSource=$source;$badSource['schema']='production';denied(fn()=>SuhoputBackup\authOwnerFullManifest($snapshot,$body,$scope,$generation,$badSource));
foreach(['../outside','/absolute','logs//a','logs/./a','manifest.json'] as $path){$bad=$manifest;$bad['files'][0]['path']=$path;$raw=json_encode($bad,JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);$row=$snapshot;$row['tags'][3]='manifest-sha:'.hash('sha256',$raw);denied(fn()=>SuhoputBackup\authOwnerFullManifest($row,$raw,$scope,$generation,$source));}
echo "PASS authenticated generation/token/path/source/manifest hash and traversal guards\n";
mkdir($root.'/payload',0700);file_put_contents($root.'/payload/db.sql','SQL');file_put_contents($root.'/payload/manifest.json',$body);
SuhoputBackup\verifyOwnerFullPayload($root.'/payload',$proof);
file_put_contents($root.'/payload/db.sql','BAD');denied(fn()=>SuhoputBackup\verifyOwnerFullPayload($root.'/payload',$proof));file_put_contents($root.'/payload/db.sql','SQL');
file_put_contents($root.'/payload/unknown','x');denied(fn()=>SuhoputBackup\verifyOwnerFullPayload($root.'/payload',$proof));unlink($root.'/payload/unknown');
unlink($root.'/payload/manifest.json');denied(fn()=>SuhoputBackup\verifyOwnerFullPayload($root.'/payload',$proof));file_put_contents($root.'/payload/manifest.json',$body);
if(PHP_OS_FAMILY!=='Windows'){symlink('/etc/passwd',$root.'/payload/link');denied(fn()=>SuhoputBackup\verifyOwnerFullPayload($root.'/payload',$proof));unlink($root.'/payload/link');}
echo "PASS entire file SHA/size tree; corrupt, unknown, missing manifest and symlink rejected\n";
// Worker tree_inventory sorts pathlib path components: the directory subtree
// precedes the similarly named blocks.php file, unlike flat string ordering.
$componentOrder=$manifest;$componentOrder['files']=[
 ['path'=>'wordpress/blocks/a.php','bytes'=>1,'sha256'=>hash('sha256','A')],
 ['path'=>'wordpress/blocks.php','bytes'=>1,'sha256'=>hash('sha256','B')]];
$orderedRaw=json_encode($componentOrder,JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);$orderedSnapshot=$snapshot;$orderedSnapshot['tags'][3]='manifest-sha:'.hash('sha256',$orderedRaw);
$orderedProof=SuhoputBackup\authOwnerFullManifest($orderedSnapshot,$orderedRaw,$scope,$generation,$source);
mkdir($root.'/component-order/wordpress/blocks',0700,true);file_put_contents($root.'/component-order/wordpress/blocks/a.php','A');file_put_contents($root.'/component-order/wordpress/blocks.php','B');file_put_contents($root.'/component-order/manifest.json',$orderedRaw);
SuhoputBackup\verifyOwnerFullPayload($root.'/component-order',$orderedProof);
$duplicate=$componentOrder;$duplicate['files'][]=$duplicate['files'][0];$duplicateRaw=json_encode($duplicate,JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);$duplicateSnapshot=$snapshot;$duplicateSnapshot['tags'][3]='manifest-sha:'.hash('sha256',$duplicateRaw);
denied(fn()=>SuhoputBackup\authOwnerFullManifest($duplicateSnapshot,$duplicateRaw,$scope,$generation,$source));
file_put_contents($root.'/component-order/wordpress/blocks.php','X');denied(fn()=>SuhoputBackup\verifyOwnerFullPayload($root.'/component-order',$orderedProof));
echo "PASS worker component-sorted manifest accepted; duplicate and altered files rejected\n";
mkdir($root.'/full',0700);mkdir($root.'/full/wordpress',0700);mkdir($root.'/full/wordpress/wp-content',0700);mkdir($root.'/full/wordpress/wp-content/uploads',0700);
file_put_contents($root.'/full/wordpress/index.php','PHP');file_put_contents($root.'/full/wordpress/имя.php','RU');file_put_contents($root.'/full/wordpress/wp-content/uploads/ignored.jpg','media');
foreach(['.env','infra/staging/compose.yaml','infra/staging/backup.override.yaml','infra/staging/safety.php','infra/staging/proxy.conf'] as $name){$dest=$root.'/full/configuration/'.$name;if(!is_dir(dirname($dest)))mkdir(dirname($dest),0700,true);file_put_contents($dest,$name);}
// Independently computed with Python worker's sorted-key ASCII JSON algorithm.
$identity=['application_sha256'=>'05a09583b92d5803532bf35eaaff44044c8b52e549e47aa120e681abf65db4b3','configuration_sha256'=>'5d9e0d54569d9ceb8547dcb1544b382fb646e537845a99fc04f4ac667afb6a99'];
must(SuhoputBackup\verifyOwnerFullIdentity($root.'/full',$identity)===$identity);
file_put_contents($root.'/full/wordpress/index.php','BAD');denied(fn()=>SuhoputBackup\verifyOwnerFullIdentity($root.'/full',$identity));file_put_contents($root.'/full/wordpress/index.php','PHP');
file_put_contents($root.'/full/configuration/.env','BAD');denied(fn()=>SuhoputBackup\verifyOwnerFullIdentity($root.'/full',$identity));
echo "PASS full WordPress/configuration SHA binding matches worker including Unicode\n";
$logs=[['file'=>'suhoput2-binlog.000001','size'=>40,'sha256'=>str_repeat('3',64)],['file'=>'suhoput2-binlog.000002','size'=>50,'sha256'=>str_repeat('4',64)]];
$chains=[['id'=>str_repeat('2',64),'manifest'=>['kind'=>'binlog','previous_count'=>0,'first_log'=>1,'last_log'=>2,'active_file'=>'suhoput2-binlog.000003','logs'=>$logs]]];
$base=['id'=>$sid,'manifest'=>$manifest];$full=$base;$tip=['file'=>'suhoput2-binlog.000002','position'=>50];
$selected=SuhoputBackup\validateOwnerFullSelection($base,$full,$chains,$tip);
must($selected===$logs);
$bad=$chains;$bad[0]['manifest']['previous_count']=1;denied(fn()=>SuhoputBackup\validateOwnerFullSelection($base,$full,$bad,$tip));
$bad=$chains;$bad[0]['manifest']['logs'][1]['file']='suhoput2-binlog.000003';denied(fn()=>SuhoputBackup\validateOwnerFullSelection($base,$full,$bad,$tip));
$bad=$chains;$bad[0]['manifest']['logs'][0]['file']='binlog.000001';denied(fn()=>SuhoputBackup\validateOwnerFullSelection($base,$full,$bad,$tip));
$bad=$full;$bad['id']=str_repeat('5',64);denied(fn()=>SuhoputBackup\validateOwnerFullSelection($base,$bad,$chains,$tip));
$bad=$base;$bad['manifest']['kind']='hourly';$bad['manifest']['full_id']=str_repeat('5',64);denied(fn()=>SuhoputBackup\validateOwnerFullSelection($bad,$full,$chains,$tip));
$bad=$full;$bad['manifest']['application_sha256']=str_repeat('9',64);denied(fn()=>SuhoputBackup\validateOwnerFullSelection($base,$bad,$chains,$tip));
denied(fn()=>SuhoputBackup\validateOwnerFullSelection($base,$full,$chains,['file'=>$tip['file'],'position'=>49]));
denied(fn()=>SuhoputBackup\validateOwnerFullSelection($base,$full,[],$tip));
echo "PASS exact full/base binding, contiguous closed chain from prefix 1 and end target\n";
if(PHP_OS_FAMILY!=='Windows'){
 $private='/control/owner-full-private-'.bin2hex(random_bytes(8));mkdir($private,0700);file_put_contents($private.'/file','private');
 SuhoputBackup\fullPrivate($private,true);SuhoputBackup\fullPrivate($private.'/file');chmod($private.'/file',0644);clearstatcache(true,$private.'/file');denied(fn()=>SuhoputBackup\fullPrivate($private.'/file'));chmod($private.'/file',0600);
 link($private.'/file',$private.'/second');denied(fn()=>SuhoputBackup\ownerFullTree($private));unlink($private.'/second');
 symlink($private,$private.'-link');denied(fn()=>SuhoputBackup\fullPrivate($private.'-link/file'));unlink($private.'-link');
 echo "PASS private owner/mode, hard-link and symlink ancestry guards\n";
}
denied(fn()=>SuhoputBackup\prepareOwnerFull(['config'=>['repository_password'=>str_repeat('1',64)]]));
denied(fn()=>SuhoputBackup\prepareOwnerFull(['AWS_SECRET_ACCESS_KEY'=>'direct-secret']));
echo "PASS direct credentials/config cannot substitute sealed recovery paths\n";
mkdir($root.'/uploads',0700);foreach(['a.jpg','thumb.jpg','custom.pdf'] as $name)file_put_contents($root.'/uploads/'.$name,'synthetic '.$name);
$tables=[['TABLE_NAME'=>'wp_posts','ENGINE'=>'InnoDB','TABLE_TYPE'=>'BASE TABLE'],['TABLE_NAME'=>'wp_postmeta','ENGINE'=>'InnoDB','TABLE_TYPE'=>'BASE TABLE'],['TABLE_NAME'=>'wp_options','ENGINE'=>'InnoDB','TABLE_TYPE'=>'BASE TABLE'],['TABLE_NAME'=>'wp_custom','ENGINE'=>'InnoDB','TABLE_TYPE'=>'BASE TABLE']];
$columns=[['TABLE_NAME'=>'wp_posts','COLUMN_NAME'=>'post_content','DATA_TYPE'=>'longtext'],['TABLE_NAME'=>'wp_postmeta','COLUMN_NAME'=>'meta_id','DATA_TYPE'=>'bigint'],['TABLE_NAME'=>'wp_options','COLUMN_NAME'=>'option_id','DATA_TYPE'=>'bigint'],['TABLE_NAME'=>'wp_custom','COLUMN_NAME'=>'document','DATA_TYPE'=>'longblob']];
$query=static function(string $sql)use($tables,$columns):array{
 if(str_starts_with($sql,'SET ')||str_starts_with($sql,'START ')||in_array($sql,['COMMIT','ROLLBACK'],true))return [];
 if(str_contains($sql,'information_schema.TABLES'))return $tables;
 if(str_contains($sql,'information_schema.COLUMNS'))return $columns;
 if(str_contains($sql,'SELECT `ID`'))return [['ID'=>'1','post_type'=>'attachment']];
 if(str_contains($sql,'SELECT `post_id`'))return [['post_id'=>'1','meta_key'=>'_wp_attached_file','meta_value'=>'a.jpg'],['post_id'=>'1','meta_key'=>'_wp_attachment_metadata','meta_value'=>serialize(['file'=>'a.jpg','sizes'=>['thumb'=>['file'=>'thumb.jpg']]])]];
 if(str_contains($sql,'SELECT `option_name`'))return [];
 if(str_contains($sql,'`wp_custom`'))return [['value'=>'wp-content/uploads/custom.pdf']];
 if(str_contains($sql,'AS `value`'))return [];
 throw new RuntimeException('unexpected fixture SQL');
};
$inventory=[];foreach(['a.jpg','custom.pdf','thumb.jpg'] as $name)$inventory[]=['path'=>$name,'bytes'=>strlen('synthetic '.$name),'sha256'=>hash('sha256','synthetic '.$name)];
$verified=SuhoputBackup\verifyOwnerFullMedia($query,$root.'/uploads',$inventory);must($verified['coverage']['tables']===4);
$partial=$inventory;array_pop($partial);denied(fn()=>SuhoputBackup\verifyOwnerFullMedia($query,$root.'/uploads',$partial));
unlink($root.'/uploads/custom.pdf');denied(fn()=>SuhoputBackup\verifyOwnerFullMedia($query,$root.'/uploads',$inventory));
echo "PASS complete DB attachment/thumb/custom-column media proof and missing/partial rejection\n";
