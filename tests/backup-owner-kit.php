<?php
declare(strict_types=1);
require '/control/input/owner-kit.php';
function check(bool $value): void { if(!$value) throw new RuntimeException('control failed'); }
function rejected(callable $call): void {
 try {$call();}catch(SuhoputBackup\OwnerKitError $e){return;}
 throw new RuntimeException('unsafe kit input accepted');
}
$config=['format'=>1,'generation'=>str_repeat('a',32),'preparation_code_sha'=>str_repeat('b',40),
 's3'=>['endpoint'=>'https://s3.invalid','region'=>'ru-1','bucket'=>'stage-test','prefix'=>'suhoput2/stage-b/',
        'access_key'=>'synthetic-access','secret_key'=>'synthetic-secret'],
 'repository_password'=>str_repeat('c',64),
 'repositories'=>['base'=>'s3:https://s3.invalid/stage-test/suhoput2/stage-b/repositories/base',
                  'binlog'=>'s3:https://s3.invalid/stage-test/suhoput2/stage-b/repositories/binlog'],
 'control'=>['repository'=>'s3:https://s3.invalid/stage-test/suhoput2/stage-b/archive-control/'.str_repeat('d',32),
             'snapshot_id'=>str_repeat('e',64)]];
SuhoputBackup\validateOwnerConfig($config);
foreach(['http://s3.invalid','https://user:pass@s3.invalid','https://s3.invalid/path','https://s3.invalid?x=1'] as $endpoint){
 $bad=$config;$bad['s3']['endpoint']=$endpoint;rejected(fn()=>SuhoputBackup\validateOwnerConfig($bad));
}
foreach(['suhoput2/','suhoput2/stage-b/../','old/'] as $prefix){
 $bad=$config;$bad['s3']['prefix']=$prefix;rejected(fn()=>SuhoputBackup\validateOwnerConfig($bad));
}
$bad=$config;$bad['repositories']['base']='s3:https://s3.invalid/stage-test/old';rejected(fn()=>SuhoputBackup\validateOwnerConfig($bad));
$bad=$config;$bad['control']['repository']=$config['repositories']['base'];rejected(fn()=>SuhoputBackup\validateOwnerConfig($bad));
$bad=$config;$bad['control']['snapshot_id']='short';rejected(fn()=>SuhoputBackup\validateOwnerConfig($bad));
foreach(['short',"valid-long-password\nsecond",str_repeat('x',16)."\0"] as $password)rejected(fn()=>SuhoputBackup\ownerPassword($password));
SuhoputBackup\ownerPassword(str_repeat('x',16));
echo "PASS owner-kit scope/endpoint/identity/password guards; no credentials, crypto or S3 used\n";
