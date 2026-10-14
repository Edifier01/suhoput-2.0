<?php
declare(strict_types=1);
// Real local crypto with synthetic credentials only; no S3 or host volumes.
umask(0077);
if(!is_dir('/control/input'))mkdir('/control/input',0700,true);
if(is_file('/binary/restic'))copy('/binary/restic','/control/input/restic');
if(is_file('/source/owner-kit.php'))copy('/source/owner-kit.php','/control/input/owner-kit.php');
require is_file('/control/input/guard-test.php')?'/control/input/guard-test.php':'/tests/backup-owner-kit.php';
$kitPassword=bin2hex(random_bytes(32));
$built=SuhoputBackup\ownerKitMain(['mode'=>'build','owner_password'=>$kitPassword,'config'=>$config]);
check(($built['result']??'')==='PASS' && ($built['encrypted_local_integrity']??false)===true);
mkdir('/control/kit',0700);check(rename('/control/export/repository','/control/kit/repository'));
check(rename('/control/work','/control/builder-work'));
$request=['mode'=>'recover','owner_password'=>$kitPassword,'snapshot_id'=>$built['snapshot_id'],'verify_s3'=>false];
$recovered=SuhoputBackup\ownerKitMain($request);
check(($recovered['result']??'')==='PASS' && $recovered['portable_decryption']===true && $recovered['manifest_integrity']===true && $recovered['wrong_password_denied']===true && $recovered['s3_read_integrity']==='not_run');
echo "PASS encrypted kit init/backup/check/restore, authenticated manifest and wrong password\n";
check(rename('/control/work','/control/recovered-work'));
$wrong=SuhoputBackup\ownerKitMain([...$request,'owner_password'=>bin2hex(random_bytes(32))]);
check(($wrong['result']??'')==='FAIL' && $wrong['failed_phase']==='check');
check(rename('/control/work','/control/wrong-work'));
$iterator=new RecursiveIteratorIterator(new RecursiveDirectoryIterator('/control/kit/repository/data',FilesystemIterator::SKIP_DOTS));
$pack=null;foreach($iterator as $file){if($file->isFile()&&!$file->isLink()){$pack=$file->getPathname();break;}}
check(is_string($pack));check(chmod($pack,0600));check(file_put_contents($pack,'deliberately corrupted synthetic pack')!==false);
$corrupt=SuhoputBackup\ownerKitMain($request);
check(($corrupt['result']??'')==='FAIL' && $corrupt['failed_phase']==='check');
echo "PASS corrupt disposable encrypted pack rejected before restore\n";
echo "RESULT owner-kit-local-crypto=PASS s3=not_run physical-second-computer=not_run stage-backup=not_run\n";
