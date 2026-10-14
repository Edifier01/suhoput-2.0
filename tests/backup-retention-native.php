<?php
declare(strict_types=1);
// Real restic semantics on fresh synthetic tmpfs bytes only. This does not
// authorize live deletion, establish receipt provenance, or prove 30-day history.
function retentionMust(bool $ok,string $code): void {if(!$ok)throw new RuntimeException($code);}
function retentionPrivate(string $path,bool $directory=false,bool $encryptedReadOnly=false): void {
 retentionMust(str_starts_with($path,'/control/retention-native-smoke')&&!is_link($path),'private-path');
 $stat=lstat($path);$modes=$directory?[0700]:($encryptedReadOnly?[0400,0600]:[0600]);retentionMust(is_array($stat)&&$stat['uid']===0&&in_array($stat['mode']&0777,$modes,true)
  &&($directory?is_dir($path):(is_file($path)&&$stat['nlink']===1)),'private-owner-mode');
}
function retentionTreePrivate(string $root): void {
 retentionPrivate($root,true);$iterator=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::SELF_FIRST);
 // Restic deliberately makes encrypted config/key/pack files0400. Preserve it.
 foreach($iterator as $entry)retentionPrivate($entry->getPathname(),$entry->isDir(),true);
}
$phase='binary';$root='/control/retention-native-smoke';$sequence=0;
try {
 umask(0077);
 retentionMust(hash_file('sha256','/binary/restic')==='20d4142678d0d95ec11a4759def1b73fd9190abc9ca19e4b62d067c0b387e639','binary-sha');
 retentionMust(!file_exists($root)&&!is_link($root),'existing-test-root');retentionMust(mkdir($root,0700),'create-test-root');
 foreach(['payload','cache'] as $name)retentionMust(mkdir($root.'/'.$name,0700),'create-test-child');
 file_put_contents($root.'/password',bin2hex(random_bytes(32))."\n");retentionPrivate($root.'/password');
 // Replace the process environment completely: no inherited cloud credentials.
 $env=['PATH'=>'/usr/local/bin:/usr/bin:/bin','HOME'=>$root,'TMPDIR'=>$root,
  'RESTIC_REPOSITORY'=>$root.'/repository','RESTIC_PASSWORD_FILE'=>$root.'/password','RESTIC_CACHE_DIR'=>$root.'/cache'];
 $run=static function(array $args)use($env,$root,&$sequence):string {
  retentionMust(in_array($args[0]??null,['init','backup','cat','dump','snapshots','forget','check','restore'],true),'command-boundary');
  foreach($args as $arg)retentionMust(is_string($arg)&&!str_contains($arg,"\0")&&!in_array($arg,['--prune','unlock','repair','prune'],true),'forbidden-command');
  $label=str_pad((string)++$sequence,3,'0',STR_PAD_LEFT);$out=$root.'/native-'.$label.'.out';$err=$root.'/native-'.$label.'.err';
  $process=proc_open(array_merge(['/binary/restic'],$args),[0=>['file','/dev/null','r'],1=>['file',$out,'x'],2=>['file',$err,'x']],$pipes,$root,$env,['bypass_shell'=>true]);
  retentionMust(is_resource($process),'process');$status=proc_close($process);retentionPrivate($out);retentionPrivate($err);
  retentionMust($status===0,'native-exit');retentionMust(filesize($out)<=16*1024*1024&&filesize($err)<=16*1024*1024,'native-output-size');
  $body=file_get_contents($out);retentionMust(is_string($body),'native-output');return $body;
 };
 $json=static function(string $body):array{$value=json_decode($body,true,32,JSON_THROW_ON_ERROR);retentionMust(is_array($value),'native-json');return $value;};
 $phase='init-format2';$run(['init','--repository-version','2']);$config=$json($run(['cat','config']));
 retentionMust(($config['version']??null)===2&&preg_match('/^[a-f0-9]{64}$/D',$config['id']??'')===1,'repository-format');
 $keys=glob($root.'/repository/keys/*');retentionMust(is_array($keys)&&count($keys)===1,'fresh-single-key');retentionTreePrivate($root.'/repository');
 $bytes=['A'=>"synthetic archived A\n",'B'=>"synthetic archived B\n",'C'=>"synthetic archived C\n"];$ids=[];
 $backup=static function(string $name)use($run,$json,$root,$bytes):string {
  file_put_contents($root.'/payload/item.txt',$bytes[$name]);retentionPrivate($root.'/payload/item.txt');
  $output=$run(['backup',$root.'/payload','--json','--host','task047-local-retention-smoke','--tag','task047-native-local','--tag','smoke:'.$name]);$summaries=[];
  foreach(array_filter(explode("\n",trim($output))) as $line){$row=$json($line);if(($row['message_type']??null)==='summary')$summaries[]=$row;}
  retentionMust(count($summaries)===1&&preg_match('/^[a-f0-9]{64}$/D',$summaries[0]['snapshot_id']??'')===1,'exact-snapshot-id');$id=$summaries[0]['snapshot_id'];
  $metadata=$json($run(['cat','snapshot',$id]));retentionMust(($metadata['paths']??null)===[$root.'/payload']&&in_array('smoke:'.$name,$metadata['tags']??[],true),'snapshot-binding');
  $dump=$run(['dump',$id,$root.'/payload/item.txt']);retentionMust(hash('sha256',$dump)===hash('sha256',$bytes[$name])&&$dump===$bytes[$name],'archived-file-sha');return $id;
 };
 $inventory=static function()use($run,$json):array {
  $rows=$json($run(['snapshots','--json']));retentionMust(array_is_list($rows),'snapshot-list');$ids=[];
  foreach($rows as $row){$id=$row['id']??null;retentionMust(is_string($id)&&preg_match('/^[a-f0-9]{64}$/D',$id)===1&&!isset($ids[$id]),'inventory-id');$ids[$id]=true;}
  $result=array_keys($ids);sort($result,SORT_STRING);return $result;
 };
 $phase='archive-A-B';foreach(['A','B'] as $name)$ids[$name]=$backup($name);
 retentionMust($ids['A']!==$ids['B']&&count($inventory())===2,'two-archives');
 $frozenCandidate=$ids['A'];$phase='arrival-C';$ids['C']=$backup('C');
 retentionMust(count(array_unique($ids))===3&&count($inventory())===3,'arrival-present');
 $phase='exact-ID-forget';$run(['forget',$frozenCandidate]);$expected=[$ids['B'],$ids['C']];sort($expected,SORT_STRING);
 retentionMust($inventory()===$expected,'only-frozen-candidate-absent');
 $phase='remaining-read-data';$run(['check','--read-data']);retentionTreePrivate($root.'/repository');
 $phase='restore-C';$run(['restore',$ids['C'],'--target',$root.'/restored','--verify']);
 $restored=$root.'/restored'.$root.'/payload/item.txt';retentionPrivate($restored);
 retentionMust(hash_file('sha256',$restored)===hash('sha256',$bytes['C'])&&file_get_contents($restored)===$bytes['C'],'restored-arrival-sha');
 echo json_encode(['result'=>'PASS','evidence_type'=>'native-local-exact-ID-forget-smoke','restic_version'=>'0.19.1','repository_format'=>2,
  'frozen_candidate'=>$frozenCandidate,'forgotten_ids'=>[$frozenCandidate],'preserved_ids'=>$expected,'arrival_id'=>$ids['C'],
  'snapshot_bytes_verified'=>3,'remaining_read_data'=>'PASS','arrival_restore_sha256'=>hash_file('sha256',$restored),
  'remote_delete_calls'=>0,'local_exact_forget_calls'=>1,'prune_run'=>false,'source_reads'=>0,'network'=>'none required by caller',
  'executor_six_proof_gate'=>'separate synthetic tests','live_s3_apply'=>'not_run','thirty_day_history'=>'not_proved'],JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR)."\n";
}catch(Throwable $error){
 echo json_encode(['result'=>'FAIL','evidence_type'=>'native-local-exact-ID-forget-smoke','failed_phase'=>$phase,'error_type'=>get_class($error),
  'safe_code'=>$error instanceof RuntimeException&&!($error instanceof JsonException)?$error->getMessage():null,
  'preserve_failure_state'=>true,'live_s3_apply'=>'not_run'],JSON_THROW_ON_ERROR)."\n";exit(1);
}
