<?php
declare(strict_types=1);
require '/input/media.php';
$source='/input/database.php';
if(!is_file($source)) {fwrite(STDERR,"FAIL complete database exporter missing\n");exit(1);}
require $source;
function must(bool $ok): void {if(!$ok) throw new RuntimeException('database exporter control failed');}
function denied(callable $call): void {try{$call();}catch(SuhoputBackup\DatabaseError|SuhoputBackup\MediaError $e){return;}throw new RuntimeException('incomplete database evidence accepted');}
$tables=[['TABLE_NAME'=>'wp_posts','ENGINE'=>'InnoDB','TABLE_TYPE'=>'BASE TABLE'],['TABLE_NAME'=>'wp_postmeta','ENGINE'=>'InnoDB','TABLE_TYPE'=>'BASE TABLE'],['TABLE_NAME'=>'wp_options','ENGINE'=>'InnoDB','TABLE_TYPE'=>'BASE TABLE'],['TABLE_NAME'=>'wp_custom','ENGINE'=>'InnoDB','TABLE_TYPE'=>'BASE TABLE']];
$columns=[['TABLE_NAME'=>'wp_posts','COLUMN_NAME'=>'post_content','DATA_TYPE'=>'longtext'],['TABLE_NAME'=>'wp_postmeta','COLUMN_NAME'=>'meta_id','DATA_TYPE'=>'bigint'],['TABLE_NAME'=>'wp_options','COLUMN_NAME'=>'option_id','DATA_TYPE'=>'bigint'],['TABLE_NAME'=>'wp_custom','COLUMN_NAME'=>'document','DATA_TYPE'=>'longblob']];
$posts=[['ID'=>'1','post_type'=>'attachment'],['ID'=>'2','post_type'=>'product']];
$meta=[['post_id'=>'1','meta_key'=>'_wp_attached_file','meta_value'=>'a.jpg'],['post_id'=>'1','meta_key'=>'_wp_attachment_metadata','meta_value'=>serialize(['file'=>'a.jpg','sizes'=>['thumbnail'=>['file'=>'thumb.jpg']]])],['post_id'=>'2','meta_key'=>'_product_image_gallery','meta_value'=>'1']];
$trace=[];$badEngine=false;$drift=false;$omitTable=false;$tableReads=0;$option='';
$query=function(string $sql) use (&$trace,&$badEngine,&$drift,&$omitTable,&$tableReads,&$option,$tables,$columns,$posts,$meta): array {
    $trace[]=$sql;
    if(str_starts_with($sql,'SET ')||str_starts_with($sql,'START ')||in_array($sql,['COMMIT','ROLLBACK'],true))return [];
    if(str_contains($sql,'information_schema.TABLES')) {++$tableReads;$t=$tables;if($badEngine)$t[0]['ENGINE']='MyISAM';if($omitTable||($drift&&$tableReads>1))array_pop($t);return $t;}
    if(str_contains($sql,'information_schema.COLUMNS'))return $columns;
    if(str_contains($sql,'SELECT `ID`'))return $posts;
    if(str_contains($sql,'SELECT `post_id`'))return $meta;
    if(str_contains($sql,'SELECT `option_name`'))return [['option_name'=>'upload_path','option_value'=>$option],['option_name'=>'upload_url_path','option_value'=>'']];
    if(str_contains($sql,'`wp_custom`.`document`')||str_contains($sql,'FROM `suhoput2_stage`.`wp_custom`'))return [['value'=>'{"url":"https:\/\/stage.invalid\/wp-content\/uploads\/custom.pdf"}']];
    if(str_contains($sql,'AS `value`'))return [['value'=>'background:url(/wp-content/uploads/a.jpg)']];
    throw new RuntimeException('unexpected query in synthetic fixture');
};
umask(0077);mkdir('/control/uploads',0700);foreach(['a.jpg','thumb.jpg','custom.pdf'] as $f)file_put_contents('/control/uploads/'.$f,'synthetic '.$f);
$r=SuhoputBackup\databaseMedia($query,'suhoput2_stage','wp_','/control/uploads');
must(array_column($r['inventory'],'path')===['a.jpg','custom.pdf','thumb.jpg']);must($r['coverage']['tables']===4&&$r['coverage']['scanned_text_columns']===2&&$r['coverage']['all_tables_innodb']===true);
must($trace[1]==='START TRANSACTION READ ONLY, WITH CONSISTENT SNAPSHOT'&&end($trace)==='COMMIT');
echo "PASS complete tables/text+blob scan, attachment sizes/gallery and custom escaped URL\n";
$badEngine=true;$tableReads=0;denied(fn()=>SuhoputBackup\databaseMedia($query,'suhoput2_stage','wp_','/control/uploads'));must(end($trace)==='ROLLBACK');$badEngine=false;
$drift=true;$tableReads=0;denied(fn()=>SuhoputBackup\databaseMedia($query,'suhoput2_stage','wp_','/control/uploads'));$drift=false;
$option='/private/uploads';$tableReads=0;denied(fn()=>SuhoputBackup\databaseMedia($query,'suhoput2_stage','wp_','/control/uploads'));$option='';
unlink('/control/uploads/custom.pdf');$tableReads=0;denied(fn()=>SuhoputBackup\databaseMedia($query,'suhoput2_stage','wp_','/control/uploads'));
foreach([['production','wp_'],['suhoput2_stage','wp_;DROP TABLE x']] as [$schema,$prefix])denied(fn()=>SuhoputBackup\databaseMedia($query,$schema,$prefix,'/control/uploads'));
echo "PASS nontransactional tables, schema drift, custom upload root, missing cross-table file and unsafe scope rejected\n";