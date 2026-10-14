<?php
declare(strict_types=1);
namespace SuhoputBackup;

// The caller must use one isolated source/control DB connection. No WP bootstrap.
final class DatabaseError extends \RuntimeException {}
function dbNeed(bool $ok): void {if(!$ok)throw new DatabaseError('Invalid complete database evidence');}
function dbIdentifier(string $name): string {dbNeed(preg_match('/^[A-Za-z0-9_]+$/D',$name)===1);return '`'.$name.'`';}
/** Scan every table and every character/binary column containing an uploads marker.
 * Read-only repeatable-read snapshot; table/column drift and unknown storage fail.
 * This validates provided DB/media now, not coherence with a separate SQL dump.
 */
function databaseMedia(callable $query,string $schema,string $prefix,string $uploads): array {
    dbNeed($schema==='suhoput2_stage'&&preg_match('/^[A-Za-z0-9_]+_$/D',$prefix)===1);
    $db=dbIdentifier($schema);$started=false;
    $tablesSql="SELECT TABLE_NAME,ENGINE,TABLE_TYPE FROM information_schema.TABLES WHERE TABLE_SCHEMA='suhoput2_stage' ORDER BY TABLE_NAME";
    $columnsSql="SELECT TABLE_NAME,COLUMN_NAME,DATA_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='suhoput2_stage' ORDER BY TABLE_NAME,ORDINAL_POSITION";
    try {
        $query('SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ');
        $query('START TRANSACTION READ ONLY, WITH CONSISTENT SNAPSHOT');$started=true;
        $tables=$query($tablesSql);$columns=$query($columnsSql);dbNeed(is_array($tables)&&$tables!==[]&&is_array($columns)&&$columns!==[]);
        $names=[];
        foreach($tables as $row) {
            dbNeed(is_string($row['TABLE_NAME']??null)&&($row['ENGINE']??null)==='InnoDB'&&($row['TABLE_TYPE']??null)==='BASE TABLE');
            $table=$row['TABLE_NAME'];dbIdentifier($table);dbNeed(!isset($names[$table]));$names[$table]=true;
        }
        foreach(['posts','postmeta','options'] as $suffix)dbNeed(isset($names[$prefix.$suffix]));
        $posts=$query('SELECT `ID`,`post_type` FROM '.$db.'.'.dbIdentifier($prefix.'posts').' ORDER BY `ID`');
        $meta=$query('SELECT `post_id`,`meta_key`,`meta_value` FROM '.$db.'.'.dbIdentifier($prefix.'postmeta')." WHERE `meta_key` IN ('_wp_attached_file','_wp_attachment_metadata','_wp_attachment_backup_sizes','_thumbnail_id','_product_image_gallery') ORDER BY `meta_id`");
        $options=$query('SELECT `option_name`,`option_value` FROM '.$db.'.'.dbIdentifier($prefix.'options')." WHERE `option_name` IN ('upload_path','upload_url_path') ORDER BY `option_name`");
        $seenOptions=[];
        foreach($options as $option) {
            $key=$option['option_name']??null;dbNeed(in_array($key,['upload_path','upload_url_path'],true)&&!isset($seenOptions[$key])&&is_string($option['option_value']??null));$seenOptions[$key]=true;
            dbNeed($option['option_value']===''||($key==='upload_path'&&$option['option_value']==='wp-content/uploads'));
        }
        $textTypes=['char','varchar','tinytext','text','mediumtext','longtext','binary','varbinary','tinyblob','blob','mediumblob','longblob','json','enum','set'];
        $texts=[];$scanned=0;$seenColumns=[];
        foreach($columns as $column) {
            $table=$column['TABLE_NAME']??null;$name=$column['COLUMN_NAME']??null;$type=$column['DATA_TYPE']??null;
            dbNeed(is_string($table)&&isset($names[$table])&&is_string($name)&&is_string($type));dbIdentifier($name);
            dbNeed(!isset($seenColumns[$table][$name]));$seenColumns[$table][$name]=true;
            if(!in_array($type,$textTypes,true))continue;
            ++$scanned;$quoted=dbIdentifier($name);
            foreach($query('SELECT '.$quoted.' AS `value` FROM '.$db.'.'.dbIdentifier($table)." WHERE LOCATE('uploads',".$quoted.')>0') as $row) {
                dbNeed(is_string($row['value']??null)&&strlen($row['value'])<=16*1024*1024);$texts[]=$row['value'];
            }
        }
        foreach(array_keys($names) as $table)dbNeed(isset($seenColumns[$table]));
        $references=mediaReferences($posts,$meta,$texts);$inventory=mediaInventory($uploads,$references);
        dbNeed($tables===$query($tablesSql)&&$columns===$query($columnsSql));
        $query('COMMIT');$started=false;
        return ['inventory'=>$inventory,'coverage'=>['tables'=>count($tables),'scanned_text_columns'=>$scanned,'attachments'=>count(array_filter($posts,static fn(array $p):bool=>$p['post_type']==='attachment')),'references'=>count($references),'all_tables_innodb'=>true,'schema_metadata_stable'=>true,'read_only_snapshot'=>true]];
    } finally {if($started)$query('ROLLBACK');}
}
/** Protected environment connection in the stage WP container; error data omitted. */
function stageDatabaseMedia(string $uploads='/var/www/html/wp-content/uploads'): array {
    dbNeed(getenv('WORDPRESS_DB_NAME')==='suhoput2_stage'&&getenv('WORDPRESS_DB_HOST')==='db:3306'&&getenv('WORDPRESS_DB_USER')==='stage');
    \mysqli_report(MYSQLI_REPORT_ERROR|MYSQLI_REPORT_STRICT);
    $connection=new \mysqli('db','stage',getenv('WORDPRESS_DB_PASSWORD'),'suhoput2_stage',3306);
    try {
        $connection->set_charset('utf8mb4');
        $query=static function(string $sql) use($connection): array {
            $result=$connection->query($sql);
            if(!$result instanceof \mysqli_result)return [];
            try{return $result->fetch_all(MYSQLI_ASSOC);}finally{$result->free();}
        };
        return databaseMedia($query,'suhoput2_stage','wp_',$uploads);
    } finally {$connection->close();}
}