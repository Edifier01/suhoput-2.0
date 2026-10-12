<?php
declare(strict_types=1);
namespace SuhoputBackup;

// No WordPress bootstrap or external side effects. Caller must supply every
// relevant restored DB row; fixture coverage is not a DB completeness proof.
final class MediaError extends \RuntimeException {}
function need(bool $condition): void { if (!$condition) throw new MediaError('Invalid media evidence'); }
function relativeMedia(string $path): string {
    need($path!=='' && $path[0]!=='/' && !str_contains($path,'\\') && !str_contains($path,':')
         && preg_match('/[\x00-\x1f\x7f]/',$path)!==1);
    foreach(explode('/',$path) as $part) need($part!=='' && $part!=='.' && $part!=='..');
    return $path;
}
function mediaId(mixed $value): string {
    need(is_string($value) && preg_match('/^[1-9][0-9]*$/D',$value)===1);
    return $value;
}
function safeMetadata(string $value): array {
    need(strlen($value)<=16*1024*1024);
    set_error_handler(static function(): never { throw new MediaError('Invalid serialized metadata'); });
    try { $data=unserialize($value,['allowed_classes'=>false,'max_depth'=>32]); }
    finally { restore_error_handler(); }
    need(is_array($data));
    $visit=static function(mixed $item,int $depth=0) use (&$visit): void {
        need($depth<=32 && !is_object($item) && !is_resource($item));
        if(is_array($item)) foreach($item as $child) $visit($child,$depth+1);
    };
    $visit($data);
    return $data;
}
function metadataSibling(string $base,mixed $name): string {
    need(is_string($name) && !str_contains($name,'/'));
    relativeMedia($name);
    $dir=dirname($base);
    return relativeMedia(($dir==='.'?'':$dir.'/').$name);
}
/** Extract core WP attachment and WooCommerce gallery references plus uploads URLs. */
function mediaReferences(array $posts,array $meta,array $texts): array {
    $attachments=[];$postIds=[];
    foreach($posts as $post) {
        $id=mediaId($post['ID']??null);need(!isset($postIds[$id]));$postIds[$id]=true;
        need(is_string($post['post_type']??null));
        if($post['post_type']==='attachment') $attachments[$id]=[];
    }
    $keys=['_wp_attached_file','_wp_attachment_metadata','_wp_attachment_backup_sizes','_thumbnail_id','_product_image_gallery'];
    $seen=[];$links=[];
    foreach($meta as $row) {
        $key=$row['meta_key']??null;
        need(is_string($key));if(!in_array($key,$keys,true)) continue;
        $id=mediaId($row['post_id']??null);need(isset($postIds[$id]));
        $value=$row['meta_value']??null;need(is_string($value));
        need(!isset($seen[$id][$key]));$seen[$id][$key]=true;
        if(str_starts_with($key,'_wp_')) {
            need(isset($attachments[$id]));$attachments[$id][$key]=$value;
        } else {
            if($value==='' || ($key==='_thumbnail_id' && $value==='0')) continue;
            need($key!=='_thumbnail_id' || !str_contains($value,','));
            foreach(explode(',',$value) as $linked) $links[]=mediaId($linked);
        }
    }
    $refs=[];
    foreach($attachments as $record) {
        need(isset($record['_wp_attached_file']));$base=relativeMedia($record['_wp_attached_file']);$refs[$base]=true;
        if(isset($record['_wp_attachment_metadata'])) {
            $data=safeMetadata($record['_wp_attachment_metadata']);
            if(isset($data['file'])) need(is_string($data['file']) && relativeMedia($data['file'])===$base);
            if(isset($data['original_image'])) $refs[metadataSibling($base,$data['original_image'])]=true;
            if(isset($data['sizes'])) {
                need(is_array($data['sizes']));
                foreach($data['sizes'] as $size) { need(is_array($size) && isset($size['file']));$refs[metadataSibling($base,$size['file'])]=true; }
            }
        }
        if(isset($record['_wp_attachment_backup_sizes'])) {
            foreach(safeMetadata($record['_wp_attachment_backup_sizes']) as $size) {
                need(is_array($size) && isset($size['file']));$refs[metadataSibling($base,$size['file'])]=true;
            }
        }
    }
    foreach($links as $id) {
        if(!isset($attachments[$id])) throw new MediaError('Referenced attachment missing');
    }
    foreach($texts as $value) {
        need(is_string($value));$value=html_entity_decode(str_replace('\\/','/',$value),ENT_QUOTES|ENT_HTML5,'UTF-8');
        // Quote ordinary unquoted CSS url() before the generic URL pass, so
        // its closing parenthesis is not mistaken for part of the filename.
        $value=preg_replace_callback('~\burl\(\s*([^"\'()]*?)\s*\)~i',static fn(array $m): string=>'"'.$m[1].'"',$value);
        need(is_string($value));
        need(preg_match_all('~/wp-content/uploads/([^\s"\'<>?#,;]+)~u',$value,$matches)!==false);
        foreach($matches[1] as $encoded) $refs[relativeMedia(rawurldecode($encoded))]=true;
    }
    $paths=array_keys($refs);sort($paths,SORT_STRING);return $paths;
}
function mediaFile(string $root,string $path): string {
    relativeMedia($path);need(is_dir($root) && !is_link($root));$realRoot=realpath($root);need($realRoot!==false);
    $file=$realRoot;
    foreach(explode('/',$path) as $part) { $file.='/'.$part;need(!is_link($file)); }
    $real=realpath($file);need($real!==false && str_starts_with($real,$realRoot.'/') && is_file($file));
    return $real;
}
function mediaInventory(string $root,array $references): array {
    $result=[];$seen=[];
    foreach($references as $path) {
        need(is_string($path) && !isset($seen[$path]));$seen[$path]=true;$file=mediaFile($root,$path);
        $bytes=filesize($file);$sha=hash_file('sha256',$file);need(is_int($bytes) && is_string($sha));
        $result[]=['path'=>$path,'bytes'=>$bytes,'sha256'=>$sha];
    }
    return $result;
}
function verifyMedia(string $root,array $inventory): void {
    $refs=[];
    foreach($inventory as $row) {
        need(is_string($row['path']??null) && is_int($row['bytes']??null) && $row['bytes']>=0
             && is_string($row['sha256']??null) && preg_match('/^[a-f0-9]{64}$/D',$row['sha256'])===1);
        $refs[]=$row['path'];
    }
    need(mediaInventory($root,$refs)===$inventory);
}
