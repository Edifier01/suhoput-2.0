<?php
declare(strict_types=1);
// Pure synthetic WordPress records; no WP bootstrap, DB, credentials or network.
require '/input/media.php';
function check(bool $condition): void { if (!$condition) throw new RuntimeException('control failed'); }
function rejected(callable $call,?string $expected=null): void {
    try { $call(); } catch (SuhoputBackup\MediaError $error) { if($expected!==null) check($error->getMessage()===$expected);return; }
    throw new RuntimeException('unsafe media evidence accepted');
}
$posts=[['ID'=>'10','post_type'=>'attachment'],['ID'=>'20','post_type'=>'product']];
$meta=[['post_id'=>'10','meta_key'=>'_wp_attached_file','meta_value'=>'2026/10/item-scaled.jpg'],
       ['post_id'=>'10','meta_key'=>'_wp_attachment_metadata','meta_value'=>serialize([
           'file'=>'2026/10/item-scaled.jpg','sizes'=>['thumbnail'=>['file'=>'item-150.jpg']],
           'original_image'=>'item.jpg'])],
       ['post_id'=>'10','meta_key'=>'_wp_attachment_backup_sizes','meta_value'=>serialize(['full-orig'=>['file'=>'item-old.jpg']])],
       ['post_id'=>'20','meta_key'=>'_thumbnail_id','meta_value'=>'10'],
       ['post_id'=>'20','meta_key'=>'_product_image_gallery','meta_value'=>'10']];
$alt=$meta;$alt[1]['meta_value']=serialize(['file'=>'2026/10/item-scaled.jpg','image_meta'=>['alt'=>'synthetic alt']]);
check(SuhoputBackup\mediaReferences($posts,$alt,[])===['2026/10/item-old.jpg','2026/10/item-scaled.jpg']);
$refs=SuhoputBackup\mediaReferences($posts,$meta,['https://stage.invalid/wp-content/uploads/2026/10/item-scaled.jpg?ver=1']);
check($refs===['2026/10/item-150.jpg','2026/10/item-old.jpg','2026/10/item-scaled.jpg','2026/10/item.jpg']);
check(SuhoputBackup\mediaReferences([],[],['background-image:url(/wp-content/uploads/2026/10/item.jpg);'])===['2026/10/item.jpg']);
check(SuhoputBackup\mediaReferences([],[],['wp-content/uploads/relative.png'])===['relative.png']);
$unknown=$meta;$unknown[1]['meta_value']=serialize(['file'=>'2026/10/item-scaled.jpg','sources'=>['image/webp'=>['file'=>'missing-source.webp']]]);
rejected(fn()=>SuhoputBackup\mediaReferences($posts,$unknown,[]));
$unknown[1]['meta_value']=serialize(['file'=>'2026/10/item-scaled.jpg','image_meta'=>['file'=>'missing-source.webp']]);
rejected(fn()=>SuhoputBackup\mediaReferences($posts,$unknown,[]));
check(SuhoputBackup\mediaReferences([],[],['prefix-wp-content/uploads/not-a-link.png'])===[]);
check(SuhoputBackup\mediaReferences([],[],['/wp-content/uploads/woocommerce_uploads/'])===['woocommerce_uploads/']);
echo "PASS originals/thumbnail/scaled-original/backup-sizes/product/gallery/URL references\n";
$badGallery=$meta;$badGallery[4]['meta_value']='99';check(count($badGallery)===count($meta));
rejected(fn()=>SuhoputBackup\mediaReferences($posts,$badGallery,[]),'Referenced attachment missing');
rejected(fn()=>SuhoputBackup\mediaReferences($posts,[...$meta,['post_id'=>'10','meta_key'=>'_wp_attached_file','meta_value'=>'other.jpg']],[]));
rejected(fn()=>SuhoputBackup\mediaReferences($posts,[['post_id'=>'10','meta_key'=>'_wp_attached_file','meta_value'=>'../private']],[]));
foreach (['broken serialized data',serialize((object)['file'=>'unsafe']),'a:1:{i:0;R:1;}'] as $value) {
    rejected(fn()=>SuhoputBackup\mediaReferences($posts,[$meta[0],['post_id'=>'10','meta_key'=>'_wp_attachment_metadata','meta_value'=>$value]],[]));
}
rejected(fn()=>SuhoputBackup\mediaReferences($posts,[],[]));
rejected(fn()=>SuhoputBackup\mediaReferences([],[],['/wp-content/uploads/%2e%2e/private']));
echo "PASS dangling/duplicate/traversal/malformed/serialized-object/missing metadata rejected\n";
umask(0077);mkdir('/control/uploads',0700);mkdir('/control/uploads/2026',0700);mkdir('/control/uploads/2026/10',0700);
foreach($refs as $path) file_put_contents('/control/uploads/'.$path,'synthetic bytes '.$path);
$inventory=SuhoputBackup\mediaInventory('/control/uploads',$refs);
check(count($inventory)===4);
SuhoputBackup\verifyMedia('/control/uploads',$inventory);
unlink('/control/uploads/2026/10/item-150.jpg');
rejected(fn()=>SuhoputBackup\verifyMedia('/control/uploads',$inventory));
file_put_contents('/control/uploads/2026/10/item-150.jpg','wrong bytes');
rejected(fn()=>SuhoputBackup\verifyMedia('/control/uploads',$inventory));
unlink('/control/uploads/2026/10/item-150.jpg');symlink('/etc/passwd','/control/uploads/2026/10/item-150.jpg');
rejected(fn()=>SuhoputBackup\mediaInventory('/control/uploads',$refs));
symlink('/etc','/control/uploads/external');
rejected(fn()=>SuhoputBackup\mediaInventory('/control/uploads',['external/passwd']));
echo "PASS all resolved files SHA/bytes, missing/corrupt/symlink rejected\n";

mkdir('/control/uploads/woocommerce_uploads',0700);
$dirs=SuhoputBackup\mediaInventory('/control/uploads',['woocommerce_uploads/']);
check($dirs===[['path'=>'woocommerce_uploads/','kind'=>'directory']]);
SuhoputBackup\verifyMedia('/control/uploads',$dirs);rmdir('/control/uploads/woocommerce_uploads');
rejected(fn()=>SuhoputBackup\verifyMedia('/control/uploads',$dirs));
echo "PASS directory URL classified separately; missing referenced directory rejected\n";
