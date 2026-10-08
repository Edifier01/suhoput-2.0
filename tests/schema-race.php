<?php
if (wp_get_environment_type() !== 'local') { throw new RuntimeException('Local tests only.'); }
global $wpdb;
$tag = $args[0] ?? '';
if (!preg_match('/\A[a-f0-9-]{36}\z/', $tag)) { throw new RuntimeException('Invalid fixture identifier.'); }
$provider = 'fixture-' . $tag;
$table = $wpdb->prefix . 'suhoput_links';
if (($args[1] ?? '') === 'cleanup') { $wpdb->delete($table, ['provider'=>$provider]); return; }
$local = (int) ($args[1] ?? 0);
if (!in_array($local, [1,2], true)) { throw new RuntimeException('Invalid fixture object.'); }
$old = $wpdb->suppress_errors(true);
$ok = $wpdb->insert($table, ['local_type'=>'fixture','local_id'=>$local,'provider'=>$provider,'external_type'=>'product','external_id'=>$tag]);
$error = $wpdb->last_error;
$wpdb->suppress_errors($old);
if ($ok !== 1 && !str_contains($error, 'Duplicate entry')) { throw new RuntimeException('Unexpected fixture database error.'); }
echo $ok === 1 ? 'RACE_WIN' : 'RACE_LOSE';
