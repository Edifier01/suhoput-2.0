<?php
use Suhoput\Core\Infrastructure\Schema;
if (wp_get_environment_type() !== 'local') { throw new RuntimeException('Local tests only.'); }
if (!class_exists(Schema::class)) { throw new RuntimeException('FAIL: own schema not implemented'); }
Schema::migrate();
global $wpdb;
$prefix = $wpdb->prefix . 'suhoput_';
$assert = static function (bool $ok, string $name): void { if (!$ok) { throw new RuntimeException('FAIL: '.$name); } };
$expected = ['links', 'accounts', 'operations', 'inbox', 'notifications', 'holds', 'order_access'];
foreach ($expected as $name) {
    $found = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($prefix . $name)));
    $assert($found === $prefix . $name, 'Table '.$name);
}
$tag = wp_generate_uuid4();
$data = ['local_type'=>'fixture','local_id'=>1,'provider'=>$tag,'external_type'=>'product','external_id'=>$tag];
$assert($wpdb->insert($prefix.'links', $data) === 1, 'First mapping inserted');
Schema::migrate();
$old = $wpdb->suppress_errors(true);
$assert($wpdb->insert($prefix.'links', $data) === false, 'Duplicate mapping rejected by database');
$data['local_id'] = 2;
$assert($wpdb->insert($prefix.'links', $data) === false, 'External mapping unique across local objects');
$wpdb->suppress_errors($old);
$wpdb->delete($prefix.'links', ['provider'=>$tag]);
$operation = wp_generate_uuid4();
$holdOrder = wc_create_order();
try { foreach ([1,2] as $variant) {
    $hold = ['hold_id'=>wp_generate_uuid4(), 'order_id'=>$holdOrder->get_id(), 'composition_version'=>1, 'variant_id'=>$variant, 'warehouse_id'=>'fixture', 'quantity'=>1, 'operation_id'=>$operation, 'expires_at'=>'2026-10-08 12:00:00'];
    $old = $wpdb->suppress_errors(true);
    $inserted = $wpdb->insert($prefix.'holds', $hold);
    $wpdb->suppress_errors($old);
    $assert($inserted === 1, 'Full-order operation supports multiple variants');
} } finally { $wpdb->delete($prefix.'holds', ['operation_id'=>$operation]); $holdOrder->delete(true); }
$assert(get_role('administrator')->has_cap('manage_suhoput'), 'Administrator capability');
$assert(get_role('shop_manager')->has_cap('manage_suhoput'), 'Manager capability');
$assert(!get_role('customer')->has_cap('manage_suhoput'), 'Customer capability denied');
$order = wc_create_order();
$order->update_meta_data('_suhoput_schema_fixture', $tag);
$order->save();
$assert(wc_get_order($order->get_id())->get_meta('_suhoput_schema_fixture') === $tag, 'CRUD with HPOS');
$order->delete(true);
echo "PASS: 7 tables, repeated migration, database uniqueness, capabilities and HPOS CRUD\n";
