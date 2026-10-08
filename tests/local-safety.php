<?php
// Run with wp eval-file; no credentials and no mutations of external systems.
$failures = [];
$assert = static function (bool $condition, string $name) use (&$failures): void {
    if (!$condition) { $failures[] = $name; }
};
$assert(wp_get_environment_type() === 'local', 'Local environment');
$assert(defined('SUHOPUT_EXTERNAL_WRITES_ENABLED') && SUHOPUT_EXTERNAL_WRITES_ENABLED === false, 'Writes disabled');
$response = wp_remote_get('https://api.moysklad.ru/api/remap/1.2/entity/product', ['timeout' => 2]);
$assert(is_wp_error($response) && $response->get_error_code() === 'suhoput_external_blocked', 'HTTP blocked before external request');
$assert(!is_plugin_active('yookassa/yookassa.php'), 'YooKassa absent');
$assert(\Automattic\WooCommerce\Utilities\OrderUtil::custom_orders_table_usage_is_enabled(), 'HPOS active');
$assert(has_action('phpmailer_init', 'suhoput_local_mail') !== false, 'Mail uses local capture');
$assert(wp_mail('safety-test@example.invalid', 'Local isolation control', 'Synthetic local test only.'), 'Mail capture accepts message');
$id = wc_create_order()->get_id();
$order = wc_get_order($id);
$assert($order instanceof WC_Order, 'WooCommerce CRUD order');
$order->delete(true);
if ($failures) { throw new RuntimeException('FAIL: ' . implode('; ', $failures)); }
echo "PASS: 8 local isolation/HPOS checks\n";
