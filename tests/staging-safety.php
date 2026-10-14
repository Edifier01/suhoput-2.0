<?php
// Run only against a fresh synthetic staging database, with wp eval-file.
$checks = 0;
$assert = static function (bool $ok, string $name) use (&$checks): void {
    ++$checks;
    if (!$ok) { throw new RuntimeException('FAIL: ' . $name); }
};
$assert(wp_get_environment_type() === 'staging', 'Staging environment required');
$assert(defined('SUHOPUT_EXTERNAL_WRITES_ENABLED') && SUHOPUT_EXTERNAL_WRITES_ENABLED === false, 'External writes disabled');
$assert(defined('DISABLE_WP_CRON') && DISABLE_WP_CRON === true, 'Visitor cron disabled');
$assert(defined('SUHOPUT_SYSTEM_QUEUE_ENABLED') && SUHOPUT_SYSTEM_QUEUE_ENABLED === false, 'System worker disabled');
$response = wp_remote_get('https://example.com/', ['timeout' => 2]);
$assert(is_wp_error($response) && $response->get_error_code() === 'suhoput_stage_http_blocked', 'HTTP stopped before transport');
$assert(apply_filters('action_scheduler_allow_async_request_runner', true) === false, 'Async runner disabled');
$assert(!is_plugin_active('yookassa/yookassa.php'), 'YooKassa absent');
$assert(\Automattic\WooCommerce\Utilities\OrderUtil::custom_orders_table_usage_is_enabled(), 'HPOS active');
$assert(wp_mail('stage-control@example.invalid', 'Staging isolation control', 'Synthetic staging control only.'), 'Synthetic mail captured');
$errno = 0; $error = '';
$socket = @fsockopen('1.1.1.1', 443, $errno, $error, 2);
if (is_resource($socket)) { fclose($socket); }
$assert($socket === false, 'Raw external socket blocked by network');
$hook = 'stage-control-' . wp_generate_uuid4();
$calls = 0;
add_action($hook, static function () use (&$calls): void { ++$calls; });
$id = as_enqueue_async_action($hook, [], 'stage-control', false);
try {
    $assert($id > 0, 'Synthetic pending action persisted');
    do_action('action_scheduler_run_queue', 'stage-control');
    $assert($calls === 0 && ActionScheduler::store()->get_status($id) === 'pending', 'Pending action remains unexecuted');
} finally {
    as_unschedule_all_actions($hook);
}
echo "PASS: {$checks} staging isolation checks\n";
