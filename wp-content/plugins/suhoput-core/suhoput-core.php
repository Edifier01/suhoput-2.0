<?php
/**
 * Plugin Name: Suhoput Core
 * Description: Правила магазина Suhoput.
 * Version: 0.1.0
 * Requires PHP: 8.3
 * Requires Plugins: woocommerce
 * License: GPL-2.0-or-later
 */
defined('ABSPATH') || exit;
// Foundation deliberately bypasses page caches. Enabling one requires TASK-023/046 proof.
if (!defined('DONOTCACHEPAGE')) { define('DONOTCACHEPAGE', true); }
spl_autoload_register(static function (string $class): void {
    $prefix = 'Suhoput\\Core\\';
    if (!str_starts_with($class, $prefix)) { return; }
    $relative = substr($class, strlen($prefix));
    if (!preg_match('/\A[A-Za-z0-9_\\\\]+\z/', $relative)) { return; }
    $file = __DIR__ . '/src/' . str_replace('\\', '/', $relative) . '.php';
    if (is_file($file)) { require_once $file; }
});
add_action('before_woocommerce_init', static function (): void {
    if (class_exists(\Automattic\WooCommerce\Utilities\FeaturesUtil::class)) {
        \Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility('custom_order_tables', __FILE__, true);
    }
});
register_activation_hook(__FILE__, [\Suhoput\Core\Infrastructure\Schema::class, 'migrate']);
add_action('plugins_loaded', static function (): void {
    if ((int) get_option('suhoput_schema_version', 0) < \Suhoput\Core\Infrastructure\Schema::VERSION) {
        \Suhoput\Core\Infrastructure\Schema::migrate();
    }
});
add_action('woocommerce_after_order_object_save', static function ($order): void {
    if ($order instanceof WC_Order) {
        \Suhoput\Core\Infrastructure\OrderOutbox::synchronize($order);
    }
});
add_action('init', [\Suhoput\Core\Infrastructure\QueueRuntime::class, 'boot'], 20);
\Suhoput\Core\Infrastructure\Accounts::boot();
add_action('plugins_loaded', [\Suhoput\Core\Accounts\Forms::class, 'boot'], 30);
add_action('plugins_loaded', [\Suhoput\Core\Orders\Access::class, 'boot'], 30);
add_action('plugins_loaded', [\Suhoput\Core\Orders\Forms::class, 'boot'], 30);
add_action('plugins_loaded', [\Suhoput\Core\Commerce\Context::class, 'boot'], 30);
add_action('plugins_loaded', [\Suhoput\Core\Commerce\Settings::class, 'boot'], 30);
