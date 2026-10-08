<?php
/**
 * Plugin Name: Suhoput MoySklad
 * Description: Граница обмена Suhoput с МойСклад.
 * Version: 0.1.0
 * Requires PHP: 8.3
 * Requires Plugins: woocommerce, suhoput-core
 * License: GPL-2.0-or-later
 */
defined('ABSPATH') || exit;
add_action('before_woocommerce_init', static function (): void {
    if (class_exists(\Automattic\WooCommerce\Utilities\FeaturesUtil::class)) {
        \Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility('custom_order_tables', __FILE__, true);
    }
});
