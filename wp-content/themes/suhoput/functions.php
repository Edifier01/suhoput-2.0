<?php
defined('ABSPATH') || exit;
add_action('after_setup_theme', static function (): void {
    add_theme_support('woocommerce');
    add_theme_support('title-tag');
});
add_action('wp_enqueue_scripts', static function (): void {
    wp_enqueue_style('suhoput', get_stylesheet_uri(), [], '0.1.0');
});
