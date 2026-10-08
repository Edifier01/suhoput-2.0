<?php
// Mounted only by local Compose; never included in production packages.
defined('ABSPATH') || exit;
if (!defined('SUHOPUT_LOCAL_SAFETY') || SUHOPUT_LOCAL_SAFETY !== true) {
    return;
}
add_filter('pre_http_request', static function ($pre, array $args, string $url) {
    // Even a restored database cannot select a real API host in this environment.
    return new WP_Error('suhoput_external_blocked', 'External HTTP is disabled in the local environment.');
}, PHP_INT_MAX, 3);
function suhoput_local_mail($mailer): void {
    $mailer->isSMTP();
    $mailer->Host = 'mailpit';
    $mailer->Port = 1025;
    $mailer->SMTPAuth = false;
    $mailer->SMTPSecure = '';
    $mailer->SMTPAutoTLS = false;
    $mailer->SMTPDebug = 0;
}
add_action('phpmailer_init', 'suhoput_local_mail', PHP_INT_MAX);
add_filter('wp_mail_from', static fn(): string => 'local@shop.example.invalid', PHP_INT_MAX);
add_filter('action_scheduler_allow_async_request_runner', '__return_false');
