<?php
// Staging infrastructure only; excluded from production application packages.
defined('ABSPATH') || exit;
if (wp_get_environment_type() !== 'staging'
    || !defined('SUHOPUT_STAGING_SAFETY') || SUHOPUT_STAGING_SAFETY !== true
    || !defined('SUHOPUT_EXTERNAL_WRITES_ENABLED') || SUHOPUT_EXTERNAL_WRITES_ENABLED !== false
    || !defined('DISABLE_WP_CRON') || DISABLE_WP_CRON !== true
    || !defined('SUHOPUT_SYSTEM_QUEUE_ENABLED') || SUHOPUT_SYSTEM_QUEUE_ENABLED !== false
    || (defined('DOING_CRON') && DOING_CRON)) {
    http_response_code(503);
    if (defined('WP_CLI') && WP_CLI) {
        fwrite(STDERR, "Staging safety configuration required.\n");
        exit(1);
    }
    exit('Staging safety configuration required.');
}
add_filter('pre_http_request', static function () {
    return new WP_Error('suhoput_stage_http_blocked', 'Staging HTTP transport is disabled.');
}, PHP_INT_MAX);
add_action('phpmailer_init', static function ($mailer): void {
    $mailer->isSMTP();
    $mailer->Host = 'mailpit';
    $mailer->Port = 1025;
    $mailer->SMTPAuth = false;
    $mailer->SMTPSecure = '';
    $mailer->SMTPAutoTLS = false;
    $mailer->SMTPDebug = 0;
}, PHP_INT_MAX);
add_filter('wp_mail_from', static fn(): string => 'stage@shop.example.invalid', PHP_INT_MAX);
add_filter('action_scheduler_allow_async_request_runner', '__return_false', PHP_INT_MAX);
add_action('wp_loaded', static function (): void {
    remove_all_actions('action_scheduler_run_queue');
}, PHP_INT_MAX);
if (defined('WP_CLI') && WP_CLI) {
    foreach (['suhoput queue tick', 'action-scheduler run', 'cron event run'] as $command) {
        WP_CLI::add_hook('before_invoke:' . $command, static function (): void {
            WP_CLI::error('Staging queue execution is disabled.');
        });
    }
}
