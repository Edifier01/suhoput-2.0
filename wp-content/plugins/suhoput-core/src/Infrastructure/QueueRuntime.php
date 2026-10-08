<?php
declare(strict_types=1);
namespace Suhoput\Core\Infrastructure;

final class QueueRuntime
{
    private static Worker $worker;
    private static Scheduler $queue;
    public static function worker(): Worker { return self::$worker; }
    public static function scheduler(): Scheduler { return self::$queue; }

    public static function boot(): void
    {
        if (isset(self::$queue)) { return; }
        $worker = new Worker();
        $queue = new Scheduler($worker);
        self::$worker = $worker;
        self::$queue = $queue;
        $queue->register();
        do_action('suhoput_register_workers', $worker, $queue);
        if (defined('WP_CLI') && WP_CLI) {
            \WP_CLI::add_command('suhoput queue tick', static function() use ($queue): void {
                if ($queue->tick()) { \WP_CLI::success('Suhoput system queue completed.'); }
                else { \WP_CLI::log('Queue busy or Action Scheduler bootstrapping; next minute will retry.'); }
            });
        }
        if (defined('SUHOPUT_SYSTEM_QUEUE_ENABLED') && SUHOPUT_SYSTEM_QUEUE_ENABLED) {
            add_filter('action_scheduler_allow_async_request_runner', '__return_false');
            remove_action('action_scheduler_run_queue', [\ActionScheduler_QueueRunner::instance(),'run']);
        }
    }
}
