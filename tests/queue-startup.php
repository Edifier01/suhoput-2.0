<?php
use Suhoput\Core\Infrastructure\QueueRuntime;
if (wp_get_environment_type() !== 'local') { throw new RuntimeException('Local tests only.'); }
global $wpdb;
if (!ActionScheduler::store() instanceof ActionScheduler_DBStore) { throw new RuntimeException('FAIL: AS bootstrap did not finish migration'); }
$groups=(int)$wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->actionscheduler_groups} WHERE slug IN ('suhoput-critical','suhoput-catalog','suhoput-photos')");
if ($groups !== 0) { throw new RuntimeException('FAIL: clean queue startup requires no own groups'); }
$hook='fixture-startup-'.wp_generate_uuid4(); $calls=0;
add_action($hook,function() use (&$calls): void { ++$calls; });
as_enqueue_async_action($hook, [], 'fixture-startup', false, 0);
try {
    if (!QueueRuntime::scheduler()->tick() || $calls !== 1) { throw new RuntimeException('FAIL: upstream work cannot run before own groups exist'); }
    echo "PASS: clean DBStore startup runs upstream work before own groups exist\n";
} finally { as_unschedule_all_actions($hook); }
