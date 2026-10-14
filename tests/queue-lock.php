<?php
use Suhoput\Core\Infrastructure\{Journal, OrderLock, QueueRuntime, RetryLater};
use Suhoput\Core\Domain\OperationResult;
if (wp_get_environment_type() !== 'local') { throw new RuntimeException('Local tests only.'); }
[$tag,$mode] = $args;
if (!preg_match('/\A[a-f0-9-]{36}\z/',$tag)) { throw new RuntimeException('Invalid fixture.'); }
global $wpdb;
$key = 'suhoput_lock_fixture_'.$tag;
$fixture = get_option($key);
$assert = static function(bool $ok, string $message): void { if (!$ok) { throw new RuntimeException('FAIL: '.$message); } };
if ($mode === 'setup') {
    $order = wc_create_order();
    (new Journal())->intend(['operation_id'=>$tag,'order_id'=>$order->get_id(),'composition_version'=>1,'provider'=>$tag,'action'=>'reserve','idempotency_key'=>$tag,'request'=>['quantity'=>1]]);
    (new Journal())->executeOnce($tag, fn()=>OperationResult::unknown());
    $action=as_schedule_single_action(time()-400, 'suhoput_job', ['operation',$tag], 'suhoput-critical', true, 0);
    ActionScheduler::store()->log_execution($action);
    $wpdb->update($wpdb->actionscheduler_actions,['last_attempt_gmt'=>gmdate('Y-m-d H:i:s',time()-400)],['action_id'=>$action]);
    update_option($key,['order_id'=>$order->get_id(),'action_id'=>$action], false);
} elseif ($mode === 'hold') {
    OrderLock::run($fixture['order_id'], static function(): void { echo "LOCKED\n"; flush(); sleep(5); });
} elseif ($mode === 'live') {
    QueueRuntime::scheduler()->sweep();
    QueueRuntime::scheduler()->tick();
    $assert(ActionScheduler::store()->get_status($fixture['action_id']) === 'in-progress', 'Live handler not reclaimed after its lease expires');
    $assert((int)(new Journal())->get($tag)['attempts'] === 1, 'Second connection cannot duplicate active operation');
    echo "PASS: live connection retains ownership\n";
} elseif ($mode === 'dead') {
    QueueRuntime::scheduler()->sweep();
    $assert(ActionScheduler::store()->get_status($fixture['action_id']) === 'failed', 'Released connection can be recovered');
    $assert((new Journal())->get($tag)['state'] === 'unknown', 'Dead worker retains unknown effect for reconciliation');
    echo "PASS: released connection recovered without POST\n";
} elseif ($mode === 'tick_hold') {
    QueueRuntime::scheduler()->periodic($tag, 'catalog', 60, static function(): void { echo "LOCKED\n"; flush(); sleep(5); });
    QueueRuntime::scheduler()->tick();
} elseif ($mode === 'tick_live') {
    $assert(QueueRuntime::scheduler()->tick() === false, 'Second system tick does not overlap active tick');
    echo "PASS: system ticks do not overlap\n";
} elseif ($mode === 'periodic_fail' || $mode === 'periodic_resume') {
    $stateKey='suhoput_periodic_'.hash('sha256',$tag); $counterKey='fixture-periodic-'.$tag;
    QueueRuntime::scheduler()->periodic($tag,'catalog',300,function() use ($counterKey): void { update_option($counterKey,(int)get_option($counterKey,0)+1,false); throw new RetryLater(900); });
    if ($mode === 'periodic_fail') {
        $failOption=static fn(string $sql): string=>str_contains($sql,$stateKey) && preg_match('/^\s*(INSERT|UPDATE)/i',$sql) ? 'SELECT * FROM suhoput_intentionally_missing_option_table' : $sql;
        $errors=$wpdb->suppress_errors(true); add_filter('query',$failOption); $failed=false;
        try { QueueRuntime::scheduler()->runPeriodic($tag); } catch (RuntimeException $error) { $failed=true; }
        finally { remove_filter('query',$failOption); $wpdb->suppress_errors($errors); }
        $assert($failed && as_next_scheduled_action('suhoput_periodic_retry',[$tag],'suhoput-catalog') >= time()+899,'Rejected option state retains AS Retry-After lower bound');
        echo "PASS: rejected option write retains durable AS lower bound\n";
    } else {
        QueueRuntime::scheduler()->runPeriodic($tag);
        $assert((int)get_option($counterKey) === 1,'New process cannot bypass Retry-After after rejected option write');
        echo "PASS: restarted periodic handler respects Retry-After\n";
    }
} elseif ($mode === 'cleanup') {
    as_unschedule_all_actions('suhoput_periodic', [$tag], 'suhoput-catalog');
    delete_option('suhoput_periodic_'.hash('sha256',$tag));
    as_unschedule_all_actions('suhoput_periodic_retry',[$tag],'suhoput-catalog');
    delete_option('fixture-periodic-'.$tag);
    if ($fixture) {
        as_unschedule_all_actions('suhoput_job', ['operation',$tag], 'suhoput-critical');
        $wpdb->delete($wpdb->prefix.'suhoput_operations',['operation_id'=>$tag]); wc_get_order($fixture['order_id'])?->delete(true); delete_option($key);
    }
}
