<?php
use Suhoput\Core\Infrastructure\{Journal, OrderOutbox, QueueRuntime, Scheduler, RetryLater};
use Suhoput\Core\Domain\OperationResult;
if (wp_get_environment_type() !== 'local') { throw new RuntimeException('Local tests only.'); }
if (!class_exists(Scheduler::class)) { throw new RuntimeException('FAIL: minute scheduler is missing'); }
global $wpdb;
$order = wc_create_order(); $tag = wp_generate_uuid4(); $id = wp_generate_uuid4();
$journal = new Journal(); $worker = QueueRuntime::worker(); $queue = QueueRuntime::scheduler();
$count = 0;
$assert = static function(bool $ok, string $name) use (&$count): void { ++$count; if (!$ok) { throw new RuntimeException('FAIL: '.$name); } };
$sequence = [];
$command = ['operation_id'=>$id, 'order_id'=>$order->get_id(), 'composition_version'=>1, 'provider'=>$tag, 'action'=>'reserve', 'idempotency_key'=>$id, 'request'=>['quantity'=>1]];
try {
    $worker->operation($tag, 'reserve', function() use (&$sequence) { $sequence[] = 'reserve'; return OperationResult::confirmed(['fixture'=>true]); }, fn()=>OperationResult::unknown(), fn()=>null);
    $queue->periodic($tag.'-catalog', 'catalog', 300, function() use (&$sequence) { $sequence[] = 'catalog'; });
    $queue->periodic($tag.'-photos', 'photos', 300, function() use (&$sequence) { $sequence[] = 'photos'; });
    add_action($tag.'-other', function() use (&$sequence) { $sequence[] = 'other'; });
    as_enqueue_async_action($tag.'-other', [], 'fixture-'.$tag, false, 0);
    OrderOutbox::save($order, $command); $queue->tick();
    // A bounded tick may drain unrelated durable fixture backlog before entering lower groups.
    for ($n=0; $n<10 && count($sequence)<4; ++$n) { $queue->tick(); }
    $assert($sequence === ['reserve','catalog','photos','other'], 'Reserve precedes catalogue/photos, and upstream groups are serviced');
    $assert($journal->get($id)['applied_at'] !== null, 'System tick runs a persisted action');
    $next = as_next_scheduled_action('suhoput_periodic', [$tag.'-catalog'], 'suhoput-catalog');
    $assert(is_int($next) && $next > time() && $next <= time()+300, 'Five minute periodic cycle preserved');
    // A retry re-reads unknown; backoff suppresses early/manual duplicate execution.
    $retry = $command; $retry['operation_id']=wp_generate_uuid4(); $retry['idempotency_key']=$retry['operation_id']; $retry['action']='retry';
    $reads = 0; $posts = 0;
    $worker->operation($tag, 'retry', function() use (&$posts) { ++$posts; return OperationResult::unknown(); }, function() use (&$reads) { ++$reads; return OperationResult::unknown(); }, fn()=>null);
    $journal->intend($retry); $queue->handle('operation', $retry['operation_id']);
    $row = $journal->get($retry['operation_id']);
    $assert($posts === 1 && strtotime($row['next_attempt_at'].' UTC') >= time()+59, 'First failure persists delayed retry');
    $queue->handle('operation', $retry['operation_id']);
    $assert($reads === 0 && $posts === 1, 'Early retry cannot execute transport');
    $wpdb->update($wpdb->prefix.'suhoput_operations', ['next_attempt_at'=>gmdate('Y-m-d H:i:s',time()-1)], ['operation_id'=>$retry['operation_id']]);
    $queue->handle('operation', $retry['operation_id']); $row=$journal->get($retry['operation_id']);
    $assert($reads === 1 && $posts === 1 && strtotime($row['next_attempt_at'].' UTC') >= time()+119, 'Second failure backs off and only reconciles');
    // A saved deadline cannot move when the queue restarts or an earlier action invokes it.
    $deadline=$command; $deadline['operation_id']=wp_generate_uuid4(); $deadline['idempotency_key']=$deadline['operation_id']; $deadline['not_before']=time()+3600;
    $journal->intend($deadline); $queue->handle('operation', $deadline['operation_id']);
    $assert((int)$journal->get($deadline['operation_id'])['attempts'] === 0, 'Deadline job cannot execute early');
    $changedDeadline=$deadline; $changedDeadline['not_before']=0; $deadlineRejected=false;
    try { $journal->intend($changedDeadline); } catch (LogicException $error) { $deadlineRejected=true; }
    $assert($deadlineRejected && strtotime($journal->get($deadline['operation_id'])['available_at'].' UTC') === $deadline['not_before'], 'Retry cannot replace the original deadline');
    // Rate-limit instruction is persisted as a lower bound, independent of exponent.
    $limited=$command; $limited['operation_id']=wp_generate_uuid4(); $limited['idempotency_key']=$limited['operation_id']; $limited['action']='limited';
    $worker->operation($tag, 'limited', fn()=>OperationResult::unknown(), fn()=>throw new RetryLater(900), fn()=>null);
    $journal->intend($limited); $journal->executeOnce($limited['operation_id'], fn()=>OperationResult::unknown());
    $queue->handle('operation', $limited['operation_id']);
    $assert(strtotime($journal->get($limited['operation_id'])['next_attempt_at'].' UTC') >= time()+899, 'Retry-After lower bound is respected');
    $noticeIdentity = ['order_id'=>$order->get_id(),'fixture'=>$tag];
    $noticeKey = hash('sha256',Journal::canonical($noticeIdentity));
    $journal->notify($noticeIdentity, ['fixture'=>true]);
    $noticePosts=0; $noticeReads=0;
    $worker->notifications(function() use (&$noticePosts) { ++$noticePosts; throw new RetryLater(900); }, function() use (&$noticeReads) { ++$noticeReads; throw new RetryLater(1200); });
    $queue->handle('notification',$noticeKey);
    $notice = $wpdb->get_row($wpdb->prepare('SELECT * FROM '.$wpdb->prefix.'suhoput_notifications WHERE notification_key=%s',$noticeKey), ARRAY_A);
    $assert($notice['state'] === 'unknown' && strtotime($notice['next_attempt_at'].' UTC') >= time()+899, 'Notification transport preserves Retry-After with unknown outcome');
    $wpdb->update($wpdb->prefix.'suhoput_notifications',['next_attempt_at'=>null],['notification_key'=>$noticeKey]);
    $queue->handle('notification',$noticeKey);
    $notice = $wpdb->get_row($wpdb->prepare('SELECT * FROM '.$wpdb->prefix.'suhoput_notifications WHERE notification_key=%s',$noticeKey), ARRAY_A);
    $assert($noticePosts === 1 && $noticeReads === 1 && strtotime($notice['next_attempt_at'].' UTC') >= time()+1199, 'Notification reconciliation respects Retry-After without a second send');
    $wpdb->delete($wpdb->prefix.'suhoput_notifications',['notification_key'=>$noticeKey]);
    // Recover a dead AS action while preserving unknown external outcome.
    $stuck=$command; $stuck['operation_id']=wp_generate_uuid4(); $stuck['idempotency_key']=$stuck['operation_id']; $stuck['action']='retry';
    $journal->intend($stuck); $journal->executeOnce($stuck['operation_id'], fn()=>OperationResult::unknown());
    $action = as_schedule_single_action(time()-400, 'suhoput_job', ['operation',$stuck['operation_id']], 'suhoput-critical', true, 0);
    $store = ActionScheduler::store(); $store->log_execution($action);
    $wpdb->update($wpdb->actionscheduler_actions, ['last_attempt_gmt'=>gmdate('Y-m-d H:i:s',time()-400)], ['action_id'=>$action]);
    $queue->sweep();
    $assert($store->get_status($action) === 'failed', 'Dead AS handler recovered after stale threshold');
    $assert($journal->get($stuck['operation_id'])['state'] === 'unknown', 'Recovery never resets unknown into queued');
    $assert(as_has_scheduled_action('suhoput_job',['operation',$stuck['operation_id']], 'suhoput-critical'), 'Lost action rebuilt from durable journal');
    $queue->sweep();
    $ids = as_get_scheduled_actions(['hook'=>'suhoput_job', 'args'=>['operation',$stuck['operation_id']], 'status'=>'pending', 'per_page'=>20], 'ids');
    $assert(count($ids) === 1, 'Repeated sweeps do not duplicate runnable action');
    // A killed batch has a real claim: its not-yet-started actions must become runnable again.
    $claimHook=$tag.'-claim'; $claimCalls=0;
    add_action($claimHook,function() use (&$claimCalls): void { ++$claimCalls; });
    $claimed=[];
    for ($n=0; $n<2; ++$n) { $claimed[]=as_schedule_single_action(time()-400,$claimHook,[$n],'fixture-'.$tag,false,0); }
    $priorGroup=$store->get_claim_filter('group'); $priorHooks=$store->get_claim_filter('hooks');
    $claim=$store->stake_claim(2,null,[$claimHook],'fixture-'.$tag);
    $store->set_claim_filter('group',$priorGroup); $store->set_claim_filter('hooks',$priorHooks);
    $assert(count($claim->get_actions()) === 2, 'Crash fixture has a real AS batch claim');
    $store->log_execution($claimed[0]);
    foreach ($claimed as $claimId) { $wpdb->update($wpdb->actionscheduler_actions,['last_attempt_gmt'=>gmdate('Y-m-d H:i:s',time()-400)],['action_id'=>$claimId]); }
    for ($n=0; $n<10 && $store->get_status($claimed[1]) !== 'complete'; ++$n) { $queue->tick(); }
    $assert($store->get_status($claimed[0]) === 'failed' && $store->get_status($claimed[1]) === 'complete' && $claimCalls === 1, 'Dead real claim releases pending batch work without rerunning its failed action');
    $store->release_claim($claim);
    // More than one sweep page of future deadlines must not bury due reconciliation.
    for ($n=0; $n<105; ++$n) {
        $future=$deadline; $future['operation_id']=wp_generate_uuid4(); $future['idempotency_key']=$future['operation_id']; $journal->intend($future);
    }
    $urgent=$retry; $urgent['operation_id']=wp_generate_uuid4(); $urgent['idempotency_key']=$urgent['operation_id']; $journal->intend($urgent);
    $journal->executeOnce($urgent['operation_id'], fn()=>OperationResult::unknown());
    $wpdb->update($wpdb->prefix.'suhoput_operations', ['next_attempt_at'=>gmdate('Y-m-d H:i:s',time()-1)], ['operation_id'=>$urgent['operation_id']]);
    $queue->sweep();
    $assert(as_has_scheduled_action('suhoput_job',['operation',$urgent['operation_id']], 'suhoput-critical'), 'Future deadline backlog cannot starve due reconciliation');
    // Periodic retries recover from a stop after saving failure but before AS scheduling.
    $periodicName = $tag.'-failure';
    $periodicCalls = 0;
    $queue->periodic($periodicName, 'catalog', 300, function() use (&$periodicCalls) { ++$periodicCalls; throw new RuntimeException('Synthetic import failure'); });
    $queue->runPeriodic($periodicName);
    as_unschedule_all_actions('suhoput_periodic_retry', [$periodicName], 'suhoput-catalog');
    $queue->sweep();
    $assert(as_has_scheduled_action('suhoput_periodic_retry', [$periodicName], 'suhoput-catalog'), 'Periodic failure survives loss of scheduled retry');
    $queue->runPeriodic($periodicName);
    $assert($periodicCalls === 1, 'Periodic backoff prevents early re-execution');
    $periodicAction = as_schedule_single_action(time()-400,'suhoput_periodic_retry',[$periodicName],'suhoput-catalog',false,100);
    $store->log_execution($periodicAction);
    $wpdb->update($wpdb->actionscheduler_actions,['last_attempt_gmt'=>gmdate('Y-m-d H:i:s',time()-400)],['action_id'=>$periodicAction]);
    $queue->sweep();
    $assert($store->get_status($periodicAction) === 'failed', 'Dead periodic handler releases its AS claim');
    $persistName=$tag.'-persist'; $persistKey='suhoput_periodic_'.hash('sha256',$persistName);
    $persistCalls=0;
    $queue->periodic($persistName,'catalog',300,function() use (&$persistCalls) { ++$persistCalls; throw new RetryLater(900); });
    $failOption = static function(string $sql) use ($persistKey): string {
        return str_contains($sql,$persistKey) && preg_match('/^\s*(INSERT|UPDATE)/i',$sql) ? 'SELECT * FROM suhoput_intentionally_missing_option_table' : $sql;
    };
    $errors=$wpdb->suppress_errors(true); add_filter('query',$failOption);
    $persistFailed=false;
    try { $queue->runPeriodic($persistName); } catch (RuntimeException $error) { $persistFailed=true; }
    finally { remove_filter('query',$failOption); $wpdb->suppress_errors($errors); }
    $assert($persistFailed && !get_option($persistKey), 'Rejected periodic backoff write cannot report successful completion');
    $queue->runPeriodic($persistName);
    $assert($persistCalls === 1 && as_next_scheduled_action('suhoput_periodic_retry',[$persistName],'suhoput-catalog') >= time()+899, 'AS retry lower bound suppresses recurring after rejected options write');
    // Critical lag produces one manager notice, while failed notification does not recurse.
    $wpdb->update($wpdb->prefix.'suhoput_operations', ['created_at'=>gmdate('Y-m-d H:i:s',time()-1000), 'next_attempt_at'=>null], ['operation_id'=>$retry['operation_id']]);
    $queue->handle('operation',$retry['operation_id']); $queue->handle('operation',$retry['operation_id']);
    $assert((int)$wpdb->get_var($wpdb->prepare('SELECT COUNT(*) FROM '.$wpdb->prefix.'suhoput_notifications WHERE order_id=%d', $order->get_id())) === 1, 'Critical lag notice deduplicates');
} finally {
    $ownIds = $wpdb->get_col($wpdb->prepare('SELECT operation_id FROM '.$wpdb->prefix.'suhoput_operations WHERE order_id=%d', $order->get_id()));
    foreach ($ownIds as $ownId) { as_unschedule_all_actions('suhoput_job', ['operation',$ownId], 'suhoput-critical'); }
    foreach (['catalog','photos'] as $lane) { as_unschedule_all_actions('suhoput_periodic', [$tag.'-'.$lane], 'suhoput-'.$lane); delete_option('suhoput_periodic_'.hash('sha256',$tag.'-'.$lane)); }
    as_unschedule_all_actions('suhoput_periodic', [$tag.'-failure'], 'suhoput-catalog');
    as_unschedule_all_actions('suhoput_periodic_retry', [$tag.'-failure'], 'suhoput-catalog');
    as_unschedule_all_actions('suhoput_periodic', [$tag.'-persist'], 'suhoput-catalog');
    as_unschedule_all_actions('suhoput_periodic_retry', [$tag.'-persist'], 'suhoput-catalog');
    delete_option('suhoput_periodic_'.hash('sha256',$tag.'-persist'));
    delete_option('suhoput_periodic_'.hash('sha256',$tag.'-failure'));
    as_unschedule_all_actions($tag.'-other', [], 'fixture-'.$tag);
    as_unschedule_all_actions($tag.'-claim', null, 'fixture-'.$tag);
    foreach (['operations','notifications','inbox'] as $table) { $wpdb->delete($wpdb->prefix.'suhoput_'.$table, ['order_id'=>$order->get_id()]); }
    $order->delete(true);
}
echo "PASS: {$count} Action Scheduler/deadline/backoff/recovery checks\n";
