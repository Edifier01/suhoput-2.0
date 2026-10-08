<?php
use Suhoput\Core\Infrastructure\{Journal, OrderOutbox, Worker};
use Suhoput\Core\Domain\OperationResult;
if (wp_get_environment_type() !== 'local') { throw new RuntimeException('Local tests only.'); }
if (!class_exists(OrderOutbox::class) || !class_exists(Worker::class)) { throw new RuntimeException('FAIL: saved order recovery and workers are missing'); }
global $wpdb;
$journal = new Journal();
$order = wc_create_order();
$provider = 'fixture-' . wp_generate_uuid4();
$id = wp_generate_uuid4();
$checks = 0;
$assert = static function(bool $ok, string $name) use (&$checks): void { ++$checks; if (!$ok) { throw new RuntimeException('FAIL: '.$name); } };
$command = ['operation_id'=>$id, 'order_id'=>$order->get_id(), 'composition_version'=>1, 'provider'=>$provider, 'action'=>'reserve', 'idempotency_key'=>$id, 'request'=>['order_uuid'=>$id, 'quantity'=>2, 'reserve_expires_at'=>time()+3600]];
$notice = ['order_id'=>$order->get_id(), 'version'=>1, 'transition'=>'reserved', 'recipient'=>'fixture@example.invalid'];
try {
    // A saved order survives a stop before journal insertion and before scheduling.
    $order->update_meta_data(OrderOutbox::META, [$id=>$command]);
    $order->save();
    $wpdb->delete($wpdb->prefix.'suhoput_operations', ['operation_id'=>$id]);
    OrderOutbox::recover();
    $assert($journal->get($id)['state'] === 'queued', 'Saved HPOS order recovers a missing intention');
    OrderOutbox::recover();
    $assert((int)$wpdb->get_var($wpdb->prepare('SELECT COUNT(*) FROM '.$wpdb->prefix.'suhoput_operations WHERE operation_id=%s', $id)) === 1, 'Repeated recovery retains one operation');
    $changed = $command; $changed['request']['quantity'] = 3;
    try { OrderOutbox::save($order, $changed); $assert(false, 'Cannot rewrite a saved command'); } catch (LogicException $e) { $assert(true, 'Saved command is immutable'); }
    $assert(wc_get_order($order->get_id())->get_meta(OrderOutbox::META)[$id]['request']['quantity'] === 2, 'Conflicting repeat leaves saved snapshot intact');
    $calls = 0; $reads = 0; $projections = 0;
    $worker = new Worker();
    $worker->operation($provider, 'reserve', function(array $row) use (&$calls, $journal, $id, $assert) {
        $assert($journal->get($id)['state'] === 'unknown' && $row['request']['quantity'] === 2, 'Persisted exact request precedes POST');
        ++$calls; throw new RuntimeException('Lost response after synthetic effect');
    }, function(array $row) use (&$reads) { ++$reads; return OperationResult::confirmed(['external_id'=>'fixture-document']); },
    function(array $row, OperationResult $result) use (&$projections, $journal, $notice) {
        ++$projections;
        $journal->notify($notice, ['subject'=>'Reserved']);
        if ($projections === 1) { throw new RuntimeException('Stop after notification persisted, before projection completion'); }
        $saved = wc_get_order((int)$row['order_id']); $saved->update_meta_data('_fixture_external', $result->evidence['external_id']); $saved->save();
    });
    $worker->runOperation($id);
    $assert($journal->get($id)['state'] === 'unknown' && $calls === 1, 'Lost response is durable unknown');
    try { $worker->runOperation($id); } catch (RuntimeException $e) { /* interrupted projection */ }
    $assert($journal->get($id)['state'] === 'confirmed' && $reads === 1 && $calls === 1, 'Restart reconciles before any repeat');
    $worker->runOperation($id); $worker->runOperation($id);
    $assert($projections === 2 && $calls === 1 && $reads === 1, 'Confirmed effect is projected once after recovery');
    $assert(wc_get_order($order->get_id())->get_meta('_fixture_external') === 'fixture-document', 'Confirmed external link reaches saved order');
    $assert((int)$wpdb->get_var($wpdb->prepare('SELECT COUNT(*) FROM '.$wpdb->prefix.'suhoput_notifications WHERE order_id=%d', $order->get_id())) === 1, 'Projection restart does not duplicate notification');
    $event = $worker->receive($provider, 'decision-1', ['source_id'=>'fixture-document'], $order->get_id());
    $assert($wpdb->get_var($wpdb->prepare('SELECT state FROM '.$wpdb->prefix.'suhoput_inbox WHERE id=%d', $event)) === 'queued', 'Return/ACK only follows durable inbox insertion');
    $assert($worker->receive($provider, 'decision-1', ['source_id'=>'fixture-document'], $order->get_id()) === $event, 'Duplicate event retains inbox identity');
    $verified = false; $applied = 0;
    $worker->event($provider, function(array $row) use (&$verified) { return $verified ? ['external_id'=>'fixture-document', 'state'=>'packing'] : null; },
    function(array $row, array $facts) use (&$applied) { ++$applied; $saved = wc_get_order((int)$row['order_id']); $saved->update_meta_data('_fixture_fulfillment', $facts['state']); $saved->save(); });
    $worker->runEvent($event);
    $assert($applied === 0, 'Unverified event cannot mutate an order');
    $verified = true; $worker->runEvent($event); $worker->runEvent($event);
    $assert($applied === 1 && wc_get_order($order->get_id())->get_meta('_fixture_fulfillment') === 'packing', 'Freshly verified event is applied and duplicate skipped');
    // A transport with an unknowable result is never called again, even after 24 hours.
    $late = $command; $late['operation_id'] = wp_generate_uuid4(); $late['idempotency_key'] = $late['operation_id'];
    $journal->intend($late); $journal->executeOnce($late['operation_id'], fn()=>OperationResult::unknown());
    $wpdb->update($wpdb->prefix.'suhoput_operations', ['created_at'=>'2026-01-01 00:00:00'], ['operation_id'=>$late['operation_id']]);
    $unknown = new Worker(); $unknown->operation($provider, 'reserve', function() use (&$calls) { ++$calls; return OperationResult::confirmed(['wrong'=>true]); }, fn()=>OperationResult::unknown(), fn()=>null);
    $unknown->runOperation($late['operation_id']);
    $assert($calls === 1 && $journal->get($late['operation_id'])['state'] === 'unknown', 'Expired unknown reconciles without POST');
    // Mail is a separately journaled external effect; uncertain delivery is reconciled.
    $mail = 0;
    $worker->notifications(function(array $row) use (&$mail) { ++$mail; throw new RuntimeException('Lost delivery result'); }, fn()=>OperationResult::unknown());
    $key = $wpdb->get_var($wpdb->prepare('SELECT notification_key FROM '.$wpdb->prefix.'suhoput_notifications WHERE order_id=%d', $order->get_id()));
    $worker->runNotification($key); $worker->runNotification($key);
    $assert($mail === 1 && $wpdb->get_var($wpdb->prepare('SELECT state FROM '.$wpdb->prefix.'suhoput_notifications WHERE notification_key=%s', $key)) === 'unknown', 'Unknown delivery does not resend mail');
    $failInsert = static function(string $sql) use ($wpdb): string {
        return str_starts_with($sql, 'INSERT INTO `'.$wpdb->prefix.'suhoput_inbox`') ? 'INSERT INTO deliberately_missing_suhoput_fixture VALUES (1)' : $sql;
    };
    $old = $wpdb->suppress_errors(true); add_filter('query', $failInsert);
    try {
        try { $worker->receive($provider, 'cannot-ack', ['source_id'=>'fixture-document'], $order->get_id()); $assert(false, 'Failed storage cannot ACK'); }
        catch (RuntimeException $e) { $assert(true, 'Failed storage cannot ACK'); }
    } finally { remove_filter('query', $failInsert); $wpdb->suppress_errors($old); }
    $assert((int)$wpdb->get_var($wpdb->prepare('SELECT COUNT(*) FROM '.$wpdb->prefix.'suhoput_inbox WHERE provider=%s', $provider)) === 1, 'Failed receive leaves no accepted event');
} finally {
    foreach (['operations','notifications','holds'] as $table) { $wpdb->delete($wpdb->prefix.'suhoput_'.$table, ['order_id'=>$order->get_id()]); }
    $wpdb->delete($wpdb->prefix.'suhoput_inbox', ['provider'=>$provider]); $order->delete(true);
}
echo "PASS: {$checks} worker/recovery checks (external effects simulated)\n";
