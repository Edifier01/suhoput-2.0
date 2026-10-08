<?php
use Suhoput\Core\Infrastructure\{Journal, OrderOutbox, Worker};
use Suhoput\Core\Domain\OperationResult;
if (wp_get_environment_type() !== 'local') { throw new RuntimeException('Local tests only.'); }
[$tag, $boundary, $mode] = $args;
if (!preg_match('/\A[a-f0-9-]{36}\z/', $tag)) { throw new RuntimeException('Invalid fixture.'); }
global $wpdb;
$option = 'suhoput_crash_'.$tag;
$fixture = get_option($option);
if ($mode === 'cleanup') {
    if ($fixture) {
        foreach (['operations','notifications','inbox'] as $table) { $wpdb->delete($wpdb->prefix.'suhoput_'.$table, ['order_id'=>$fixture['order_id']]); }
        wc_get_order($fixture['order_id'])?->delete(true); delete_option($option);
    }
    return;
}
$assert = static function(bool $ok, string $message): void { if (!$ok) { throw new RuntimeException('FAIL: '.$message); } };
$journal = new Journal();
if ($mode === 'stop') {
    $order = wc_create_order();
    $fixture = ['order_id'=>$order->get_id(), 'posts'=>0, 'mail'=>0];
    update_option($option, $fixture, false);
    $command = ['operation_id'=>$tag, 'order_id'=>$order->get_id(), 'composition_version'=>1, 'provider'=>$tag, 'action'=>'reserve', 'idempotency_key'=>$tag, 'request'=>['quantity'=>2]];
    if ($boundary === 'order_saved') {
        add_filter('query', static function(string $sql) use ($wpdb): string {
            if (str_starts_with($sql, 'INSERT INTO `'.$wpdb->prefix.'suhoput_operations`')) { exit(73); }
            return $sql;
        });
    }
    OrderOutbox::save($order, $command);
    if ($boundary === 'intention') { exit(73); }
}
$worker = new Worker();
$worker->operation($tag, 'reserve', function() use ($mode, $boundary, $option) {
    if ($mode === 'stop' && $boundary === 'before_request') { exit(73); }
    $current = get_option($option); ++$current['posts']; update_option($option, $current, false);
    if ($mode === 'stop' && $boundary === 'after_request') { exit(73); }
    return OperationResult::confirmed(['external_id'=>'synthetic-'.$current['order_id']]);
}, function() use ($option) {
    $current = get_option($option);
    return $current['posts'] > 0 ? OperationResult::confirmed(['external_id'=>'synthetic-'.$current['order_id']]) : OperationResult::unknown();
}, function(array $row) use ($mode, $boundary, $journal) {
    if ($mode === 'stop' && $boundary === 'result') { exit(73); }
    $saved = wc_get_order((int)$row['order_id']); $saved->update_meta_data('_fixture_reserved', true); $saved->save();
    $journal->notify(['order_id'=>(int)$row['order_id'], 'transition'=>'reserved'], ['subject'=>'Synthetic']);
    if ($mode === 'stop' && $boundary === 'projection') { exit(73); }
});
$isEvent = str_starts_with($boundary, 'event_');
$isMail = str_starts_with($boundary, 'mail_');
if ($isEvent) {
    $worker->event($tag, function() use ($mode, $boundary) {
        if ($mode === 'stop' && $boundary === 'event_verified') { exit(73); }
        return ['state'=>'packing'];
    }, function(array $row, array $facts) use ($mode, $boundary, $journal) {
        $saved = wc_get_order((int)$row['order_id']); $saved->update_meta_data('_fixture_event', $facts['state']); $saved->save();
        $journal->notify(['order_id'=>(int)$row['order_id'], 'transition'=>'packing'], ['subject'=>'Synthetic event']);
        if ($mode === 'stop' && $boundary === 'event_projection') { exit(73); }
    });
    $event = $worker->receive($tag, 'event', ['source_id'=>'synthetic'], (int)$fixture['order_id']);
    if ($mode === 'stop' && $boundary === 'event_saved') { exit(73); }
    $worker->runEvent($event);
} elseif ($isMail) {
    $journal->notify(['order_id'=>(int)$fixture['order_id'], 'transition'=>'mail'], ['subject'=>'Synthetic mail']);
    $key = $wpdb->get_var($wpdb->prepare('SELECT notification_key FROM '.$wpdb->prefix.'suhoput_notifications WHERE order_id=%d', $fixture['order_id']));
    $worker->notifications(function() use ($option, $mode, $boundary) {
        if ($mode === 'stop' && $boundary === 'mail_before_request') { exit(73); }
        $current = get_option($option); ++$current['mail']; update_option($option, $current, false);
        if ($mode === 'stop') { exit(73); }
        return OperationResult::confirmed(['message_id'=>'synthetic']);
    }, function() use ($option) { return get_option($option)['mail'] > 0 ? OperationResult::confirmed(['message_id'=>'synthetic']) : OperationResult::unknown(); });
    $worker->runNotification($key); $worker->runNotification($key);
    if ($mode === 'resume') {
        $assert(get_option($option)['mail'] === ($boundary === 'mail_before_request' ? 0 : 1), 'Mail is not sent twice');
        echo "PASS: {$boundary}\n"; return;
    }
} else {
    OrderOutbox::recover(); $worker->runOperation($tag); $worker->runOperation($tag);
}
if ($mode === 'resume') {
    $current = get_option($option);
    if ($isEvent) {
        $assert(wc_get_order($fixture['order_id'])->get_meta('_fixture_event') === 'packing', 'Event recovers after abrupt stop');
    } elseif ($boundary === 'before_request') {
        $assert($current['posts'] === 0 && $journal->get($tag)['state'] === 'unknown', 'Uncertain unsent request remains unknown until proven');
    } else {
        $assert($current['posts'] === 1 && $journal->get($tag)['applied_at'] !== null, 'One external effect, completed local projection');
    }
    $notices = (int)$wpdb->get_var($wpdb->prepare('SELECT COUNT(*) FROM '.$wpdb->prefix.'suhoput_notifications WHERE order_id=%d', $fixture['order_id']));
    $assert($notices === ($boundary === 'before_request' ? 0 : 1), 'Notification not duplicated after process death');
    echo "PASS: {$boundary}\n";
}
