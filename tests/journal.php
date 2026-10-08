<?php
use Suhoput\Core\Infrastructure\Journal;
use Suhoput\Core\Domain\OperationResult;
if (wp_get_environment_type() !== 'local') { throw new RuntimeException('Local tests only.'); }
if (!class_exists(Journal::class)) { throw new RuntimeException('FAIL: durable operation journal not implemented'); }
global $wpdb;
$order = wc_create_order();
$id = wp_generate_uuid4();
$provider = 'fixture-' . wp_generate_uuid4();
$journal = new Journal();
$count=0;
$assert=static function(bool $ok,string $name) use (&$count): void { ++$count; if(!$ok){throw new RuntimeException('FAIL: '.$name);} };
$reject=static function(callable $call,string $name) use ($assert): void { try{$call();}catch(InvalidArgumentException|LogicException $e){$assert(true,$name);return;}$assert(false,$name); };
try {
    $command=['operation_id'=>$id,'order_id'=>$order->get_id(),'composition_version'=>1,'provider'=>$provider,'action'=>'reserve','idempotency_key'=>$id,'request'=>['quantity'=>1,'amount_minor'=>1300000]];
    $journal->intend($command);
    $copy=$command; $copy['request']=['amount_minor'=>1300000,'quantity'=>1];
    $journal->intend($copy);
    $assert($journal->get($id)['state']==='queued', 'Intention persisted before execution');
    $copy['request']['quantity']=2;
    $reject(fn()=>$journal->intend($copy),'Immutable request on repeat');
    $copy=$command; $copy['operation_id']=wp_generate_uuid4();
    $reject(fn()=>$journal->intend($copy),'Same provider key cannot become a new operation');
    $calls=0;
    $result=$journal->executeOnce($id, function(array $row) use (&$calls,$journal,$id,$assert){
        ++$calls;
        $assert($journal->get($id)['state']==='unknown', 'Unknown persisted before simulated POST');
        throw new RuntimeException('Simulated process stop/lost response');
    });
    $assert($result->status==='unknown' && $calls===1,'Lost response remains unknown');
    $journal=new Journal();
    $journal->executeOnce($id,function()use(&$calls){++$calls;return OperationResult::confirmed(['fixture'=>true]);});
    $assert($calls===1,'Restart cannot resend unknown operation');
    $journal->record($id,OperationResult::confirmed(['external_id'=>'synthetic']));
    $journal->record($id,OperationResult::refused('stale'));
    $assert($journal->get($id)['state']==='confirmed','Late event cannot erase confirmed result');
    $journal->receive($provider,'event-1',['status'=>'confirmed']);
    $journal->receive($provider,'event-1',['status'=>'confirmed']);
    $reject(fn()=>$journal->receive($provider,'event-1',['status'=>'canceled']),'Conflicting incoming event is visible');
    $assert((int)$wpdb->get_var($wpdb->prepare('SELECT COUNT(*) FROM '.$wpdb->prefix.'suhoput_inbox WHERE provider=%s',$provider))===1,'Incoming event persisted once');
    $notice=['order_id'=>$order->get_id(),'transition'=>'confirmed','version'=>1,'recipient'=>'fixture@example.invalid'];
    $journal->notify($notice,['subject'=>'Synthetic']);
    $journal->notify($notice,['subject'=>'Synthetic']);
    $assert((int)$wpdb->get_var($wpdb->prepare('SELECT COUNT(*) FROM '.$wpdb->prefix.'suhoput_notifications WHERE order_id=%d',$order->get_id()))===1,'Notification has independent deduplication');
} finally {
    foreach(['operations','notifications','holds'] as $table){$wpdb->delete($wpdb->prefix.'suhoput_'.$table,['order_id'=>$order->get_id()]);}
    $wpdb->delete($wpdb->prefix.'suhoput_inbox',['provider'=>$provider]);
    $order->delete(true);
}
echo "PASS: {$count} journal checks, lost response/restart/event/notification simulations\n";
