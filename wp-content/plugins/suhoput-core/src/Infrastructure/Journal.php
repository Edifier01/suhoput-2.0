<?php
declare(strict_types=1);
namespace Suhoput\Core\Infrastructure;

use Suhoput\Core\Domain\OperationResult;

/** Persistence only. Provider adapters separately enforce access/write policy. */
final class Journal
{
    public function intend(array $command): void
    {
        global $wpdb;
        foreach (['operation_id','provider','action'] as $key) {
            if (!is_string($command[$key] ?? null) || $command[$key] === '' || strlen($command[$key]) > ($key === 'operation_id' ? 36 : 64)) {
                throw new \InvalidArgumentException('Invalid command identifier.');
            }
        }
        foreach (['order_id','composition_version'] as $key) {
            if (!is_int($command[$key] ?? null) || $command[$key] < 1) { throw new \InvalidArgumentException('Invalid command version/order.'); }
        }
        $key = $command['idempotency_key'] ?? null;
        if ($key !== null && (!is_string($key) || $key === '' || strlen($key) > 64)) { throw new \InvalidArgumentException('Invalid operation key.'); }
        $body = self::canonical($command['request'] ?? null);
        $row = [
            'operation_id'=>$command['operation_id'], 'order_id'=>$command['order_id'],
            'composition_version'=>$command['composition_version'], 'provider'=>$command['provider'],
            'action'=>$command['action'], 'idempotency_key'=>$key, 'request_body'=>$body,
            'request_hash'=>hash('sha256',$body), 'created_at'=>gmdate('Y-m-d H:i:s'), 'updated_at'=>gmdate('Y-m-d H:i:s'),
        ];
        $old = $wpdb->suppress_errors(true);
        try { $inserted = $wpdb->insert($this->table('operations'), $row); }
        finally { $wpdb->suppress_errors($old); }
        if ($inserted === 1) { return; }
        $existing = $this->get($command['operation_id'], false);
        if (!$existing) {
            if ($key !== null && $wpdb->get_var($wpdb->prepare('SELECT operation_id FROM '.$this->table('operations').' WHERE provider=%s AND idempotency_key=%s',$command['provider'],$key))) {
                throw new \LogicException('Operation key already belongs to another intention.');
            }
            throw new \RuntimeException('Could not persist operation intention.');
        }
        foreach (['order_id','composition_version','provider','action','idempotency_key','request_hash'] as $field) {
            if (($existing[$field] === null ? null : (string)$existing[$field]) !== ($row[$field] === null ? null : (string)$row[$field])) {
                throw new \LogicException('An operation intention is immutable.');
            }
        }
    }

    public function get(string $id, bool $required = true): ?array
    {
        global $wpdb;
        $row = $wpdb->get_row($wpdb->prepare('SELECT * FROM '.$this->table('operations').' WHERE operation_id=%s', $id), ARRAY_A);
        if (!$row && $required) { throw new \InvalidArgumentException('Unknown operation.'); }
        return $row;
    }

    /** Unknown means reconcile, even after restart. This primitive never blindly retries. */
    public function executeOnce(string $id, callable $effect): OperationResult
    {
        global $wpdb;
        $row = $this->get($id);
        $lock = 'suhoput_order_' . substr(hash('sha256',$wpdb->prefix.':'.$row['order_id']),0,32);
        if ((int)$wpdb->get_var($wpdb->prepare('SELECT GET_LOCK(%s, 5)',$lock)) !== 1) { return OperationResult::unknown(); }
        try {
            $row = $this->get($id);
            if ($row['state'] !== 'queued') { return $this->result($row); }
            // Written before invoking the effect: a crash at any later boundary is unknown.
            $changed = $wpdb->query($wpdb->prepare('UPDATE '.$this->table('operations')." SET state='unknown', attempts=attempts+1, lease_until=%s, updated_at=%s WHERE operation_id=%s AND state='queued'",gmdate('Y-m-d H:i:s',time()+300),gmdate('Y-m-d H:i:s'),$id));
            if ($changed !== 1) { return OperationResult::unknown(); }
            try {
                $result = $effect($this->get($id));
                if (!$result instanceof OperationResult) { throw new \LogicException('Provider result must be explicit.'); }
            } catch (\Throwable $error) {
                // Do not log request, exception content, headers or secrets.
                return OperationResult::unknown();
            }
            $this->record($id,$result);
            return $this->result($this->get($id));
        } finally { $wpdb->get_var($wpdb->prepare('SELECT RELEASE_LOCK(%s)',$lock)); }
    }

    public function record(string $id, OperationResult $result): void
    {
        global $wpdb;
        $row = $this->get($id);
        if ($row['state'] === 'confirmed') { return; }
        $body = self::canonical($result->evidence);
        $old = $wpdb->suppress_errors(true);
        try {
            $ok = $wpdb->query($wpdb->prepare('UPDATE '.$this->table('operations')." SET state=%s, result_body=%s, lease_until=NULL, updated_at=%s WHERE operation_id=%s AND state <> 'confirmed'",$result->status,$body,gmdate('Y-m-d H:i:s'),$id));
        } finally { $wpdb->suppress_errors($old); }
        if ($ok === false) { throw new \RuntimeException('Could not persist operation result.'); }
    }

    public function receive(string $provider, string $eventId, array $body): void
    {
        $this->uniquePayload('inbox', ['provider'=>$provider,'event_key'=>hash('sha256',$eventId)],
            ['body'=>self::canonical($body),'body_hash'=>hash('sha256',self::canonical($body)),'received_at'=>gmdate('Y-m-d H:i:s')], 'body');
    }

    public function notify(array $identity, array $payload): void
    {
        if (!is_int($identity['order_id'] ?? null) || $identity['order_id'] < 1) { throw new \InvalidArgumentException('Invalid notification order.'); }
        $this->uniquePayload('notifications',['notification_key'=>hash('sha256',self::canonical($identity))],
            ['order_id'=>$identity['order_id'],'payload'=>self::canonical($payload),'created_at'=>gmdate('Y-m-d H:i:s')], 'payload');
    }

    private function uniquePayload(string $table, array $identity, array $data, string $bodyField): void
    {
        global $wpdb;
        $old = $wpdb->suppress_errors(true);
        try { $inserted = $wpdb->insert($this->table($table),$identity+$data); }
        finally { $wpdb->suppress_errors($old); }
        if ($inserted === 1) { return; }
        $where=[];
        foreach($identity as $key=>$value){$where[]=$wpdb->prepare($key.'=%s',$value);}
        $existing = $wpdb->get_row('SELECT * FROM '.$this->table($table).' WHERE '.implode(' AND ',$where),ARRAY_A);
        if (!$existing) { throw new \RuntimeException('Could not persist durable event.'); }
        if ($existing[$bodyField] !== $data[$bodyField]) { throw new \LogicException('Conflicting payload for a durable event.'); }
    }

    private function result(array $row): OperationResult
    {
        $proof = json_decode($row['result_body'] ?? '[]',true,512,JSON_THROW_ON_ERROR);
        return match($row['state']) {
            'confirmed'=>OperationResult::confirmed($proof),
            'refused'=>OperationResult::refused($proof['reason'] ?? 'refused'),
            default=>OperationResult::unknown(),
        };
    }

    private function table(string $name): string { global $wpdb; return $wpdb->prefix.'suhoput_'.$name; }

    public static function canonical(mixed $value): string
    {
        $normalize = static function(mixed $node) use (&$normalize): mixed {
            if (is_float($node) || is_object($node) || is_resource($node)) { throw new \InvalidArgumentException('Noncanonical request value.'); }
            if (!is_array($node)) { return $node; }
            if (!array_is_list($node)) { ksort($node,SORT_STRING); }
            foreach ($node as $key=>$item) {
                if (is_string($key) && preg_match('/\A(authorization|password|token|api_key|client_secret)\z/i',$key)) { throw new \InvalidArgumentException('Secrets do not belong in the journal.'); }
                $node[$key]=$normalize($item);
            }
            return $node;
        };
        return json_encode($normalize($value),JSON_THROW_ON_ERROR|JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
    }
}
