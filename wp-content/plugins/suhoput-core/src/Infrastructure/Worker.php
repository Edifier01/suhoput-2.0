<?php
declare(strict_types=1);
namespace Suhoput\Core\Infrastructure;

use Suhoput\Core\Domain\OperationResult;

/** Provider adapters register explicit send/read paths. No transport is enabled by default. */
final class Worker
{
    private array $operations = [];
    private array $events = [];
    private ?array $mail = null;

    public function operation(string $provider, string $action, callable $send, callable $reconcile, callable $apply): void
    {
        $key = $provider . ':' . $action;
        if (isset($this->operations[$key])) { throw new \LogicException('Operation already has an executor.'); }
        $this->operations[$key] = [$send, $reconcile, $apply];
    }

    public function event(string $provider, callable $verify, callable $apply): void
    {
        if (isset($this->events[$provider])) { throw new \LogicException('Event already has an executor.'); }
        $this->events[$provider] = [$verify, $apply];
    }

    public function notifications(callable $send, callable $reconcile): void
    {
        if ($this->mail !== null) { throw new \LogicException('Notifications already have an executor.'); }
        $this->mail = [$send, $reconcile];
    }

    public function receive(string $provider, string $eventId, array $body, int $orderId): int
    {
        $id = (new Journal())->receive($provider, $eventId, $body, $orderId);
        // Queue loss is harmless: the persisted inbox is rediscovered by the minute sweep.
        do_action('suhoput_event_ready', $id);
        return $id;
    }

    public function runOperation(string $id): bool
    {
        $journal = new Journal();
        $row = $journal->get($id);
        return OrderLock::run((int)$row['order_id'], function() use ($journal, $id): bool {
            $row = $journal->get($id);
            $handlers = $this->operations[$row['provider'].':'.$row['action']] ?? null;
            if (!$handlers) { throw new \RuntimeException('Operation adapter is unavailable.'); }
            $row['request'] = json_decode($row['request_body'], true, 512, JSON_THROW_ON_ERROR);
            if (!hash_equals($row['request_hash'], hash('sha256', Journal::canonical($row['request'])))) { throw new \LogicException('Corrupt persisted request.'); }
            if ($row['state'] === 'queued') {
                $result = $journal->executeOnce($id, static fn()=>$handlers[0]($row));
            } elseif ($row['state'] === 'unknown') {
                // This is a read. Never convert an uncertain effect into a new POST, even after 24h.
                $this->attempt('operations', 'operation_id', $id);
                $result = $handlers[1]($row);
                if (!$result instanceof OperationResult) { throw new \LogicException('Reconciliation must be explicit.'); }
                $journal->record($id, $result);
            } else {
                $proof = json_decode($row['result_body'] ?? '[]', true, 512, JSON_THROW_ON_ERROR);
                $result = $row['state'] === 'confirmed' ? OperationResult::confirmed($proof) : OperationResult::refused($proof['reason'] ?? 'refused');
            }
            if ($result->status === 'unknown') { return false; }
            if ($journal->get($id)['applied_at'] === null) {
                // Projection may repeat after a crash: CRUD state is monotone, notices use Journal::notify.
                // This callback must not perform external effects; those require another intention.
                $handlers[2]($row, $result);
                $this->update('operations', 'operation_id', $id, ['applied_at'=>gmdate('Y-m-d H:i:s'), 'lease_until'=>null, 'next_attempt_at'=>null]);
            }
            return true;
        }) ?? false;
    }

    public function runEvent(int $id): bool
    {
        $row = $this->get('inbox', 'id', $id);
        if (!$row['order_id']) { throw new \RuntimeException('Event order must be resolved by its adapter.'); }
        return OrderLock::run((int)$row['order_id'], function() use ($id): bool {
            $row = $this->get('inbox', 'id', $id);
            if ($row['state'] === 'processed') { return true; }
            $handlers = $this->events[$row['provider']] ?? null;
            if (!$handlers) { throw new \RuntimeException('Event adapter is unavailable.'); }
            $row['payload'] = json_decode($row['body'], true, 512, JSON_THROW_ON_ERROR);
            $this->attempt('inbox', 'id', $id);
            $facts = $handlers[0]($row); // Current external object and its linkage, not webhook assertions.
            if ($facts === null) { return false; }
            if (!is_array($facts) || $facts === []) { throw new \LogicException('Verified event needs current facts.'); }
            $handlers[1]($row, $facts); // Idempotent local projection, same restriction as operations.
            $this->update('inbox', 'id', $id, ['state'=>'processed', 'processed_at'=>gmdate('Y-m-d H:i:s'), 'lease_until'=>null, 'next_attempt_at'=>null]);
            return true;
        }) ?? false;
    }

    public function runNotification(string $key): bool
    {
        $row = $this->get('notifications', 'notification_key', $key);
        return OrderLock::run((int)$row['order_id'], function() use ($key): bool {
            $row = $this->get('notifications', 'notification_key', $key);
            if (in_array($row['state'], ['confirmed','refused'], true)) { return true; }
            if (!$this->mail) { throw new \RuntimeException('Notification adapter is unavailable.'); }
            $row['payload'] = json_decode($row['payload'], true, 512, JSON_THROW_ON_ERROR);
            $this->attempt('notifications', 'notification_key', $key);
            $this->update('notifications', 'notification_key', $key, ['state'=>'unknown']);
            try { $result = ($row['state'] === 'queued' ? $this->mail[0] : $this->mail[1])($row); }
            catch (\Throwable $error) { return false; }
            if (!$result instanceof OperationResult) { throw new \LogicException('Delivery result must be explicit.'); }
            $this->update('notifications', 'notification_key', $key, ['state'=>$result->status, 'result_body'=>Journal::canonical($result->evidence), 'lease_until'=>null]);
            return $result->status !== 'unknown';
        }) ?? false;
    }

    private function get(string $table, string $key, int|string $id): array
    {
        global $wpdb;
        $row = $wpdb->get_row($wpdb->prepare('SELECT * FROM '.$wpdb->prefix.'suhoput_'.$table.' WHERE '.$key.'=%s', $id), ARRAY_A);
        if (!$row) { throw new \InvalidArgumentException('Durable job is missing.'); }
        return $row;
    }

    private function attempt(string $table, string $key, int|string $id): void
    {
        global $wpdb;
        if ($wpdb->query($wpdb->prepare('UPDATE '.$wpdb->prefix.'suhoput_'.$table.' SET attempts=attempts+1, lease_until=%s WHERE '.$key.'=%s', gmdate('Y-m-d H:i:s', time()+300), $id)) !== 1) {
            throw new \RuntimeException('Could not persist job attempt.');
        }
    }

    private function update(string $table, string $key, int|string $id, array $data): void
    {
        global $wpdb;
        if ($wpdb->update($wpdb->prefix.'suhoput_'.$table, $data, [$key=>$id]) === false) { throw new \RuntimeException('Could not persist job progress.'); }
    }
}
