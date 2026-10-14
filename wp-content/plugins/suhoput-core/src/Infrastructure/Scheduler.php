<?php
declare(strict_types=1);
namespace Suhoput\Core\Infrastructure;

/** Action Scheduler is a recoverable execution index; journals remain the durable source. */
final class Scheduler
{
    private const JOBS = ['operation'=>['operations','operation_id',0], 'event'=>['inbox','id',1], 'notification'=>['notifications','notification_key',5]];
    private array $periodic = [];

    public function __construct(private readonly Worker $worker) {}

    public function register(): void
    {
        add_action('suhoput_job', [$this, 'handle'], 10, 2);
        add_action('suhoput_periodic', [$this, 'runPeriodic']);
        add_action('suhoput_periodic_retry', [$this, 'runPeriodic']);
        add_action('suhoput_operation_ready', fn(string $id)=>$this->enqueue('operation', $id));
        add_action('suhoput_event_ready', fn(int $id)=>$this->enqueue('event', $id));
    }

    public function periodic(string $name, string $lane, int $interval, callable $work): void
    {
        if (!in_array($lane, ['catalog','photos'], true) || $name === '' || $interval < 60) { throw new \InvalidArgumentException('Invalid periodic job.'); }
        if (isset($this->periodic[$name])) { throw new \LogicException('Periodic job already has an executor.'); }
        $this->periodic[$name] = [$lane, $interval, $work];
        if (!as_has_scheduled_action('suhoput_periodic', [$name], 'suhoput-'.$lane)) {
            if (!as_schedule_recurring_action(time(), $interval, 'suhoput_periodic', [$name], 'suhoput-'.$lane, true, $lane === 'catalog' ? 100 : 200)) { throw new \RuntimeException('Could not schedule periodic job.'); }
        }
    }

    public function enqueue(string $kind, int|string $id): void
    {
        if (!did_action('action_scheduler_init')) { return; } // Minute sweep repairs an early/lost signal.
        $row = $this->row($kind, $id);
        if (!$row || $this->complete($kind, $row)) { return; }
        $args = [$kind, $id];
        if (!as_has_scheduled_action('suhoput_job', $args, 'suhoput-critical')) {
            $due = max(time(), $this->timestamp($row['next_attempt_at']), $this->timestamp($row['available_at'] ?? null));
            if (!as_schedule_single_action($due, 'suhoput_job', $args, 'suhoput-critical', true, self::JOBS[$kind][2])) { throw new \RuntimeException('Could not schedule durable job.'); }
        }
    }

    public function sweep(): void
    {
        global $wpdb;
        $this->recoverStale();
        $page = max(1, (int)get_option('suhoput_outbox_page', 1));
        $more = OrderOutbox::recover($page);
        update_option('suhoput_outbox_page', $more ? $page+1 : 1, false);
        foreach (self::JOBS as $kind=>[$table,$key]) {
            $condition = match($kind) {
                'operation'=>"(state IN ('queued','unknown') OR (state IN ('confirmed','refused') AND applied_at IS NULL))",
                'event'=>"state <> 'processed'",
                'notification'=>"state IN ('queued','unknown')",
            };
            // Schedule due/nearest work first. Completed rows and far-future deadlines cannot starve due jobs.
            $due = $kind === 'operation' ? "GREATEST(COALESCE(next_attempt_at,'1970-01-01'),COALESCE(available_at,'1970-01-01'))" : "COALESCE(next_attempt_at,'1970-01-01')";
            $ids = $wpdb->get_col('SELECT '.$key.' FROM '.$wpdb->prefix.'suhoput_'.$table.' WHERE '.$condition.' ORDER BY '.$due.', id LIMIT 100');
            foreach ($ids as $id) { $this->enqueue($kind, $kind === 'event' ? (int)$id : $id); }
        }
        foreach ($this->periodic as $name=>[$lane]) {
            $state = get_option('suhoput_periodic_'.hash('sha256',$name));
            if ($state && $state['failures'] > 0 && !as_has_scheduled_action('suhoput_periodic_retry', [$name], 'suhoput-'.$lane)) {
                if (!as_schedule_single_action(max(time(),$state['next_at']), 'suhoput_periodic_retry', [$name], 'suhoput-'.$lane, true, $lane === 'catalog' ? 100 : 200)) { throw new \RuntimeException('Could not recover periodic retry.'); }
            }
        }
    }

    public function handle(string $kind, int|string $id): void
    {
        $row = $this->row($kind, $id);
        if (!$row || $this->complete($kind, $row)) { return; }
        OrderLock::run((int)$row['order_id'], function() use ($kind,$id): void {
            global $wpdb;
            $row = $this->row($kind, $id);
            if ($this->complete($kind, $row) || max($this->timestamp($row['next_attempt_at']), $this->timestamp($row['available_at'] ?? null)) > time()) { return; }
            $delay = 0;
            try {
                $done = match($kind) {
                    'operation'=>$this->worker->runOperation((string)$id),
                    'event'=>$this->worker->runEvent((int)$id),
                    'notification'=>$this->worker->runNotification((string)$id),
                };
            } catch (RetryLater $error) { $done = false; $delay = $error->seconds; }
            catch (\Throwable $error) { $done = false; } // No PII/secrets in AS logs.
            [$table,$key] = self::JOBS[$kind];
            $failures = $done ? 0 : (int)$row['retry_count']+1;
            $next = $done ? null : gmdate('Y-m-d H:i:s',time()+max($delay,$this->backoff($failures)));
            if ($wpdb->update($wpdb->prefix.'suhoput_'.$table, ['retry_count'=>$failures,'next_attempt_at'=>$next,'lease_until'=>null], [$key=>$id]) === false) { throw new \RuntimeException('Could not persist retry schedule.'); }
            if (!$done) { $this->problem($kind, (string)$id, $row, $failures); }
        });
    }

    public function runPeriodic(string $name): void
    {
        $job = $this->periodic[$name] ?? null;
        if (!$job) { throw new \RuntimeException('Periodic adapter is unavailable.'); }
        OrderLock::named($this->lock('periodic:'.$name), function() use ($name,$job): void {
            $key = 'suhoput_periodic_'.hash('sha256',$name);
            $state = get_option($key, ['failures'=>0, 'next_at'=>0]);
            // Pending retry also carries a durable lower bound if the options write was rejected.
            if (max($state['next_at'],$this->periodicRetryAt($name)) > time()) { return; }
            try {
                $job[2](); // Checkpointed/idempotent import; never a monetary effect.
                $this->savePeriodic($key, ['failures'=>0,'next_at'=>0,'last_success'=>time()]);
            } catch (\Throwable $error) {
                $failures = $state['failures']+1;
                $due = time()+max($this->backoff($failures), $error instanceof RetryLater ? $error->seconds : 0);
                if ($this->periodicRetryAt($name) < $due) {
                    // An in-progress retry must not suppress the next retry. The periodic lock serializes this check.
                    if (!as_schedule_single_action($due, 'suhoput_periodic_retry', [$name], 'suhoput-'.$job[0], false, $job[0] === 'catalog' ? 100 : 200)) { throw new \RuntimeException('Could not persist periodic retry.'); }
                }
                $this->savePeriodic($key, ['failures'=>$failures,'next_at'=>$due,'last_success'=>$state['last_success'] ?? null]);
                update_option('suhoput_queue_periodic_error', ['job_hash'=>hash('sha256',$name),'at'=>time()], false);
            }
        });
    }

    /** Called only by WP-CLI, under the system minute timer; priority is explicit between groups. */
    public function tick(): bool
    {
        if (!defined('WP_CLI') || !WP_CLI) { throw new \RuntimeException('System queue requires WP-CLI.'); }
        return OrderLock::named($this->lock('tick'), function(): bool {
            $start = time();
            update_option('suhoput_queue_started_at', $start, false);
            if (\ActionScheduler::store() instanceof \ActionScheduler_HybridStore) {
                // Fresh sites need AS's own supported migration; grouping the legacy store can fail.
                $runner = new \Action_Scheduler\Migration\Runner(\Action_Scheduler\Migration\Controller::instance()->get_migration_config_object());
                $runner->init_destination();
                if ($runner->run(100) === 0) { (new \Action_Scheduler\Migration\Scheduler())->mark_complete(); }
                update_option('suhoput_queue_bootstrap_at', time(), false);
                return false; // Reopen WP on the next system tick to select the completed DB store.
            }
            $this->sweep();
            foreach (['critical','catalog','photos'] as $lane) {
                // Finish critical work before starting a lower lane, and recheck after catalogue.
                if ($lane !== 'critical' && $this->due('critical')) { break; }
                if (!$this->due($lane)) { continue; }
                if (time()-$start >= 45) { break; }
                $this->runBatch($lane === 'critical' ? 20 : 5, 'suhoput-'.$lane);
            }
            if (!$this->due('critical') && time()-$start < 45) {
                // The system runner also owns WooCommerce/AS housekeeping when async is disabled.
                $this->runBatch(10, '', true);
            }
            update_option('suhoput_queue_completed_at', time(), false);
            update_option('suhoput_queue_tick_count', (int)get_option('suhoput_queue_tick_count',0)+1, false);
            return true;
        }) ?? false;
    }

    private function recoverStale(): void
    {
        foreach (['suhoput_job','suhoput_periodic','suhoput_periodic_retry'] as $hook) {
            $ids = as_get_scheduled_actions(['hook'=>$hook,'status'=>'in-progress','modified'=>time()-300,'modified_compare'=>'<=','per_page'=>100], 'ids');
            foreach ($ids as $actionId) {
                $action = \ActionScheduler::store()->fetch_action($actionId);
                if ($hook !== 'suhoput_job') {
                    [$name] = $action->get_args();
                    OrderLock::named($this->lock('periodic:'.$name), function() use ($name,$actionId): void {
                        $key = 'suhoput_periodic_'.hash('sha256',$name);
                        $state = get_option($key, ['failures'=>0,'next_at'=>0]);
                        $failures = $state['failures']+1;
                        $this->savePeriodic($key, ['failures'=>$failures,'next_at'=>max($state['next_at'],time()+$this->backoff($failures)),'last_success'=>$state['last_success'] ?? null]);
                        \ActionScheduler::store()->mark_failure($actionId);
                    });
                    continue;
                }
                [$kind,$id] = $action->get_args();
                $row = $this->row($kind,$id);
                if (!$row) { \ActionScheduler::store()->mark_failure($actionId); continue; }
                // A slow live worker keeps its connection lock even after its lease expires.
                OrderLock::run((int)$row['order_id'], static function() use ($actionId): void { \ActionScheduler::store()->mark_failure($actionId); });
            }
        }
    }

    private function runBatch(int $size, string $group, bool $upstream = false): void
    {
        global $wpdb;
        $store = \ActionScheduler::store();
        $previous = [];
        foreach (['group','hooks','exclude-groups'] as $filter) { $previous[$filter] = $store->get_claim_filter($filter); }
        $store->set_claim_filter('group', $group);
        $store->set_claim_filter('hooks', []);
        if ($upstream) {
            $excluded = array_merge(array_filter((array)$previous['exclude-groups'], static fn($value)=>$value !== ''), ['suhoput-critical','suhoput-catalog','suhoput-photos']);
            // AS 4.1.0 throws if every excluded slug is absent on a fresh DB store.
            $existing = $wpdb->get_col($wpdb->prepare('SELECT slug FROM '.$wpdb->actionscheduler_groups.' WHERE slug IN ('.implode(',',array_fill(0,count($excluded),'%s')).')', ...$excluded));
            $store->set_claim_filter('exclude-groups', $existing);
        }
        $runner = new \ActionScheduler_WPCLI_QueueRunner($store, null, new QueueCleaner($store));
        try { $runner->setup($size, [], $group); $runner->run('Suhoput system minute'); }
        finally {
            foreach ($previous as $filter=>$value) { $store->set_claim_filter($filter, $value); }
            remove_action('action_scheduler_before_execute', [$runner,'before_execute']);
            remove_action('action_scheduler_after_execute', [$runner,'after_execute']);
            remove_action('action_scheduler_failed_execution', [$runner,'action_failed']);
        }
    }

    private function due(string $lane): bool
    {
        return as_get_scheduled_actions(['group'=>'suhoput-'.$lane,'status'=>'pending','date'=>time(),'date_compare'=>'<=','per_page'=>1], 'ids') !== [];
    }

    private function row(string $kind, int|string $id): ?array
    {
        global $wpdb;
        if (!isset(self::JOBS[$kind])) { throw new \InvalidArgumentException('Unknown job kind.'); }
        [$table,$key] = self::JOBS[$kind];
        return $wpdb->get_row($wpdb->prepare('SELECT * FROM '.$wpdb->prefix.'suhoput_'.$table.' WHERE '.$key.'=%s',$id), ARRAY_A);
    }

    private function complete(string $kind, array $row): bool
    {
        return match($kind) {
            'operation'=>in_array($row['state'], ['confirmed','refused'], true) && $row['applied_at'] !== null,
            'event'=>$row['state'] === 'processed',
            'notification'=>in_array($row['state'], ['confirmed','refused'], true),
        };
    }

    private function problem(string $kind, string $id, array $row, int $failures): void
    {
        $created = $row['created_at'] ?? $row['received_at'];
        $critical = $failures >= 8 || time()-$this->timestamp($created) >= 600;
        update_option('suhoput_queue_error', ['kind'=>$kind,'id_hash'=>hash('sha256',$id),'order_id'=>(int)$row['order_id'],'failures'=>$failures,'critical'=>$critical,'at'=>time()], false);
        if ($critical && $kind !== 'notification' && (int)$row['order_id'] > 0) {
            (new Journal())->notify(['order_id'=>(int)$row['order_id'],'transition'=>'queue_delayed','kind'=>$kind,'operation_id'=>$id,'recipient'=>'manager'], ['type'=>'queue_delayed','kind'=>$kind]);
        }
    }

    private function timestamp(?string $date): int { return $date === null ? 0 : (int)strtotime($date.' UTC'); }
    private function periodicRetryAt(string $name): int
    {
        $actions = as_get_scheduled_actions(['hook'=>'suhoput_periodic_retry','args'=>[$name],'status'=>'pending','orderby'=>'date','order'=>'DESC','per_page'=>1]);
        return $actions ? reset($actions)->get_schedule()->get_date()->getTimestamp() : 0;
    }
    private function savePeriodic(string $key, array $state): void
    {
        if (!update_option($key, $state, false) && get_option($key) !== $state) { throw new \RuntimeException('Could not persist periodic retry state.'); }
    }
    private function backoff(int $failures): int { return min(3600, 60*(2**min(6,max(0,$failures-1)))); }
    private function lock(string $name): string { global $wpdb; return 'suhoput_queue_'.substr(hash('sha256',$wpdb->prefix.':'.$name),0,32); }
}
