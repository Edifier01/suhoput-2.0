<?php
declare(strict_types=1);
namespace Suhoput\Core\Infrastructure;

/** AS 4.1.0's timeout-only cleanup must not bypass our connection-scoped ownership. */
final class QueueCleaner extends \ActionScheduler_QueueCleaner
{
    public function __construct(private readonly \ActionScheduler_Store $store) { parent::__construct($store); }

    public function mark_failures($time_limit = 300)
    {
        $timeout = apply_filters('action_scheduler_failure_period', $time_limit);
        if ($timeout < 0) { return; }
        $ids = $this->store->query_actions([
            'status'=>\ActionScheduler_Store::STATUS_RUNNING,
            'modified'=>as_get_datetime_object($timeout.' seconds ago'),
            'modified_compare'=>'<=', 'per_page'=>$this->get_batch_size(), 'orderby'=>'none',
        ]);
        foreach ($ids as $id) {
            if (in_array($this->store->fetch_action($id)->get_hook(), ['suhoput_job','suhoput_periodic','suhoput_periodic_retry'], true)) { continue; }
            $this->store->mark_failure($id);
            do_action('action_scheduler_failed_action', $id, $timeout);
        }
    }
}
