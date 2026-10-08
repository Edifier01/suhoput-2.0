<?php
declare(strict_types=1);
namespace Suhoput\Core\Infrastructure;

/** Durable source for rebuilding the journal. Only server-side checkout calls save(). */
final class OrderOutbox
{
    public const META = '_suhoput_commands';

    public static function save(\WC_Order $order, array $command): void
    {
        Journal::validateCommand($command);
        if ($order->get_id() !== $command['order_id']) { throw new \InvalidArgumentException('Command belongs to another order.'); }
        $saved = OrderLock::run($order->get_id(), static function() use ($order, $command): bool {
            $fresh = wc_get_order($order->get_id());
            if (!$fresh) { throw new \RuntimeException('Saved order is missing.'); }
            $commands = $fresh->get_meta(self::META) ?: [];
            $id = $command['operation_id'];
            if (isset($commands[$id]) && Journal::canonical($commands[$id]) !== Journal::canonical($command)) {
                throw new \LogicException('Saved order command is immutable.');
            }
            $commands[$id] = $command;
            $fresh->update_meta_data(self::META, $commands);
            $fresh->save(); // A stop here leaves a recoverable command before journal insertion.
            self::synchronize($fresh);
            return true;
        });
        if ($saved !== true) { throw new \RuntimeException('Order is busy.'); }
    }

    public static function synchronize(\WC_Order $order): void
    {
        $journal = new Journal();
        foreach (($order->get_meta(self::META) ?: []) as $command) {
            if ($command['order_id'] !== $order->get_id()) { throw new \LogicException('Invalid saved command order.'); }
            $journal->intend($command);
            do_action('suhoput_operation_ready', $command['operation_id']);
        }
    }

    /** Bounded cyclic scan; HPOS and legacy storage are queried only through CRUD. */
    public static function recover(int $page = 1, int $limit = 50): bool
    {
        $orders = wc_get_orders(['limit'=>$limit, 'page'=>$page, 'orderby'=>'ID', 'order'=>'ASC', 'type'=>'shop_order',
            'meta_query'=>[['key'=>self::META, 'compare'=>'EXISTS']]]);
        foreach ($orders as $order) { self::synchronize($order); }
        return count($orders) === $limit;
    }
}
