<?php
declare(strict_types=1);
namespace Suhoput\Core\Infrastructure;

/** Connection-scoped locks survive lease expiry and release on process death. */
final class OrderLock
{
    public static function run(int $orderId, callable $work): mixed
    {
        global $wpdb;
        $key = 'suhoput_order_' . substr(hash('sha256', $wpdb->prefix.':'.$orderId), 0, 32);
        return self::named($key, $work);
    }

    public static function named(string $key, callable $work): mixed
    {
        global $wpdb;
        if ((int)$wpdb->get_var($wpdb->prepare('SELECT GET_LOCK(%s, 0)', $key)) !== 1) { return null; }
        try { return $work(); }
        finally { $wpdb->get_var($wpdb->prepare('SELECT RELEASE_LOCK(%s)', $key)); }
    }
}
