<?php
declare(strict_types=1);
namespace Suhoput\Core\Commerce;

/** Abuse quotas only. This is not an inventory/reservation coordinator. */
final class GuestLimits
{
    public const COOKIE='suhoput_guest';
    public const DEFAULTS=['actor_rate'=>10,'ip_rate'=>120,'window'=>60,'actor_holds'=>2,'ip_holds'=>20];

    public static function settings(): array
    {
        return self::validate(get_option('suhoput_guest_limits',self::DEFAULTS));
    }

    public static function validate(mixed $input): array
    {
        if (!is_array($input)) { throw new \InvalidArgumentException('Invalid guest policy.'); }
        $result=[];
        foreach (self::DEFAULTS as $key=>$default) {
            $value=$input[$key] ?? $default;
            if (filter_var($value,FILTER_VALIDATE_INT) === false || (int)$value < 1 || (int)$value > ($key === 'window' ? 3600 : 10000)) {
                throw new \InvalidArgumentException('Invalid guest policy.');
            }
            $result[$key]=(int)$value;
        }
        if ($result['ip_rate'] < $result['actor_rate'] || $result['ip_holds'] < $result['actor_holds']) { throw new \InvalidArgumentException('Shared IP limit must cover a browser limit.'); }
        return $result;
    }

    public static function prepareCookie(): void
    {
        if (self::actor() !== null || (defined('WP_CLI') && WP_CLI)) { return; }
        $random=bin2hex(random_bytes(32));
        $value=$random.'.'.hash_hmac('sha256',$random,wp_salt('auth'));
        setcookie(self::COOKIE,$value,['expires'=>time()+7*DAY_IN_SECONDS,'path'=>'/','secure'=>is_ssl(),'httponly'=>true,'samesite'=>'Lax']);
        $_COOKIE[self::COOKIE]=$value;
    }

    public static function actor(): ?string
    {
        $value=$_COOKIE[self::COOKIE] ?? '';
        if (!is_string($value) || !preg_match('/\A([a-f0-9]{64})\.([a-f0-9]{64})\z/',$value,$m) || !hash_equals(hash_hmac('sha256',$m[1],wp_salt('auth')),$m[2])) { return null; }
        return hash_hmac('sha256','actor:'.$m[1],wp_salt('auth'));
    }

    public static function ip(): ?string
    {
        // Forwarded headers supplied by the caller never define a quota identity.
        // Deployment must configure trusted proxy REMOTE_ADDR before PHP (TASK-046).
        $ip=$_SERVER['REMOTE_ADDR'] ?? '';
        if (!is_string($ip) || filter_var($ip,FILTER_VALIDATE_IP) === false) { return null; }
        return hash_hmac('sha256','ip:'.inet_pton($ip),wp_salt('auth'));
    }

    public static function currentAttempt(): bool
    {
        return self::actor() !== null && self::ip() !== null && self::attempt(self::actor(),self::ip());
    }

    /** Both counters are durable and serialized across PHP workers, regardless of cache. */
    public static function attempt(string $actor,string $ip): bool
    {
        return self::locked(static function() use($actor,$ip): bool {
            self::hashes($actor,$ip); $settings=self::settings(); global $wpdb;
            $table=$wpdb->prefix.'suhoput_guest_rates'; $now=time();
            foreach ([$actor=>$settings['actor_rate'],$ip=>$settings['ip_rate']] as $key=>$limit) {
                $row=$wpdb->get_row($wpdb->prepare("SELECT * FROM {$table} WHERE bucket_key=%s",$key),ARRAY_A); self::sql();
                if ($row && (!isset($row['window_start'],$row['attempts']))) { throw new \RuntimeException('Invalid quota row.'); }
                $count=$row && (int)$row['window_start'] > $now-$settings['window'] ? (int)$row['attempts'] : 0;
                if ($count >= $limit) { return false; }
            }
            foreach ([$actor,$ip] as $key) {
                $changed=$wpdb->query($wpdb->prepare("INSERT INTO {$table} (bucket_key,window_start,attempts) VALUES (%s,%d,1) ON DUPLICATE KEY UPDATE attempts=IF(window_start<=%d,1,attempts+1),window_start=IF(window_start<=%d,%d,window_start)",$key,$now,$now-$settings['window'],$now-$settings['window'],$now));
                if ($changed === false) { throw new \RuntimeException('Rate persistence failed.'); } self::sql();
            }
            // Bounded cleanup: never expires slots whose external/payment outcome may be unknown.
            if ($wpdb->query($wpdb->prepare("DELETE FROM {$table} WHERE window_start<%d LIMIT 100",$now-3600)) === false) { throw new \RuntimeException('Rate cleanup failed.'); }
            return true;
        });
    }

    /** Called before a guest reservation intention; retries use the same server UUID. */
    public static function admit(string $intent,string $actor,string $ip): bool
    {
        return self::locked(static function() use($intent,$actor,$ip): bool {
            self::hashes($actor,$ip);
            if (!wp_is_uuid($intent)) { return false; }
            global $wpdb; $table=$wpdb->prefix.'suhoput_guest_slots'; $settings=self::settings();
            self::reconcilePaid($actor,$ip);
            $row=$wpdb->get_row($wpdb->prepare("SELECT * FROM {$table} WHERE intent_id=%s",$intent),ARRAY_A); self::sql();
            if ($row) { return $row['state'] === 'active' && hash_equals($row['actor_hash'],$actor) && hash_equals($row['ip_hash'],$ip); }
            foreach (['actor_hash'=>[$actor,$settings['actor_holds']],'ip_hash'=>[$ip,$settings['ip_holds']]] as $column=>[$value,$limit]) {
                $count=(int)$wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$table} WHERE {$column}=%s AND state='active'",$value)); self::sql();
                if ($count >= $limit) { return false; }
            }
            if ($wpdb->insert($table,['intent_id'=>$intent,'actor_hash'=>$actor,'ip_hash'=>$ip,'created_at'=>time()]) !== 1) { throw new \RuntimeException('Quota persistence failed.'); }
            return true;
        });
    }

    /** Trusted server adapter only: paid or confirmed released, never a client cancellation/TTL. */
    public static function settle(string $intent,string $state): bool
    {
        return self::locked(static function() use($intent,$state): bool {
            if (!wp_is_uuid($intent) || !in_array($state,['paid','released'],true)) { return false; }
            global $wpdb;
            $changed=$wpdb->query($wpdb->prepare('UPDATE '.$wpdb->prefix."suhoput_guest_slots SET state=%s WHERE intent_id=%s AND state='active'",$state,$intent));
            self::sql(); return $changed === 1;
        });
    }

    private static function hashes(string ...$keys): void
    {
        foreach ($keys as $key) { if (!preg_match('/\A[a-f0-9]{64}\z/',$key)) { throw new \InvalidArgumentException('Invalid quota key.'); } }
        if ($keys[0] === $keys[1]) { throw new \InvalidArgumentException('Independent quota keys required.'); }
    }

    /** A failed payment_complete projection is recovered from the durable WC fact
     * before counting quotas. Unknown/unpaid intentions are deliberately retained. */
    private static function reconcilePaid(string $actor,string $ip): void
    {
        global $wpdb; $table=$wpdb->prefix.'suhoput_guest_slots';
        $intents=$wpdb->get_col($wpdb->prepare("SELECT intent_id FROM {$table} WHERE state='active' AND (actor_hash=%s OR ip_hash=%s)",$actor,$ip)); self::sql();
        foreach ($intents as $intent) {
            $ids=wc_get_orders(['type'=>'shop_order','limit'=>2,'return'=>'ids','status'=>array_keys(wc_get_order_statuses()),
                'meta_query'=>[['key'=>'_suhoput_guest_intent','value'=>$intent,'compare'=>'=']],
                'meta_key'=>'_suhoput_guest_intent','meta_value'=>$intent]); self::sql();
            if (count($ids) !== 1) { continue; }
            $order=new \WC_Order((int)$ids[0]);
            if ($order->get_meta('_suhoput_guest_intent') !== $intent || !$order->get_date_paid()) { continue; }
            if ($wpdb->query($wpdb->prepare("UPDATE {$table} SET state='paid' WHERE intent_id=%s AND state='active'",$intent)) === false) { throw new \RuntimeException('Paid quota projection failed.'); }
        }
    }

    private static function sql(): void { global $wpdb; if ($wpdb->last_error !== '') { throw new \RuntimeException('Quota storage unavailable.'); } }

    private static function locked(callable $callback): bool
    {
        global $wpdb; $name='suhoput_guest_'.substr(hash('sha256',DB_NAME.'|'.$wpdb->prefix),0,24);
        $retries=$wpdb->reconnect_retries; $wpdb->reconnect_retries=0;
        $guard=null;
        try {
            if ((int)$wpdb->get_var($wpdb->prepare('SELECT GET_LOCK(%s,5)',$name)) !== 1) { return false; }
            $connection=(int)$wpdb->get_var('SELECT CONNECTION_ID()');
            $guard=static function(string $sql) use($connection,$name,$wpdb): string {
                // Check the native connection directly to avoid recursively invoking this filter.
                if ($wpdb->last_error !== '' || !($wpdb->dbh instanceof \mysqli)) { throw new \RuntimeException('Quota connection unavailable.'); }
                $check=mysqli_query($wpdb->dbh,"SELECT CONNECTION_ID(), IS_USED_LOCK('".mysqli_real_escape_string($wpdb->dbh,$name)."')");
                $row=$check ? mysqli_fetch_row($check) : null;
                if (!$row || (int)$row[0] !== $connection || (int)$row[1] !== $connection) { throw new \RuntimeException('Quota lock lost.'); }
                return $sql;
            };
            add_filter('query',$guard,PHP_INT_MAX);
            return (bool)$callback();
        } catch (\Throwable $error) { return false; }
        finally {
            if ($guard !== null) { remove_filter('query',$guard,PHP_INT_MAX); }
            $wpdb->get_var($wpdb->prepare('SELECT RELEASE_LOCK(%s)',$name)); $wpdb->reconnect_retries=$retries;
        }
    }
}
