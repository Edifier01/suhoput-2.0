<?php
declare(strict_types=1);
namespace Suhoput\Core\Orders;

use Suhoput\Core\Infrastructure\Accounts;
use Suhoput\Core\Infrastructure\OrderLock;

/** Customer access is independent of price rights and external counterparty links. */
final class Access
{
    public const COOKIE = 'suhoput_order_browser';
    public const PROOF_TTL = 1800;
    public const GRANT_TTL = 3600;
    private static ?array $claim = null;

    public static function boot(): void
    {
        add_filter('woocommerce_my_account_my_orders_query',[self::class,'historyQuery'],PHP_INT_MAX);
        add_filter('user_has_cap',static function(array $caps,array $required,array $args): array {
            if (in_array($args[0] ?? '',['view_order','pay_for_order','cancel_order','order_again'],true) && isset($args[2])) {
                $caps[$args[0]]=self::canView(wc_get_order((int)$args[2]),(int)$args[1]);
            }
            return $caps;
        },PHP_INT_MAX,3);
        add_action('woocommerce_checkout_create_order',static function(\WC_Order $order): void {
            $order->update_meta_data('_suhoput_origin','site');
            $order->set_customer_id(get_current_user_id());
        },PHP_INT_MAX);
        add_action('woocommerce_checkout_order_created',[self::class,'checkoutGrant']);
        add_action('woocommerce_before_order_object_save',[self::class,'guardBinding'],PHP_INT_MAX);
        add_filter('rest_pre_dispatch',[self::class,'guardRest'],PHP_INT_MAX,3);
        add_filter('woocommerce_shortcode_order_tracking_order_id',static fn($id) => self::canView(wc_get_order((int)$id),get_current_user_id()) ? $id : 0,PHP_INT_MAX);
        add_action('rest_api_init',[self::class,'routes']);
        add_filter('rest_post_dispatch',static function($response,$server,$request) {
            if (preg_match('#^/(suhoput/v1/orders|wc/(store(?:/v\d+)?/(order|checkout)|v\d+/orders))#i',$request->get_route())) {
                $response->header('Cache-Control','private, no-store, max-age=0');
                $response->header('Vary','Cookie, Authorization');
            }
            return $response;
        },PHP_INT_MAX,3);
    }

    public static function historyQuery(array $query): array
    {
        // Never trust a caller's customer/email/status/meta selectors.
        return [
            'type'=>'shop_order','customer_id'=>get_current_user_id() ?: -1,
            'status'=>array_keys(wc_get_order_statuses()),
            'meta_query'=>[['key'=>'_suhoput_origin','value'=>'site','compare'=>'=']],
            'meta_key'=>'_suhoput_origin','meta_value'=>'site',
            'limit'=>isset($query['limit']) ? (int)$query['limit'] : 10,
            'page'=>max(1,(int)($query['page'] ?? 1)),
            'paginate'=>(bool)($query['paginate'] ?? false),
            'return'=>$query['return'] ?? 'objects','orderby'=>'date','order'=>'DESC',
        ];
    }

    public static function isSite(mixed $order): bool
    {
        return $order instanceof \WC_Order && $order->get_type() === 'shop_order' && $order->get_meta('_suhoput_origin') === 'site';
    }

    private static function load(int $id): mixed
    {
        if ($id <= 0) { return false; }
        try { return new \WC_Order($id); } catch (\Exception $e) { return false; }
    }

    public static function canView(mixed $order,int $userId): bool
    {
        if (!self::isSite($order)) { return false; }
        if ($order->get_customer_id() > 0) { return $userId > 0 && $order->get_customer_id() === $userId; }
        // A guest grant stays bound to the requesting browser, not to its email/account.
        global $wpdb;
        $browser=self::browserHash();
        if ($browser === null) { return false; }
        $row=$wpdb->get_row($wpdb->prepare('SELECT browser_hash,email_hash,state,purpose,grant_expires_at FROM '.self::table().' WHERE order_id=%d',$order->get_id()),ARRAY_A);
        return $row && $row['state'] === 'used' && $row['purpose'] === 'view' && (int)$row['grant_expires_at'] > time()
            && hash_equals($row['browser_hash'],$browser) && hash_equals($row['email_hash'],self::emailHash($order));
    }

    public static function browserHash(): ?string
    {
        $value=$_COOKIE[self::COOKIE] ?? null;
        return is_string($value) && preg_match('/\A[a-f0-9]{64}\z/',$value) ? hash('sha256',$value) : null;
    }

    private static function emailHash(\WC_Order $order): string
    {
        return hash('sha256',Accounts::normalize($order->get_billing_email()) ?? '');
    }

    private static function table(): string { global $wpdb; return $wpdb->prefix.'suhoput_order_access'; }

    public static function requestProof(int $orderId,string $email,string $purpose,int $userId): bool
    {
        if (!in_array($purpose,['view','claim'],true) || ($purpose === 'claim' && ($userId <= 0 || get_current_user_id() !== $userId)) || self::browserHash() === null) { return false; }
        return (bool)OrderLock::run($orderId,static function() use($orderId,$email,$purpose,$userId): bool {
            global $wpdb;
            $order=self::load($orderId);
            if (!self::isSite($order) || $order->get_customer_id() !== 0 || Accounts::normalize($email) === null || Accounts::normalize($email) !== Accounts::normalize($order->get_billing_email())) { return false; }
            $last=$wpdb->get_var($wpdb->prepare('SELECT requested_at FROM '.self::table().' WHERE order_id=%d',$orderId));
            if ($wpdb->last_error !== '' || ($last !== null && (int)$last > time()-60)) { return false; }
            $token=bin2hex(random_bytes(32));
            $row=['order_id'=>$orderId,'token_hash'=>hash('sha256',$token),'browser_hash'=>self::browserHash(),'email_hash'=>self::emailHash($order),'purpose'=>$purpose,'user_id'=>$purpose === 'claim' ? $userId : 0,'state'=>'issued','requested_at'=>time(),'expires_at'=>time()+self::PROOF_TTL,'grant_expires_at'=>0];
            if ($wpdb->replace(self::table(),$row) === false) { return false; }
            $url=add_query_arg(['suhoput_proof_order'=>$orderId,'suhoput_token'=>$token,'suhoput_purpose'=>$purpose],wc_get_page_permalink('myaccount'));
            return wp_mail($order->get_billing_email(),'Подтверждение доступа к заказу Suhoput',"Откройте ссылку в том же браузере и подтвердите действие. Ссылка действует 30 минут и используется один раз.\n".$url);
        });
    }

    public static function consume(int $orderId,string $token,string $purpose,int $userId): bool
    {
        if (!preg_match('/\A[a-f0-9]{64}\z/',$token) || !in_array($purpose,['view','claim'],true) || self::browserHash() === null || ($purpose === 'claim' && ($userId <= 0 || get_current_user_id() !== $userId))) { return false; }
        return (bool)OrderLock::run($orderId,static function() use($orderId,$token,$purpose,$userId): bool {
            global $wpdb;
            $order=self::load($orderId);
            if (!self::isSite($order) || $order->get_customer_id() !== 0) { return false; }
            $connection=(int)$wpdb->get_var('SELECT CONNECTION_ID()');
            // Atomic one-use transition precedes any grant or CRUD ownership effect.
            $changed=$wpdb->query($wpdb->prepare('UPDATE '.self::table()." SET state='used',grant_expires_at=%d WHERE order_id=%d AND state='issued' AND token_hash=%s AND browser_hash=%s AND email_hash=%s AND purpose=%s AND user_id=%d AND expires_at>%d",
                $purpose === 'view' ? time()+self::GRANT_TTL : 0,$orderId,hash('sha256',$token),self::browserHash(),self::emailHash($order),$purpose,$purpose === 'claim' ? $userId : 0,time()));
            if ($changed !== 1) { return false; }
            if ($purpose === 'claim') {
                self::$claim=[$orderId,$userId,$connection];
                try { $order->set_customer_id($userId); $order->save(); }
                catch (\Throwable $e) { return false; }
                finally { self::$claim=null; }
                return (new \WC_Order($orderId))->get_customer_id() === $userId;
            }
            return self::canView(new \WC_Order($orderId),$userId);
        });
    }

    public static function guardBinding(\WC_Order $order): void
    {
        if (!$order->get_id() || !array_key_exists('customer_id',$order->get_changes()) || $order->get_customer_id() <= 0) { return; }
        $previous=new \WC_Order($order->get_id());
        if (!$previous || $previous->get_customer_id() !== 0) { return; }
        global $wpdb;
        $lock='suhoput_order_'.substr(hash('sha256',$wpdb->prefix.':'.$order->get_id()),0,32);
        if (self::$claim === null || self::$claim[0] !== $order->get_id() || self::$claim[1] !== $order->get_customer_id()
            || (int)$wpdb->get_var($wpdb->prepare('SELECT IS_USED_LOCK(%s)',$lock)) !== self::$claim[2]) {
            throw new \WC_Data_Exception('suhoput_ownership','Привязка гостевого заказа требует подтверждения владения.');
        }
    }

    /** The originating checkout session itself proves ownership of its new guest order. */
    public static function checkoutGrant(\WC_Order $order): void
    {
        if (!self::isSite($order) || $order->get_customer_id() !== 0 || self::browserHash() === null) { return; }
        global $wpdb;
        $wpdb->insert(self::table(),['order_id'=>$order->get_id(),'token_hash'=>hash('sha256',random_bytes(32)),'browser_hash'=>self::browserHash(),'email_hash'=>self::emailHash($order),'purpose'=>'view','user_id'=>0,'state'=>'used','requested_at'=>time(),'expires_at'=>time(),'grant_expires_at'=>time()+self::GRANT_TTL]);
    }

    public static function guardRest(mixed $result,\WP_REST_Server $server,\WP_REST_Request $request): mixed
    {
        $route=$request->get_route();
        if (preg_match('#^/wc/store(?:/v\d+)?/(?:order|checkout)/(\d+)(?:/|$)#i',$route,$match)) {
            // WP JSON/body/query parameters precede URL parameters in native handlers.
            $shadow=$request->get_param('id');
            if ($shadow !== null && ((!is_string($shadow) && !is_int($shadow)) || (string)$shadow !== $match[1])) { return self::denied(); }
            if (!self::canView(wc_get_order((int)$match[1]),get_current_user_id())) { return self::denied(); }
        }
        // Management API is for explicitly authorized staff; customer API is below.
        if (preg_match('#^/wc/v\d+/orders(?:/|$)#i',$route) && !current_user_can('manage_woocommerce')) { return self::denied(); }
        return $result;
    }

    private static function denied(): \WP_Error { return new \WP_Error('suhoput_order_access','Заказ недоступен.',['status'=>404]); }

    public static function routes(): void
    {
        register_rest_route('suhoput/v1','/orders',[
            'methods'=>'GET','permission_callback'=>static fn() => get_current_user_id() > 0 ? true : self::denied(),
            'callback'=>static function(\WP_REST_Request $request) {
                $query=self::historyQuery(['page'=>max(1,(int)$request->get_param('page')),'limit'=>10,'paginate'=>true]);
                $found=wc_get_orders($query);
                return rest_ensure_response(['orders'=>array_map([self::class,'summary'],$found->orders),'pages'=>$found->max_num_pages]);
            },
        ]);
        register_rest_route('suhoput/v1','/orders/(?P<id>\d+)',[
            'methods'=>'GET','permission_callback'=>static fn(\WP_REST_Request $request) => self::canView(wc_get_order((int)$request['id']),get_current_user_id()) ? true : self::denied(),
            'callback'=>static fn(\WP_REST_Request $request) => rest_ensure_response(self::summary(wc_get_order((int)$request['id']))),
        ]);
    }

    public static function summary(\WC_Order $order): array
    {
        // Deliberate allowlist: no external links, internal metadata, notes or codes.
        return ['id'=>$order->get_id(),'number'=>$order->get_order_number(),'status'=>$order->get_status(),'total'=>$order->get_total(),'currency'=>$order->get_currency(),'created_at'=>$order->get_date_created()?->date(DATE_ATOM)];
    }
}
