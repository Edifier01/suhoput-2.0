<?php
declare(strict_types=1);
namespace Suhoput\Core\Commerce;

use Suhoput\Core\Domain\Money;

final class Context
{
    private static ?\WeakMap $prices=null;
    private static bool $apiAttempt=false;
    public const REVIEW='Права или сессия изменились. Проверьте состав, цены и итог корзины и подтвердите их перед оформлением.';
    public const WHOLESALE_CHECKOUT='Отправка оптовой заявки пока недоступна. Онлайн-оплата оптовых заказов не предусмотрена.';

    public static function boot(): void
    {
        add_action('init',[GuestLimits::class,'prepareCookie'],1);
        add_action('woocommerce_cart_loaded_from_session',[self::class,'reconcile'],PHP_INT_MAX);
        add_action('woocommerce_before_calculate_totals',[self::class,'reconcile'],PHP_INT_MAX);
        foreach (['woocommerce_product_get_price','woocommerce_product_variation_get_price'] as $hook) {
            add_filter($hook,static fn($value,$product) => self::$prices !== null && isset(self::$prices[$product]) ? self::$prices[$product] : $value,PHP_INT_MAX,2);
        }
        add_filter('woocommerce_get_variation_prices_hash',static function(array $hash): array { $hash['suhoput_context']=self::current() ?? 'disabled'; return $hash; },PHP_INT_MAX);
        add_filter('woocommerce_coupons_enabled','__return_false',PHP_INT_MAX);
        add_filter('woocommerce_coupon_is_valid','__return_false',PHP_INT_MAX);
        add_action('woocommerce_cart_calculate_fees',static function($cart): void {
            $fees=array_filter($cart->get_fees(),static fn($fee) => (float)$fee->amount >= 0);
            $cart->fees_api()->set_fees($fees);
        },PHP_INT_MAX);
        add_filter('woocommerce_calculated_total',static fn($total,$cart) => round(
            (float)$cart->get_cart_contents_total()+(float)$cart->get_shipping_total()+(float)$cart->get_fee_total()+(float)$cart->get_total_tax(),
            wc_get_price_decimals()),PHP_INT_MAX,2);
        add_filter('woocommerce_add_to_cart_validation',static function($valid): bool {
            if (!$valid || self::current() === null) { wc_add_notice('Покупка недоступна.','error'); return false; }
            if (!get_current_user_id() && !self::$apiAttempt && !GuestLimits::currentAttempt()) { wc_add_notice('Слишком много действий. Повторите позже.','error'); return false; }
            return true;
        },PHP_INT_MAX);
        add_action('woocommerce_checkout_process',static function(): void {
            WC()->cart->calculate_totals();
            if (self::current() === null || self::needsReview()) { wc_add_notice(self::REVIEW,'error'); }
            // TASK-025/029 supply the separate wholesale request workflow. Native
            // checkout must neither invoke a gateway nor complete a free order.
            if (self::current() === 'wholesale') { wc_add_notice(self::WHOLESALE_CHECKOUT,'error'); }
            if (!get_current_user_id() && !GuestLimits::currentAttempt()) { wc_add_notice('Слишком много действий. Повторите позже.','error'); }
        },PHP_INT_MAX);
        add_action('woocommerce_checkout_create_order',[self::class,'createOrder'],PHP_INT_MAX,2);
        add_action('woocommerce_before_order_object_save',[self::class,'guardOrder'],PHP_INT_MAX);
        add_action('woocommerce_payment_complete',static function($id): void {
            $order=new \WC_Order((int)$id);
            if ($order->get_date_paid()) { GuestLimits::settle((string)$order->get_meta('_suhoput_guest_intent'),'paid'); }
        });
        add_action('woocommerce_before_pay_action',static function($order): void { if (!self::canPay($order)) { throw new \Exception('Онлайн-оплата этого заказа недоступна.'); } },PHP_INT_MAX);
        add_filter('woocommerce_my_account_my_orders_actions',static function(array $actions,$order): array {
            if (!self::canPay($order)) { unset($actions['pay']); } return $actions;
        },PHP_INT_MAX,2);
        add_filter('user_has_cap',static function(array $caps,array $required,array $args): array {
            if (($args[0] ?? '') === 'pay_for_order' && isset($args[2]) && !self::canPay(wc_get_order((int)$args[2]))) { $caps['pay_for_order']=false; }
            return $caps;
        },PHP_INT_MAX,3);
        add_action('wp_loaded',[self::class,'earlyPayGuard'],16);
        add_action('template_redirect',[self::class,'pageGuard'],1);
        add_action('woocommerce_before_cart',[self::class,'reviewForm']);
        add_action('woocommerce_before_checkout_form',[self::class,'reviewForm']);
        add_filter('rest_pre_dispatch',[self::class,'guardRest'],PHP_INT_MAX,3);
        add_action('rest_api_init',[self::class,'routes']);
        add_filter('rest_post_dispatch',static function($response,$server,$request) {
            if (preg_match('#^/(wc/store(?:/|$)|suhoput/v1/(commerce|wholesale)(?:/|$))#i',$request->get_route())) {
                $response->header('Cache-Control','private, no-store, max-age=0');
                $response->header('Vary','Cookie, Authorization, Cart-Token');
            }
            return $response;
        },PHP_INT_MAX,3);
    }

    /** No browser input, role, email or counterparty locator grants a buyer context. */
    public static function current(): ?string
    {
        $id=get_current_user_id(); if (!$id) { return 'retail'; }
        global $wpdb;
        $row=$wpdb->get_row($wpdb->prepare('SELECT buyer_type,access_enabled,counterparty_id FROM '.$wpdb->prefix.'suhoput_accounts WHERE user_id=%d',$id),ARRAY_A);
        if ($wpdb->last_error !== '' || !$row) { return null; }
        if ($row['buyer_type'] === 'retail') { return 'retail'; }
        return $row['buyer_type'] === 'wholesale' && (int)$row['access_enabled'] === 1 && !empty($row['counterparty_id']) ? 'wholesale' : null;
    }

    private static function signature(): string
    {
        return hash('sha256',wp_json_encode([get_current_user_id(),self::current(),wp_get_session_token(),WC()->session?->get_customer_id(),GuestLimits::actor()]));
    }

    /** Canonical imported price contract: public regular retail, separate wholesale decimal. */
    public static function price(\WC_Product $product,string $context): ?string
    {
        $value=$context === 'wholesale' ? $product->get_meta('_suhoput_wholesale_price',true,'edit') : $product->get_regular_price('edit');
        try { $money=Money::fromDecimal((string)$value); return $money->minor > 0 ? $money->decimal() : null; }
        catch (\Throwable $error) { return null; }
    }

    public static function reconcile(\WC_Cart $cart): void
    {
        if (!WC()->session) { return; }
        $context=self::current(); $signature=self::signature();
        $old=WC()->session->get('suhoput_cart_identity');
        if ($old !== null && $old !== $signature && !$cart->is_empty()) { WC()->session->set('suhoput_cart_review',true); }
        WC()->session->set('suhoput_cart_identity',$signature);
        $cart->set_applied_coupons([]);
        if ($context === null) { $cart->empty_cart(); return; }
        self::$prices ??=new \WeakMap();
        $lines=[];
        foreach ($cart->get_cart() as $key=>$item) {
            $product=wc_get_product((int)($item['variation_id'] ?: $item['product_id']));
            $price=$product ? self::price($product,$context) : null;
            if ($price === null) { $cart->remove_cart_item($key); WC()->session->set('suhoput_cart_review',true); continue; }
            $product=clone $product; $product->set_price($price); self::$prices[$product]=$price;
            $cart->cart_contents[$key]['data']=$product;
            $cart->cart_contents[$key]['suhoput_context']=$context;
            $lines[]=[$key,(int)$item['quantity'],$price];
        }
        if (self::needsReview()) {
            $fingerprint=hash('sha256',wp_json_encode([$signature,$lines]));
            if (WC()->session->get('suhoput_review_fingerprint') !== $fingerprint) {
                WC()->session->set('suhoput_review_fingerprint',$fingerprint);
                WC()->session->set('suhoput_review_token',bin2hex(random_bytes(32)));
            }
        }
    }

    public static function needsReview(): bool { return (bool)WC()->session?->get('suhoput_cart_review',false); }
    public static function reviewToken(): string { return (string)WC()->session?->get('suhoput_review_token',''); }

    public static function confirm(string $token): bool
    {
        if (!WC()->cart || self::current() === null) { return false; }
        WC()->cart->calculate_totals(); $expected=self::reviewToken();
        if (!$expected || !hash_equals($expected,$token) || !self::needsReview()) { return false; }
        WC()->session->set('suhoput_cart_review',false); WC()->session->set('suhoput_review_token','');
        WC()->session->set('suhoput_review_fingerprint',''); return true;
    }

    public static function createOrder(\WC_Order $order,array $data=[]): void
    {
        WC()->cart?->calculate_totals(); $context=self::current();
        if ($context === null || self::needsReview()) { throw new \Exception(self::REVIEW); }
        if ($order->get_customer_id() !== get_current_user_id()) { throw new \Exception('Владелец заказа не соответствует сессии.'); }
        $order->update_meta_data('_suhoput_context',$context);
        if ($order->get_items('coupon') || (float)$order->get_discount_total() !== 0.0) { throw new \Exception('Скидки недоступны.'); }
        foreach ($order->get_items('fee') as $fee) { if ((float)$fee->get_total() < 0) { throw new \Exception('Скидки недоступны.'); } }
        foreach ($order->get_items('line_item') as $item) {
            $product=wc_get_product($item->get_variation_id() ?: $item->get_product_id());
            $price=$product ? self::price($product,$context) : null;
            $expected=$price !== null ? wc_get_price_excluding_tax($product,['qty'=>$item->get_quantity(),'price'=>$price]) : null;
            if ($expected === null || wc_format_decimal($item->get_subtotal(),wc_get_price_decimals()) !== wc_format_decimal($expected,wc_get_price_decimals())
                || (float)$item->get_total() !== (float)$item->get_subtotal()) { throw new \Exception('Цена недоступна или содержит скидку.'); }
        }
        if (WC()->cart && wc_format_decimal($order->get_total(),wc_get_price_decimals()) !== wc_format_decimal(WC()->cart->get_total('edit'),wc_get_price_decimals())) { throw new \Exception('Итог не соответствует корзине.'); }
        if (!$order->get_customer_id()) {
            // New intention for each order; checkout retries of a saved order retain its UUID.
            $intent=(string)$order->get_meta('_suhoput_guest_intent') ?: wp_generate_uuid4();
            if (GuestLimits::actor() === null || GuestLimits::ip() === null || !GuestLimits::admit($intent,GuestLimits::actor(),GuestLimits::ip())) { throw new \Exception('Достигнут лимит неоплаченных заказов. Дождитесь подтверждения оплаты или освобождения удержания.'); }
            $order->update_meta_data('_suhoput_guest_intent',$intent);
        }
    }

    public static function guardOrder(\WC_Order $order): void
    {
        if (!$order->get_id()) { return; }
        $saved=new \WC_Order($order->get_id()); $context=$saved->get_meta('_suhoput_context');
        if (in_array($context,['retail','wholesale'],true) && $order->get_meta('_suhoput_context') !== $context) {
            throw new \WC_Data_Exception('suhoput_context','Контекст сохранённого заказа неизменяем.');
        }
    }

    public static function canPay(mixed $order): bool
    {
        if (!$order instanceof \WC_Order) { return false; }
        $saved=$order->get_id() ? new \WC_Order($order->get_id()) : $order;
        $snapshot=$saved->get_meta('_suhoput_snapshot');
        return $saved->get_meta('_suhoput_context') !== 'wholesale' && (!is_array($snapshot) || ($snapshot['context'] ?? '') !== 'wholesale');
    }

    public static function earlyPayGuard(): void
    {
        if (isset($_POST['woocommerce_pay'])) {
            $key=isset($_GET['key']) && is_string($_GET['key']) ? wc_clean(wp_unslash($_GET['key'])) : '';
            if (!self::canPay(wc_get_order(wc_get_order_id_by_order_key($key)))) { self::deny(); }
        }
    }

    public static function pageGuard(): void
    {
        global $wp;
        $wholesale=is_page('wholesale') || preg_match('#^/wholesale(?:/|$)#i',(string)wp_parse_url($_SERVER['REQUEST_URI'] ?? '',PHP_URL_PATH));
        if (get_current_user_id() || $wholesale || is_cart() || is_checkout() || is_account_page()) { self::noCache(); }
        if ($wholesale && self::current() !== 'wholesale') { self::deny(); }
        if (isset($wp->query_vars['order-pay']) && !self::canPay(wc_get_order((int)$wp->query_vars['order-pay']))) { self::deny(); }
        if ((is_cart() || is_checkout()) && !isset($wp->query_vars['order-received']) && !isset($wp->query_vars['order-pay']) && self::current() === null) { self::deny(); }
        if (isset($_POST['suhoput_cart_confirm']) && is_string($_POST['suhoput_cart_confirm'])) {
            $nonce=$_POST['suhoput_cart_nonce'] ?? '';
            if (!is_string($nonce) || !wp_verify_nonce(wp_unslash($nonce),'suhoput_cart_confirm') || !self::confirm(wp_unslash($_POST['suhoput_cart_confirm']))) { wc_add_notice(self::REVIEW,'error'); }
        }
    }

    private static function noCache(): void
    {
        if (!defined('DONOTCACHEPAGE')) { define('DONOTCACHEPAGE',true); }
        nocache_headers(); header('Cache-Control: private, no-store, max-age=0'); header('Vary: Cookie, Authorization',false);
    }

    private static function deny(): never { self::noCache(); wp_die('Покупка недоступна.','',['response'=>403]); }

    public static function reviewForm(): void
    {
        WC()->cart?->calculate_totals(); if (!self::needsReview()) { return; }
        echo '<form method="post" class="suhoput-cart-review"><p>'.esc_html(self::REVIEW).'</p><p>Итог: '.wp_kses_post(WC()->cart->get_total()).'</p>';
        wp_nonce_field('suhoput_cart_confirm','suhoput_cart_nonce');
        echo '<button name="suhoput_cart_confirm" value="'.esc_attr(self::reviewToken()).'">Подтверждаю состав и итог</button></form>';
    }

    public static function guardRest(mixed $result,\WP_REST_Server $server,\WP_REST_Request $request): mixed
    {
        if (is_wp_error($result)) { return $result; }
        $route=$request->get_route();
        // WC reads the OUTER PHP header even for WordPress batch subrequests.
        if (preg_match('#^/wc/store(?:/|$)#i',$route) && ($request->get_header('Cart-Token') || !empty($_SERVER['HTTP_CART_TOKEN']))) { return self::error('suhoput_context',403); }
        if (preg_match('#^/suhoput/v1/wholesale(?:/|$)#i',$route) && self::current() !== 'wholesale') { return self::error('suhoput_context',403); }
        if (preg_match('#^/wc/store(?:/v\d+)?/(checkout|cart)(?:/|$)#i',$route,$m)) {
            if (strtolower($m[1]) === 'checkout') { return self::error('suhoput_classic_checkout',403); }
            if (self::current() === null) { return self::error('suhoput_context',403); }
            if (preg_match('#/(?:apply-coupon|coupons)(?:/|$)#i',$route)) { return self::error('suhoput_discounts',403); }
            if ($request->get_method() !== 'GET' && $request->get_method() !== 'OPTIONS' && !get_current_user_id()) {
                if (!GuestLimits::currentAttempt()) { return self::error('suhoput_guest_limit',429); }
                self::$apiAttempt=true;
            }
        }
        return $result;
    }

    private static function error(string $code,int $status): \WP_Error { return new \WP_Error($code,'Действие недоступно.',['status'=>$status]); }

    public static function routes(): void
    {
        register_rest_route('suhoput/v1','/wholesale/context',['methods'=>'GET','permission_callback'=>static fn() => self::current() === 'wholesale' ? true : self::error('suhoput_context',403),'callback'=>static fn() => ['context'=>'wholesale']]);
        register_rest_route('suhoput/v1','/commerce/context',['methods'=>'GET','permission_callback'=>'__return_true','callback'=>static function() {
            if (!WC()->cart) { wc_load_cart(); } WC()->cart->calculate_totals();
            return ['context'=>self::current(),'review_required'=>self::needsReview(),'review_token'=>self::reviewToken(),'total'=>WC()->cart->get_total('edit')];
        }]);
        register_rest_route('suhoput/v1','/commerce/confirm',['methods'=>'POST','permission_callback'=>'__return_true','callback'=>static function($request) {
            if (!WC()->cart) { wc_load_cart(); }
            $token=$request->get_param('token'); return is_string($token) && self::confirm($token) ? ['confirmed'=>true] : self::error('suhoput_review',409);
        }]);
    }
}
