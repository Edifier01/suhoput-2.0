<?php
use Suhoput\Core\Commerce\Context;
use Suhoput\Core\Commerce\GuestLimits;
use Suhoput\Core\Infrastructure\Accounts;
use Suhoput\Core\Orders\Access;
if (wp_get_environment_type() !== 'local') { throw new RuntimeException('Local tests only.'); }
$checks=0;
$assert=static function(bool $ok,string $name) use(&$checks): void { if (!$ok) { throw new RuntimeException('FAIL: '.$name); } $checks++; };
// Removing the policy must re-enable a real WooCommerce coupon: this test catches that bypass.
$couponOption=get_option('woocommerce_enable_coupons'); update_option('woocommerce_enable_coupons','yes');
$assert(wc_coupons_enabled() === false,'Coupons disabled on server');
$assert(class_exists(Context::class) && class_exists(GuestLimits::class),'Commerce policy installed');
global $wpdb;
$tag='commerce-'.bin2hex(random_bytes(6)); $users=[]; $orders=[]; $products=[]; $uuids=[];
$option=get_option('suhoput_guest_limits',null);
try {
    foreach (['retail','wholesale'] as $type) {
        $id=wp_insert_user(['user_login'=>$tag.$type,'user_email'=>$tag.$type.'@example.invalid','user_pass'=>wp_generate_password(28),'role'=>'customer']);
        $assert(!is_wp_error($id),'Fixture account'); $users[$type]=$id;
    }
    $wpdb->update($wpdb->prefix.'suhoput_accounts',['buyer_type'=>'wholesale','access_enabled'=>1,'counterparty_id'=>$tag],['user_id'=>$users['wholesale']]);
    wp_set_current_user(0); $_REQUEST=['context'=>'wholesale','buyer_type'=>'wholesale','counterparty_id'=>$tag];
    $assert(Context::current() === 'retail','Guest cannot select wholesale');
    wp_set_current_user($users['retail']); $assert(Context::current() === 'retail','Retail request cannot select wholesale');
    wp_set_current_user($users['wholesale']); $assert(Context::current() === 'wholesale','Active wholesale server context');
    $product=new WC_Product_Simple(); $product->set_name('Commerce fixture'); $product->set_regular_price('13000'); $product->set_price('13000');
    $product->update_meta_data('_suhoput_wholesale_price','12000.00'); $product->set_status('publish'); $product->save(); $products[]=$product;
    WC()->initialize_session(); WC()->cart=new WC_Cart();
    WC()->cart->add_to_cart($product->get_id()); WC()->cart->calculate_totals();
    $assert((float)WC()->cart->get_subtotal() === 12000.0,'Wholesale cart canonical price');
    $assert(wc_get_product($product->get_id())->get_price() === '13000','Public product keeps retail price');
    wp_set_current_user($users['retail']); WC()->cart->calculate_totals();
    $assert((float)WC()->cart->get_subtotal() === 13000.0,'Login change reprices retained cart');
    $assert(Context::needsReview(),'Changed principal requires review');
    $assert(!Context::confirm('forged'),'Forged review rejected');
    $assert(Context::confirm(Context::reviewToken()),'Current server review accepted');
    $assert(!Context::needsReview(),'Review clears gate');
    (new ReflectionProperty(WC_Session::class,'_customer_id'))->setValue(WC()->session,'new-fixture-session'); WC()->cart->calculate_totals();
    $assert(Context::needsReview(),'Session replacement requires new review');
    $assert(Context::confirm(Context::reviewToken()),'Changed session can confirm current cart');
    wp_set_current_user($users['wholesale']); WC()->cart->calculate_totals();
    $oldToken=Context::reviewToken();
    $wpdb->update($wpdb->prefix.'suhoput_accounts',['access_enabled'=>0],['user_id'=>$users['wholesale']]);
    $assert(Context::current() === null,'Revocation read immediately without cached rights');
    WC()->cart->calculate_totals();
    $assert(WC()->cart->is_empty(),'Revoked wholesale cart cannot silently become retail');
    $assert(!Context::confirm($oldToken),'Stale authorization review denied');
    $order=wc_create_order(['customer_id'=>$users['wholesale']]); $orders[]=$order;
    $order->update_meta_data('_suhoput_origin','site'); $order->update_meta_data('_suhoput_context','wholesale'); $order->set_total('12000'); $order->save();
    $assert(Access::canView(new WC_Order($order->get_id()),$users['wholesale']),'Revoked wholesale retains own history');
    $assert(!Context::canPay(new WC_Order($order->get_id())),'Own wholesale order cannot be paid online');
    $assert($order->needs_payment(),'Wholesale unpaid obligation must not trigger native payment_complete without payment');
    $assert(!current_user_can('pay_for_order',$order->get_id()),'Native pay capability denied');
    $order->update_meta_data('_suhoput_context','retail'); $order->save();
    $assert((new WC_Order($order->get_id()))->get_meta('_suhoput_context') === 'wholesale','Saved context immutable despite CRUD save swallowing exception');
    wp_set_current_user(0); WC()->cart->add_to_cart($product->get_id()); WC()->cart->calculate_totals();
    $assert(Context::current() === 'retail','Logout restores guest retail');
    Context::confirm(Context::reviewToken());
    $coupon=new WC_Coupon(); $coupon->set_code($tag); $coupon->set_discount_type('percent'); $coupon->set_amount(90); $coupon->save();
    try {
        $assert(!WC()->cart->apply_coupon($tag),'Real direct coupon rejected');
        WC()->cart->set_applied_coupons([$tag]);
        $personal=static function($price,$p) { return '1'; }; add_filter('woocommerce_product_get_price',$personal,10,2);
        $fee=static function($cart): void { $cart->add_fee('personal discount',-1000); }; add_action('woocommerce_cart_calculate_fees',$fee);
        WC()->cart->calculate_totals();
        $assert((float)WC()->cart->get_subtotal() === 13000.0,'Personal price filter cannot discount cart');
        $assert(WC()->cart->get_applied_coupons() === [],'Persisted coupon removed');
        $assert((float)WC()->cart->get_discount_total() === 0.0 && (float)WC()->cart->get_fee_total() === 0.0,'Coupon and negative fee do not lower sum');
        remove_filter('woocommerce_product_get_price',$personal,10); remove_action('woocommerce_cart_calculate_fees',$fee);
    } finally { $coupon->delete(true); }
    $grandDiscount=static fn($total) => 1; add_filter('woocommerce_calculated_total',$grandDiscount,10);
    try { WC()->cart->calculate_totals(); $assert((float)WC()->cart->get_total('edit') === 13000.0,'Personal grand-total filter cannot lower canonical total'); }
    finally { remove_filter('woocommerce_calculated_total',$grandDiscount,10); WC()->cart->calculate_totals(); }
    $hashRetail=apply_filters('woocommerce_get_variation_prices_hash',[], $product,false);
    $wpdb->update($wpdb->prefix.'suhoput_accounts',['access_enabled'=>1],['user_id'=>$users['wholesale']]); wp_set_current_user($users['wholesale']);
    $assert($hashRetail !== apply_filters('woocommerce_get_variation_prices_hash',[],$product,false),'Variant price cache segregated by context');
    WC()->cart->calculate_totals(); if (Context::needsReview()) { Context::confirm(Context::reviewToken()); }
    wc_clear_notices(); do_action('woocommerce_checkout_process');
    $assert(wc_notice_count('error') > 0,'Native wholesale checkout blocked before payment branch'); wc_clear_notices();
    wp_set_current_user(0);
    // A line-item hook could lower total and subtotal together, bypassing a discount-total check.
    wp_set_current_user($users['retail']); WC()->cart->calculate_totals(); if (Context::needsReview()) { Context::confirm(Context::reviewToken()); }
    $tampered=new WC_Order(); $tampered->set_customer_id($users['retail']);
    $item=new WC_Order_Item_Product(); $item->set_product($product); $item->set_quantity(1); $item->set_subtotal('1'); $item->set_total('1'); $tampered->add_item($item);
    $refused=false; try { Context::createOrder($tampered); } catch (Exception $error) { $refused=true; }
    $assert($refused,'Equal discounted subtotal and total cannot persist');
    wp_set_current_user(0);
    foreach (['/suhoput/v1/wholesale/context','/SuHoPuT/v1/Wholesale/context','/wc/store/v1/checkout','/WC/Store/checkout/123','/wc/store/v1/cart/apply-coupon'] as $route) {
        $request=new WP_REST_Request('POST',$route); $request->set_param('context','wholesale');
        $result=Context::guardRest(null,rest_get_server(),$request);
        $assert(is_wp_error($result),'API bypass denied '.$route);
    }
    update_option('suhoput_guest_limits',['actor_rate'=>2,'ip_rate'=>4,'window'=>60,'actor_holds'=>1,'ip_holds'=>2],false);
    $actor=hash('sha256',$tag.'actor'); $ip=hash('sha256',$tag.'ip'); $second=hash('sha256',$tag.'second');
    $assert(GuestLimits::attempt($actor,$ip),'Guest action 1'); $assert(GuestLimits::attempt($actor,$ip),'Guest action 2');
    $assert(!GuestLimits::attempt($actor,$ip),'Per-browser rate bounded');
    $assert(GuestLimits::attempt($second,$ip),'Shared IP second browser action 1'); $assert(GuestLimits::attempt($second,$ip),'Shared IP second browser action 2');
    $assert(!GuestLimits::attempt(hash('sha256',$tag.'third'),$ip),'Cookie rotation bounded by aggregate IP');
    $uuid=wp_generate_uuid4(); $uuids[]=$uuid;
    $assert(GuestLimits::admit($uuid,$actor,$ip),'Unpaid intent admitted');
    $assert(GuestLimits::admit($uuid,$actor,$ip),'Same intent retry idempotent');
    $assert(!GuestLimits::admit($uuid,$second,$ip),'Another browser cannot reuse intent');
    $next=wp_generate_uuid4(); $uuids[]=$next; $assert(!GuestLimits::admit($next,$actor,$ip),'Active unpaid actor limit');
    $wpdb->update($wpdb->prefix.'suhoput_guest_slots',['created_at'=>1],['intent_id'=>$uuid]);
    $assert(!GuestLimits::admit($next,$actor,$ip),'Old/unknown hold is not released by wall clock');
    $next=wp_generate_uuid4(); $uuids[]=$next; $assert(GuestLimits::admit($next,$second,$ip),'Two guests on shared IP can hold');
    $next=wp_generate_uuid4(); $uuids[]=$next; $assert(!GuestLimits::admit($next,hash('sha256',$tag.'third'),$ip),'Aggregate active hold limit');
    GuestLimits::settle($uuid,'paid'); $next=wp_generate_uuid4(); $uuids[]=$next;
    $assert(GuestLimits::admit($next,$actor,$ip),'Confirmed paid frees unpaid quota');
    GuestLimits::settle($next,'released');
    $assert(!GuestLimits::admit($next,$actor,$ip),'Settled intent cannot reopen');
    $paidIntent=wp_generate_uuid4(); $uuids[]=$paidIntent; $assert(GuestLimits::admit($paidIntent,$actor,$ip),'Paid-recovery fixture admitted');
    $paid=wc_create_order(); $orders[]=$paid; $paid->set_total('100'); $paid->update_meta_data('_suhoput_guest_intent',$paidIntent); $paid->save();
    $failSettle=static fn($sql) => str_starts_with($sql,'UPDATE '.$wpdb->prefix.'suhoput_guest_slots') ? 'SELECT * FROM intentionally_missing_commerce_table' : $sql;
    $old=$wpdb->suppress_errors(true); add_filter('query',$failSettle);
    try { $paid->payment_complete(); } finally { remove_filter('query',$failSettle); $wpdb->suppress_errors($old); }
    $assert((new WC_Order($paid->get_id()))->get_date_paid() !== null,'Paid fact persists despite failed quota projection');
    $recoveredIntent=wp_generate_uuid4(); $uuids[]=$recoveredIntent;
    $assert(GuestLimits::admit($recoveredIntent,$actor,$ip),'Persisted paid order recovers quota after failed payment hook');
    GuestLimits::settle($recoveredIntent,'released');
    $table=$wpdb->prefix.'suhoput_guest_rates';
    $wpdb->query($wpdb->prepare("UPDATE {$table} SET window_start=0 WHERE bucket_key IN (%s,%s,%s)",$actor,$ip,$second));
    $assert(GuestLimits::attempt($actor,$ip),'Rate window recovers');
    $broken=static fn($sql) => str_contains($sql,'suhoput_guest_rates') && str_starts_with($sql,'INSERT') ? 'SELECT * FROM intentionally_missing_commerce_table' : $sql;
    $old=$wpdb->suppress_errors(true); add_filter('query',$broken);
    try { $assert(!GuestLimits::attempt(hash('sha256',$tag.'failure'),$ip),'Failed persistence closes admission'); }
    finally { remove_filter('query',$broken); $wpdb->suppress_errors($old); }
    $failedIntent=wp_generate_uuid4(); $uuids[]=$failedIntent;
    $brokenSlot=static fn($sql) => str_contains($sql,'suhoput_guest_slots') && str_starts_with($sql,'INSERT') ? 'SELECT * FROM intentionally_missing_commerce_table' : $sql;
    $old=$wpdb->suppress_errors(true); add_filter('query',$brokenSlot);
    try { $assert(!GuestLimits::admit($failedIntent,hash('sha256',$tag.'failure'),hash('sha256',$tag.'failureip')),'Failed slot persistence closes admission'); }
    finally { remove_filter('query',$brokenSlot); $wpdb->suppress_errors($old); }
    $lockName='suhoput_guest_'.substr(hash('sha256',DB_NAME.'|'.$wpdb->prefix),0,24); $released=false;
    $loseLock=static function($sql) use($lockName,&$released,$wpdb) { if (!$released && str_contains($sql,'SELECT * FROM '.$wpdb->prefix.'suhoput_guest_rates')) { $released=true; return $wpdb->prepare('SELECT RELEASE_LOCK(%s)',$lockName); } return $sql; };
    add_filter('query',$loseLock);
    try { $assert(!GuestLimits::attempt(hash('sha256',$tag.'failure'),hash('sha256',$tag.'failureip')),'Lost connection lock closes admission'); }
    finally { remove_filter('query',$loseLock); }
    update_option('suhoput_guest_limits',['actor_rate'=>0],false);
    $assert(!GuestLimits::attempt($actor,$ip),'Invalid configuration fails closed');
    $_COOKIE[GuestLimits::COOKIE]=str_repeat('a',64).'.'.str_repeat('b',64);
    $assert(GuestLimits::actor() === null,'Forged signed actor rejected');
    $_SERVER['REMOTE_ADDR']='2001:db8::1'; $_SERVER['HTTP_X_FORWARDED_FOR']='192.0.2.1'; $oneIp=GuestLimits::ip();
    $_SERVER['REMOTE_ADDR']='2001:0db8:0:0:0:0:0:1'; $_SERVER['HTTP_X_FORWARDED_FOR']='192.0.2.2';
    $assert($oneIp === GuestLimits::ip(),'IP normalization and forged forwarded header cannot rotate bucket');
    echo 'PASS: '.$checks.' commerce server checks'."\n";
} finally {
    wp_set_current_user(0); WC()->cart?->empty_cart(); WC()->session?->destroy_session();
    foreach ($uuids as $uuid) { $wpdb->delete($wpdb->prefix.'suhoput_guest_slots',['intent_id'=>$uuid]); }
    foreach (['actor','ip','second','third','failure','failureip'] as $suffix) { $wpdb->delete($wpdb->prefix.'suhoput_guest_rates',['bucket_key'=>hash('sha256',$tag.$suffix)]); }
    foreach ($orders as $order) { $order->delete(true); } foreach ($products as $product) { $product->delete(true); }
    require_once ABSPATH.'wp-admin/includes/user.php';
    foreach ($users as $id) { $wpdb->delete($wpdb->prefix.'suhoput_accounts',['user_id'=>$id]); wp_delete_user($id); }
    if ($option === null) { delete_option('suhoput_guest_limits'); } else { update_option('suhoput_guest_limits',$option,false); }
    update_option('woocommerce_enable_coupons',$couponOption);
}
