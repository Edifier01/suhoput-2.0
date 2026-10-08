<?php
use Suhoput\Core\Commerce\Context;
use Suhoput\Core\Commerce\GuestLimits;
if (wp_get_environment_type() !== 'local' || !defined('SUHOPUT_LOCAL_SAFETY')) { throw new RuntimeException('Local tests only.'); }
[$tag,$mode]=$args;
if (!preg_match('/\Acart-[a-f0-9]{12}\z/',$tag)) { throw new RuntimeException('Invalid fixture.'); }
global $wpdb; $key='suhoput_test_'.$tag; $state=get_option($key,[]);
$hash=static fn(string $kind) => hash('sha256',$tag.$kind);
if ($mode === 'setup') {
    if ($state) { throw new RuntimeException('Fixture already exists.'); }
    $state=['settings'=>get_option('suhoput_guest_limits',null),'coming_soon'=>get_option('woocommerce_coming_soon',null),'users'=>[],'orders'=>[],'intents'=>[],'actors'=>[]]; add_option($key,$state,'','no');
    // The closed local store's Coming Soon overlay hides cart HTML from customers.
    // Temporarily expose only these localhost tests, restoring the original option.
    update_option('woocommerce_coming_soon','no');
    foreach (['retail','wholesale','manager'] as $type) {
        $id=wp_insert_user(['user_login'=>$tag.$type,'user_email'=>$tag.$type.'@example.invalid','user_pass'=>$args[2],'role'=>'customer']);
        if (is_wp_error($id)) { throw new RuntimeException('Fixture user failed.'); }
        if ($type === 'manager') { get_userdata($id)->set_role('shop_manager'); }
        $state['users'][$type]=$id; update_option($key,$state,false);
    }
    $wpdb->update($wpdb->prefix.'suhoput_accounts',['buyer_type'=>'wholesale','counterparty_id'=>$tag,'access_enabled'=>1],['user_id'=>$state['users']['wholesale']]);
    $product=new WC_Product_Simple(); $product->set_name('Commerce isolated fixture'); $product->set_regular_price('13000'); $product->set_price('13000');
    $product->set_virtual(true); $product->set_status('publish'); $product->update_meta_data('_suhoput_wholesale_price','12000.00'); $product->update_meta_data('_suhoput_commerce_fixture',$tag); $product->save();
    $state['product']=$product->get_id(); update_option($key,$state,false);
    foreach (['retail','wholesale'] as $type) {
        $order=wc_create_order(['customer_id'=>$state['users'][$type]]); $state['orders'][]=$order->get_id(); update_option($key,$state,false);
        $order->update_meta_data('_suhoput_origin','site'); $order->update_meta_data('_suhoput_context',$type); $order->update_meta_data('_suhoput_commerce_fixture',$tag);
        $order->add_product($product,1); $order->calculate_totals(); $order->save();
        $output[$type]=['id'=>$order->get_id(),'pay'=>$order->get_checkout_payment_url(),'view'=>$order->get_view_order_url(),'key'=>$order->get_order_key()];
    }
    // Independent tagged endpoints avoid collisions with any real pages.
    $page=wp_insert_post(['post_type'=>'page','post_status'=>'publish','post_title'=>'Local wholesale fixture','post_name'=>'wholesale','post_content'=>'Private wholesale fixture']);
    update_post_meta($page,'_suhoput_commerce_fixture',$tag); $state['page']=$page; update_option($key,$state,false);
    for ($i=0;$i<10;$i++) { $state['intents'][]=wp_generate_uuid4(); } update_option($key,$state,false);
    echo wp_json_encode($output+['account'=>wc_get_page_permalink('myaccount'),'cart'=>wc_get_cart_url(),'checkout'=>wc_get_checkout_url(),'product'=>$product->get_id(),'wholesalePage'=>get_permalink($page)])."\n"; return;
}
if (!$state) { throw new RuntimeException('Fixture missing.'); }
if ($mode === 'nonce') { wp_set_current_user($state['users'][$args[2]]); $_COOKIE[LOGGED_IN_COOKIE]=rawurldecode($args[3]); echo wp_create_nonce('wp_rest')."\n"; return; }
if ($mode === 'revoke') { $wpdb->update($wpdb->prefix.'suhoput_accounts',['access_enabled'=>0],['user_id'=>$state['users']['wholesale']]); echo "REVOKED\n"; return; }
if ($mode === 'restore') { $wpdb->update($wpdb->prefix.'suhoput_accounts',['access_enabled'=>1],['user_id'=>$state['users']['wholesale']]); echo "RESTORED\n"; return; }
if ($mode === 'rate-policy') { update_option('suhoput_guest_limits',['actor_rate'=>2,'ip_rate'=>4,'window'=>60,'actor_holds'=>1,'ip_holds'=>2],false); echo "CONFIGURED\n"; return; }
if ($mode === 'settings') { echo wp_json_encode(GuestLimits::settings())."\n"; return; }
if ($mode === 'wholesale-count') { echo count(wc_get_orders(['customer_id'=>$state['users']['wholesale'],'limit'=>-1,'return'=>'ids']))."\n"; return; }
if ($mode === 'rate') { echo GuestLimits::attempt($hash('rateactor'),$hash('rateip')) ? "WIN\n" : "DENIED\n"; return; }
if ($mode === 'hold') { $i=(int)$args[2]; echo GuestLimits::admit($state['intents'][$i],$hash('holdactor'),$hash('holdip')) ? "WIN\n" : "DENIED\n"; return; }
if ($mode === 'ip-hold') { $i=(int)$args[2]; echo GuestLimits::admit($state['intents'][$i],$hash('actor'.$i),$hash('sharedip')) ? "WIN\n" : "DENIED\n"; return; }
if ($mode === 'simulate-checkout') {
    $cookies=json_decode($args[2],true,16,JSON_THROW_ON_ERROR);
    foreach ($cookies as $cookie) { if (str_starts_with($cookie['name'],'wp_woocommerce_session_') || $cookie['name'] === GuestLimits::COOKIE) { $_COOKIE[$cookie['name']]=rawurldecode($cookie['value']); } }
    // WP-CLI has already run wp_loaded with no browser cookies. Reload the real handler.
    $_SERVER['REMOTE_ADDR']='192.0.2.19'; WC()->session=null; WC()->cart=null; wc_load_cart();
    (new WC_Cart_Session(WC()->cart))->get_cart_from_session(); WC()->cart->calculate_totals();
    if (WC()->cart->is_empty()) { throw new RuntimeException('Checkout fixture cart empty.'); }
    if (Context::needsReview()) { throw new RuntimeException('Checkout fixture review required.'); }
    $id=WC()->checkout()->create_order(['billing_email'=>$tag.'guest@example.invalid','billing_first_name'=>'Local','billing_last_name'=>'Fixture','payment_method'=>'','terms'=>1]);
    if (is_wp_error($id)) { throw new RuntimeException('Checkout fixture failed: '.$id->get_error_code()); }
    $order=new WC_Order($id); $state['orders'][]=$id; $state['intents'][]=(string)$order->get_meta('_suhoput_guest_intent'); $state['actors'][]=GuestLimits::actor(); update_option($key,$state,false);
    $order->update_meta_data('_suhoput_commerce_fixture',$tag); $order->save();
    if ($order->get_customer_id() !== 0 || $order->get_meta('_suhoput_context') !== 'retail' || (float)$order->get_total() !== 13000.0) { throw new RuntimeException('Invalid guest checkout.'); }
    wp_mail($tag.'guest@example.invalid','Local simulated order','Изолированный заказ создан. Внешние операции имитированы.');
    echo "GUEST_CREATED\n"; return;
}
if ($mode !== 'cleanup') { throw new RuntimeException('Invalid mode.'); }
foreach ($state['orders'] as $id) {
    $order=new WC_Order($id); if ($order->get_meta('_suhoput_commerce_fixture') !== $tag) { throw new RuntimeException('Order ownership mismatch.'); }
    $wpdb->delete($wpdb->prefix.'suhoput_order_access',['order_id'=>$id]); $order->delete(true);
}
$product=wc_get_product($state['product']); if ($product->get_meta('_suhoput_commerce_fixture') !== $tag) { throw new RuntimeException('Product ownership mismatch.'); } $product->delete(true);
if (get_post_meta($state['page'],'_suhoput_commerce_fixture',true) !== $tag) { throw new RuntimeException('Page ownership mismatch.'); } wp_delete_post($state['page'],true);
require_once ABSPATH.'wp-admin/includes/user.php';
foreach ($state['users'] as $type=>$id) {
    if (get_userdata($id)->user_email !== $tag.$type.'@example.invalid') { throw new RuntimeException('User ownership mismatch.'); }
    $wpdb->delete($wpdb->prefix.'suhoput_accounts',['user_id'=>$id]); wp_delete_user($id);
    $wpdb->delete($wpdb->prefix.'woocommerce_sessions',['session_key'=>(string)$id]);
}
foreach ($state['intents'] as $intent) { $wpdb->delete($wpdb->prefix.'suhoput_guest_slots',['intent_id'=>$intent]); }
foreach (array_merge($state['actors'],array_map($hash,['rateactor','rateip','holdactor','holdip','sharedip','actor0','actor1','actor2','actor3'])) as $bucket) { $wpdb->delete($wpdb->prefix.'suhoput_guest_rates',['bucket_key'=>$bucket]); }
if ($state['settings'] === null) { delete_option('suhoput_guest_limits'); } else { update_option('suhoput_guest_limits',$state['settings'],false); }
if ($state['coming_soon'] === null) { delete_option('woocommerce_coming_soon'); } else { update_option('woocommerce_coming_soon',$state['coming_soon'],false); }
delete_option($key); echo "CLEANUP\n";
