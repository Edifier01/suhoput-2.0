<?php
use Suhoput\Core\Orders\Access;
if (wp_get_environment_type() !== 'local' || !defined('SUHOPUT_LOCAL_SAFETY')) { throw new RuntimeException('Local tests only.'); }
global $wpdb;
$tag='history-'.substr(wp_generate_uuid4(),0,8); $users=[]; $orders=[]; $checks=0;
$assert=static function(bool $ok,string $name) use (&$checks): void { if (!$ok) { throw new RuntimeException('FAIL: '.$name); } ++$checks; };
$user=static function(string $suffix) use($tag,&$users): int {
    $id=wp_insert_user(['user_login'=>$tag.$suffix,'user_email'=>$tag.$suffix.'@example.invalid','user_pass'=>wp_generate_password(28),'role'=>'customer']);
    if (is_wp_error($id)) { throw new RuntimeException('Fixture user failed'); } $users[]=$id; return $id;
};
$order=static function(int $owner,string $status='pending',bool $site=true) use($tag,&$orders): WC_Order {
    $o=wc_create_order(['customer_id'=>$owner,'status'=>$status]); $orders[]=$o->get_id();
    $o->set_billing_email($tag.'@example.invalid'); $o->update_meta_data('_suhoput_history_fixture',$tag);
    if ($site) { $o->update_meta_data('_suhoput_origin','site'); } $o->save(); return $o;
};
try {
    $one=$user('one'); $two=$user('two'); wp_set_current_user($one);
    $own=$order($one); $manual=$order($one,'pending',false); $foreign=$order($two);
    $query=apply_filters('woocommerce_my_account_my_orders_query',['customer'=>$one,'limit'=>-1,'return'=>'ids']);
    $ids=wc_get_orders($query);
    $assert(in_array($own->get_id(),$ids,true) && !in_array($manual->get_id(),$ids,true) && !in_array($foreign->get_id(),$ids,true),'History excludes manual/external and foreign orders');
    $assert(class_exists(Access::class),'Order ownership implemented');
    foreach (array_keys(wc_get_order_statuses()) as $status) { $order($one,substr($status,3)); }
    $query=apply_filters('woocommerce_my_account_my_orders_query',['customer'=>$two,'status'=>'completed','limit'=>-1,'return'=>'ids']);
    $assert(count(wc_get_orders($query)) === count(wc_get_order_statuses())+1,'All states and server owner override caller selectors');
    $assert(current_user_can('view_order',$own->get_id()) && !current_user_can('view_order',$foreign->get_id()) && !current_user_can('view_order',$manual->get_id()),'Capability checks owner and site origin');
    $assert(apply_filters('woocommerce_shortcode_order_tracking_order_id',$foreign->get_id()) === 0,'Native tracking filter rejects foreign ID');
    $wpdb->update($wpdb->prefix.'suhoput_accounts',['buyer_type'=>'wholesale','access_enabled'=>0,'counterparty_id'=>$tag],['user_id'=>$one]);
    $assert(Access::canView($own,$one),'Disabled wholesale access retains own history');
    $guest=$order(0); $guest->set_billing_email(get_userdata($two)->user_email); $guest->save();
    $assert(!Access::canView($guest,$two),'Same email does not prove ownership');
    $rejected=false; try { wc_update_new_customer_past_orders($two); } catch (Throwable $e) { $rejected=true; }
    $assert((new WC_Order($guest->get_id()))->get_customer_id() === 0,'Native email-only past-order linking cannot change owner');
    $attempt=wc_get_order($guest->get_id()); $attempt->set_customer_id($two); $rejected=false;
    try { $attempt->save(); } catch (WC_Data_Exception $e) { $rejected=true; }
    $assert((new WC_Order($guest->get_id()))->get_customer_id() === 0,'Direct CRUD guest binding requires proof; swallowed save error cannot change owner');
    wp_set_current_user(0); $_COOKIE[Access::COOKIE]=bin2hex(random_bytes(32));
    $token=null; $capture=static function($mail) use (&$token) { if (preg_match('/suhoput_token=([a-f0-9]{64})/',$mail['message'],$m)) { $token=$m[1]; } return $mail; };
    add_filter('wp_mail',$capture);
    $assert(Access::requestProof($guest->get_id(),$guest->get_billing_email(),'view',0),'Guest challenge sent');
    $assert(is_string($token) && strlen($token) === 64,'High entropy confirmation in email');
    $assert(!Access::requestProof($guest->get_id(),$guest->get_billing_email(),'view',0),'Immediate resend throttled on server');
    $assert(!Access::canView($guest,0),'Email challenge issuance alone reveals nothing');
    $checkout=new WP_REST_Request('POST','/wc/store/v1/checkout/'.$guest->get_id());
    $checkout->set_param('key',$guest->get_order_key()); $checkout->set_param('billing_email',$guest->get_billing_email());
    $assert(rest_do_request($checkout)->get_status() === 404,'Store checkout-by-ID cannot access unproven guest order');
    foreach (['/WC/Store/v1/Order/','/wc/store/order/'] as $path) {
        $alias=new WP_REST_Request('GET',$path.$guest->get_id());
        $alias->set_query_params(['key'=>$guest->get_order_key(),'billing_email'=>$guest->get_billing_email()]);
        $assert(rest_do_request($alias)->get_status() === 404,'Native Store GET alias requires guest proof');
    }
    foreach (['/WC/Store/v1/Checkout/','/wc/store/checkout/'] as $path) {
        $alias=new WP_REST_Request('POST',$path.$guest->get_id());
        $alias->set_body_params(['key'=>$guest->get_order_key(),'billing_email'=>$guest->get_billing_email()]);
        $assert(rest_do_request($alias)->get_status() === 404,'Native Store POST alias requires guest proof');
    }
    wp_set_current_user($one);
    $shadow=new WP_REST_Request('GET','/wc/store/v1/order/'.$own->get_id());
    $shadow->set_query_params(['id'=>$guest->get_id(),'key'=>$guest->get_order_key(),'billing_email'=>$guest->get_billing_email()]);
    $assert(rest_do_request($shadow)->get_status() === 404,'Store query ID cannot substitute unproven guest for authorized path');
    $shadow=new WP_REST_Request('POST','/wc/store/v1/checkout/'.$own->get_id());
    $shadow->set_body_params(['id'=>$guest->get_id(),'key'=>$guest->get_order_key(),'billing_email'=>$guest->get_billing_email()]);
    $assert(rest_do_request($shadow)->get_status() === 404,'Store body ID cannot substitute unproven guest for authorized path');
    wp_set_current_user(0);
    $assert(!Access::consume($own->get_id(),$token,'view',0),'Substituted order ID rejected');
    $cookie=$_COOKIE[Access::COOKIE]; $_COOKIE[Access::COOKIE]=bin2hex(random_bytes(32));
    $assert(!Access::consume($guest->get_id(),$token,'view',0),'Other browser cannot consume confirmation');
    $_COOKIE[Access::COOKIE]=$cookie;
    $assert(!Access::consume($guest->get_id(),$token,'claim',$two),'Purpose/user substitution rejected');
    $assert(Access::consume($guest->get_id(),$token,'view',0),'Guest confirmation grants access');
    $assert(Access::canView(wc_get_order($guest->get_id()),0),'Verified guest sees only proven order');
    $assert(!Access::canView($own,0) && !Access::canView($foreign,0),'Guest grant cannot expose others');
    $assert(!Access::consume($guest->get_id(),$token,'view',0),'Used confirmation cannot be replayed');
    $table=$wpdb->prefix.'suhoput_order_access';
    $wpdb->update($table,['requested_at'=>time()-61],['order_id'=>$guest->get_id()]);
    wp_set_current_user($two);
    $assert(Access::requestProof($guest->get_id(),$guest->get_billing_email(),'claim',$two),'Claim requires fresh proof');
    $assert(!Access::consume($guest->get_id(),$token,'claim',$one),'Different account cannot claim');
    $assert(Access::consume($guest->get_id(),$token,'claim',$two),'Proven guest order bound to current account');
    $assert(wc_get_order($guest->get_id())->get_customer_id() === $two,'Claim persisted through CRUD');
    $assert(!Access::consume($guest->get_id(),$token,'claim',$two),'Claim replay rejected');
    wp_set_current_user(0); $assert(!Access::canView(wc_get_order($guest->get_id()),0),'Claim revokes previous guest session');
    $exp=$order(0); $assert(Access::requestProof($exp->get_id(),$exp->get_billing_email(),'view',0),'Expiry fixture issued');
    $wpdb->update($table,['expires_at'=>time()-1],['order_id'=>$exp->get_id()]);
    $assert(!Access::consume($exp->get_id(),$token,'view',0),'Expired confirmation rejected');
    $wpdb->update($table,['requested_at'=>time()-61],['order_id'=>$exp->get_id()]); $old=$token;
    $assert(Access::requestProof($exp->get_id(),$exp->get_billing_email(),'view',0),'New challenge replaces expired one');
    $assert(!Access::consume($exp->get_id(),$old,'view',0),'Replaced confirmation rejected');
    $exp->set_billing_email($tag.'-new@example.invalid'); $exp->save();
    $assert(!Access::consume($exp->get_id(),$token,'view',0),'Changed order email invalidates proof');
    $assert(!Access::requestProof($manual->get_id(),$manual->get_billing_email(),'view',0),'Manual document cannot acquire customer proof');
    $assert(!Access::requestProof(PHP_INT_MAX,$email ?? 'none@example.invalid','view',0),'Missing order produces generic failure');
    $exp2=$order(0); $assert(Access::requestProof($exp2->get_id(),$exp2->get_billing_email(),'view',0),'Failure fixture issued');
    $fail=static fn(string $sql): string => str_starts_with($sql,'UPDATE '.$table." SET state='used'") ? 'UPDATE suhoput_nonexistent_proof_table SET state=1' : $sql;
    $silence=$wpdb->suppress_errors(true); add_filter('query',$fail);
    $assert(!Access::consume($exp2->get_id(),$token,'view',0),'SQL failure cannot grant access');
    remove_filter('query',$fail); $wpdb->suppress_errors($silence);
    $assert(!Access::canView($exp2,0),'Failed consumption remains inaccessible');
    $assert(Access::consume($exp2->get_id(),$token,'view',0),'Unused proof may succeed after failed SQL');
    $wpdb->update($table,['grant_expires_at'=>time()-1],['order_id'=>$exp2->get_id()]);
    $assert(!Access::canView($exp2,0),'Expired guest grant cannot read');
    wp_set_current_user($one);
    foreach ([$foreign->get_id(),$manual->get_id(),PHP_INT_MAX] as $id) {
        $r=rest_do_request(new WP_REST_Request('GET','/suhoput/v1/orders/'.$id));
        $assert($r->get_status() === 404,'API rejects foreign/manual/missing order');
    }
    $r=rest_do_request(new WP_REST_Request('GET','/suhoput/v1/orders/'.$own->get_id()));
    $assert($r->get_status() === 200 && !isset($r->get_data()['meta_data']),'Own API returns allowlisted data');
    $r=rest_do_request(new WP_REST_Request('GET','/suhoput/v1/orders'));
    $assert($r->get_status() === 200 && count($r->get_data()['orders']) === count(wc_get_order_statuses())+1,'API list owns all states');
    $r=rest_do_request(new WP_REST_Request('GET','/wc/v3/orders'));
    $assert($r->get_status() === 404,'Management API rejects customer');
    wp_set_current_user(0);
    $r=rest_do_request(new WP_REST_Request('GET','/suhoput/v1/orders'));
    $assert($r->get_status() === 404,'Guest cannot enumerate history');
    $checkoutOrder=new WC_Order(); $checkoutOrder->set_customer_id($two); wp_set_current_user($one);
    do_action('woocommerce_checkout_create_order',$checkoutOrder,[]);
    $checkoutOrder->save(); $orders[]=$checkoutOrder->get_id();
    $assert(Access::isSite($checkoutOrder) && $checkoutOrder->get_customer_id() === $one,'Checkout uses server session owner and site origin');
    wp_set_current_user(0); $checkoutOrder=new WC_Order(); $checkoutOrder->set_billing_email($tag.'@example.invalid');
    do_action('woocommerce_checkout_create_order',$checkoutOrder,[]); $checkoutOrder->save(); $orders[]=$checkoutOrder->get_id();
    do_action('woocommerce_checkout_order_created',$checkoutOrder);
    $assert(Access::canView($checkoutOrder,0),'Originating checkout browser can access its new guest order');
    $_COOKIE[Access::COOKIE]=bin2hex(random_bytes(32));
    $assert(!Access::canView($checkoutOrder,0),'Other browser cannot reuse checkout session proof');
    $manager=$user('manager'); get_userdata($manager)->set_role('shop_manager'); wp_set_current_user($manager);
    $r=rest_do_request(new WP_REST_Request('GET','/wc/v3/orders'));
    $assert($r->get_status() === 200,'Authorized staff retains management API');
    remove_filter('wp_mail',$capture);
    echo 'PASS: '.$checks.' order ownership and proof checks; fixture='.$tag."\n";
} finally {
    wp_set_current_user(0);
    foreach ($orders as $id) { if (class_exists(Access::class)) { $wpdb->delete($wpdb->prefix.'suhoput_order_access',['order_id'=>$id]); } wc_get_order($id)?->delete(true); }
    require_once ABSPATH.'wp-admin/includes/user.php';
    foreach ($users as $id) { $wpdb->delete($wpdb->prefix.'suhoput_accounts',['user_id'=>$id]); wp_delete_user($id); }
}
