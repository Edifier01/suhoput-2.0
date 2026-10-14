<?php
use Suhoput\Core\Orders\Access;
if (wp_get_environment_type() !== 'local' || !defined('SUHOPUT_LOCAL_SAFETY')) { throw new RuntimeException('Local tests only.'); }
[$tag,$mode]=$args;
if (!preg_match('/\Aorders-[a-f0-9]{12}\z/',$tag)) { throw new RuntimeException('Invalid fixture'); }
global $wpdb;
$key='suhoput_test_'.$tag; $state=get_option($key,[]); $table=$wpdb->prefix.'suhoput_order_access';
if ($mode === 'setup') {
    $state=['users'=>[],'orders'=>[]]; add_option($key,$state,'','no');
    foreach (['one','two'] as $suffix) {
        $id=wp_insert_user(['user_login'=>$tag.$suffix,'user_email'=>$tag.$suffix.'@example.invalid','user_pass'=>$args[2],'role'=>'customer']);
        if (is_wp_error($id)) { throw new RuntimeException('Fixture user failed'); }
        $state['users'][$suffix]=$id; update_option($key,$state,false);
    }
    $wpdb->update($wpdb->prefix.'suhoput_accounts',['buyer_type'=>'wholesale','access_enabled'=>0,'counterparty_id'=>$tag],['user_id'=>$state['users']['one']]);
    $output=['account'=>wc_get_page_permalink('myaccount'),'checkout'=>wc_get_checkout_url(),'orders'=>[]];
    $types=['own'=>$state['users']['one'],'foreign'=>$state['users']['two'],'manual'=>$state['users']['one'],'guest'=>0,'race'=>0];
    foreach (array_keys(wc_get_order_statuses()) as $status) { $types['state-'.substr($status,3)]=$state['users']['one']; }
    foreach ($types as $name=>$owner) {
        $order=wc_create_order(['customer_id'=>$owner]); $state['orders'][$name]=$order->get_id(); update_option($key,$state,false);
        $order->update_meta_data('_suhoput_history_fixture',$tag);
        if ($name !== 'manual') { $order->update_meta_data('_suhoput_origin','site'); }
        $order->update_meta_data('_suhoput_external_order_id','private-external-'.$tag);
        $order->set_billing_email($tag.'one@example.invalid'); $order->set_billing_first_name('Private '.$name);
        if (str_starts_with($name,'state-')) { $order->set_status(substr($name,6)); }
        $item=new WC_Order_Item_Product(); $item->set_name('Private item '.$name); $item->set_quantity(1); $item->set_total('100'); $order->add_item($item); $order->calculate_totals(); $order->save();
        $output['orders'][$name]=['id'=>$order->get_id(),'key'=>$order->get_order_key(),'received'=>$order->get_checkout_order_received_url(),'pay'=>$order->get_checkout_payment_url(),'view'=>$order->get_view_order_url()];
    }
    $page=wp_insert_post(['post_type'=>'page','post_status'=>'publish','post_title'=>'Local order proof fixture','post_content'=>'[woocommerce_order_tracking]']);
    update_post_meta($page,'_suhoput_history_fixture',$tag); $state['page']=$page; update_option($key,$state,false); $output['tracking']=get_permalink($page);
    echo wp_json_encode($output)."\n"; return;
}
if ($mode === 'race-setup') {
    $_COOKIE[Access::COOKIE]=$args[2]; $purpose=$args[3]; $user=$purpose === 'claim' ? $state['users']['one'] : 0; wp_set_current_user($user);
    $id=$state['orders']['race']; $wpdb->update($table,['requested_at'=>time()-61],['order_id'=>$id]);
    $token=null;
    add_filter('wp_mail',static function($mail) use(&$token) { if (preg_match('/suhoput_token=([a-f0-9]{64})/',$mail['message'],$m)) { $token=$m[1]; } return $mail; });
    if (!Access::requestProof($id,$tag.'one@example.invalid',$purpose,$user) || !$token) { throw new RuntimeException('Race setup failed'); }
    echo wp_json_encode(['token'=>$token])."\n"; return;
}
if ($mode === 'race-consume') {
    $_COOKIE[Access::COOKIE]=$args[2]; $purpose=$args[4]; $user=$purpose === 'claim' ? $state['users']['one'] : 0; wp_set_current_user($user);
    echo Access::consume($state['orders']['race'],$args[3],$purpose,$user) ? "WIN\n" : "DENIED\n"; return;
}
if ($mode === 'rest-nonce') {
    // Generate nonce for the actual browser session token supplied by the test runner.
    wp_set_current_user($state['users'][$args[2]]); $_COOKIE[LOGGED_IN_COOKIE]=rawurldecode($args[3]);
    echo wp_create_nonce('wp_rest')."\n"; return;
}
if ($mode === 'advance-guest') { $wpdb->update($table,['requested_at'=>time()-61],['order_id'=>$state['orders']['guest']]); echo "ADVANCED\n"; return; }
if ($mode === 'verify') {
    if ((new WC_Order($state['orders']['guest']))->get_customer_id() !== $state['users']['one']) { throw new RuntimeException('Claim missing'); }
    echo "VERIFIED\n"; return;
}
if ($mode !== 'cleanup') { throw new RuntimeException('Invalid mode'); }
foreach ($state['orders'] ?? [] as $id) {
    $order=wc_get_order($id);
    if (!$order || $order->get_meta('_suhoput_history_fixture') !== $tag) { throw new RuntimeException('Order fixture ownership mismatch'); }
    $wpdb->delete($table,['order_id'=>$id]); $order->delete(true);
}
if (isset($state['page'])) { if (get_post_meta($state['page'],'_suhoput_history_fixture',true) !== $tag) { throw new RuntimeException('Page ownership mismatch'); } wp_delete_post($state['page'],true); }
require_once ABSPATH.'wp-admin/includes/user.php';
foreach ($state['users'] ?? [] as $id) {
    if (get_userdata($id)->user_email !== $tag.(array_search($id,$state['users'],true)).'@example.invalid') { throw new RuntimeException('User fixture ownership mismatch'); }
    $wpdb->delete($wpdb->prefix.'suhoput_accounts',['user_id'=>$id]); wp_delete_user($id);
}
delete_option($key); echo "CLEANUP\n";
