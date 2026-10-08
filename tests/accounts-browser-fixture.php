<?php
if (wp_get_environment_type() !== 'local' || !defined('SUHOPUT_LOCAL_SAFETY')) { throw new RuntimeException('Local tests only.'); }
[$tag,$mode]=$args;
if (!preg_match('/\Aweb-[a-f0-9]{12}\z/',$tag)) { throw new RuntimeException('Invalid fixture.'); }
global $wpdb;
$name='suhoput_test_'.$tag; $table=$wpdb->prefix.'suhoput_accounts'; $state=get_option($name,[]);
if ($mode === 'setup') {
    $user=wp_insert_user(['user_login'=>$tag.'-other','user_email'=>$tag.'-other@example.invalid','user_pass'=>wp_generate_password(28),'role'=>'customer']);
    if (is_wp_error($user)) { throw new RuntimeException('Fixture creation failed.'); }
    $product=new WC_Product_Simple(); $product->set_name('Account checkout fixture'); $product->set_regular_price('100'); $product->set_status('publish'); $product->update_meta_data('_suhoput_account_fixture',$tag); $product->save();
    $state=['product'=>$product->get_id()]; add_option($name,$state,'','no');
    echo wp_json_encode(['account'=>wc_get_page_permalink('myaccount'),'checkout'=>wc_get_checkout_url(),'product'=>$product->get_id()])."\n"; return;
}
if ($mode === 'guest') {
    $before=(int)$wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$wpdb->users} WHERE user_email=%s",$tag.'-changed@example.invalid'));
    $order=wc_create_order(['customer_id'=>0]); $order->set_billing_email($tag.'-changed@example.invalid'); $order->update_meta_data('_suhoput_account_fixture',$tag); $order->save();
    $state['order']=$order->get_id(); update_option($name,$state,false);
    if ($order->get_customer_id() !== 0 || $before !== (int)$wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$wpdb->users} WHERE user_email=%s",$tag.'-changed@example.invalid'))) { throw new RuntimeException('Guest account changed.'); }
    echo "GUEST_PRESERVED\n"; return;
}
if ($mode === 'verify') {
    $rows=$wpdb->get_results($wpdb->prepare("SELECT u.ID,u.user_email,a.buyer_type,a.email_key FROM {$wpdb->users} u LEFT JOIN {$table} a ON a.user_id=u.ID WHERE u.user_email LIKE %s",$wpdb->esc_like($tag).'%@example.invalid'),ARRAY_A);
    if (count($rows) !== 2) { throw new RuntimeException('Unexpected account count.'); }
    foreach ($rows as $row) { if ($row['buyer_type'] !== 'retail' || $row['email_key'] !== $row['user_email']) { throw new RuntimeException('Wrong binding/type.'); } }
    echo "BROWSER_VERIFIED\n"; return;
}
if ($mode !== 'cleanup') { throw new RuntimeException('Invalid mode.'); }
foreach (['order','product'] as $kind) {
    if (isset($state[$kind])) {
        $object=$kind === 'order' ? wc_get_order($state[$kind]) : wc_get_product($state[$kind]);
        if (!$object || $object->get_meta('_suhoput_account_fixture') !== $tag) { throw new RuntimeException('Fixture ownership mismatch.'); }
        $object->delete(true);
    }
}
require_once ABSPATH.'wp-admin/includes/user.php';
foreach ($wpdb->get_results($wpdb->prepare("SELECT ID,user_email FROM {$wpdb->users} WHERE user_email LIKE %s",$wpdb->esc_like($tag).'%@example.invalid')) as $row) {
    if (!str_starts_with($row->user_email,$tag) || get_userdata($row->ID)->roles !== ['customer']) { throw new RuntimeException('User ownership mismatch.'); }
    $wpdb->delete($table,['user_id'=>$row->ID]); wp_delete_user($row->ID);
}
delete_option($name); echo "CLEANUP\n";
