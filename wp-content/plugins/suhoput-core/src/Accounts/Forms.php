<?php
declare(strict_types=1);
namespace Suhoput\Core\Accounts;
use Suhoput\Core\Infrastructure\Accounts;

final class Forms
{
    public static function boot(): void
    {
        add_action('wp_loaded',static function (): void {
            remove_action('template_redirect',['WC_Form_Handler','save_account_details']);
            add_action('template_redirect',[self::class,'saveAccountDetails']);
        },0);
        add_action('woocommerce_before_customer_object_save',static function ($customer,$dataStore): void {
            // Session customers are not persistent accounts (guest checkout stays guest).
            if (is_a($dataStore->get_current_class_name(),'WC_Customer_Data_Store_Session',true)) { return; }
            if ($customer->get_id() === 0 && $customer->get_email() === '') { return; }
            $error=Accounts::validate((string)$customer->get_email(),(int)$customer->get_id());
            if ($error !== null) { throw new \WC_Data_Exception('suhoput_account',$error); }
            $customer->set_email(Accounts::normalize((string)$customer->get_email()));
        },PHP_INT_MAX,2);
        foreach (['woocommerce_enable_myaccount_registration'=>'yes','woocommerce_registration_generate_username'=>'yes','woocommerce_registration_generate_password'=>'no','woocommerce_enable_guest_checkout'=>'yes','woocommerce_enable_signup_and_login_from_checkout'=>'no'] as $option=>$value) {
            add_filter('pre_option_'.$option,static fn() => $value);
        }
        add_action('wp_loaded',[self::class,'normalizePost'],0);
        add_action('woocommerce_register_form_start',static function (): void { echo '<p class="suhoput-account-rule">'.esc_html(Accounts::RULE).'</p>'; });
        add_filter('woocommerce_process_registration_errors',static function ($errors,$username,$password,$email) {
            if (!$errors->has_errors()) { $error=Accounts::validate($email); if ($error !== null) { $errors->add('suhoput_account',Accounts::message($error)); } }
            return $errors;
        },PHP_INT_MAX,4);
        add_action('woocommerce_save_account_details_errors',static function ($errors,$user): void {
            if (!$errors->has_errors() && wc_notice_count('error') === 0) {
                $key=Accounts::normalize((string)($user->user_email ?? ''));
                $error=Accounts::validate((string)($user->user_email ?? ''),(int)$user->ID);
                if ($error !== null) { $errors->add('suhoput_account',Accounts::message($error)); } else { $user->user_email=$key; }
            }
        },PHP_INT_MAX,2);
        add_filter('registration_errors',static function ($errors,$login,$email) {
            $error=Accounts::validate($email);
            if ($error !== null) { $errors->remove('email_exists'); $errors->add('suhoput_account',Accounts::message($error)); }
            return $errors;
        },PHP_INT_MAX,3);
        add_filter('authenticate',static function ($user,$username,$password) {
            if (!$user && Accounts::normalize($username) !== null) { return wp_authenticate_email_password(null,Accounts::normalize($username),$password); }
            return $user;
        },15,3);
    }

    public static function saveAccountDetails(): void
    {
        try { \WC_Form_Handler::save_account_details(); }
        catch (\Throwable $e) {
            Accounts::abort();
            wc_add_notice('Не удалось сохранить аккаунт. Повторите попытку.','error');
        }
    }

    public static function normalizePost(): void
    {
        foreach (['email','account_email'] as $field) {
            if (isset($_POST[$field]) && is_string($_POST[$field])) { $_POST[$field]=wp_slash(strtolower(trim(wp_unslash($_POST[$field])))); }
        }
    }
}
