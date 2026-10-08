<?php
declare(strict_types=1);
namespace Suhoput\Core\Orders;

final class Forms
{
    public const REQUEST_NOTICE = 'Если данные верны, письмо для подтверждения доступа отправлено. Откройте его в этом браузере.';
    public const DENIED = 'Подтверждение недоступно. Запросите новое письмо в том же браузере.';

    public static function boot(): void
    {
        add_action('template_redirect',[self::class,'prepare'],0);
        add_action('template_redirect',[self::class,'handle'],1);
        add_action('wp_loaded',static function(): void {
            // Native payment POST is processed before template_redirect.
            if (isset($_POST['woocommerce_pay'])) {
                $id=wc_get_order_id_by_order_key(self::input($_GET,'key'));
                if (!Access::canView(wc_get_order($id),get_current_user_id())) { self::deny(); }
            }
        },15);
        add_action('woocommerce_before_customer_login_form',[self::class,'render']);
        add_action('woocommerce_before_my_account',[self::class,'render']);
        add_action('init',static function(): void {
            // The stock tracking shortcode treats a typed email as sufficient proof.
            add_shortcode('woocommerce_order_tracking',static function(): string { ob_start(); self::render(); return ob_get_clean(); });
        },30);
    }

    private static function input(array $source,string $key): string
    {
        return isset($source[$key]) && is_string($source[$key]) ? wp_unslash($source[$key]) : '';
    }

    private static function id(string $value): int
    {
        return preg_match('/\A[1-9][0-9]*\z/',$value) ? (int)$value : 0;
    }

    public static function prepare(): void
    {
        $tracking=is_singular() && has_shortcode((string)get_post()?->post_content,'woocommerce_order_tracking');
        if (is_account_page() || is_checkout() || $tracking) {
            nocache_headers(); header('Cache-Control: private, no-store, max-age=0'); header('Referrer-Policy: no-referrer'); header('Vary: Cookie',false);
            if (Access::browserHash() === null) {
                $value=bin2hex(random_bytes(32));
                setcookie(Access::COOKIE,$value,['expires'=>time()+86400,'path'=>'/','secure'=>is_ssl(),'httponly'=>true,'samesite'=>'Lax']);
                $_COOKIE[Access::COOKIE]=$value;
            }
        }
        global $wp;
        foreach (['view-order','order-received','order-pay'] as $endpoint) {
            if (isset($wp->query_vars[$endpoint]) && !Access::canView(wc_get_order((int)$wp->query_vars[$endpoint]),get_current_user_id())) { self::deny(); }
        }
    }

    private static function deny(): never
    {
        nocache_headers(); header('Cache-Control: private, no-store, max-age=0');
        wp_die('Заказ недоступен. Подтвердите владение в кабинете.','Заказ недоступен.',['response'=>404]);
    }

    public static function handle(): void
    {
        if (!isset($_POST['suhoput_order_action'])) { return; }
        $action=self::input($_POST,'suhoput_order_action');
        if (!wp_verify_nonce(self::input($_POST,'suhoput_order_nonce'),'suhoput_order_access')) { wc_add_notice(self::DENIED,'error'); return; }
        $id=self::id(self::input($_POST,'suhoput_order_id'));
        $purpose=self::input($_POST,'suhoput_purpose');
        $user=get_current_user_id();
        if ($action === 'request') {
            Access::requestProof($id,self::input($_POST,'suhoput_email'),$purpose,$user);
            wc_add_notice(self::REQUEST_NOTICE,'notice');
        } elseif ($action === 'confirm') {
            if (Access::consume($id,self::input($_POST,'suhoput_token'),$purpose,$user)) {
                $order=wc_get_order($id);
                $url=$purpose === 'claim' ? $order->get_view_order_url() : add_query_arg('suhoput_guest_order',$id,wc_get_page_permalink('myaccount'));
                wp_safe_redirect($url); exit;
            }
            wc_add_notice(self::DENIED,'error');
        }
    }

    public static function render(): void
    {
        $id=self::id(self::input($_GET,'suhoput_guest_order'));
        if ($id && Access::canView(wc_get_order($id),get_current_user_id())) {
            $order=wc_get_order($id);
            echo '<section class="suhoput-proven-order"><h3>Заказ №'.esc_html($order->get_order_number()).'</h3><p>'.esc_html(wc_get_order_status_name($order->get_status())).'</p>';
            woocommerce_order_details_table($id); echo '</section>';
        }
        $confirm=self::id(self::input($_GET,'suhoput_proof_order'));
        if ($confirm) {
            echo '<form class="suhoput-order-confirm" method="post" action="'.esc_url(wc_get_page_permalink('myaccount')).'">';
            wp_nonce_field('suhoput_order_access','suhoput_order_nonce');
            foreach (['suhoput_order_id'=>(string)$confirm,'suhoput_token'=>self::input($_GET,'suhoput_token'),'suhoput_purpose'=>self::input($_GET,'suhoput_purpose')] as $name=>$value) {
                echo '<input type="hidden" name="'.esc_attr($name).'" value="'.esc_attr($value).'">';
            }
            echo '<p>Подтвердите получение доступа. Для привязки заказа войдите в аккаунт, из которого запрашивали письмо.</p><button name="suhoput_order_action" value="confirm">Подтвердить доступ</button></form>';
        }
        echo '<form class="suhoput-order-request" method="post" action="'.esc_url(wc_get_page_permalink('myaccount')).'"><h3>Доступ к гостевому заказу</h3>';
        wp_nonce_field('suhoput_order_access','suhoput_order_nonce');
        echo '<p><label>Номер заказа <input name="suhoput_order_id" inputmode="numeric" pattern="[1-9][0-9]*" required></label></p><p><label>Email заказа <input type="email" name="suhoput_email" required></label></p>';
        echo '<p><label>Действие <select name="suhoput_purpose"><option value="view">Посмотреть заказ</option>';
        if (get_current_user_id() > 0) { echo '<option value="claim">Привязать к моему аккаунту</option>'; }
        echo '</select></label></p><button name="suhoput_order_action" value="request">Получить письмо для подтверждения</button></form>';
    }
}
