<?php

    /*
    Plugin Name: Appless Trusona for Web Authentication
    Plugin URI: https://wordpress.org/plugins/trusona-webauthn/
    Description: Login to your WordPress with Trusona’s FREE #NoPasswords plugin.
    Version: 0.0.1
    Author: Trusona
    Author URI: https://trusona.com
    License: MIT
    */

    defined('ABSPATH') or die();

    require_once plugin_dir_path(__FILE__) . 'includes/trusona-functions.php';
    require_once plugin_dir_path(__FILE__) . 'includes/jwt-functions.php';

class TrusonaWebAuthnOpenID
{
    public const PLUGIN_ID_PREFIX = 'trusona_openid_appless_';
    public const SCOPES           = 'offline_access offline openid';

    /* config parameters on admin page. */
    public static $PUBLIC_PARAMETERS = array(
      'only_trusona'            => 'Require #NoPasswords for Enabled Users',
      'self_service_onboarding' => 'Self-Service Onboarding',
      'disable_wp_form'         => 'Disable Default Form',
      'trusona_enabled'         => 'Enable Trusona',
    );

    public static $INTERNAL_PARAMETERS = array(
      'token_url'     => 'Token Validation URL',
      'client_secret' => 'Client Secret Key',
      'userinfo_url'  => 'Userinfo URL',
      'client_id'     => 'Client ID',
      'login_url'     => 'Login URL'
    );

    public static $PARAMETERS; // assigned in the constructor;

    public static $ERR_MES = array(
      1 => 'Cannot get authorization response',
      2 => 'Cannot get token response',
      3 => 'Cannot get user claims',
      4 => 'Cannot get valid token',
      5 => 'Cannot get user key',
      6 => 'User is not currently paired with Trusona.',
      7 => 'Cannot get dynamic registration to complete',
      8 => 'Unknown error',
      9 => 'You haven’t been authorized to access this WordPress site. Contact the admin for access',
      10 => 'Cannot validate ID Token'
    );

    public function __construct()
    {
        ob_start();

        $url = "https://trusonafy.me/.well-known/openid-configuration";

        $this->configuration = json_decode(file_get_contents($url));
        $this->jwks = json_decode(file_get_contents($this->configuration->jwks_uri), true);

        $this->callback_url = admin_url('admin-ajax.php?action=trusona_openid-callback');

        add_action('validate_registration_action', array($this, 'validate_registration'));
        do_action('validate_registration_action');

        add_action('wp_logout', array($this, 'trusona_openid_logout'));
        add_action('login_footer', array($this, 'login_footer'));
        add_action('login_form', array(&$this, 'login_form'));
        add_action('login_enqueue_scripts', array(&$this, 'add_trusona_jquery'));
        add_action('login_enqueue_scripts', array(&$this, 'add_trusona_css'));

        if (is_admin()) {
            add_action('wp_ajax_nopriv_trusona_openid-callback', array($this, 'callback'));
            add_action('wp_ajax_trusona_openid-callback', array($this, 'callback'));
            add_action('admin_notices', array($this, 'activation_email_notice_info'));
            add_action('admin_menu', array($this, 'admin_menu'));
            add_action('admin_init', array($this, 'admin_init'));

            add_filter('plugin_action_links_' . plugin_basename(__FILE__), array($this, 'filter_plugin_actions'));

            register_deactivation_hook(__FILE__, array($this, 'deactivate_trusona'));
            register_activation_hook(__FILE__, array($this, 'activate_defaults'));
            register_uninstall_hook(__FILE__, 'trusona_wp_uninstall');
        }

        self::$PARAMETERS = array_merge(self::$INTERNAL_PARAMETERS, self::$PUBLIC_PARAMETERS);

        foreach (self::$PARAMETERS as $key => $val) {
            $this->$key = get_option(self::PLUGIN_ID_PREFIX . $key);
        }
    }

    public function add_trusona_jquery()
    {
        if (!wp_script_is('jquery-core')) {
            wp_enqueue_script('jquery-core');
        }
    }

    public function add_trusona_css()
    {
        wp_enqueue_style(self::PLUGIN_ID_PREFIX . '0', 'https://static.trusona.net/web-sdk/1.2.1/css/trusona.css?' . time());
        wp_enqueue_style(self::PLUGIN_ID_PREFIX . '1', plugins_url('css/trusona-openid.css?'. time(), __FILE__));
    }

    public function activation_email_notice_info()
    {
        $user = wp_get_current_user();
        $when = (int)get_option(self::PLUGIN_ID_PREFIX . 'activation');

        if ($user instanceof WP_User && time() < ($when + 15)) { // show notice for 15 seconds after activation
            $notice = '';

            $notice .= '<div class="notice notice-info is-dismissible">';
            $notice .= '<p>Please add <span style="font-weight:bold;">' . $user->user_email . '</span>';
            $notice .= '&nbsp;to your Trusona app to complete setup.';
            $notice .= '</p></div>';

            echo $notice;
        }
    }

    public function activate_defaults()
    {
        if ($this->is_not_registered()) {
            $this->remote_registration();
        }

        if ($this->is_registered()) {
            update_option(self::PLUGIN_ID_PREFIX . 'self_service_onboarding', false);
            update_option(self::PLUGIN_ID_PREFIX . 'disable_wp_form', false);
            update_option(self::PLUGIN_ID_PREFIX . 'trusona_enabled', true);
            update_option(self::PLUGIN_ID_PREFIX . 'activation', time());
        }
    }

    private function is_not_registered()
    {
        return !get_option(self::PLUGIN_ID_PREFIX . 'client_id', false)
        || !get_option(self::PLUGIN_ID_PREFIX . 'client_secret', false)
        || !get_option(self::PLUGIN_ID_PREFIX . 'registration_access_token', false);
    }

    private function is_registered()
    {
        return !$this->is_not_registered();
    }

    public function validate_registration()
    {
        $token = get_option(self::PLUGIN_ID_PREFIX . 'registration_access_token');
        $uri = get_option(self::PLUGIN_ID_PREFIX . 'registration_client_uri');

        if ($token !== false && $uri !== false) {
            // read this ... https://datatracker.ietf.org/doc/html/rfc7592
            $authorization = 'Bearer ' . $token;
            $headers = array('accept' => '*/*', 'authorization' => $authorization, 'user-agent' => user_agent());
            $response = wp_safe_remote_get($uri, array('headers' => $headers));
            $body = json_decode(wp_remote_retrieve_body($response));

            if (success($response['response']['code'])) {
                return;
            }
        }

        $this->remote_registration();
    }

    private function site_name()
    {
        $site_name = get_bloginfo('name');
        return !isset($site_name) || trim($site_name) == '' ? 'blog-without-name' : trim($site_name);
    }

    private function remote_registration()
    {
        $body = array(
          'token_endpoint_auth_method' => 'client_secret_post',
          'redirect_uris' => array($this->callback_url),
          'scope' => self::SCOPES,
          'client_name' => $this->site_name(),
          'grant_types' => array('implicit', 'authorization_code'),
          'response_types' => array('code', 'id_token')
        );

        $headers = array('content-type' => 'application/json', 'user-agent' => user_agent());

        // reference - https://openid.net/specs/openid-connect-registration-1_0.html
        $response = wp_safe_remote_post(
            $this->configuration->registration_endpoint,
            array('headers' => $headers, 'body' => json_encode($body))
        );

        if (is_array($response) && intval($response['response']['code']) == 201) {
            $body = json_decode(wp_remote_retrieve_body($response));

            $this->registration_access_token = $body->registration_access_token;
            $this->registration_client_uri = $body->registration_client_uri;
            $this->client_secret = $body->client_secret;
            $this->client_name = $body->client_name;
            $this->client_id = $body->client_id;

            update_option(self::PLUGIN_ID_PREFIX . 'registration_access_token', $this->registration_access_token);
            update_option(self::PLUGIN_ID_PREFIX . 'registration_client_uri', $this->registration_client_uri);
            update_option(self::PLUGIN_ID_PREFIX . 'client_secret', $this->client_secret);
            update_option(self::PLUGIN_ID_PREFIX . 'client_name', $this->client_name);
            update_option(self::PLUGIN_ID_PREFIX . 'client_id', $this->client_id);

            $this->debug_log("IDP registration completed successfully");
        } else {
            $this->debug_log("IDP registration failed");
        }
    }

    public function deactivate_trusona()
    {
        delete_option(self::PLUGIN_ID_PREFIX . 'userinfo_url');
        delete_option(self::PLUGIN_ID_PREFIX . 'self_service_onboarding');
        delete_option(self::PLUGIN_ID_PREFIX . 'disable_wp_form');
        delete_option(self::PLUGIN_ID_PREFIX . 'trusona_enabled');
        delete_option(self::PLUGIN_ID_PREFIX . 'login_url');
        delete_option(self::PLUGIN_ID_PREFIX . 'token_url');
        delete_option(self::PLUGIN_ID_PREFIX . 'activation');
        delete_option(self::PLUGIN_ID_PREFIX . 'client_id');
        delete_option(self::PLUGIN_ID_PREFIX . 'client_secret');
    }

    public function callback()
    {
        if (!isset($_GET['code'], $_GET['state'])) {
            $this->error_redirect(1);
            return;
        } elseif (isset($_GET['error'])) {
            $this->error_redirect(8);
            return;
        }

        $response = wp_remote_post(
            $this->configuration->token_endpoint,
            array(
              'headers' => array('content-type' => 'application/x-www-form-urlencoded'),
              'body' => array(
                'code'          => $_GET['code'],
                'state'         => $_GET['state'],
                'nonce'         => random_nonce(),
                'client_id'     => $this->client_id,
                'client_secret' => $this->client_secret,
                'redirect_uri'  => $this->callback_url,
                'grant_type'    => 'authorization_code'
              ))
        );

        if (is_wp_error($response)) {
            $this->error_redirect(2);
            return;
        }

        $response = json_decode(wp_remote_retrieve_body($response));
        $jwt = decode_jwt($response->id_token, $this->jwks);

        if (is_null($jwt)) {
            $this->error_redirect(10);
            return;
        }

        $subject = strtolower($jwt->sub);
        $user = get_user_by('email', $subject);

        if (isset($user) && $user instanceof WP_User && intval($user->ID) > 0) {
            list($is_admin, $user) = $this->has_admin(array($user));
            wp_set_auth_cookie($user->ID, false);

            update_user_meta($user->ID, self::PLUGIN_ID_PREFIX . 'enabled', true);
            update_user_meta($user->ID, self::PLUGIN_ID_PREFIX . 'paired', true);

            if ($is_admin) {
                wp_safe_redirect(admin_url());
            } else {
                wp_safe_redirect(home_url());
            }
            exit;
        }

        $self_service = get_option(self::PLUGIN_ID_PREFIX . 'self_service_onboarding');

        if ($self_service) {
            $email = $subject;
            $password = hash('whirlpool', base64_encode(random_nonce() . $email . time()));
            $value = wp_create_user($email, $password, $email);

            if (is_wp_error($value)) {
                $this->debug_log("failed at creating self-service account");
                $this->error_redirect(9);
            } else {
                $this->debug_log("successfully created self-service account");
                wp_set_auth_cookie($value, false, false);

                update_user_meta($value, self::PLUGIN_ID_PREFIX . 'enabled', true);
                update_user_meta($value, self::PLUGIN_ID_PREFIX . 'paired', true);

                wp_safe_redirect(home_url());
                exit;
            }
        } else {
            $this->error_redirect(9);
        }
    }

    public function admin_init()
    {
        register_setting('trusona_options_group', 'trusona_keys');
        add_settings_section('setting_section_id', 'Trusona WordPress Settings', null, 'trusona-admin-settings');
    }

    public function admin_menu()
    {
        add_options_page('Trusona', 'Trusona', 'manage_options', 'trusona-admin-settings', array($this, 'create_admin_menu'));

        if (isset($_POST['option_page']) && $_POST['option_page'] === 'trusona_options_group') {
            $checked = (bool)(isset($_POST['trusona_keys']['disable_wp_form']));
            update_option(self::PLUGIN_ID_PREFIX . 'disable_wp_form', $checked);

            $checked = (bool)(isset($_POST['trusona_keys']['self_service_onboarding']));
            update_option(self::PLUGIN_ID_PREFIX . 'self_service_onboarding', $checked);
        }
    }

    public function print_bool_field($key)
    {
        $value = $this->$key ? 'value="1" checked="checked"' : 'value="0"';
        echo '<input type="checkbox" id="' . $key . '" name="trusona_keys[' . $key . ']" ' . $value . ' >';
    }

    public function create_admin_menu()
    {
        echo '<div class="wrap">';
        screen_icon();
        echo '<table class="form-table"><tbody>';
        echo '<form method="post" action="options.php">';
        settings_fields('trusona_options_group');
        do_settings_sections('trusona-admin-settings');

        echo '<tr><td style="vertical-align: top;" width="2em">';
        $this->print_bool_field('disable_wp_form');
        echo '</td><td>Trusona ONLY Mode <br/><br/>';
        echo '<span style="font-size: smaller;">';
        echo '<span style="color: red; font-weight: bolder;">WARNING!</span>&nbsp;';
        echo 'By checking this box, you disable the ability to toggle between <span style="font-weight: bolder;">Login with Trusona</span> and username and passwords.<br/>';
        echo 'You should make this selection ONLY if you have access to the WP server independent of the login page, as otherwise you <br/>are blocking all other options to login.';
        echo '</span></td></tr>';

        echo '<tr><td style="vertical-align: top;" width="2em">';
        $this->print_bool_field('self_service_onboarding');
        echo '</td><td>Self-Service Account Creation<br/><br/>';
        echo '<span style="font-size: smaller;">';
        echo '<span style="color: red; font-weight: bolder;">WARNING!</span>&nbsp;';
        echo 'By checking this box, you allow the Trusona plugin to create basic (subscriber) accounts for your WordPress site if an <br/>';
        echo 'account is not found for that Trusona user - thus allowing for a true <span style="font-weight: bolder;">#NoPasswords</span> experience!<br/>';

        echo '</span></td></tr>';
        echo '<tr><td colspan="2">';
        submit_button();
        echo '</td></tr>';
        echo '<tr><td style="color: #c0c0c0; font-size: smaller;" colspan="2">PHP ' . phpversion();
        echo '<br/>WordPress ' . get_bloginfo('version') . '</td></tr>';
        echo '</form></tbody></table></div>';
    }

    public function filter_plugin_actions($links)
    {
        $settings_link = '<a href="options-general.php?page=trusona-admin-settings">Settings</a>';
        array_unshift($links, $settings_link); // before other links
        return $links;
    }

    private function has_admin($users)
    {
        $regular_user = null;

        foreach ($users as $user) {
            if (in_array('administrator', $user->roles)) {
                return array(true, $user);
            } else {
                if (is_null($regular_user)) {
                    $regular_user = $user;
                }
            }
        }

        return array(false, $regular_user);
    }

    private function error_redirect($errno, $authed_user_id = null)
    {
        $url = wp_login_url() . '?trusona-openid-error=' . $errno;

        if (isset($authed_user_id)) {
            $url .= '&authed_user_id=' . $authed_user_id;
        }

        wp_safe_redirect($url);
        exit;
    }

    /**
     * logout method - called from wp_logout action
     */
    public function trusona_openid_logout()
    {
        wp_clear_auth_cookie();
        wp_safe_redirect(admin_url('index.php'));
        exit;
    }

    private function build_openid_url($redirect_url)
    {
        return $this->configuration->authorization_endpoint . '?state=' . hash('ripemd160', random_bytes(2048))
               . '&nonce=' . hash('ripemd160', random_bytes(2048))
               . '&scope=' . urlencode(self::SCOPES)
               . '&response_type=code&client_id=' . urlencode($this->client_id)
               . '&redirect_uri=' . urlencode($redirect_url);
    }

    public function login_form()
    {
        if ($this->trusona_enabled) {
            $url = $this->build_openid_url($this->callback_url);

            $this->disable_wp_form = apply_filters('trusona_login_form_disable_wp_form', $this->disable_wp_form);

            if ($this->disable_wp_form) {
                $html = ob_get_clean();
                $x    = strpos($html, '<form name="loginform" ');

                if ($x > 0) {
                    $html = substr($html, 0, $x) . trusona_custom_login($url, false);
                }

                ob_start();
            } else {
                $html = trusona_custom_login($url, true);
            }

            echo $html;
        }
    }

    public function login_footer()
    {
        if ($this->trusona_enabled) {
            $this->disable_wp_form = apply_filters('trusona_login_footer_disable_wp_form', $this->disable_wp_form);

            if ($this->disable_wp_form) {
                $html = ob_get_clean();

                $html = $this->remove_block($html, '<p class="forgetmenot">', '</form>');
                $html = $this->remove_block($html, '<p id="nav">', '</p>');
                ob_start();

                echo $html;
            }
        }
    }

    private function remove_block($html, $selector, $end)
    {
        $x = strpos($html, $selector);
        $y = strpos($html, $end, $x);

        if ($x > 0 && $y > 0) {
            $html = substr_replace($html, null, $x, ($y + strlen($end)) - $x);
        }

        return $html;
    }

    private function debug_log($message)
    {
        if (WP_DEBUG) {
            error_log($message);
        }
    }
}

new TrusonaWebAuthnOpenID();

function trusona_wp_uninstall()
{
    foreach (TrusonaWebAuthnOpenID::$PARAMETERS as $key => $val) {
        if (WP_DEBUG) {
            error_log("deleting " . TrusonaWebAuthnOpenID::PLUGIN_ID_PREFIX . $key);
        }
        delete_option(TrusonaWebAuthnOpenID::PLUGIN_ID_PREFIX . $key);
    }

    $users = get_users(array('meta_key' => TrusonaWebAuthnOpenID::PLUGIN_ID_PREFIX . 'enabled'));

    foreach ($users as $user) {
        delete_user_meta($user->ID, TrusonaWebAuthnOpenID::PLUGIN_ID_PREFIX . 'subject_id');
        delete_user_meta($user->ID, TrusonaWebAuthnOpenID::PLUGIN_ID_PREFIX . 'enabled');
        delete_user_meta($user->ID, TrusonaWebAuthnOpenID::PLUGIN_ID_PREFIX . 'paired');
    }
}
