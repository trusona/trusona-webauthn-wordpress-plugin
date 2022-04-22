<?php

function is_production($url)
{
    return strpos($url, '.staging.') === false;
}

function success($code)
{
    return intval($code) >= 200 && intval($code) < 300;
}

function random_nonce()
{
    return hash('ripemd160', random_bytes(2048));
}

function basic_auth_header($username, $password)
{
    return base64_encode($username . ':' . $password);
}

function user_agent()
{
    return 'WordPress ' . get_bloginfo('version') . '; ' . home_url();
}

function trusona_custom_login($url, $allow_wp_form)
{
    $allow_wp_form = apply_filters('trusona_allow_wp_form', $allow_wp_form, $url);

    $data = '<div>';

    if ($allow_wp_form) {
        $data .= '<style type="text/css">form > p {display: none;} p#nav {display: none;} .user-pass-wrap {display: none;}</style>';
    }

    $data .= '<div><a href="' . $url . '" alt="Login with Biometrics" style="text-decoration:none;font-size:1.3em;" class="appless-employee-button">Login with Biometrics</a></div>';

    if (isset($_GET['trusona-openid-error'])) {
        $err_code = $_GET['trusona-openid-error'];
        $message  = TrusonaOpenID::$ERR_MES[$err_code];

        $data .= trusona_error_message($message);
    }

    if ($allow_wp_form) {
        $data .= '<div style="text-align: center;"><br/><script>jQuery(document).ready(function() { jQuery(\'#login\').width(\'350px\').addClass(\'login_center\'); });</script>';
        $data .= '<a href="#" style="font-size:smaller;color:#c0c0c0;" onclick="jQuery(\'form > p\').toggle();jQuery(\'.user-pass-wrap\').toggle();jQuery(\'#user_pass\').prop(\'disabled\',false);this.blur();return false;">Toggle Classic Login</a></div><br/>';
    }

    $data .= '</div>';

    return $data;
}

function trusona_error_message($message)
{
    $str = '<div style="text-align:center;margin-top:2em;color:#907878;background-color:#f1e8e5;border:1px solid darkgray;width:100%;border-radius:3px;font-weight:bolder;">';
    $str .= '<p style="line-height:1.6em;">' . $message . '</p></div><br/>';

    return $str;
}
