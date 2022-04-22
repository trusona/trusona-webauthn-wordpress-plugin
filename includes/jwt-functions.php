<?php

require_once plugin_dir_path(__FILE__) . '../vendor/autoload.php';

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;

function decode_jwt($token, $jwks)
{
    try {
        return JWT::decode($token, JWK::parseKeySet($jwks));
    } catch (Exception $e) {
        return null;
    }
}
