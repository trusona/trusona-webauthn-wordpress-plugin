<?php

function scim_user_registration($url, $token, $email) {
  $json = <<<JSON
  {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "$email",
    "name": {
      "givenName": "",
      "familyName": ""
    }
  }
  JSON;

  $headers = array(
    'Authorization' => "Bearer $token",
    'content-type' => 'application/scim+json',
    'accept' => 'application/scim+json'
  );

  try {
    $response = wp_safe_remote_post($url, array('headers' => $headers, 'body' => $json));
  } catch (Exception $e) { }
}
