#!/usr/bin/env php
<?php

  // include helper
  require_once(__DIR__."/helper.php");

  function decryptMetaData($file, $private_key, $user_name) {
    // parse the meta data file
    $json = json_decode($file, true, 4, JSON_OBJECT_AS_ARRAY);

    // find the encrypted meta data key
    $metadatakey = null;
    foreach ($json["users"] as $item) {
      if (0 === strcasecmp($item["userId"], $user_name)) {
        $metadatakey = base64_decode($item["encryptedMetadataKey"]);
      }
    }

    // parse the encrypted meta data
    $parts      = explode("|", $json["metadata"]["ciphertext"]);
    $ciphertext = substr(base64_decode($parts[0]), 0, -16);
    $nonce      = base64_decode($parts[1]);

    // decrypt the meta data key
    $secret = rsaDecrypt($metadatakey, $private_key);

    // decrypt the meta data
    $nonce    = convertGCMtoCTR($nonce, $secret, "aes-128-ecb");
    $metadata = openssl_decrypt($ciphertext, "aes-128-ctr", $secret, OPENSSL_RAW_DATA, $nonce);

    // decompress the meta data
    $output = gzdecode($metadata);

    return $output;
  }

  if (!defined("IGNORE_MAIN")) {
    function main($arguments) {
      // read the file contents
      if (array_key_exists(1, $arguments)) {
        $file = @file_get_contents($arguments[1]);
      }

      // read the private key
      if (array_key_exists(2, $arguments)) {
        $private_key = @file_get_contents($arguments[2]);
      }

      // derive the user name from the private key
      if (array_key_exists(2, $arguments)) {
        $user_name = basename($arguments[2], ".private.key");
      }

      print(decryptMetaData($file, $private_key, $user_name));

      // return exit code of the script
      return 0;
    }

    // parse the .env file
    $ini = parse_ini_file(__DIR__."/.env");
    if (is_array($ini)) {
      foreach ($ini as $key => $value) {
        putenv("$key=$value");
      }
    }

    // execute the main method
    exit(main($argv));
  }

