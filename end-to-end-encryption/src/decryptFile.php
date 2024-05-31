#!/usr/bin/env php
<?php

  // include helper
  require_once(__DIR__."/helper.php");

  function decryptFile($file, $meta_data, $file_name) {
    // parse the meta data
    $json   = json_decode($meta_data, true, 4, JSON_OBJECT_AS_ARRAY);
    $nonce  = base64_decode($json["files"][$file_name]["nonce"]);
    $secret = base64_decode($json["files"][$file_name]["key"]);

    // decrypt the file
    $nonce  = convertGCMtoCTR($nonce, $secret, "aes-128-ecb");
    $output = openssl_decrypt(substr($file, 0, -16), "aes-128-ctr", $secret, OPENSSL_RAW_DATA, $nonce);

    return $output;
  }

  if (!defined("IGNORE_MAIN")) {
    function main($arguments) {
      // read the file
      if (array_key_exists(1, $arguments)) {
        $file = @file_get_contents($arguments[1]);
      }

      // read the meta data
      if (array_key_exists(2, $arguments)) {
        $meta_data = @file_get_contents($arguments[2]);
      }

      // derive the file name from the file
      if (array_key_exists(1, $arguments)) {
        $file_name = basename($arguments[1]);
      }

      print(decryptFile($file, $meta_data, $file_name));

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

