#!/usr/bin/env php
<?php

  function decryptJson($file) {
    // parse the JSON content file
    $parts      = explode("|", $file);
    $ciphertext = hex2bin($parts[0]);
    $iv         = hex2bin($parts[1]);

    // derive the decryption key
    $secret = substr(hash_hkdf("sha512", getenv("SECRET")), 0, 32);
    $secret = hash_pbkdf2("sha1", $secret, "phpseclib", 1000, 16, true);

    // decrypt the JSON content
    $json = openssl_decrypt($ciphertext, "aes-128-cbc", $secret, OPENSSL_RAW_DATA, $iv);

    // parse the JSON content
    $json   = json_decode($json, true);
    $output = base64_decode($json["key"]);

    return $output;
  }

  if (!defined("IGNORE_MAIN")) {
    function main($arguments) {
      // read the file contents
      if (array_key_exists(1, $arguments)) {
        $file = @file_get_contents($arguments[1]);
      }

      print(decryptJson($file));

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

