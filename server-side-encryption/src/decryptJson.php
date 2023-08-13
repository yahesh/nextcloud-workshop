#!/usr/bin/env php
<?php

  function decryptJson($file) {
    $parts      = explode("|", $file);
    $ciphertext = hex2bin($parts[0]);
    $iv         = hex2bin($parts[1]);

    // derive the decryption key
    $secret = substr(hash_hkdf("sha512", getenv("SECRET")), 0, 32);
    $secret = hash_pbkdf2("sha1", $secret, "phpseclib", 1000, 16, true);

    // decrypt the JSON content
    $json = openssl_decrypt($ciphertext, "aes-128-cbc", $secret, OPENSSL_RAW_DATA, $iv);

    // JSON-decode the JSON content
    $json = json_decode($json, true);

    // base64-decode the JSON value
    $output = base64_decode($json["key"]);

    return $output;
  }

  if (!defined("IGNORE_MAIN")) {
    function main($arguments, $stdin) {
      // read the file contents
      if (array_key_exists(1, $arguments)) {
        $stdin = @file_get_contents($arguments[1]);
      }

      print(decryptJson($stdin));

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

    // read STDIN
    $read   = [STDIN];
    $write  = [];
    $except = [];
    $stdin = "";
    if (0 < stream_select($read, $write, $except, 0, 0)) {
      $stdin = stream_get_contents(STDIN);
    }

    // execute the main method
    exit(main($argv, $stdin));
  }

