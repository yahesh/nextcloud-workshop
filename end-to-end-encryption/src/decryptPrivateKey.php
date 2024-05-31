#!/usr/bin/env php
<?php

  // include helper
  require_once(__DIR__."/helper.php");

  function decryptPrivateKey($file) {
    // parse the private key file
    $parts      = explode("|", $file);
    $ciphertext = substr(base64_decode($parts[0]), 0, -16);
    $nonce      = base64_decode($parts[1]);
    $salt       = base64_decode($parts[2]);

    // derive the decryption key
    $secret = hash_pbkdf2("sha1", preg_replace("@\s+@", "", strtolower(getenv("USER_MNEMONIC"))), $salt, 1024, 32, true);

    // decrypt the private key
    $nonce  = convertGCMtoCTR($nonce, $secret, "aes-256-ecb");
    $output = base64_decode(openssl_decrypt($ciphertext, "aes-256-ctr", $secret, OPENSSL_RAW_DATA, $nonce));

    return $output;
  }

  if (!defined("IGNORE_MAIN")) {
    function main($arguments) {
      // read the file contents
      if (array_key_exists(1, $arguments)) {
        $file = @file_get_contents($arguments[1]);
      }

      print(decryptPrivateKey($file));

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

