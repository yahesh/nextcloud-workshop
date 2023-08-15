#!/usr/bin/env php
<?php

  function decryptPrivateKey($file) {
    // parse the private key file
    $file       = substr($file, strpos($file, "HEND")+strlen("HEND"));
    $ciphertext = substr($file, 0,                                         strrpos($file, "00iv00"));
    $iv         = substr($file, strrpos($file, "00iv00")+strlen("00iv00"), strrpos($file, "00sig00")-strrpos($file, "00iv00")-strlen("00iv00"));

    // derive the decryption key 
    $salt   = hash("sha256", basename(getenv("PRIVATE_KEY"), ".privateKey").getenv("INSTANCEID").getenv("SECRET"), true);
    $secret = hash_pbkdf2("sha256", getenv("SECRET"), $salt, 100000, 32, true);

    // decrypt the private key
    $output = openssl_decrypt($ciphertext, "aes-256-ctr", $secret, OPENSSL_RAW_DATA, $iv);

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

