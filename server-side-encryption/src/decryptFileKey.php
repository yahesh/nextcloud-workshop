#!/usr/bin/env php
<?php

  function decryptFileKey($file, $private_key) {
    // decrypt the file key
    openssl_private_decrypt($file, $output, $private_key, OPENSSL_PKCS1_OAEP_PADDING);

    return $output;
  }

  if (!defined("IGNORE_MAIN")) {
    function main($arguments, $stdin) {
      // read the file contents
      if (array_key_exists(1, $arguments)) {
        $stdin = @file_get_contents($arguments[1]);
      }

      // read the private key
      if (array_key_exists(2, $arguments)) {
        $private_key = @file_get_contents($arguments[2]);
      }

      print(decryptFileKey($stdin, $private_key));

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

