#!/usr/bin/env php
<?php

  function decryptFile($file, $file_key) {
    // decrypt the file
    $first  = true;
    $output = "";
    while (0 < strlen($file)) {
      // get the next block
      $block = substr($file, 0, 8192);
      $file  = substr($file, 8192);

      // ignore the first block which just contains the header
      if (!$first) {
        // parse the block
        $ciphertext = substr($block, 0, strrpos($block, "00iv00"));
        $iv         = substr($block, strrpos($block, "00iv00")+strlen("00iv00"), strrpos($block, "00sig00")-strrpos($block, "00iv00")-strlen("00iv00"));

        // decrypt the block
        $output = $output.openssl_decrypt($ciphertext, "aes-256-ctr", $file_key, OPENSSL_RAW_DATA, $iv);
      }
      $first = false;
    }

    return $output;
  }

  if (!defined("IGNORE_MAIN")) {
    function main($arguments) {
      // read the file contents
      if (array_key_exists(1, $arguments)) {
        $file = @file_get_contents($arguments[1]);
      }

      // read the file key
      if (array_key_exists(2, $arguments)) {
        $file_key = @file_get_contents($arguments[2]);
      }

      print(decryptFile($file, $file_key));

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

