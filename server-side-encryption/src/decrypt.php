#!/usr/bin/env php
<?php

  // we include scripts and don't want them to execute
  define("IGNORE_MAIN", true);

  // include scripts
  require_once(__DIR__."/decryptFile.php");
  require_once(__DIR__."/decryptFileKey.php");
  require_once(__DIR__."/decryptJson.php");
  require_once(__DIR__."/decryptPrivateKey.php");

  function main($arguments, $stdin) {
    // prepare key material
    $private_key = decryptPrivateKey(decryptJson(file_get_contents(__DIR__."/".getenv("PRIVATE_KEY"))));
    $file_key    = decryptFileKey(decryptJson(file_get_contents(__DIR__."/".getenv("SHARE_KEY"))), $private_key);

    // decrypt file
    $output = decryptFile(file_get_contents(__DIR__."/".getenv("FILE")), $file_key);
    print($output);

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

