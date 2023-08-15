#!/usr/bin/env php
<?php

  // we include scripts and don't want them to execute
  define("IGNORE_MAIN", true);

  // include scripts
  require_once(__DIR__."/decryptFile.php");
  require_once(__DIR__."/decryptMetaData.php");
  require_once(__DIR__."/decryptPrivateKey.php");

  function main($arguments) {
    // prepare the key material
    $private_key = decryptPrivateKey(file_get_contents(__DIR__."/".getenv("PRIVATE_KEY")));
    $meta_data   = decryptMetaData(file_get_contents(__DIR__."/".getenv("META_DATA")), $private_key, basename(getenv("FILE")));

    // decrypt the file
    $output = decryptFile(file_get_contents(__DIR__."/".getenv("FILE")), $meta_data);
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

  // execute the main method
  exit(main($argv));

