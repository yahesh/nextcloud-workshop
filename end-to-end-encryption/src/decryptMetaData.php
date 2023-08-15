#!/usr/bin/env php
<?php

  // include helper
  require_once(__DIR__."/helper.php");

  // we need a specific implementation of RSA that is not provided by PHP
  require_once(__DIR__."/vendor/autoload.php");
  use phpseclib3\Crypt\RSA;

  function decryptMetaData($file, $private_key, $file_name) {
    // parse the meta data file
    $json        = json_decode($file, true, 4, JSON_OBJECT_AS_ARRAY);
    $metadatakey = base64_decode($json["metadata"]["metadataKey"]);
    $parts       = explode("|", $json["files"][$file_name]["encrypted"]);
    $ciphertext  = substr(base64_decode($parts[0]), 0, -16);
    $iv          = base64_decode($parts[1]);

    // decrypt the meta data key
    $metadatakey = base64_decode(base64_decode(RSA::loadPrivateKey($private_key)
                                               ->withPadding(RSA::ENCRYPTION_OAEP)
                                               ->withHash("sha256")
                                               ->withMGFHash("sha256")
                                               ->decrypt($metadatakey)));

    // decrypt the meta data
    $iv       = convertGCMtoCTR($iv, $metadatakey, "aes-128-ecb");
    $metadata = base64_decode(openssl_decrypt($ciphertext, "aes-128-ctr", $metadatakey, OPENSSL_RAW_DATA, $iv));

    // add the iv to the metadata
    $metadata                         = json_decode($metadata, true, 2, JSON_OBJECT_AS_ARRAY);
    $metadata["initializationVector"] = $json["files"][$file_name]["initializationVector"];
    $output                           = json_encode($metadata, JSON_FORCE_OBJECT).PHP_EOL;

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

      // read the target file name
      if (array_key_exists(3, $arguments)) {
        $file_name = basename($arguments[3]);
      }

      print(decryptMetaData($file, $private_key, $file_name));

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

