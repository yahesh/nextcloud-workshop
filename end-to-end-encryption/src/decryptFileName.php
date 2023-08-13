#!/usr/bin/env php
<?php

  function main($arguments, $stdin) {
    // !!! do something

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

