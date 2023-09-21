<?php

  // convert a GCM nonce to a CTR counter
  function convertGCMtoCTR($iv, $key, $algo) {
    $result = null;

    // check special case first
    if (0x0C === strlen($iv)) {
      $result = $iv."\x00\x00\x00\x01";
    } else {
      // produce GHASH of the nonce
      $subkey = openssl_encrypt("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                                $algo,
                                $key,
                                OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
      if (false !== $subkey) {
        // store for later use
        $ivlen = strlen($iv);

        // pad iv to 128 bit block
        if (0x00 !== ($ivlen % 0x10)) {
          $iv = $iv.str_repeat("\x00", 0x10 - ($ivlen % 0x10));
        }

        // append zero padding
        $iv = $iv."\x00\x00\x00\x00\x00\x00\x00\x00";

        // append 64-bit iv length
        $iv = $iv."\x00\x00\x00\x00".pack("N", ($ivlen << 0x03));

        // actual GHASH calculation
        $result = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        for ($i = 0x00; $i < strlen($iv)/0x10; $i++) {
          $block  = $result ^ substr($iv, $i * 0x10, 0x10);
          $tmp    = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
          $tmpkey = $subkey;

          // execute the multipliation
          for ($index = 0x00; $index < strlen($block); $index++) {
            for ($bit = 0x07; $bit >= 0x00; $bit--) {
              // store for later use
              $adder = (ord($tmpkey[strlen($tmpkey)-0x01]) & 0x01);
              $mixer = ((ord($block[$index]) >> $bit) & 0x01);

              // merge tmpkey into tmp,
              // do this in a loop for constant time
              for ($byte = 0x00; $byte < strlen($tmp); $byte++) {
                $tmp[$byte] = chr(ord($tmp[$byte]) ^ (ord($tmpkey[$byte]) * $mixer));
              }

              // shift least significant bit out of the tmpkey,
              // afterwards mix the adder into tmpkey,
              // do this in constant time
              $shifted = 0x00;
              for ($byte = 0x00; $byte < strlen($tmpkey); $byte++) {
                $tmpval        = (ord($tmpkey[$byte]) & 0x01);
                $tmpkey[$byte] = chr((($shifted << 0x07) & 0x80) | ((ord($tmpkey[$byte]) >> 0x01) & 0x7F));
                $shifted       = $tmpval;
              }
              $tmpkey[0x00] = chr(ord($tmpkey[0x00]) ^ (0xE1 * $adder));
            }
          }

          $result = $tmp;
        }
      }
    }

    // we need to increment the counter once because we do not need
    // the inital GCM block that is only used for the authentication tag
    if (null !== $result) {
      // add increment to the result
      $increment = 0x01;
      for ($index = strlen($result)-0x01; $index >= 0x00; $index--) {
        $tmp            = (((ord($result[$index]) + $increment) >> 0x08) & 0xFF);
        $result[$index] = chr((ord($result[$index]) + $increment) & 0xFF);
        $increment      = $tmp;
      }
    }

    return $result;
  }

  // decrypt RSA blob with OAEP unpadding
  function rsaDecrypt($ciphertext, $privatekey, $algo = "sha256") {
    $result = false;

    // parse RSA key
    $key = openssl_pkey_get_private($privatekey);
    if (false !== $key) {
      try {
        // get RSA key details
        $details = openssl_pkey_get_details($key);
        if (false !== $details) {
          if (array_key_exists("rsa", $details) &&
              array_key_exists("d",   $details["rsa"]) &&
              array_key_exists("n",   $details["rsa"])) {
            // get big number representations
            $c = gmp_import($ciphertext,          strlen($ciphertext),          GMP_BIG_ENDIAN);
            $d = gmp_import($details["rsa"]["d"], strlen($details["rsa"]["d"]), GMP_BIG_ENDIAN);
            $n = gmp_import($details["rsa"]["n"], strlen($details["rsa"]["n"]), GMP_BIG_ENDIAN);

            // decrypt content
            $tmp = gmp_powm($c, $d, $n);
            $tmp = gmp_export($tmp, strlen($details["rsa"]["n"]), GMP_BIG_ENDIAN);

            // unpad message
            $result = rsaOAEP($tmp, $algo);
          }
        }
      } finally {
        // prevent deprecation notice in PHP 8.0 and above
        if (0 > version_compare(PHP_VERSION, "8.0.0")) {
          openssl_free_key($key);
        }
      }
    }

    return $result;
  }

  // mask generation function
  function rsaMGF1($seed, $length, $algo = "sha256") {
    $result = false;

    // parameter check
    if (0 < $length) {
      $result = "";

      $hashLength = strlen(hash($algo, "", true));
      for ($counter = 0; $counter < ceil($length / $hashLength); $counter++) {
        $result .= hash($algo, $seed.pack("N", $counter), true);
      }

      // get the requested length
      $result = substr($result, 0, $length);
    }

    return $result;
  }

  // optimal asymmetric encryption padding
  function rsaOAEP($content, $algo = "sha256", $oaepLabel = "") {
    $result = false;

    // check that the first byte is zero
    if ((1 < strlen($content)) &&
        ("\x00" === $content[0])) {
      $hashLength = strlen(hash($algo, "", true));

      // parse message
      $maskedSeed = substr($content, 1, $hashLength);
      $maskedDB   = substr($content, $hashLength+1);

      // derive seed from maskedSeed and maskedDB
      $seedMask = rsaMGF1($maskedDB, $hashLength);
      $seed     = $maskedSeed ^ $seedMask;

      // unmask actual data
      $dbMask = rsaMGF1($seed, strlen($maskedDB));
      $db     = $maskedDB ^ $dbMask;

      // parse the unmasked content
      $hash = substr($db, 0, $hashLength);
      if (hash_equals($hash, hash($algo, $oaepLabel, true))) {
        $tmp = substr($db, $hashLength);
        $tmp = ltrim($tmp, "\x00");

        // check that the first byte is one
        if ((1 < strlen($tmp)) &&
            ("\x01" === $tmp[0])) {
          $result = substr($tmp, 1);
        }
      }
    }

    return $result;
  }


