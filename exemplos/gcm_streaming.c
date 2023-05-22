Skip to content
 
Search…
All gists
Back to GitHub
@Malkverbena 
@unprovable
unprovable/mbedtls_gcm_esp32_example.ino
Last active 5 months ago • Report abuse
6
0
Code
Revisions
2
Stars
6
<script src="https://gist.github.com/unprovable/892a677d672990f46bca97194ae549bc.js"></script>
MBEDTLS AES GCM example
mbedtls_gcm_esp32_example.ino
// This is shockingly bad code... but I threw it together in ~4mins...
// because I couldn't find one anywhere and needed it for some ESP32 experimentation...
// See the MBED reference for this:
//    https://tls.mbed.org/api/gcm_8h.html

#include "mbedtls/gcm.h"

void setup() {
  Serial.begin(115200);
  mbedtls_gcm_context aes;
  char *key = "abcdefghijklmnop";
  char *input = "Mark C's ESP32 GCM Example code!";
  char *iv = "abababababababab";
  unsigned char output[64] = {0};
  unsigned char fin[64] = {0};
  Serial.println("[i] Encrypted into buffer:");
  // init the context...
  mbedtls_gcm_init( &aes );
  // Set the key. This next line could have CAMELLIA or ARIA as our GCM mode cipher...
  mbedtls_gcm_setkey( &aes,MBEDTLS_CIPHER_ID_AES , (const unsigned char*) key, strlen(key) * 8);
  // Initialise the GCM cipher...
  mbedtls_gcm_starts(&aes, MBEDTLS_GCM_ENCRYPT, (const unsigned char*)iv, strlen(iv),NULL, 0);
  // Send the intialised cipher some data and store it...
  mbedtls_gcm_update(&aes,strlen(input),(const unsigned char*)input, output);
  // Free up the context.
  mbedtls_gcm_free( &aes );
  for (int i = 0; i < strlen(input); i++) {  
    char str[3];
    sprintf(str, "%02x", (int)output[i]);
    Serial.print(str);
  }
  Serial.println("");
  Serial.println("[i] Decrypted from buffer:");
  mbedtls_gcm_init( &aes );
  mbedtls_gcm_setkey( &aes,MBEDTLS_CIPHER_ID_AES , (const unsigned char*) key, strlen(key) * 8);
  mbedtls_gcm_starts(&aes, MBEDTLS_GCM_DECRYPT, (const unsigned char*)iv, strlen(iv),NULL, 0);
  mbedtls_gcm_update(&aes,64,(const unsigned char*)output, fin);
  mbedtls_gcm_free( &aes );
  for (int i = 0; i < strlen(input); i++) {  
    char str[3];
    sprintf(str, "%c", (int)fin[i]);
    Serial.print(str);
  }
}

void loop() {}
@ONLYstcm
ONLYstcm commented on Feb 8, 2020
Hi thank you for your example, it helped me alot. I'm not sure if you experienced this but sometimes when encrypting the encrypted strings will are randomly cut off, and the decryption will be a truncated string of the original. It's hard to debug but my initial guess is that some encryption strings have a '\0' character which cuts of the string.

@danintel
danintel commented on May 26, 2020 • 
strlen() should not be used to determine the length of a binary string. The length of the key and IV are known and should be passed as parameters or set as named constants. It is also missing mbedtls_gcm_finish() to flush non-(0 mod blocksize) out and to write the 16-byte auth tag that's appended to the end. Except for that, this is a good, simple example.

@mu578
mu578 commented on Jun 16, 2021
@danintel exactly and most notable; the key that you pass must be the result of some of derivation process from an "original secret passphrase"; I would say that's like the infamous "using namespace std;" (global scope) program examples, it's a mark of total ignorance of the very topic, should be instantly discarded by any readers, bad juju.

@carloscn
carloscn commented on Dec 6, 2022
Thanks for your example. I think the mbedtls_gcm_finish(&aes, tag, 4); should be inserted under the mbedtls_gcm_update.



