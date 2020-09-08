#include "embeddable_speck.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

// the test vector was obtained from
// https://nsacyber.github.io/simon-speck/implementations/ImplementationGuide1.1.pdf

static const uint64_t key_schedule[EMBEDDABLE_SPECK__ROUND] = {
    0x0706050403020100, 0x37253b31171d0309, 0xf91d89cc90c4085c,
    0xc6b1f07852cc7689, 0x014fcdf4f9c2d6f0, 0xb5fae1e4fe24cfd6,
    0xa36d6954b0737cfe, 0xf511691ea02f35f3, 0x5374abb75a2b455d,
    0x8dd5f6204ddcb2a5, 0xb243d7c9869cac18, 0x753e7a7c6660459e,
    0x78d648a3a5b0e63b, 0x87152b23cbc0a8d2, 0xa8ff8b8c54a3b6f2,
    0x4873be3c43b3ea79, 0x771ebffcbf05cb13, 0xe8a6bcaf25863d20,
    0xe6c2ea8b5c520c93, 0x4d71b5c1ac5214f5, 0xdc60b2ae253070dc,
    0xb01d0abbe1fb9741, 0xd7987684a318b54a, 0xa22c5282e600d319,
    0xe029d67ebdf90048, 0x67559234c84efdbf, 0x65173cf0cb01695c,
    0x24cf1f1879819519, 0x38a36ed2dbafb72a, 0xded93cfe31bae304,
    0xc53d18b91770b265, 0x2199c870db8ec93f,
};

static const uint8_t plain_text[EMBEDDABLE_SPECK__BLOCK_SIZE] = {
    0x20,
    0x6d,
    0x61,
    0x64,
    0x65,
    0x20,
    0x69,
    0x74,
    0x20,
    0x65,
    0x71,
    0x75,
    0x69,
    0x76,
    0x61,
    0x6c,
};

static const uint8_t cipher_text[EMBEDDABLE_SPECK__BLOCK_SIZE] = {
    0x18,
    0x0d,
    0x57,
    0x5c,
    0xdf,
    0xfe,
    0x60,
    0x78,
    0x65,
    0x32,
    0x78,
    0x79,
    0x51,
    0x98,
    0x5d,
    0xa6,
};

static void encrypted_handler(uint8_t *result);
static const EmbeddableSpeck_Config encryption_config = {
    .key_schedule = (uint64_t *)key_schedule,
    .finished = &encrypted_handler,
};

static void decrypted_handler(uint8_t *result);
static const EmbeddableSpeck_Config decryption_config = {
    .key_schedule = (uint64_t *)key_schedule,
    .finished = &decrypted_handler,
};

static EmbeddableSpeck_State encryption_state;
static EmbeddableSpeck_State decryption_state;

int main(void) {
  embeddable_speck__init(&encryption_state);
  embeddable_speck__init(&decryption_state);
  embeddable_speck__start(&encryption_state, (uint8_t *)plain_text);
  for (uint16_t i = 0; i < 1024; i++) {
    embeddable_speck__encryption_poll(&encryption_config, &encryption_state);
    embeddable_speck__decryption_poll(&decryption_config, &decryption_state);
  }
  puts("Done!");
  return 0;
}

static bool encryption_check(uint8_t *result);
static void encrypted_handler(uint8_t *result) {
  if (encryption_check(result)) {
    puts("Encryption test PASSED");
  } else {
    puts("Encryption test FAILED");
  }
  embeddable_speck__start(&decryption_state, result);
}

static bool encryption_check(uint8_t *result) {
  for (uint8_t i = 0; i < EMBEDDABLE_SPECK__BLOCK_SIZE; i++)
    if (cipher_text[i] != result[i])
      return false;
  return true;
}

static bool decryption_check(uint8_t *result);
static void decrypted_handler(uint8_t *result) {
  if (decryption_check(result)) {
    puts("Decryption test PASSED");
  } else {
    puts("Decryption test FAILED");
  }
  embeddable_speck__start(&decryption_state, result);
}

static bool decryption_check(uint8_t *result) {
  for (uint8_t i = 0; i < EMBEDDABLE_SPECK__BLOCK_SIZE; i++)
    if (plain_text[i] != result[i])
      return false;
  return true;
}
