// Copyright (c) 2020 Sarun Rattanasiri
// under the 3-Clause BSD License
// https://opensource.org/licenses/BSD-3-Clause

#include "embeddable_speck.h"

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define __REQUIRE_SWAP
#endif

#ifdef __REQUIRE_SWAP
#if __has_include(<byteswap.h>)
#include <byteswap.h>
#else
#define bswap_64 __builtin_bswap64
#endif
#endif

bool embeddable_speck__start(EmbeddableSpeck_State *state, uint8_t *data) {
  if (state->step != 0)
    return false; // rejected
#ifdef __REQUIRE_SWAP
  state->scratch_pad[0] = bswap_64(((uint64_t *)data)[0]);
  state->scratch_pad[1] = bswap_64(((uint64_t *)data)[1]);
#else
  state->scratch_pad[0] = ((uint64_t *)data)[0];
  state->scratch_pad[1] = ((uint64_t *)data)[1];
#endif
  state->step++;
  return true; // accepted
}

static void embeddable_speck__poll(
    const EmbeddableSpeck_Config *config,
    EmbeddableSpeck_State *state,
    void (*round_handler)(
        const EmbeddableSpeck_Config *,
        EmbeddableSpeck_State *)) {
  uint8_t step = state->step;
  // nothing to do
  if (step < 1)
    return;
  // perform cryptographic round
  if (step < (1 + EMBEDDABLE_SPECK__ROUND)) {
    round_handler(config, state);
    state->step++;
    return;
  }
  // normalize output
  if (step < (1 + EMBEDDABLE_SPECK__ROUND + 1)) {
    uint64_t *output = (uint64_t *)state->output;
    uint64_t *raw = state->scratch_pad;

#ifdef __REQUIRE_SWAP
    output[0] = bswap_64(((uint64_t *)raw)[0]);
    output[1] = bswap_64(((uint64_t *)raw)[1]);
#else
    output[0] = ((uint64_t *)raw)[0];
    output[1] = ((uint64_t *)raw)[1];
#endif
    state->step++;
    return;
  }
  // emit and reset
  state->step = 0;
  if (config->finished)
    config->finished(state->output);
}

#define ER64(x, y, k)                                                          \
  (x = _EMBEDDABLE_SPECK__ROTR64(x, 8),                                        \
   x += y,                                                                     \
   x ^= k,                                                                     \
   y = _EMBEDDABLE_SPECK__ROTL64(y, 3),                                        \
   y ^= x)

static void encryption_round(
    const EmbeddableSpeck_Config *config,
    EmbeddableSpeck_State *state) {
  uint8_t step = state->step;
  uint64_t round_key = config->key_schedule[step - 1];
  ER64((state->scratch_pad[1]), (state->scratch_pad[0]), round_key);
}

void embeddable_speck__encryption_poll(
    const EmbeddableSpeck_Config *config,
    EmbeddableSpeck_State *state) {
  embeddable_speck__poll(config, state, &encryption_round);
}

#define DR64(x, y, k)                                                          \
  (y ^= x,                                                                     \
   y = _EMBEDDABLE_SPECK__ROTR64(y, 3),                                        \
   x ^= k,                                                                     \
   x -= y,                                                                     \
   x = _EMBEDDABLE_SPECK__ROTL64(x, 8))

static void decryption_round(
    const EmbeddableSpeck_Config *config,
    EmbeddableSpeck_State *state) {
  uint8_t step = state->step;
  uint64_t round_key =
      config->key_schedule[(EMBEDDABLE_SPECK__ROUND - 1) - (step - 1)];
  DR64((state->scratch_pad[1]), (state->scratch_pad[0]), round_key);
}

void embeddable_speck__decryption_poll(
    const EmbeddableSpeck_Config *config,
    EmbeddableSpeck_State *state) {
  embeddable_speck__poll(config, state, &decryption_round);
}
