// Copyright (c) 2020 Sarun Rattanasiri
// under the 3-Clause BSD License
// https://opensource.org/licenses/BSD-3-Clause

#include "embeddable_speck.h"

void embeddable_speck__start(EmbeddableSpeck_Config *config,
                             EmbeddableSpeck_State *state, uint8_t *data) {
  if (state->step != 0) {
    if (config->rejected) {
      config->rejected(data);
    }
    return;
  }
  state->scratch_pad[0] =
      (uint64_t)data[0] | ((uint64_t)data[1] << 8) | ((uint64_t)data[2] << 16) |
      ((uint64_t)data[3] << 24) | ((uint64_t)data[4] << 32) |
      ((uint64_t)data[5] << 40) | ((uint64_t)data[6] << 48) |
      ((uint64_t)data[7] << 56);
  state->scratch_pad[1] =
      (uint64_t)data[8 + 0] | ((uint64_t)data[8 + 1] << 8) |
      ((uint64_t)data[8 + 2] << 16) | ((uint64_t)data[8 + 3] << 24) |
      ((uint64_t)data[8 + 4] << 32) | ((uint64_t)data[8 + 5] << 40) |
      ((uint64_t)data[8 + 6] << 48) | ((uint64_t)data[8 + 7] << 56);
  state->step++;
  if (config->started) {
    config->started(data);
  }
}

static void embeddable_speck__poll(
    EmbeddableSpeck_Config *config, EmbeddableSpeck_State *state,
    void (*round_handler)(EmbeddableSpeck_Config *, EmbeddableSpeck_State *)) {
  uint8_t step = state->step;
  if (step < 1) {
    // nothing to do
    return;
  }
  if (step < (1 + EMBEDDABLE_SPECK__ROUND)) {
    // perform cryptographic round
    round_handler(config, state);

    state->step++;
    return;
  }
  if (step < (1 + EMBEDDABLE_SPECK__ROUND + 1)) {
    // normalize output
    uint8_t *output = state->output;
    uint64_t *raw = state->scratch_pad;

    output[0] = (uint8_t)raw[0];
    output[0 + 1] = (uint8_t)(raw[0] >> 8);
    output[0 + 2] = (uint8_t)(raw[0] >> 16);
    output[0 + 3] = (uint8_t)(raw[0] >> 24);
    output[0 + 4] = (uint8_t)(raw[0] >> 32);
    output[0 + 5] = (uint8_t)(raw[0] >> 40);
    output[0 + 6] = (uint8_t)(raw[0] >> 48);
    output[0 + 7] = (uint8_t)(raw[0] >> 56);

    output[8] = (uint8_t)raw[1];
    output[8 + 1] = (uint8_t)(raw[1] >> 8);
    output[8 + 2] = (uint8_t)(raw[1] >> 16);
    output[8 + 3] = (uint8_t)(raw[1] >> 24);
    output[8 + 4] = (uint8_t)(raw[1] >> 32);
    output[8 + 5] = (uint8_t)(raw[1] >> 40);
    output[8 + 6] = (uint8_t)(raw[1] >> 48);
    output[8 + 7] = (uint8_t)(raw[1] >> 56);

    state->step++;
    return;
  }
  // emit and reset
  if (config->finished) {
    config->finished(state->output);
  }
  state->step = 0;
}

#define ER64(x, y, k)                                                          \
  (x = _EMBEDDABLE_SPECK__ROTR64(x, 8), x += y, x ^= k,                        \
   y = _EMBEDDABLE_SPECK__ROTL64(y, 3), y ^= x)

static void encryption_round(EmbeddableSpeck_Config *config,
                             EmbeddableSpeck_State *state) {
  uint8_t step = state->step;
  uint64_t round_key = config->key_schedule[step - 1];
  ER64((state->scratch_pad[1]), (state->scratch_pad[0]), round_key);
}

static void embeddable_speck__encryption_poll(EmbeddableSpeck_Config *config,
                                              EmbeddableSpeck_State *state) {
  embeddable_speck__poll(config, state, &encryption_round);
}

#define DR64(x, y, k)                                                          \
  (y ^= x, y = _EMBEDDABLE_SPECK__ROTR64(y, 3), x ^= k, x -= y,                \
   x = _EMBEDDABLE_SPECK__ROTL64(x, 8))

static void decryption_round(EmbeddableSpeck_Config *config,
                             EmbeddableSpeck_State *state) {
  uint8_t step = state->step;
  uint64_t round_key =
      config->key_schedule[(EMBEDDABLE_SPECK__ROUND - 1) - (step - 1)];
  DR64((state->scratch_pad[1]), (state->scratch_pad[0]), round_key);
}

static void embeddable_speck__decryption_poll(EmbeddableSpeck_Config *config,
                                              EmbeddableSpeck_State *state) {
  embeddable_speck__poll(config, state, &decryption_round);
}
