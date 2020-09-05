// Copyright (c) 2020 Sarun Rattanasiri
// under the 3-Clause BSD License
// https://opensource.org/licenses/BSD-3-Clause

#ifndef __EMBEDDABLE_SPECK_H
#define __EMBEDDABLE_SPECK_H

#define EMBEDDABLE_SPECK__ROUND 32
#define EMBEDDABLE_SPECK__BLOCK_SIZE 16
#define EMBEDDABLE_SPECK__WORD (EMBEDDABLE_SPECK__BLOCK_SIZE >> 3)

// private usage
#define _EMBEDDABLE_SPECK__ROTL64(x, r) (((x) << (r)) | (x >> (64 - (r))))
#define _EMBEDDABLE_SPECK__ROTR64(x, r) (((x) >> (r)) | ((x) << (64 - (r))))

#include <stdbool.h>
#include <stdint.h>

typedef struct _embeddable_speck__config {
  uint64_t key_schedule[EMBEDDABLE_SPECK__ROUND];
  void (*started)(uint8_t *accepted_input);
  void (*rejected)(uint8_t *rejected_input);
  void (*finished)(uint8_t *result);
} EmbeddableSpeck_Config;

typedef struct _embeddable_speck__state {
  uint8_t step;
  uint64_t scratch_pad[EMBEDDABLE_SPECK__WORD];
  uint8_t output[EMBEDDABLE_SPECK__BLOCK_SIZE];
} EmbeddableSpeck_State;

#define embeddable_speck__init(state)                                          \
  do {                                                                         \
    (state)->step = 0;                                                         \
  } while (0)

void embeddable_speck__start(EmbeddableSpeck_Config *config,
                             EmbeddableSpeck_State *state, uint8_t *data);

void embeddable_speck__encryption_poll(EmbeddableSpeck_Config *config,
                                       EmbeddableSpeck_State *state);

void embeddable_speck__decryption_poll(EmbeddableSpeck_Config *config,
                                       EmbeddableSpeck_State *state);

#endif
