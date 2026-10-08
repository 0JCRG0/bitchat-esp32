/*
 * alertam_store.h - Alertam state persisted in flash
 *
 * Zephyr settings on ZMS, in the board's storage_partition. Keys:
 *   alertam/id      identity private material (Noise X25519 key + Ed25519 seed)
 *   alertam/nick    nickname
 *   alertam/circle  private SOS circle (peer ID + name per member)
 *   alertam/sos     SOS text
 * Record layouts: alertam_record.h.
 *
 * SECURITY: the private keys sit unencrypted in flash for now; ESP32 flash
 * encryption is a later hardening step. Never print them.
 *
 * If the backend fails to mount, everything keeps working from RAM (as before)
 * and the save functions return an error.
 */
#ifndef ALERTAM_STORE_H
#define ALERTAM_STORE_H

#include <stdbool.h>
#include "alertam_record.h"
#include "bitchat_protocol.h"

/* Mount the settings backend and load the "alertam" subtree. Call first in main. */
int astore_init(void);

/* Identity: load the persisted one, or generate + save a new one. Fills the keys
 * in id (via bcw_identity_init_from) and sets *created. Leaves id->nickname alone. */
int astore_identity_load(struct bitchat_identity *id, bool *created);
/* 'keys generate': fresh random identity, saved */
int astore_identity_regenerate(struct bitchat_identity *id);

/* Saved nickname, or NULL if none */
const char *astore_nick(void);
int astore_save_nick(const char *nick);

/* Saved SOS text, or NULL if none */
const char *astore_sos(void);
int astore_save_sos(const char *text);

/* Loads up to max members; returns the count (0 if none / malformed) */
int astore_load_circle(struct arec_member *m, int max);
int astore_save_circle(const struct arec_member *m, int n);

#endif /* ALERTAM_STORE_H */
