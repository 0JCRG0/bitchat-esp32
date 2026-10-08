/*
 * alertam_record.h - flash record encoding for Alertam settings (Zephyr-free,
 * host-testable; see tests/test_store.c)
 *
 * Records (settings keys under "alertam/", see alertam_store.h):
 *   id      1 version + 32 Noise X25519 private key + 32 Ed25519 seed  = 65 bytes
 *   circle  1 version + 1 count + count x (16 hex peer ID + 1 len + name) <= 202 bytes
 *   nick    raw nickname bytes (no NUL)
 *   sos     raw SOS text bytes (no NUL)
 */
#ifndef ALERTAM_RECORD_H
#define ALERTAM_RECORD_H

#include <stddef.h>
#include <stdint.h>

#define AREC_VERSION     1
#define AREC_ID_LEN      65
#define AREC_CIRCLE_MAX  5
#define AREC_NAME_LEN    24 /* incl. NUL */
#define AREC_CIRCLE_CAP  (2 + AREC_CIRCLE_MAX * (16 + 1 + AREC_NAME_LEN - 1))

struct arec_member {
	char name[AREC_NAME_LEN];
	char id_hex[17]; /* 16 lowercase hex + NUL */
};

void arec_id_encode(uint8_t out[AREC_ID_LEN], const uint8_t noise_priv[32],
		    const uint8_t ed_seed[32]);
/* Returns 0, or -1 if the record is malformed */
int arec_id_decode(const uint8_t *in, size_t len, uint8_t noise_priv[32], uint8_t ed_seed[32]);

/* Returns the encoded length, or -1 if n is out of range / cap too small */
int arec_circle_encode(uint8_t *out, size_t cap, const struct arec_member *m, int n);
/* Returns the number of members decoded (0..max), or -1 if malformed */
int arec_circle_decode(const uint8_t *in, size_t len, struct arec_member *m, int max);

#endif /* ALERTAM_RECORD_H */
