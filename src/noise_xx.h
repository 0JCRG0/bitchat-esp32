/*
 * noise_xx.h - Noise_XX_25519_ChaChaPoly_SHA256 (Alertam fork)
 *
 * Spec-conformant Noise XX (revision 34), portable C with no Zephyr
 * dependencies so it can be tested on a host against the cacophony vectors.
 * X25519 and ChaCha20/Poly1305 come from Monocypher; SHA-256/HMAC/HKDF are
 * implemented here.
 *
 * BitChat transport framing (bitchat/Noise/NoiseProtocol.swift): every
 * transport ciphertext is prefixed with the low 32 bits of the nonce counter,
 * big-endian, and the receiver uses that nonce with a 1024-message replay
 * window. nx_transport_* implement that framing; nx_cipher_* are plain Noise.
 */
#ifndef NOISE_XX_H
#define NOISE_XX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define NX_KEY   32
#define NX_TAG   16
#define NX_NONCE_PREFIX 4
#define NX_REPLAY_WINDOW 1024

struct nx_cipher {
	uint8_t k[NX_KEY];
	uint64_t n;
	bool has_key;
};

struct nx_session {
	/* SymmetricState */
	struct nx_cipher cs;
	uint8_t ck[32];
	uint8_t h[32];
	/* HandshakeState */
	bool initiator;
	uint8_t s_priv[32], s_pub[32];
	uint8_t e_priv[32], e_pub[32];
	uint8_t rs[32], re[32];
	int msg_index;      /* 0,1,2 = next handshake message; 3 = done */
	/* Transport */
	struct nx_cipher tx, rx;
	uint64_t rx_highest;
	bool rx_any;
	uint8_t rx_window[NX_REPLAY_WINDOW / 8];
};

/* Platform randomness for ephemeral keys */
typedef void (*nx_random_fn)(uint8_t *buf, size_t len);

void nx_x25519_keypair(uint8_t priv[32], uint8_t pub[32], nx_random_fn rnd);

/* Initialize. If e_priv is non-NULL it is used as the ephemeral key (tests). */
void nx_init(struct nx_session *s, bool initiator,
	     const uint8_t s_priv[32], const uint8_t s_pub[32],
	     const uint8_t *prologue, size_t prologue_len,
	     const uint8_t *e_priv, nx_random_fn rnd);

/* Handshake. Return 0 on success, <0 on error. */
int nx_write_message(struct nx_session *s, const uint8_t *payload, size_t plen,
		     uint8_t *out, size_t cap, size_t *out_len);
int nx_read_message(struct nx_session *s, const uint8_t *in, size_t len,
		    uint8_t *payload, size_t cap, size_t *plen);
bool nx_handshake_done(const struct nx_session *s);
/* Next handshake message is ours to write */
bool nx_my_turn(const struct nx_session *s);

/* Plain Noise CipherState (implicit nonce) - used by tests */
int nx_cipher_encrypt(struct nx_cipher *c, const uint8_t *ad, size_t ad_len,
		      const uint8_t *pt, size_t len, uint8_t *out);
int nx_cipher_decrypt(struct nx_cipher *c, const uint8_t *ad, size_t ad_len,
		      const uint8_t *ct, size_t len, uint8_t *out);

/* BitChat transport: out = BE32(nonce) || ct || tag (len + 20 bytes) */
int nx_transport_encrypt(struct nx_session *s, const uint8_t *pt, size_t len,
			 uint8_t *out, size_t cap, size_t *out_len);
int nx_transport_decrypt(struct nx_session *s, const uint8_t *in, size_t len,
			 uint8_t *out, size_t cap, size_t *out_len);

/* SHA-256 (exposed for peer ID derivation and tests) */
void nx_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

void nx_wipe(struct nx_session *s);

#endif /* NOISE_XX_H */
