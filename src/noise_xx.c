/*
 * noise_xx.c - Noise_XX_25519_ChaChaPoly_SHA256 (Alertam fork)
 * See noise_xx.h.
 */
#include "noise_xx.h"

#include <string.h>

#include "../lib/monocypher/monocypher.h"

/* ---------- SHA-256 (FIPS 180-4) ---------- */

struct sha256_ctx {
	uint32_t state[8];
	uint64_t bits;
	uint8_t buf[64];
	size_t used;
};

static const uint32_t K256[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(struct sha256_ctx *c, const uint8_t *p)
{
	uint32_t w[64], a, b, d, e, f, g, h, cc, t1, t2;
	for (int i = 0; i < 16; i++) {
		w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 |
		       (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
	}
	for (int i = 16; i < 64; i++) {
		uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
		uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	a = c->state[0]; b = c->state[1]; cc = c->state[2]; d = c->state[3];
	e = c->state[4]; f = c->state[5]; g = c->state[6]; h = c->state[7];
	for (int i = 0; i < 64; i++) {
		t1 = h + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
		t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & cc) ^ (b & cc));
		h = g; g = f; f = e; e = d + t1; d = cc; cc = b; b = a; a = t1 + t2;
	}
	c->state[0] += a; c->state[1] += b; c->state[2] += cc; c->state[3] += d;
	c->state[4] += e; c->state[5] += f; c->state[6] += g; c->state[7] += h;
}

static void sha256_init(struct sha256_ctx *c)
{
	static const uint32_t iv[8] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	};
	memcpy(c->state, iv, sizeof(iv));
	c->bits = 0;
	c->used = 0;
}

static void sha256_update(struct sha256_ctx *c, const uint8_t *p, size_t len)
{
	c->bits += (uint64_t)len * 8;
	while (len > 0) {
		size_t take = 64 - c->used;
		if (take > len) {
			take = len;
		}
		memcpy(c->buf + c->used, p, take);
		c->used += take;
		p += take;
		len -= take;
		if (c->used == 64) {
			sha256_block(c, c->buf);
			c->used = 0;
		}
	}
}

static void sha256_final(struct sha256_ctx *c, uint8_t out[32])
{
	uint64_t bits = c->bits;
	uint8_t pad = 0x80;
	sha256_update(c, &pad, 1);
	pad = 0;
	while (c->used != 56) {
		sha256_update(c, &pad, 1);
	}
	uint8_t len_be[8];
	for (int i = 0; i < 8; i++) {
		len_be[i] = (uint8_t)(bits >> (56 - 8 * i));
	}
	sha256_update(c, len_be, 8);
	for (int i = 0; i < 8; i++) {
		out[4 * i] = (uint8_t)(c->state[i] >> 24);
		out[4 * i + 1] = (uint8_t)(c->state[i] >> 16);
		out[4 * i + 2] = (uint8_t)(c->state[i] >> 8);
		out[4 * i + 3] = (uint8_t)c->state[i];
	}
	crypto_wipe(c, sizeof(*c));
}

void nx_sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
	struct sha256_ctx c;
	sha256_init(&c);
	sha256_update(&c, data, len);
	sha256_final(&c, out);
}

/* ---------- HMAC-SHA256 / HKDF (Noise section 4.3) ---------- */

static void hmac_sha256(const uint8_t key[32],
			const uint8_t *d1, size_t l1, const uint8_t *d2, size_t l2,
			uint8_t out[32])
{
	uint8_t pad[64];
	uint8_t inner[32];
	struct sha256_ctx c;

	memset(pad, 0x36, 64);
	for (int i = 0; i < 32; i++) {
		pad[i] ^= key[i];
	}
	sha256_init(&c);
	sha256_update(&c, pad, 64);
	sha256_update(&c, d1, l1);
	if (d2) {
		sha256_update(&c, d2, l2);
	}
	sha256_final(&c, inner);

	memset(pad, 0x5c, 64);
	for (int i = 0; i < 32; i++) {
		pad[i] ^= key[i];
	}
	sha256_init(&c);
	sha256_update(&c, pad, 64);
	sha256_update(&c, inner, 32);
	sha256_final(&c, out);
	crypto_wipe(pad, sizeof(pad));
	crypto_wipe(inner, sizeof(inner));
}

static void hkdf2(const uint8_t ck[32], const uint8_t *ikm, size_t ikm_len,
		  uint8_t out1[32], uint8_t out2[32])
{
	uint8_t temp[32];
	uint8_t one = 0x01, two = 0x02;
	hmac_sha256(ck, ikm, ikm_len, NULL, 0, temp);
	hmac_sha256(temp, &one, 1, NULL, 0, out1);
	hmac_sha256(temp, out1, 32, &two, 1, out2);
	crypto_wipe(temp, sizeof(temp));
}

/* ---------- ChaCha20-Poly1305 (RFC 8439) ---------- */

static void make_nonce(uint64_t n, uint8_t nonce[12])
{
	memset(nonce, 0, 4);
	for (int i = 0; i < 8; i++) {
		nonce[4 + i] = (uint8_t)(n >> (8 * i)); /* little-endian */
	}
}

static void poly_mac(const uint8_t poly_key[32], const uint8_t *ad, size_t ad_len,
		     const uint8_t *ct, size_t ct_len, uint8_t tag[16])
{
	static const uint8_t zeros[16];
	uint8_t lens[16];
	crypto_poly1305_ctx p;

	crypto_poly1305_init(&p, poly_key);
	crypto_poly1305_update(&p, ad, ad_len);
	crypto_poly1305_update(&p, zeros, (16 - ad_len % 16) % 16);
	crypto_poly1305_update(&p, ct, ct_len);
	crypto_poly1305_update(&p, zeros, (16 - ct_len % 16) % 16);
	for (int i = 0; i < 8; i++) {
		lens[i] = (uint8_t)((uint64_t)ad_len >> (8 * i));
		lens[8 + i] = (uint8_t)((uint64_t)ct_len >> (8 * i));
	}
	crypto_poly1305_update(&p, lens, 16);
	crypto_poly1305_final(&p, tag);
}

static void aead_encrypt(const uint8_t k[32], uint64_t n, const uint8_t *ad, size_t ad_len,
			 const uint8_t *pt, size_t len, uint8_t *out)
{
	uint8_t nonce[12], poly_key[32];
	make_nonce(n, nonce);
	crypto_chacha20_ietf(poly_key, NULL, 32, k, nonce, 0);
	crypto_chacha20_ietf(out, pt, len, k, nonce, 1);
	poly_mac(poly_key, ad, ad_len, out, len, out + len);
	crypto_wipe(poly_key, sizeof(poly_key));
}

static int aead_decrypt(const uint8_t k[32], uint64_t n, const uint8_t *ad, size_t ad_len,
			const uint8_t *ct, size_t len, uint8_t *out)
{
	uint8_t nonce[12], poly_key[32], tag[16];
	if (len < NX_TAG) {
		return -1;
	}
	size_t plen = len - NX_TAG;
	make_nonce(n, nonce);
	crypto_chacha20_ietf(poly_key, NULL, 32, k, nonce, 0);
	poly_mac(poly_key, ad, ad_len, ct, plen, tag);
	crypto_wipe(poly_key, sizeof(poly_key));
	if (crypto_verify16(tag, ct + plen) != 0) {
		return -1;
	}
	crypto_chacha20_ietf(out, ct, plen, k, nonce, 1);
	return 0;
}

/* ---------- CipherState ---------- */

static void cs_init(struct nx_cipher *c, const uint8_t *k)
{
	if (k) {
		memcpy(c->k, k, 32);
		c->has_key = true;
	} else {
		memset(c->k, 0, 32);
		c->has_key = false;
	}
	c->n = 0;
}

int nx_cipher_encrypt(struct nx_cipher *c, const uint8_t *ad, size_t ad_len,
		      const uint8_t *pt, size_t len, uint8_t *out)
{
	if (!c->has_key) {
		memmove(out, pt, len);
		return (int)len;
	}
	if (c->n == UINT64_MAX) {
		return -1;
	}
	aead_encrypt(c->k, c->n, ad, ad_len, pt, len, out);
	c->n++;
	return (int)(len + NX_TAG);
}

int nx_cipher_decrypt(struct nx_cipher *c, const uint8_t *ad, size_t ad_len,
		      const uint8_t *ct, size_t len, uint8_t *out)
{
	if (!c->has_key) {
		memmove(out, ct, len);
		return (int)len;
	}
	if (aead_decrypt(c->k, c->n, ad, ad_len, ct, len, out) != 0) {
		return -1;
	}
	c->n++;
	return (int)(len - NX_TAG);
}

/* ---------- SymmetricState ---------- */

static void mix_hash(struct nx_session *s, const uint8_t *data, size_t len)
{
	struct sha256_ctx c;
	sha256_init(&c);
	sha256_update(&c, s->h, 32);
	sha256_update(&c, data, len);
	sha256_final(&c, s->h);
}

static void mix_key(struct nx_session *s, const uint8_t *ikm, size_t len)
{
	uint8_t k[32];
	hkdf2(s->ck, ikm, len, s->ck, k);
	cs_init(&s->cs, k);
	crypto_wipe(k, sizeof(k));
}

static int encrypt_and_hash(struct nx_session *s, const uint8_t *pt, size_t len,
			    uint8_t *out, size_t cap)
{
	size_t need = len + (s->cs.has_key ? NX_TAG : 0);
	if (need > cap) {
		return -1;
	}
	int n = nx_cipher_encrypt(&s->cs, s->h, 32, pt, len, out);
	if (n < 0) {
		return n;
	}
	mix_hash(s, out, (size_t)n);
	return n;
}

static int decrypt_and_hash(struct nx_session *s, const uint8_t *ct, size_t len,
			    uint8_t *out, size_t cap)
{
	size_t plen = s->cs.has_key ? len - NX_TAG : len;
	if ((s->cs.has_key && len < NX_TAG) || plen > cap) {
		return -1;
	}
	uint8_t h_before[32];
	memcpy(h_before, s->h, 32);
	int n = nx_cipher_decrypt(&s->cs, h_before, 32, ct, len, out);
	if (n < 0) {
		return n;
	}
	mix_hash(s, ct, len);
	return n;
}

/* ---------- HandshakeState (XX) ---------- */

void nx_x25519_keypair(uint8_t priv[32], uint8_t pub[32], nx_random_fn rnd)
{
	rnd(priv, 32);
	crypto_x25519_public_key(pub, priv);
}

void nx_init(struct nx_session *s, bool initiator,
	     const uint8_t s_priv[32], const uint8_t s_pub[32],
	     const uint8_t *prologue, size_t prologue_len,
	     const uint8_t *e_priv, nx_random_fn rnd)
{
	static const char name[] = "Noise_XX_25519_ChaChaPoly_SHA256"; /* exactly 32 bytes */

	memset(s, 0, sizeof(*s));
	memcpy(s->h, name, 32);
	memcpy(s->ck, s->h, 32);
	cs_init(&s->cs, NULL);
	mix_hash(s, prologue, prologue_len);

	s->initiator = initiator;
	memcpy(s->s_priv, s_priv, 32);
	memcpy(s->s_pub, s_pub, 32);
	if (e_priv) {
		memcpy(s->e_priv, e_priv, 32);
		crypto_x25519_public_key(s->e_pub, s->e_priv);
	} else {
		nx_x25519_keypair(s->e_priv, s->e_pub, rnd);
	}
}

static bool bad_point(const uint8_t k[32])
{
	uint8_t acc0 = 0, accff = 0xff;
	for (int i = 0; i < 32; i++) {
		acc0 |= k[i];
		accff &= k[i];
	}
	return acc0 == 0 || accff == 0xff;
}

static int dh_mix(struct nx_session *s, const uint8_t priv[32], const uint8_t pub[32])
{
	uint8_t shared[32];
	crypto_x25519(shared, priv, pub);
	uint8_t acc = 0;
	for (int i = 0; i < 32; i++) {
		acc |= shared[i];
	}
	if (acc == 0) {
		return -1; /* low-order point */
	}
	mix_key(s, shared, 32);
	crypto_wipe(shared, sizeof(shared));
	return 0;
}

static void split(struct nx_session *s)
{
	uint8_t k1[32], k2[32];
	hkdf2(s->ck, NULL, 0, k1, k2);
	cs_init(&s->tx, s->initiator ? k1 : k2);
	cs_init(&s->rx, s->initiator ? k2 : k1);
	crypto_wipe(k1, sizeof(k1));
	crypto_wipe(k2, sizeof(k2));
	crypto_wipe(&s->cs, sizeof(s->cs));
	crypto_wipe(s->e_priv, sizeof(s->e_priv));
	s->rx_any = false;
	s->rx_highest = 0;
	memset(s->rx_window, 0, sizeof(s->rx_window));
	s->msg_index = 3;
}

bool nx_handshake_done(const struct nx_session *s)
{
	return s->msg_index >= 3;
}

bool nx_my_turn(const struct nx_session *s)
{
	if (s->msg_index >= 3) {
		return false;
	}
	/* messages 0 and 2 are written by the initiator */
	return s->initiator == ((s->msg_index % 2) == 0);
}

int nx_write_message(struct nx_session *s, const uint8_t *payload, size_t plen,
		     uint8_t *out, size_t cap, size_t *out_len)
{
	if (!nx_my_turn(s)) {
		return -1;
	}
	size_t off = 0;
	int n;

	switch (s->msg_index) {
	case 0: /* -> e */
		if (cap < 32) {
			return -1;
		}
		memcpy(out, s->e_pub, 32);
		mix_hash(s, s->e_pub, 32);
		off = 32;
		break;
	case 1: /* <- e, ee, s, es */
		if (cap < 32) {
			return -1;
		}
		memcpy(out, s->e_pub, 32);
		mix_hash(s, s->e_pub, 32);
		off = 32;
		if (dh_mix(s, s->e_priv, s->re) != 0) {
			return -1;
		}
		n = encrypt_and_hash(s, s->s_pub, 32, out + off, cap - off);
		if (n < 0) {
			return -1;
		}
		off += (size_t)n;
		if (dh_mix(s, s->s_priv, s->re) != 0) { /* es: responder uses s */
			return -1;
		}
		break;
	case 2: /* -> s, se */
		n = encrypt_and_hash(s, s->s_pub, 32, out, cap);
		if (n < 0) {
			return -1;
		}
		off = (size_t)n;
		if (dh_mix(s, s->s_priv, s->re) != 0) { /* se: initiator uses s */
			return -1;
		}
		break;
	default:
		return -1;
	}

	n = encrypt_and_hash(s, payload, plen, out + off, cap - off);
	if (n < 0) {
		return -1;
	}
	off += (size_t)n;
	*out_len = off;

	s->msg_index++;
	if (s->msg_index == 3) {
		split(s);
	}
	return 0;
}

int nx_read_message(struct nx_session *s, const uint8_t *in, size_t len,
		    uint8_t *payload, size_t cap, size_t *plen)
{
	if (nx_handshake_done(s) || nx_my_turn(s)) {
		return -1;
	}
	size_t off = 0;
	int n;

	switch (s->msg_index) {
	case 0: /* responder reads -> e */
		if (len < 32) {
			return -1;
		}
		memcpy(s->re, in, 32);
		if (bad_point(s->re)) {
			return -1;
		}
		mix_hash(s, s->re, 32);
		off = 32;
		break;
	case 1: /* initiator reads <- e, ee, s, es */
		if (len < 32 + 32 + NX_TAG) {
			return -1;
		}
		memcpy(s->re, in, 32);
		if (bad_point(s->re)) {
			return -1;
		}
		mix_hash(s, s->re, 32);
		off = 32;
		if (dh_mix(s, s->e_priv, s->re) != 0) {
			return -1;
		}
		if (decrypt_and_hash(s, in + off, 32 + NX_TAG, s->rs, 32) != 32) {
			return -1;
		}
		off += 32 + NX_TAG;
		if (bad_point(s->rs) || dh_mix(s, s->e_priv, s->rs) != 0) { /* es */
			return -1;
		}
		break;
	case 2: /* responder reads -> s, se */
		if (len < 32 + NX_TAG) {
			return -1;
		}
		if (decrypt_and_hash(s, in, 32 + NX_TAG, s->rs, 32) != 32) {
			return -1;
		}
		off = 32 + NX_TAG;
		if (bad_point(s->rs) || dh_mix(s, s->e_priv, s->rs) != 0) { /* se */
			return -1;
		}
		break;
	default:
		return -1;
	}

	n = decrypt_and_hash(s, in + off, len - off, payload, cap);
	if (n < 0) {
		return -1;
	}
	*plen = (size_t)n;

	s->msg_index++;
	if (s->msg_index == 3) {
		split(s);
	}
	return 0;
}

/* ---------- BitChat transport framing ---------- */

int nx_transport_encrypt(struct nx_session *s, const uint8_t *pt, size_t len,
			 uint8_t *out, size_t cap, size_t *out_len)
{
	if (!nx_handshake_done(s) || cap < len + NX_NONCE_PREFIX + NX_TAG ||
	    s->tx.n >= 0xFFFFFFFFu) {
		return -1;
	}
	uint32_t n = (uint32_t)s->tx.n;
	out[0] = (uint8_t)(n >> 24);
	out[1] = (uint8_t)(n >> 16);
	out[2] = (uint8_t)(n >> 8);
	out[3] = (uint8_t)n;
	aead_encrypt(s->tx.k, s->tx.n, NULL, 0, pt, len, out + NX_NONCE_PREFIX);
	s->tx.n++;
	*out_len = len + NX_NONCE_PREFIX + NX_TAG;
	return 0;
}

static bool window_seen(struct nx_session *s, uint64_t n)
{
	size_t i = n % NX_REPLAY_WINDOW;
	return s->rx_window[i / 8] & (1u << (i % 8));
}

static void window_mark(struct nx_session *s, uint64_t n)
{
	if (!s->rx_any || n > s->rx_highest) {
		/* clear the slots we slide over */
		uint64_t from = s->rx_any ? s->rx_highest + 1 : 0;
		if (n - from >= NX_REPLAY_WINDOW) {
			memset(s->rx_window, 0, sizeof(s->rx_window));
		} else {
			for (uint64_t k = from; k < n; k++) {
				size_t i = k % NX_REPLAY_WINDOW;
				s->rx_window[i / 8] &= (uint8_t)~(1u << (i % 8));
			}
		}
		s->rx_highest = n;
		s->rx_any = true;
	}
	size_t i = n % NX_REPLAY_WINDOW;
	s->rx_window[i / 8] |= (uint8_t)(1u << (i % 8));
}

int nx_transport_decrypt(struct nx_session *s, const uint8_t *in, size_t len,
			 uint8_t *out, size_t cap, size_t *out_len)
{
	if (!nx_handshake_done(s) || len < NX_NONCE_PREFIX + NX_TAG) {
		return -1;
	}
	uint64_t n = (uint64_t)in[0] << 24 | (uint64_t)in[1] << 16 | (uint64_t)in[2] << 8 | in[3];
	size_t ct_len = len - NX_NONCE_PREFIX;
	if (ct_len - NX_TAG > cap) {
		return -1;
	}
	if (s->rx_any) {
		if (n + NX_REPLAY_WINDOW <= s->rx_highest) {
			return -2; /* too old */
		}
		if (n <= s->rx_highest && window_seen(s, n)) {
			return -2; /* replay */
		}
	}
	if (aead_decrypt(s->rx.k, n, NULL, 0, in + NX_NONCE_PREFIX, ct_len, out) != 0) {
		return -1;
	}
	window_mark(s, n);
	*out_len = ct_len - NX_TAG;
	return 0;
}

void nx_wipe(struct nx_session *s)
{
	crypto_wipe(s, sizeof(*s));
}
