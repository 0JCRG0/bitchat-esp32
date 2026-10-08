/* Host test: noise_xx.c against the cacophony-style vectors shipped with
 * BitChat, plus a BitChat transport-framing round trip.
 * Build: cc -O2 -I../lib/monocypher test_noise.c ../src/noise_xx.c ../lib/monocypher/monocypher.c -o test_noise */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/noise_xx.h"
#include "../lib/monocypher/monocypher.h"
#include "noise_vectors.h"

static void rnd(uint8_t *b, size_t n) { arc4random_buf(b, n); }
static int fails;
#define CHECK(c, ...) do { if (!(c)) { printf("FAIL: " __VA_ARGS__); printf("\n"); fails++; } } while (0)

static void run_vector(int idx, const struct vec *v)
{
	struct nx_session I, R;
	uint8_t ipub[32], rpub[32], out[1024], pt[1024];
	size_t ol, pl;
	crypto_x25519_public_key(ipub, (const uint8_t *)v->is);
	crypto_x25519_public_key(rpub, (const uint8_t *)v->rs);
	nx_init(&I, true, (const uint8_t *)v->is, ipub, (const uint8_t *)v->prologue, v->prl, (const uint8_t *)v->ie, rnd);
	nx_init(&R, false, (const uint8_t *)v->rs, rpub, (const uint8_t *)v->prologue, v->prl, (const uint8_t *)v->re, rnd);

	for (int m = 0; m < v->nmsgs; m++) {
		const struct msg *mm = &v->msgs[m];
		bool i_writes = (m % 2) == 0;
		struct nx_session *W = i_writes ? &I : &R, *Rd = i_writes ? &R : &I;
		if (m < 3) {
			CHECK(nx_write_message(W, (const uint8_t *)mm->p, mm->pl, out, sizeof(out), &ol) == 0, "v%d msg%d write", idx, m);
			CHECK(ol == (size_t)mm->cl && memcmp(out, mm->c, ol) == 0, "v%d msg%d ciphertext mismatch", idx, m);
			CHECK(nx_read_message(Rd, out, ol, pt, sizeof(pt), &pl) == 0, "v%d msg%d read", idx, m);
			CHECK(pl == (size_t)mm->pl && memcmp(pt, mm->p, pl) == 0, "v%d msg%d payload mismatch", idx, m);
		} else {
			struct nx_cipher *tx = &W->tx, *rx = &Rd->rx;
			int n = nx_cipher_encrypt(tx, NULL, 0, (const uint8_t *)mm->p, mm->pl, out);
			CHECK(n == mm->cl && memcmp(out, mm->c, n) == 0, "v%d transport msg%d mismatch", idx, m);
			n = nx_cipher_decrypt(rx, NULL, 0, out, n, pt);
			CHECK(n == mm->pl && memcmp(pt, mm->p, n) == 0, "v%d transport msg%d decrypt", idx, m);
		}
	}
	CHECK(v->hhl == 0 || memcmp(I.h, v->hh, 32) == 0 && memcmp(R.h, v->hh, 32) == 0, "v%d handshake hash", idx);
	CHECK(memcmp(I.rs, rpub, 32) == 0 && memcmp(R.rs, ipub, 32) == 0, "v%d remote static", idx);
	printf("vector %d: %s\n", idx, fails ? "errors so far" : "ok");
}

static void bitchat_framing(void)
{
	struct nx_session I, R;
	uint8_t is[32], ip[32], rs[32], rp[32], pt[256], hs[256];
	size_t l, pl;
	nx_x25519_keypair(is, ip, rnd);
	nx_x25519_keypair(rs, rp, rnd);
	nx_init(&I, true, is, ip, NULL, 0, NULL, rnd);
	nx_init(&R, false, rs, rp, NULL, 0, NULL, rnd);
	CHECK(nx_write_message(&I, NULL, 0, hs, sizeof(hs), &l) == 0 && l == 32, "bitchat msg1 size %zu", l);
	CHECK(nx_read_message(&R, hs, l, pt, sizeof(pt), &pl) == 0, "bitchat read1");
	CHECK(nx_write_message(&R, NULL, 0, hs, sizeof(hs), &l) == 0 && l == 96, "bitchat msg2 size %zu", l);
	CHECK(nx_read_message(&I, hs, l, pt, sizeof(pt), &pl) == 0, "bitchat read2");
	CHECK(nx_write_message(&I, NULL, 0, hs, sizeof(hs), &l) == 0 && l == 64, "bitchat msg3 size %zu", l);
	CHECK(nx_read_message(&R, hs, l, pt, sizeof(pt), &pl) == 0, "bitchat read3");
	CHECK(nx_handshake_done(&I) && nx_handshake_done(&R), "bitchat done");

	uint8_t c0[64], c1[64];
	size_t l0, l1;
	CHECK(nx_transport_encrypt(&I, (const uint8_t *)"hola", 4, c0, sizeof(c0), &l0) == 0 && l0 == 24, "enc0");
	CHECK(nx_transport_encrypt(&I, (const uint8_t *)"mundo", 5, c1, sizeof(c1), &l1) == 0, "enc1");
	CHECK(c1[0] == 0 && c1[3] == 1, "nonce prefix BE");
	/* out of order is accepted, replay is not */
	CHECK(nx_transport_decrypt(&R, c1, l1, pt, sizeof(pt), &pl) == 0 && pl == 5 && !memcmp(pt, "mundo", 5), "dec1");
	CHECK(nx_transport_decrypt(&R, c0, l0, pt, sizeof(pt), &pl) == 0 && pl == 4 && !memcmp(pt, "hola", 4), "dec0 reordered");
	CHECK(nx_transport_decrypt(&R, c0, l0, pt, sizeof(pt), &pl) == -2, "replay rejected");
	CHECK(nx_transport_encrypt(&I, (const uint8_t *)"x", 1, c1, sizeof(c1), &l1) == 0, "enc2");
	c1[6] ^= 1;
	CHECK(nx_transport_decrypt(&R, c1, l1, pt, sizeof(pt), &pl) == -1, "tamper rejected");
	CHECK(nx_transport_encrypt(&R, (const uint8_t *)"ok", 2, c0, sizeof(c0), &l0) == 0 &&
	      nx_transport_decrypt(&I, c0, l0, pt, sizeof(pt), &pl) == 0 && pl == 2, "reverse direction");
	printf("bitchat framing: %s\n", fails ? "errors so far" : "ok");
}

int main(void)
{
	uint8_t d[32];
	nx_sha256((const uint8_t *)"abc", 3, d);
	CHECK(d[0] == 0xba && d[1] == 0x78 && d[31] == 0xad, "sha256(abc)");
	for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
		run_vector((int)i, &vectors[i]);
	}
	bitchat_framing();
	printf(fails ? "FAILED (%d)\n" : "ALL PASS\n", fails);
	return fails != 0;
}
