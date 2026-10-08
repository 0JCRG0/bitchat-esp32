/*
 * bitchat_wire.c - current BitChat wire protocol (Alertam fork)
 * See bitchat_wire.h for the format notes.
 */
#include "bitchat_wire.h"

#include <string.h>
#include <zephyr/kernel.h>
#include <psa/crypto.h>

#include "../lib/monocypher/monocypher.h"
#include "../lib/monocypher/monocypher-ed25519.h"

#define HDR_V1     14
#define ID_SIZE    8
#define SIG_SIZE   64

#define FLAG_HAS_RECIPIENT 0x01
#define FLAG_HAS_SIGNATURE 0x02
#define FLAG_IS_COMPRESSED 0x04
#define FLAG_HAS_ROUTE     0x08

#define TLV_NICKNAME 0x01
#define TLV_NOISE    0x02
#define TLV_SIGNING  0x03

/* Any timestamp outside this window is not a real wall clock (2020..2096) */
#define MIN_WALL_MS 1577836800000ULL
#define MAX_WALL_MS 4000000000000ULL

#define MAX_KNOWN_PEERS 8

static uint8_t ed_secret[64];
static uint8_t ed_public[32];
static uint8_t peer_id[ID_SIZE];

static bool clock_synced;
static int64_t clock_offset_ms;
static void (*clock_sync_cb)(void);

static bcw_peer_cb peer_cb;
static bcw_message_cb message_cb;

static struct {
	bool used;
	uint8_t id[ID_SIZE];
	uint8_t sign_pub[32];
	char nickname[bitchat_NICKNAME_LEN];
} known[MAX_KNOWN_PEERS];

/* Scratch buffers: everything runs on the BLE work queue, one at a time */
static uint8_t scratch[BCW_MAX_PACKET];

/* ---------- identity ---------- */

int bcw_identity_init(struct bitchat_identity *id)
{
	uint8_t seed[32];
	if (psa_generate_random(seed, sizeof(seed)) != PSA_SUCCESS) {
		return -1;
	}
	crypto_ed25519_key_pair(ed_secret, ed_public, seed); /* wipes seed */
	memcpy(id->sign_public, ed_public, 32);
	memset(id->sign_private, 0, sizeof(id->sign_private)); /* unused: secret lives here */

	uint8_t digest[32];
	size_t olen;
	if (psa_hash_compute(PSA_ALG_SHA_256, id->noise_public, 32,
			     digest, sizeof(digest), &olen) != PSA_SUCCESS) {
		return -1;
	}
	memcpy(peer_id, digest, ID_SIZE);
	return 0;
}

const uint8_t *bcw_peer_id(void)
{
	return peer_id;
}

/* ---------- clock ---------- */

bool bcw_clock_synced(void)
{
	return clock_synced;
}

uint64_t bcw_now_ms(void)
{
	return (uint64_t)(k_uptime_get() + clock_offset_ms);
}

void bcw_set_clock_sync_cb(void (*cb)(void))
{
	clock_sync_cb = cb;
}

static void observe_timestamp(uint64_t ts)
{
	if (ts < MIN_WALL_MS || ts > MAX_WALL_MS) {
		return;
	}
	int64_t candidate = (int64_t)ts - k_uptime_get();
	bool first = !clock_synced;
	/* Packets are stamped when sent, so the newest one is the best estimate */
	if (first || candidate > clock_offset_ms) {
		clock_offset_ms = candidate;
		clock_synced = true;
	}
	if (first && clock_sync_cb) {
		clock_sync_cb();
	}
}

/* ---------- encoding (mirrors BinaryProtocol.encode in the app) ---------- */

static int encode(uint8_t type, uint8_t ttl, uint64_t ts,
		  const uint8_t *sender, const uint8_t *recipient,
		  const uint8_t *payload, uint16_t plen,
		  const uint8_t *sig, uint8_t *out, size_t cap)
{
	size_t len = HDR_V1 + ID_SIZE + (recipient ? ID_SIZE : 0) + plen + (sig ? SIG_SIZE : 0);
	if (len > cap) {
		return -1;
	}
	uint8_t *p = out;
	*p++ = 1;    /* version */
	*p++ = type;
	*p++ = ttl;
	for (int shift = 56; shift >= 0; shift -= 8) {
		*p++ = (uint8_t)(ts >> shift);
	}
	*p++ = (recipient ? FLAG_HAS_RECIPIENT : 0) | (sig ? FLAG_HAS_SIGNATURE : 0);
	*p++ = (uint8_t)(plen >> 8);
	*p++ = (uint8_t)plen;
	memcpy(p, sender, ID_SIZE);
	p += ID_SIZE;
	if (recipient) {
		memcpy(p, recipient, ID_SIZE);
		p += ID_SIZE;
	}
	memcpy(p, payload, plen);
	p += plen;
	if (sig) {
		memcpy(p, sig, SIG_SIZE);
		p += SIG_SIZE;
	}

	/* MessagePadding: smallest block with 16 bytes of headroom; the pad
	 * length is a single byte, so skip padding when it would exceed 255 */
	static const uint16_t blocks[] = { 256, 512, 1024, 2048 };
	size_t target = len;
	for (size_t i = 0; i < ARRAY_SIZE(blocks); i++) {
		if (len + 16 <= blocks[i]) {
			target = blocks[i];
			break;
		}
	}
	size_t need = target - len;
	if (need > 0 && need <= 255 && target <= cap) {
		memset(out + len, (uint8_t)need, need);
		len = target;
	}
	return (int)len;
}

static int build_signed(uint8_t type, const uint8_t *payload, uint16_t plen,
			uint8_t *out, size_t cap)
{
	uint64_t ts = bcw_now_ms();
	uint8_t sig[SIG_SIZE];

	/* toBinaryDataForSigning: ttl=0, no signature, padded */
	int n = encode(type, 0, ts, peer_id, NULL, payload, plen, NULL, scratch, sizeof(scratch));
	if (n < 0) {
		return n;
	}
	crypto_ed25519_sign(sig, ed_secret, scratch, (size_t)n);
	return encode(type, BCW_TTL, ts, peer_id, NULL, payload, plen, sig, out, cap);
}

int bcw_build_announce(const struct bitchat_identity *id, uint8_t *out, size_t cap)
{
	uint8_t tlv[2 + bitchat_NICKNAME_LEN + 2 + 32 + 2 + 32];
	uint8_t *p = tlv;
	size_t nick_len = strnlen(id->nickname, bitchat_NICKNAME_LEN - 1);

	*p++ = TLV_NICKNAME;
	*p++ = (uint8_t)nick_len;
	memcpy(p, id->nickname, nick_len);
	p += nick_len;
	*p++ = TLV_NOISE;
	*p++ = 32;
	memcpy(p, id->noise_public, 32);
	p += 32;
	*p++ = TLV_SIGNING;
	*p++ = 32;
	memcpy(p, ed_public, 32);
	p += 32;

	return build_signed(BCW_TYPE_ANNOUNCE, tlv, (uint16_t)(p - tlv), out, cap);
}

int bcw_build_public_message(const char *text, uint8_t *out, size_t cap)
{
	size_t len = strlen(text);
	if (len == 0 || len > 400) {
		return -1;
	}
	return build_signed(BCW_TYPE_MESSAGE, (const uint8_t *)text, (uint16_t)len, out, cap);
}

/* ---------- receiving ---------- */

void bcw_set_callbacks(bcw_peer_cb on_peer, bcw_message_cb on_message)
{
	peer_cb = on_peer;
	message_cb = on_message;
}

static int known_find(const uint8_t *id)
{
	for (int i = 0; i < MAX_KNOWN_PEERS; i++) {
		if (known[i].used && memcmp(known[i].id, id, ID_SIZE) == 0) {
			return i;
		}
	}
	return -1;
}

static void known_store(const uint8_t *id, const uint8_t *sign_pub, const char *nick)
{
	int slot = known_find(id);
	for (int i = 0; slot < 0 && i < MAX_KNOWN_PEERS; i++) {
		if (!known[i].used) {
			slot = i;
		}
	}
	if (slot < 0) {
		slot = 0; /* table full: overwrite the oldest-ish slot */
	}
	known[slot].used = true;
	memcpy(known[slot].id, id, ID_SIZE);
	memcpy(known[slot].sign_pub, sign_pub, 32);
	strncpy(known[slot].nickname, nick, sizeof(known[slot].nickname) - 1);
	known[slot].nickname[sizeof(known[slot].nickname) - 1] = '\0';
}

static bool verify(uint8_t type, uint64_t ts, const uint8_t *sender, const uint8_t *recipient,
		   const uint8_t *payload, uint16_t plen, const uint8_t *sig, const uint8_t *sign_pub)
{
	int n = encode(type, 0, ts, sender, recipient, payload, plen, NULL, scratch, sizeof(scratch));
	if (n < 0) {
		return false;
	}
	return crypto_ed25519_check(sig, sign_pub, scratch, (size_t)n) == 0;
}

bool bcw_handle_rx(const uint8_t *pkt, uint16_t len)
{
	if (len < HDR_V1 + ID_SIZE) {
		return false;
	}
	uint8_t version = pkt[0];
	uint8_t type = pkt[1];
	uint64_t ts = 0;
	for (int i = 0; i < 8; i++) {
		ts = (ts << 8) | pkt[3 + i];
	}
	observe_timestamp(ts);

	if (version != 1 || (type != BCW_TYPE_ANNOUNCE && type != BCW_TYPE_MESSAGE)) {
		return false;
	}
	uint8_t flags = pkt[11];
	if (flags & FLAG_IS_COMPRESSED) {
		return true; /* small announces/messages are never compressed; drop */
	}
	uint16_t plen = ((uint16_t)pkt[12] << 8) | pkt[13];
	const uint8_t *p = pkt + HDR_V1;
	const uint8_t *sender = p;
	p += ID_SIZE;
	const uint8_t *recipient = NULL;
	if (flags & FLAG_HAS_RECIPIENT) {
		recipient = p;
		p += ID_SIZE;
	}
	const uint8_t *payload = p;
	const uint8_t *sig = NULL;
	size_t need = (size_t)(p - pkt) + plen;
	if (flags & FLAG_HAS_SIGNATURE) {
		sig = payload + plen;
		need += SIG_SIZE;
	}
	if (need > len) {
		return true; /* truncated */
	}
	if (memcmp(sender, peer_id, ID_SIZE) == 0) {
		return true; /* our own packet relayed back */
	}

	if (type == BCW_TYPE_ANNOUNCE) {
		char nick[bitchat_NICKNAME_LEN] = "";
		const uint8_t *noise = NULL, *sign = NULL;
		for (uint16_t off = 0; off + 2 <= plen;) {
			uint8_t t = payload[off], l = payload[off + 1];
			const uint8_t *v = payload + off + 2;
			if (off + 2 + l > plen) {
				break;
			}
			if (t == TLV_NICKNAME) {
				size_t n = MIN(l, sizeof(nick) - 1);
				memcpy(nick, v, n);
				nick[n] = '\0';
			} else if (t == TLV_NOISE && l == 32) {
				noise = v;
			} else if (t == TLV_SIGNING && l == 32) {
				sign = v;
			}
			off += 2 + l;
		}
		if (!noise || !sign) {
			return true;
		}
		bool ok = sig && verify(type, ts, sender, recipient, payload, plen, sig, sign);
		if (ok) {
			known_store(sender, sign, nick);
		}
		if (peer_cb) {
			peer_cb(sender, nick, noise, sign, ok);
		}
		return true;
	}

	/* Public message: raw UTF-8, broadcast only */
	if (recipient) {
		bool broadcast = true;
		for (int i = 0; i < ID_SIZE; i++) {
			broadcast &= recipient[i] == 0xFF;
		}
		if (!broadcast) {
			return true;
		}
	}
	char text[401];
	size_t n = MIN(plen, sizeof(text) - 1);
	memcpy(text, payload, n);
	text[n] = '\0';

	int k = known_find(sender);
	bool ok = k >= 0 && sig && verify(type, ts, sender, recipient, payload, plen, sig, known[k].sign_pub);
	if (message_cb) {
		message_cb(sender, k >= 0 ? known[k].nickname : "?", text, ok);
	}
	return true;
}
