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
#include "noise_xx.h"

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
/* Noise static key, copied from the identity for noise_xx.c */
static struct {
	uint8_t priv[32];
	uint8_t pub[32];
} noise_static;
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

static void platform_random(uint8_t *buf, size_t len)
{
	(void)psa_generate_random(buf, len);
}

int bcw_identity_init(struct bitchat_identity *id)
{
	uint8_t seed[32];
	/* Noise static key: raw X25519 (Monocypher) so noise_xx.c can use it */
	nx_x25519_keypair(id->noise_private, id->noise_public, platform_random);
	if (psa_generate_random(seed, sizeof(seed)) != PSA_SUCCESS) {
		return -1;
	}
	crypto_ed25519_key_pair(ed_secret, ed_public, seed); /* wipes seed */
	memcpy(id->sign_public, ed_public, 32);
	memcpy(noise_static.priv, id->noise_private, 32);
	memcpy(noise_static.pub, id->noise_public, 32);
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

/* ---------- private messages: Noise sessions ---------- */

#define MAX_SESSIONS 4
#define HANDSHAKE_TIMEOUT_MS 20000
#define PM_TYPE_PRIVATE_MESSAGE 0x01
#define PM_TYPE_READ_RECEIPT    0x02
#define PM_TYPE_DELIVERED       0x03
#define PM_TLV_MESSAGE_ID 0x00
#define PM_TLV_CONTENT    0x01

static struct {
	bool used;
	uint8_t id[ID_SIZE];
	struct nx_session nx;
	int64_t started;
	char pending[256];   /* one PM waiting for the handshake */
} sessions[MAX_SESSIONS];

static bcw_send_fn send_fn;
static bcw_private_cb private_cb;
static bcw_event_cb event_cb;
static uint8_t txbuf[BCW_MAX_PACKET];

void bcw_set_send(bcw_send_fn send)
{
	send_fn = send;
}

void bcw_set_private_callbacks(bcw_private_cb on_private, bcw_event_cb on_event)
{
	private_cb = on_private;
	event_cb = on_event;
}

static void event(const char *msg)
{
	if (event_cb) {
		event_cb(msg);
	}
}

int bcw_session_count(void)
{
	int n = 0;
	for (int i = 0; i < MAX_SESSIONS; i++) {
		n += sessions[i].used && nx_handshake_done(&sessions[i].nx);
	}
	return n;
}

static int session_find(const uint8_t *id)
{
	for (int i = 0; i < MAX_SESSIONS; i++) {
		if (sessions[i].used && memcmp(sessions[i].id, id, ID_SIZE) == 0) {
			return i;
		}
	}
	return -1;
}

static int session_new(const uint8_t *id, bool initiator)
{
	int slot = session_find(id);
	if (slot < 0) {
		int64_t oldest = INT64_MAX;
		for (int i = 0; i < MAX_SESSIONS; i++) {
			if (!sessions[i].used) {
				slot = i;
				break;
			}
			if (sessions[i].started < oldest) {
				oldest = sessions[i].started;
				slot = i;
			}
		}
	}
	char keep[sizeof(sessions[0].pending)];
	strcpy(keep, sessions[slot].used && memcmp(sessions[slot].id, id, ID_SIZE) == 0
		     ? sessions[slot].pending : "");
	nx_wipe(&sessions[slot].nx);
	sessions[slot].used = true;
	memcpy(sessions[slot].id, id, ID_SIZE);
	sessions[slot].started = k_uptime_get();
	strcpy(sessions[slot].pending, keep);
	/* BitChat uses an empty prologue */
	nx_init(&sessions[slot].nx, initiator, noise_static.priv, noise_static.pub,
		NULL, 0, NULL, platform_random);
	return slot;
}

/* Directed, unsigned packet (0x10 / 0x11) */
static int send_directed(uint8_t type, const uint8_t *to, const uint8_t *payload, uint16_t plen)
{
	if (!send_fn) {
		return -1;
	}
	int n = encode(type, BCW_TTL, bcw_now_ms(), peer_id, to, payload, plen, NULL,
		       txbuf, sizeof(txbuf));
	if (n < 0) {
		return n;
	}
	return send_fn(txbuf, (uint16_t)n);
}

static int send_typed(int slot, uint8_t ptype, const uint8_t *body, size_t blen)
{
	uint8_t plain[300], ct[300 + NX_NONCE_PREFIX + NX_TAG];
	size_t clen;
	if (blen + 1 > sizeof(plain)) {
		return -1;
	}
	plain[0] = ptype;
	memcpy(plain + 1, body, blen);
	if (nx_transport_encrypt(&sessions[slot].nx, plain, blen + 1, ct, sizeof(ct), &clen) != 0) {
		return -1;
	}
	return send_directed(BCW_TYPE_NOISE_ENCRYPTED, sessions[slot].id, ct, (uint16_t)clen);
}

static void make_message_id(char out[37])
{
	/* UUID v4 string, uppercase like the app's UUID().uuidString */
	uint8_t r[16];
	static const char hex[] = "0123456789ABCDEF";
	platform_random(r, sizeof(r));
	r[6] = (r[6] & 0x0F) | 0x40;
	r[8] = (r[8] & 0x3F) | 0x80;
	int o = 0;
	for (int i = 0; i < 16; i++) {
		if (i == 4 || i == 6 || i == 8 || i == 10) {
			out[o++] = '-';
		}
		out[o++] = hex[r[i] >> 4];
		out[o++] = hex[r[i] & 0x0F];
	}
	out[o] = '\0';
}

static int send_pm_now(int slot, const char *text)
{
	char mid[37];
	uint8_t body[2 + 36 + 2 + 255];
	size_t tlen = strlen(text);
	if (tlen > 255) {
		tlen = 255;
	}
	make_message_id(mid);
	size_t o = 0;
	body[o++] = PM_TLV_MESSAGE_ID;
	body[o++] = 36;
	memcpy(body + o, mid, 36);
	o += 36;
	body[o++] = PM_TLV_CONTENT;
	body[o++] = (uint8_t)tlen;
	memcpy(body + o, text, tlen);
	o += tlen;
	return send_typed(slot, PM_TYPE_PRIVATE_MESSAGE, body, o);
}

static int start_handshake(int slot)
{
	uint8_t msg[64];
	size_t len;
	if (nx_write_message(&sessions[slot].nx, NULL, 0, msg, sizeof(msg), &len) != 0) {
		return -1;
	}
	event("[PM] Starting Noise handshake");
	return send_directed(BCW_TYPE_NOISE_HANDSHAKE, sessions[slot].id, msg, (uint16_t)len);
}

static void session_established(int slot)
{
	/* The app binds the session to SHA-256(remote static)[0..7] == sender ID */
	uint8_t d[32];
	nx_sha256(sessions[slot].nx.rs, 32, d);
	if (memcmp(d, sessions[slot].id, ID_SIZE) != 0) {
		event("[PM] Handshake peer identity mismatch, dropping session");
		nx_wipe(&sessions[slot].nx);
		sessions[slot].used = false;
		return;
	}
	event("[PM] Noise session established (end-to-end encrypted)");
	if (sessions[slot].pending[0]) {
		send_pm_now(slot, sessions[slot].pending);
		sessions[slot].pending[0] = '\0';
	}
}

static const char *nick_for(const uint8_t *id)
{
	int k = known_find(id);
	return k >= 0 ? known[k].nickname : "?";
}

static void handle_handshake(const uint8_t *sender, const uint8_t *msg, uint16_t len)
{
	uint8_t pl[64], out[128];
	size_t plen, olen;
	int slot = session_find(sender);
	bool fresh_init = (len == 32);

	if (fresh_init) {
		if (slot >= 0 && !nx_handshake_done(&sessions[slot].nx) &&
		    sessions[slot].nx.initiator && sessions[slot].nx.msg_index == 1 &&
		    memcmp(peer_id, sender, ID_SIZE) < 0) {
			return; /* crossed initiations: lower ID keeps the initiator role */
		}
		slot = session_new(sender, false);
	} else if (slot < 0 || nx_handshake_done(&sessions[slot].nx)) {
		return; /* not a message we are waiting for */
	}

	if (nx_read_message(&sessions[slot].nx, msg, len, pl, sizeof(pl), &plen) != 0) {
		event("[PM] Handshake message rejected");
		sessions[slot].used = false;
		return;
	}
	if (nx_my_turn(&sessions[slot].nx)) {
		if (nx_write_message(&sessions[slot].nx, NULL, 0, out, sizeof(out), &olen) != 0) {
			sessions[slot].used = false;
			return;
		}
		send_directed(BCW_TYPE_NOISE_HANDSHAKE, sender, out, (uint16_t)olen);
	}
	if (nx_handshake_done(&sessions[slot].nx)) {
		session_established(slot);
	}
}

static void handle_encrypted(const uint8_t *sender, const uint8_t *ct, uint16_t len)
{
	uint8_t pt[300];
	size_t plen;
	int slot = session_find(sender);
	if (slot < 0 || !nx_handshake_done(&sessions[slot].nx)) {
		/* App answers a 0x11 from an unknown session by re-handshaking; we
		 * start one ourselves so the next message gets through */
		slot = session_new(sender, true);
		start_handshake(slot);
		return;
	}
	if (nx_transport_decrypt(&sessions[slot].nx, ct, len, pt, sizeof(pt) - 1, &plen) != 0 ||
	    plen < 1) {
		return;
	}
	uint8_t ptype = pt[0];
	const uint8_t *body = pt + 1;
	size_t blen = plen - 1;

	if (ptype == PM_TYPE_PRIVATE_MESSAGE) {
		const uint8_t *mid = NULL, *content = NULL;
		uint8_t mid_len = 0, content_len = 0;
		for (size_t o = 0; o + 2 <= blen;) {
			uint8_t t = body[o], l = body[o + 1];
			if (o + 2 + l > blen) {
				return;
			}
			if (t == PM_TLV_MESSAGE_ID) {
				mid = body + o + 2;
				mid_len = l;
			} else if (t == PM_TLV_CONTENT) {
				content = body + o + 2;
				content_len = l;
			}
			o += 2 + l;
		}
		if (!mid || !content) {
			return;
		}
		char text[256];
		memcpy(text, content, content_len);
		text[content_len] = '\0';
		if (private_cb) {
			private_cb(sender, nick_for(sender), text);
		}
		/* Delivery ACK: 0x03 || messageID (raw UTF-8) */
		send_typed(slot, PM_TYPE_DELIVERED, mid, mid_len);
	} else if (ptype == PM_TYPE_DELIVERED) {
		event("[PM] Delivered");
	} else if (ptype == PM_TYPE_READ_RECEIPT) {
		event("[PM] Read");
	}
	/* 0x21 authenticatedPeerState and others: ignored */
}

static void private_rx(uint8_t type, const uint8_t *sender, const uint8_t *payload, uint16_t plen)
{
	if (type == BCW_TYPE_NOISE_HANDSHAKE) {
		handle_handshake(sender, payload, plen);
	} else {
		handle_encrypted(sender, payload, plen);
	}
}

static int hexval(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

int bcw_lookup_peer(const char *who, uint8_t id[ID_SIZE])
{
	for (int i = 0; i < MAX_KNOWN_PEERS; i++) {
		if (known[i].used && strcmp(known[i].nickname, who) == 0) {
			memcpy(id, known[i].id, ID_SIZE);
			return 0;
		}
	}
	if (strlen(who) != 16) {
		return -ENOENT;
	}
	for (int i = 0; i < ID_SIZE; i++) {
		int hi = hexval(who[2 * i]), lo = hexval(who[2 * i + 1]);
		if (hi < 0 || lo < 0) {
			return -ENOENT;
		}
		id[i] = (uint8_t)(hi << 4 | lo);
	}
	return 0;
}

int bcw_send_private(const char *who, const char *text)
{
	uint8_t id[ID_SIZE];
	if (bcw_lookup_peer(who, id) != 0) {
		return -ENOENT;
	}

	int slot = session_find(id);
	if (slot >= 0 && nx_handshake_done(&sessions[slot].nx)) {
		return send_pm_now(slot, text);
	}
	if (slot >= 0 && k_uptime_get() - sessions[slot].started < HANDSHAKE_TIMEOUT_MS) {
		strncpy(sessions[slot].pending, text, sizeof(sessions[slot].pending) - 1);
		return 0; /* handshake already in flight */
	}
	slot = session_new(id, true);
	strncpy(sessions[slot].pending, text, sizeof(sessions[slot].pending) - 1);
	sessions[slot].pending[sizeof(sessions[slot].pending) - 1] = '\0';
	return start_handshake(slot);
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

	if (version != 1 || (type != BCW_TYPE_ANNOUNCE && type != BCW_TYPE_MESSAGE &&
			     type != BCW_TYPE_NOISE_HANDSHAKE && type != BCW_TYPE_NOISE_ENCRYPTED)) {
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
	if (type == BCW_TYPE_NOISE_HANDSHAKE || type == BCW_TYPE_NOISE_ENCRYPTED) {
		/* Directed only: drop anything not addressed to us */
		if (recipient && memcmp(recipient, peer_id, ID_SIZE) == 0) {
			private_rx(type, sender, payload, plen);
		}
		return true;
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
