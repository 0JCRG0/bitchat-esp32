/*
 * bitchat_wire.h - current BitChat wire protocol (Alertam fork)
 *
 * Implements the packet format used by the BitChat iOS/Android apps as of
 * permissionlesstech/bitchat 5e9287f (Sep 2026):
 *   - v1 header: version, type, ttl, timestamp(ms, BE64), flags, length(BE16)
 *   - 8-byte sender ID = first 8 bytes of SHA-256(Noise static public key)
 *   - Ed25519 signature over the packet encoded with ttl=0 and no signature
 *   - PKCS#7-style padding to 256/512/1024/2048 (only when it fits in 255)
 *   - 0x01 announce (TLV nickname / noise key / signing key), 0x02 public
 *     message (raw UTF-8)
 *
 * The device has no RTC; wall-clock time is learned from the timestamps of
 * packets received from phones (the app rejects announces older than 15 min).
 */
#ifndef BITCHAT_WIRE_H
#define BITCHAT_WIRE_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "bitchat_protocol.h"

#define BCW_TYPE_ANNOUNCE 0x01
#define BCW_TYPE_MESSAGE  0x02
#define BCW_TYPE_LEAVE    0x03

#define BCW_TTL 7
#define BCW_MAX_PACKET 512

/* Generate the Ed25519 identity and derive the peer ID from id->noise_public.
 * Copies the Ed25519 public key into id->sign_public. */
int bcw_identity_init(struct bitchat_identity *id);

/* 8-byte peer ID (SHA-256(noise_public)[0..7]) */
const uint8_t *bcw_peer_id(void);

bool bcw_clock_synced(void);
uint64_t bcw_now_ms(void);

/* Build a signed announce / public message. Returns padded length or <0. */
int bcw_build_announce(const struct bitchat_identity *id, uint8_t *out, size_t cap);
int bcw_build_public_message(const char *text, uint8_t *out, size_t cap);

/* Callbacks the RX handler uses to report what it saw */
typedef void (*bcw_peer_cb)(const uint8_t peer_id[8], const char *nickname,
			    const uint8_t noise_pub[32], const uint8_t sign_pub[32],
			    bool verified);
typedef void (*bcw_message_cb)(const uint8_t peer_id[8], const char *nickname,
			       const char *text, bool verified);
void bcw_set_callbacks(bcw_peer_cb on_peer, bcw_message_cb on_message);

/* Feed a received (padded) packet. Learns the clock from any packet.
 * Returns true if the packet was an announce / public message and was consumed. */
bool bcw_handle_rx(const uint8_t *pkt, uint16_t len);

/* Callback fired once, the first time the clock gets synced */
void bcw_set_clock_sync_cb(void (*cb)(void));

#endif /* BITCHAT_WIRE_H */
