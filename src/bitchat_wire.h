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

/* ---------- Private messages (Noise XX, see noise_xx.h) ---------- */

#define BCW_TYPE_NOISE_HANDSHAKE 0x10
#define BCW_TYPE_NOISE_ENCRYPTED 0x11

/* Writes a finished packet to the link(s). Called from the BLE work queue. */
typedef int (*bcw_send_fn)(const uint8_t *pkt, uint16_t len);
void bcw_set_send(bcw_send_fn send);

typedef void (*bcw_private_cb)(const uint8_t peer_id[8], const char *nickname,
			       const char *text);
typedef void (*bcw_event_cb)(const char *fmt_msg);
void bcw_set_private_callbacks(bcw_private_cb on_private, bcw_event_cb on_event);

/* Send a private message to a known peer (by nickname or 16-hex peer ID).
 * Starts a handshake first if there is no session. Must run on the BLE queue.
 * Returns 0 if sent or queued. */
int bcw_send_private(const char *who, const char *text);

/* Same, with a caller-chosen messageID (36-char UUID string, see
 * bcw_new_message_id). Retries with the same ID are deduped by the app. */
int bcw_send_private_with_id(const char *who, const char *text, const char *msg_id);
void bcw_new_message_id(char out[37]);

/* Delivered ACK (or read receipt) for one of our PMs: 0x03 || messageID */
typedef void (*bcw_delivered_cb)(const uint8_t peer_id[8], const char *msg_id);
void bcw_set_delivered_cb(bcw_delivered_cb on_delivered);

/* Write a finished packet to every ready link through the bcw_send_fn.
 * BLE queue only. Returns 0 if at least one link took it. */
int bcw_broadcast(const uint8_t *pkt, uint16_t len);

/* Resolve a nickname or 16-hex peer ID to a peer ID. Returns 0 on success. */
int bcw_lookup_peer(const char *who, uint8_t id_out[8]);

/* Number of established Noise sessions */
int bcw_session_count(void);

/* Callback fired once, the first time the clock gets synced */
void bcw_set_clock_sync_cb(void (*cb)(void));

#endif /* BITCHAT_WIRE_H */
