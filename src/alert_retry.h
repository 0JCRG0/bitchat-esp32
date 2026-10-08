/*
 * alert_retry.h - retry / re-broadcast scheduling for Alertam alerts
 *
 * Pure state machines (no Zephyr, no I/O): the caller feeds a millisecond
 * clock and whether it can send right now (a link is ready and the wall clock
 * is synced), and gets back what to do. Unit-tested on the host
 * (tests/test_alert_retry.c).
 *
 * Public alert (signed broadcast, no ACK exists):
 *   PENDING  nothing written to any link yet. Retry every AR_PUB_RETRY_MS and
 *            on every new link; rebuild the signed packet whenever the cached
 *            one is AR_PUB_STALE_MS old (the app rejects |skew| > 120 s).
 *   SENT     written to at least one link. Re-send the same cached bytes every
 *            AR_PUB_REBROADCAST_MS until the cache is stale (the app dedups
 *            identical packets, so phones that already have it see nothing new).
 *            After that, only a new link triggers a rebuild + send (a rebuild is
 *            a new chat line). Ends AR_LIFETIME_MS after the first write.
 *   A PENDING alert never expires: it must go out at least once.
 *
 * Private SOS (Noise PM per circle member, the app ACKs with the messageID):
 *   PENDING -> SENT (written, waiting for the ACK) -> DELIVERED, or EXPIRED
 *   AR_LIFETIME_MS after the SOS started. Undelivered recipients are retried
 *   with backoff 5, 10, 20, 30, 30... s, each one on its own schedule.
 */
#ifndef ALERT_RETRY_H
#define ALERT_RETRY_H

#include <stdbool.h>
#include <stdint.h>

#define AR_PUB_RETRY_MS        5000
#define AR_PUB_REBROADCAST_MS 20000
#define AR_PUB_STALE_MS      100000
#define AR_LIFETIME_MS       600000
#define AR_PM_BACKOFF_MIN_MS   5000
#define AR_PM_BACKOFF_MAX_MS  30000
#define AR_PM_KICK_GAP_MS      2000 /* min gap between attempts when a link comes up */
#define AR_MAX_RCPT 5

enum ar_action {
	AR_NONE = 0,
	AR_SEND,         /* write the cached packet */
	AR_REBUILD_SEND, /* build a fresh signed packet, cache it, write it */
};

/* ---------- public alert ---------- */

enum ar_pub_state {
	AR_PUB_IDLE = 0,
	AR_PUB_PENDING,
	AR_PUB_SENT,
};

struct ar_public {
	enum ar_pub_state state;
	bool have_packet;
	int64_t started;    /* trigger time */
	int64_t built;      /* build time of the cached packet */
	int64_t first_sent; /* first successful write (lifetime anchor) */
	int64_t last_try;   /* last write attempt, -1 = none since (re)start */
	uint32_t writes;    /* successful writes */
	uint32_t builds;
};

/* Start an alert. keep_packet: a re-trigger with the same text keeps a still
 * fresh cached packet (no duplicate chat line) and just refreshes the lifetime
 * and forces an immediate send. */
void ar_pub_start(struct ar_public *p, int64_t now, bool keep_packet);
void ar_pub_stop(struct ar_public *p);
/* Decide what to do now. new_link: a link just became usable. Also ends the
 * alert when its lifetime is over (state goes back to IDLE). */
enum ar_action ar_pub_poll(struct ar_public *p, int64_t now, bool can_send, bool new_link);
void ar_pub_built(struct ar_public *p, int64_t now);
/* Result of the write the last poll asked for. Returns true on the first
 * successful write (PENDING -> SENT). */
bool ar_pub_wrote(struct ar_public *p, int64_t now, bool ok);
bool ar_pub_fresh(const struct ar_public *p, int64_t now);

/* ---------- private SOS ---------- */

enum ar_rcpt_state {
	AR_RCPT_UNUSED = 0,
	AR_RCPT_PENDING,   /* never written */
	AR_RCPT_SENT,      /* written at least once, no ACK yet */
	AR_RCPT_DELIVERED, /* ACK received */
	AR_RCPT_EXPIRED,   /* lifetime over without an ACK */
};

struct ar_rcpt {
	enum ar_rcpt_state state;
	uint32_t attempts;  /* successful writes */
	uint32_t failures;  /* writes that failed locally */
	int64_t next;       /* next attempt due at */
	int64_t last_try;
	int64_t delivered_at;
};

struct ar_private {
	bool active;
	int64_t started;
	int n;
	struct ar_rcpt r[AR_MAX_RCPT];
};

/* Backoff after the n-th successful attempt (n >= 1) */
int64_t ar_pm_backoff(uint32_t n);

void ar_priv_start(struct ar_private *p, int64_t now, int n);
/* Re-trigger: refresh the lifetime and make every undelivered recipient due now */
void ar_priv_restart(struct ar_private *p, int64_t now);
void ar_priv_stop(struct ar_private *p);
/* Lifetime / completion bookkeeping. Returns the number of recipients that
 * just expired (so the caller can log them). Clears active when done. */
int ar_priv_tick(struct ar_private *p, int64_t now);
bool ar_priv_due(const struct ar_private *p, int i, int64_t now, bool can_send);
void ar_priv_attempted(struct ar_private *p, int i, int64_t now, bool ok);
/* A link came up: pull undelivered retries forward (not more often than
 * AR_PM_KICK_GAP_MS per recipient). */
void ar_priv_link_up(struct ar_private *p, int64_t now);
/* ACK for recipient i. Returns true if this is the first one. */
bool ar_priv_ack(struct ar_private *p, int i, int64_t now);
/* Earliest time any undelivered recipient is due (or -1 if none) */
int64_t ar_priv_next_due(const struct ar_private *p);
int ar_priv_count(const struct ar_private *p, enum ar_rcpt_state s);

const char *ar_pub_state_name(enum ar_pub_state s);
const char *ar_rcpt_state_name(enum ar_rcpt_state s);

#endif /* ALERT_RETRY_H */
