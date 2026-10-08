/*
 * alert_retry.c - retry / re-broadcast scheduling for Alertam alerts.
 * See alert_retry.h.
 */
#include "alert_retry.h"

#include <string.h>

/* ---------- public alert ---------- */

bool ar_pub_fresh(const struct ar_public *p, int64_t now)
{
	return p->have_packet && now - p->built < AR_PUB_STALE_MS;
}

void ar_pub_start(struct ar_public *p, int64_t now, bool keep_packet)
{
	if (keep_packet && p->state != AR_PUB_IDLE && ar_pub_fresh(p, now)) {
		/* Same alert again: extend it, send right away, no new chat line */
		p->started = now;
		if (p->state == AR_PUB_SENT) {
			p->first_sent = now;
		}
		p->last_try = -1;
		return;
	}
	memset(p, 0, sizeof(*p));
	p->state = AR_PUB_PENDING;
	p->started = now;
	p->last_try = -1;
}

void ar_pub_stop(struct ar_public *p)
{
	p->state = AR_PUB_IDLE;
}

enum ar_action ar_pub_poll(struct ar_public *p, int64_t now, bool can_send, bool new_link)
{
	if (p->state == AR_PUB_IDLE) {
		return AR_NONE;
	}
	if (p->state == AR_PUB_SENT && now - p->first_sent >= AR_LIFETIME_MS) {
		p->state = AR_PUB_IDLE;
		return AR_NONE;
	}
	if (!can_send) {
		return AR_NONE;
	}
	bool fresh = ar_pub_fresh(p, now);
	bool never = p->last_try < 0;

	if (p->state == AR_PUB_PENDING) {
		if (!fresh) {
			return AR_REBUILD_SEND; /* nothing cached yet, or about to go stale */
		}
		if (never || new_link || now - p->last_try >= AR_PUB_RETRY_MS) {
			return AR_SEND;
		}
		return AR_NONE;
	}
	/* SENT */
	if (fresh) {
		if (never || new_link || now - p->last_try >= AR_PUB_REBROADCAST_MS) {
			return AR_SEND;
		}
		return AR_NONE;
	}
	/* Re-broadcast window over: only a phone that just came into range is
	 * worth a new (re-signed) packet */
	return new_link || never ? AR_REBUILD_SEND : AR_NONE;
}

void ar_pub_built(struct ar_public *p, int64_t now)
{
	p->have_packet = true;
	p->built = now;
	p->builds++;
}

bool ar_pub_wrote(struct ar_public *p, int64_t now, bool ok)
{
	p->last_try = now;
	if (!ok) {
		return false;
	}
	p->writes++;
	if (p->state == AR_PUB_PENDING) {
		p->state = AR_PUB_SENT;
		p->first_sent = now;
		return true;
	}
	return false;
}

/* ---------- private SOS ---------- */

int64_t ar_pm_backoff(uint32_t n)
{
	int64_t d = AR_PM_BACKOFF_MIN_MS;
	for (uint32_t i = 1; i < n && d < AR_PM_BACKOFF_MAX_MS; i++) {
		d *= 2;
	}
	return d > AR_PM_BACKOFF_MAX_MS ? AR_PM_BACKOFF_MAX_MS : d;
}

static bool undelivered(const struct ar_rcpt *r)
{
	return r->state == AR_RCPT_PENDING || r->state == AR_RCPT_SENT;
}

void ar_priv_start(struct ar_private *p, int64_t now, int n)
{
	memset(p, 0, sizeof(*p));
	p->n = n > AR_MAX_RCPT ? AR_MAX_RCPT : (n < 0 ? 0 : n);
	p->active = p->n > 0;
	p->started = now;
	for (int i = 0; i < p->n; i++) {
		p->r[i].state = AR_RCPT_PENDING;
		p->r[i].next = now;
		p->r[i].last_try = -1;
	}
}

void ar_priv_restart(struct ar_private *p, int64_t now)
{
	p->started = now;
	for (int i = 0; i < p->n; i++) {
		struct ar_rcpt *r = &p->r[i];
		if (r->state == AR_RCPT_EXPIRED) {
			r->state = r->attempts ? AR_RCPT_SENT : AR_RCPT_PENDING;
		}
		if (undelivered(r)) {
			r->next = now;
			r->attempts = 0; /* backoff starts over */
		}
	}
	p->active = ar_priv_count(p, AR_RCPT_PENDING) + ar_priv_count(p, AR_RCPT_SENT) > 0;
}

void ar_priv_stop(struct ar_private *p)
{
	p->active = false;
}

int ar_priv_tick(struct ar_private *p, int64_t now)
{
	if (!p->active) {
		return 0;
	}
	int expired = 0;
	if (now - p->started >= AR_LIFETIME_MS) {
		for (int i = 0; i < p->n; i++) {
			if (undelivered(&p->r[i])) {
				p->r[i].state = AR_RCPT_EXPIRED;
				expired++;
			}
		}
	}
	bool left = false;
	for (int i = 0; i < p->n; i++) {
		left |= undelivered(&p->r[i]);
	}
	p->active = left;
	return expired;
}

bool ar_priv_due(const struct ar_private *p, int i, int64_t now, bool can_send)
{
	return p->active && can_send && i >= 0 && i < p->n && undelivered(&p->r[i]) &&
	       now >= p->r[i].next;
}

void ar_priv_attempted(struct ar_private *p, int i, int64_t now, bool ok)
{
	struct ar_rcpt *r = &p->r[i];
	r->last_try = now;
	if (ok) {
		r->attempts++;
		if (r->state == AR_RCPT_PENDING) {
			r->state = AR_RCPT_SENT;
		}
		r->next = now + ar_pm_backoff(r->attempts);
	} else {
		/* local failure (link dropped, encrypt error): short retry, no backoff */
		r->failures++;
		r->next = now + AR_PM_BACKOFF_MIN_MS;
	}
}

void ar_priv_link_up(struct ar_private *p, int64_t now)
{
	for (int i = 0; p->active && i < p->n; i++) {
		struct ar_rcpt *r = &p->r[i];
		if (undelivered(r) && r->next > now &&
		    (r->last_try < 0 || now - r->last_try >= AR_PM_KICK_GAP_MS)) {
			r->next = now;
		}
	}
}

bool ar_priv_ack(struct ar_private *p, int i, int64_t now)
{
	if (i < 0 || i >= p->n || p->r[i].state == AR_RCPT_DELIVERED ||
	    p->r[i].state == AR_RCPT_UNUSED) {
		return false;
	}
	/* A late ACK after expiry still counts: the message did arrive */
	p->r[i].state = AR_RCPT_DELIVERED;
	p->r[i].delivered_at = now;
	return true;
}

int64_t ar_priv_next_due(const struct ar_private *p)
{
	int64_t best = -1;
	for (int i = 0; p->active && i < p->n; i++) {
		if (undelivered(&p->r[i]) && (best < 0 || p->r[i].next < best)) {
			best = p->r[i].next;
		}
	}
	return best;
}

int ar_priv_count(const struct ar_private *p, enum ar_rcpt_state s)
{
	int c = 0;
	for (int i = 0; i < p->n; i++) {
		c += p->r[i].state == s;
	}
	return c;
}

const char *ar_pub_state_name(enum ar_pub_state s)
{
	switch (s) {
	case AR_PUB_PENDING: return "pending";
	case AR_PUB_SENT:    return "sent";
	default:             return "idle";
	}
}

const char *ar_rcpt_state_name(enum ar_rcpt_state s)
{
	switch (s) {
	case AR_RCPT_PENDING:   return "pending";
	case AR_RCPT_SENT:      return "sent, waiting ACK";
	case AR_RCPT_DELIVERED: return "delivered";
	case AR_RCPT_EXPIRED:   return "EXPIRED";
	default:                return "-";
	}
}
