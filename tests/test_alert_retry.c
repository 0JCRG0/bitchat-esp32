/* Host test for src/alert_retry.c.
 * cc -O2 -Wall test_alert_retry.c ../src/alert_retry.c -o /tmp/test_alert_retry && /tmp/test_alert_retry */
#include <stdio.h>
#include "../src/alert_retry.h"

static int fails;

#define CHECK(cond) do { \
	if (!(cond)) { printf("  FAIL line %d: %s\n", __LINE__, #cond); fails++; } \
} while (0)

/* Drive a public alert the way alertam.c does: poll, build if asked, write.
 * Returns the action taken. */
static enum ar_action pub_step(struct ar_public *p, int64_t now, bool can_send, bool new_link)
{
	enum ar_action a = ar_pub_poll(p, now, can_send, new_link);
	if (a == AR_REBUILD_SEND) {
		ar_pub_built(p, now);
	}
	if (a != AR_NONE) {
		ar_pub_wrote(p, now, can_send);
	}
	return a;
}

static void test_pub_pending_then_first_delivery(void)
{
	printf("public: pending -> first delivery\n");
	struct ar_public p;
	ar_pub_start(&p, 0, false);
	CHECK(p.state == AR_PUB_PENDING);
	/* no phone for 60 s: nothing is built or written */
	for (int64_t t = 0; t < 60000; t += 1000) {
		CHECK(pub_step(&p, t, false, false) == AR_NONE);
	}
	CHECK(p.builds == 0 && p.state == AR_PUB_PENDING);
	/* link comes up: build + send at once */
	CHECK(pub_step(&p, 60000, true, true) == AR_REBUILD_SEND);
	CHECK(p.state == AR_PUB_SENT && p.first_sent == 60000 && p.writes == 1);
	/* next second: nothing (re-broadcast every 20 s) */
	CHECK(pub_step(&p, 61000, true, false) == AR_NONE);
	CHECK(pub_step(&p, 80000, true, false) == AR_SEND);
	CHECK(p.builds == 1 && p.writes == 2);
}

static void test_pub_failed_write_retries(void)
{
	printf("public: failed write retried every 5 s with the same bytes\n");
	struct ar_public p;
	ar_pub_start(&p, 0, false);
	CHECK(ar_pub_poll(&p, 0, true, false) == AR_REBUILD_SEND);
	ar_pub_built(&p, 0);
	CHECK(!ar_pub_wrote(&p, 0, false));
	CHECK(p.state == AR_PUB_PENDING);
	CHECK(ar_pub_poll(&p, 4000, true, false) == AR_NONE);
	CHECK(ar_pub_poll(&p, 5000, true, false) == AR_SEND);
	CHECK(ar_pub_wrote(&p, 5000, true));
	CHECK(p.state == AR_PUB_SENT && p.builds == 1);
}

static void test_pub_stale_rebuild(void)
{
	printf("public: never delivered -> rebuild before the cache goes stale\n");
	struct ar_public p;
	ar_pub_start(&p, 0, false);
	/* built while a link looked ready, but every write fails */
	CHECK(ar_pub_poll(&p, 0, true, false) == AR_REBUILD_SEND);
	ar_pub_built(&p, 0);
	ar_pub_wrote(&p, 0, false);
	int builds_before_stale = 0, rebuild_at = -1;
	for (int64_t t = 1000; t <= 150000; t += 1000) {
		enum ar_action a = ar_pub_poll(&p, t, true, false);
		if (a == AR_REBUILD_SEND) {
			ar_pub_built(&p, t);
			if (rebuild_at < 0) {
				rebuild_at = (int)t;
			}
		}
		if (a != AR_NONE) {
			ar_pub_wrote(&p, t, false);
		}
		if (t < AR_PUB_STALE_MS) {
			builds_before_stale = (int)p.builds;
		}
	}
	CHECK(builds_before_stale == 1);
	CHECK(rebuild_at == AR_PUB_STALE_MS);
	CHECK(p.state == AR_PUB_PENDING); /* still active, never expires */
	/* pending alert outlives the lifetime */
	CHECK(ar_pub_poll(&p, AR_LIFETIME_MS * 3, false, false) == AR_NONE);
	CHECK(p.state == AR_PUB_PENDING);
	/* delivered at last: from a fresh rebuild */
	CHECK(pub_step(&p, AR_LIFETIME_MS * 3, true, true) == AR_REBUILD_SEND);
	CHECK(p.state == AR_PUB_SENT);
}

static void test_pub_window_and_lifetime(void)
{
	printf("public: re-broadcast window end, lifetime end\n");
	struct ar_public p;
	ar_pub_start(&p, 0, false);
	CHECK(pub_step(&p, 0, true, false) == AR_REBUILD_SEND);
	int sends = 0, rebuilds = 0;
	for (int64_t t = 1000; t < 200000; t += 1000) {
		enum ar_action a = pub_step(&p, t, true, false);
		sends += a == AR_SEND;
		rebuilds += a == AR_REBUILD_SEND;
	}
	/* same bytes at 20, 40, 60, 80 s; nothing after the 100 s window */
	CHECK(sends == 4);
	CHECK(rebuilds == 0);
	/* a phone shows up later: one fresh packet, then its own window */
	CHECK(pub_step(&p, 300000, true, true) == AR_REBUILD_SEND);
	CHECK(p.builds == 2);
	CHECK(pub_step(&p, 320000, true, false) == AR_SEND);
	/* link flaps inside the window: cached bytes, no rebuild */
	CHECK(pub_step(&p, 321000, true, true) == AR_SEND);
	CHECK(p.builds == 2);
	/* lifetime is measured from the first write (t=0) */
	CHECK(pub_step(&p, AR_LIFETIME_MS - 1, true, true) != AR_NONE);
	CHECK(p.state == AR_PUB_SENT);
	CHECK(pub_step(&p, AR_LIFETIME_MS, true, true) == AR_NONE);
	CHECK(p.state == AR_PUB_IDLE);
	CHECK(pub_step(&p, AR_LIFETIME_MS + 5000, true, true) == AR_NONE);
}

static void test_pub_retrigger(void)
{
	printf("public: re-trigger refreshes, no duplicate chat line\n");
	struct ar_public p;
	ar_pub_start(&p, 0, false);
	pub_step(&p, 0, true, false);
	/* pressed again 30 s later, same text: keep packet, send now */
	ar_pub_start(&p, 30000, true);
	CHECK(p.state == AR_PUB_SENT && p.first_sent == 30000);
	CHECK(pub_step(&p, 30000, true, false) == AR_SEND);
	CHECK(p.builds == 1);
	/* pressed again after the cache went stale: new packet */
	ar_pub_start(&p, 150000, true);
	CHECK(p.state == AR_PUB_PENDING && !p.have_packet);
	CHECK(pub_step(&p, 150000, true, false) == AR_REBUILD_SEND);
}

static void test_backoff(void)
{
	printf("private: backoff progression\n");
	CHECK(ar_pm_backoff(1) == 5000);
	CHECK(ar_pm_backoff(2) == 10000);
	CHECK(ar_pm_backoff(3) == 20000);
	CHECK(ar_pm_backoff(4) == 30000);
	CHECK(ar_pm_backoff(50) == 30000);

	struct ar_private p;
	ar_priv_start(&p, 0, 1);
	int64_t times[8];
	int k = 0;
	for (int64_t t = 0; t < 130000 && k < 8; t += 1000) {
		ar_priv_tick(&p, t);
		if (ar_priv_due(&p, 0, t, true)) {
			ar_priv_attempted(&p, 0, t, true);
			times[k++] = t;
		}
	}
	/* 0, +5, +10, +20, +30, +30 ... */
	CHECK(k >= 6);
	CHECK(times[0] == 0 && times[1] == 5000 && times[2] == 15000 &&
	      times[3] == 35000 && times[4] == 65000 && times[5] == 95000);
	CHECK(p.r[0].state == AR_RCPT_SENT);
}

static void test_ack(void)
{
	printf("private: per-recipient ACK\n");
	struct ar_private p;
	ar_priv_start(&p, 0, 2);
	CHECK(ar_priv_due(&p, 0, 0, true) && ar_priv_due(&p, 1, 0, true));
	CHECK(!ar_priv_due(&p, 0, 0, false)); /* no link: wait, attempts not burnt */
	ar_priv_attempted(&p, 0, 0, true);
	ar_priv_attempted(&p, 1, 0, true);
	CHECK(ar_priv_ack(&p, 0, 800));
	CHECK(!ar_priv_ack(&p, 0, 900)); /* duplicate ACK */
	ar_priv_tick(&p, 1000);
	CHECK(p.active);
	CHECK(!ar_priv_due(&p, 0, 60000, true)); /* delivered: never again */
	CHECK(ar_priv_due(&p, 1, 5000, true));
	CHECK(ar_priv_ack(&p, 1, 6000));
	ar_priv_tick(&p, 6000);
	CHECK(!p.active);
	CHECK(ar_priv_count(&p, AR_RCPT_DELIVERED) == 2);
}

static void test_one_fails_other_delivers(void)
{
	printf("private: one recipient failing never blocks another\n");
	struct ar_private p;
	ar_priv_start(&p, 0, 3);
	int tries[3] = {0};
	int expired = 0;
	for (int64_t t = 0; t <= AR_LIFETIME_MS + 1000; t += 1000) {
		expired += ar_priv_tick(&p, t);
		for (int i = 0; i < 3; i++) {
			if (!ar_priv_due(&p, i, t, true)) {
				continue;
			}
			tries[i]++;
			/* 0: phone answers the 2nd try; 1: never answers;
			 * 2: local write fails twice, then works and is ACKed */
			bool ok = !(i == 2 && tries[i] <= 2);
			ar_priv_attempted(&p, i, t, ok);
			if ((i == 0 && tries[i] == 2) || (i == 2 && tries[i] == 3)) {
				ar_priv_ack(&p, i, t + 300);
			}
		}
	}
	CHECK(p.r[0].state == AR_RCPT_DELIVERED && tries[0] == 2);
	CHECK(p.r[2].state == AR_RCPT_DELIVERED && tries[2] == 3);
	CHECK(p.r[2].failures == 2);
	CHECK(p.r[1].state == AR_RCPT_EXPIRED && expired == 1);
	/* 10 min at <= 30 s apart: about 22 attempts, never more than one per 5 s */
	CHECK(tries[1] >= 20 && tries[1] <= 25);
	CHECK(!p.active);
	/* late ACK after expiry still counts */
	CHECK(ar_priv_ack(&p, 1, AR_LIFETIME_MS + 2000));
}

static void test_link_up_kick(void)
{
	printf("private: new link pulls retries forward (rate limited)\n");
	struct ar_private p;
	ar_priv_start(&p, 0, 1);
	for (int i = 0; i < 4; i++) {
		ar_priv_attempted(&p, 0, 0, true); /* backoff now 30 s */
	}
	CHECK(ar_priv_next_due(&p) == 30000);
	ar_priv_link_up(&p, 1000); /* too soon after the last try */
	CHECK(ar_priv_next_due(&p) == 30000);
	ar_priv_link_up(&p, 3000);
	CHECK(ar_priv_next_due(&p) == 3000 && ar_priv_due(&p, 0, 3000, true));
	/* restart: lifetime refreshed, backoff starts over */
	ar_priv_restart(&p, 500000);
	CHECK(p.started == 500000 && p.r[0].attempts == 0 && ar_priv_due(&p, 0, 500000, true));
}

int main(void)
{
	test_pub_pending_then_first_delivery();
	test_pub_failed_write_retries();
	test_pub_stale_rebuild();
	test_pub_window_and_lifetime();
	test_pub_retrigger();
	test_backoff();
	test_ack();
	test_one_fails_other_delivers();
	test_link_up_kick();
	printf(fails ? "FAILED (%d)\n" : "ALL PASS\n", fails);
	return fails != 0;
}
