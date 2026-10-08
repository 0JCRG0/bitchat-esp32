/*
 * alertam.c - Alertam panic-button behavior. See alertam.h.
 */
#include "alertam.h"

#include <string.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/shell/shell.h>
#include <zephyr/sys/printk.h>

#include "alert_retry.h"
#include "alertam_store.h"
#include "bitchat_wire.h"
#include "gesture.h"

#define CIRCLE_MAX 5
#define POLL_MS 10

static const struct gpio_dt_spec btn_ext = GPIO_DT_SPEC_GET(DT_ALIAS(alertam_button), gpios);
static const struct gpio_dt_spec btn_boot = GPIO_DT_SPEC_GET(DT_ALIAS(alertam_boot_button), gpios);
static const struct gpio_dt_spec led = GPIO_DT_SPEC_GET(DT_ALIAS(led0), gpios);

static struct k_work_q *ble_q;
static alertam_links_fn links_ready;

static char sos_text[200] = "SOS - Alertam: necesito ayuda";

static struct {
	bool used;
	char name[24];  /* nickname at the time it was added */
	char id_hex[17];
} circle[CIRCLE_MAX];

/* ---------- alerts (run on the BLE work queue) ----------
 *
 * Nothing is fire-and-forget: both alerts stay active and are retried by
 * retry_work (1 s tick while anything is active) until delivered, see
 * alert_retry.h for the rules. State is shared with the shell ('sos status',
 * 'sos cancel'), hence alert_lock. */

#define RETRY_TICK_MS 1000

BUILD_ASSERT(CIRCLE_MAX <= AR_MAX_RCPT, "one SOS recipient slot per circle member");

static K_MUTEX_DEFINE(alert_lock);
static atomic_t link_kick; /* a link became usable since the last tick */

static struct ar_public pub;
static char pub_text[sizeof(sos_text)];  /* text the cached packet carries */
static uint8_t pub_pkt[BCW_MAX_PACKET];
static int pub_len;

static struct ar_private priv;
static char priv_text[sizeof(sos_text)];
static struct {
	char name[24];
	char id_hex[17];
	uint8_t id[8];
	char msg_id[37]; /* one per SOS: retries are deduped by the app */
} rcpt[AR_MAX_RCPT];

static void retry_handler(struct k_work *work);
static K_WORK_DELAYABLE_DEFINE(retry_work, retry_handler);

static bool can_send(void)
{
	return bcw_clock_synced() && links_ready && links_ready() > 0;
}

static const char *why_not(void)
{
	return !bcw_clock_synced() ? "no phone seen yet (clock not synced)" : "no phone in range";
}

static void led_confirm(void);

static void public_step(int64_t now, bool ok_to_send, bool new_link)
{
	enum ar_pub_state before = pub.state;
	enum ar_action a = ar_pub_poll(&pub, now, ok_to_send, new_link);

	if (before == AR_PUB_SENT && pub.state == AR_PUB_IDLE) {
		printk("[Alertam] PUBLIC alert finished (%u writes, %u packets, %d min active)\n",
		       pub.writes, pub.builds, AR_LIFETIME_MS / 60000);
		return;
	}
	if (a == AR_NONE) {
		return;
	}
	if (a == AR_REBUILD_SEND) {
		int n = bcw_build_public_message(pub_text, pub_pkt, sizeof(pub_pkt));
		if (n < 0) {
			printk("[Alertam] PUBLIC alert: cannot build packet (%d), dropped\n", n);
			ar_pub_stop(&pub);
			return;
		}
		pub_len = n;
		if (pub.builds > 0) {
			printk("[Alertam] PUBLIC alert re-signed (%s)\n", pub.state == AR_PUB_PENDING
			       ? "cached packet about to go stale" : "phone came into range");
		}
		ar_pub_built(&pub, now);
	}
	int ret = bcw_broadcast(pub_pkt, (uint16_t)pub_len);
	if (ar_pub_wrote(&pub, now, ret == 0)) {
		printk("[Alertam] PUBLIC alert sent (pending %lld s): \"%s\" - re-broadcasting "
		       "every %d s for %d s\n", (now - pub.started) / 1000, pub_text,
		       AR_PUB_REBROADCAST_MS / 1000, AR_PUB_STALE_MS / 1000);
		led_confirm();
	} else if (ret == 0) {
		printk("[Alertam] PUBLIC alert re-broadcast #%u (packet age %lld s)\n",
		       pub.writes - 1, (now - pub.built) / 1000);
	} else {
		printk("[Alertam] PUBLIC alert write failed (%d), retry in %d s\n", ret,
		       AR_PUB_RETRY_MS / 1000);
	}
}

static void private_step(int64_t now, bool ok_to_send, bool new_link)
{
	if (!priv.active) {
		return;
	}
	if (ar_priv_tick(&priv, now) > 0) {
		for (int i = 0; i < priv.n; i++) {
			if (priv.r[i].state == AR_RCPT_EXPIRED) {
				printk("[Alertam] private SOS -> %s: NOT delivered after %u attempts, "
				       "giving up\n", rcpt[i].name, priv.r[i].attempts);
			}
		}
	}
	if (new_link) {
		ar_priv_link_up(&priv, now);
	}
	for (int i = 0; i < priv.n; i++) {
		if (!ar_priv_due(&priv, i, now, ok_to_send)) {
			continue;
		}
		/* one failing member must not block the others */
		int ret = bcw_send_private_with_id(rcpt[i].id_hex, priv_text, rcpt[i].msg_id);
		ar_priv_attempted(&priv, i, now, ret == 0);
		printk("[Alertam] private SOS -> %s: attempt %u %s, next in %lld s\n", rcpt[i].name,
		       priv.r[i].attempts + priv.r[i].failures,
		       ret == 0 ? "sent/queued" : "failed", (priv.r[i].next - now) / 1000);
	}
}

static void retry_handler(struct k_work *work)
{
	int64_t now = k_uptime_get();
	bool new_link = atomic_clear(&link_kick) != 0;
	bool ok_to_send = can_send();

	k_mutex_lock(&alert_lock, K_FOREVER);
	public_step(now, ok_to_send, new_link);
	private_step(now, ok_to_send, new_link);
	bool active = pub.state != AR_PUB_IDLE || priv.active;
	k_mutex_unlock(&alert_lock);

	if (active) {
		k_work_reschedule_for_queue(ble_q, &retry_work, K_MSEC(RETRY_TICK_MS));
	}
}

static void public_alert_handler(struct k_work *work)
{
	int64_t now = k_uptime_get();
	k_mutex_lock(&alert_lock, K_FOREVER);
	bool same = pub.state != AR_PUB_IDLE && strcmp(pub_text, sos_text) == 0;
	if (pub.state != AR_PUB_IDLE) {
		printk("[Alertam] PUBLIC alert re-triggered (%s)\n",
		       same && ar_pub_fresh(&pub, now) ? "same packet, lifetime refreshed"
						       : "new packet");
	}
	ar_pub_start(&pub, now, same);
	strcpy(pub_text, sos_text);
	if (!can_send()) {
		printk("[Alertam] PUBLIC alert pending (%s): \"%s\"\n", why_not(), pub_text);
	}
	k_mutex_unlock(&alert_lock);
	k_work_reschedule_for_queue(ble_q, &retry_work, K_NO_WAIT);
}

/* Is the active SOS for the same text and the same circle? */
static bool same_sos(void)
{
	int n = 0;
	if (!priv.active || strcmp(priv_text, sos_text) != 0) {
		return false;
	}
	for (int i = 0; i < CIRCLE_MAX; i++) {
		if (!circle[i].used) {
			continue;
		}
		bool found = false;
		for (int j = 0; j < priv.n && !found; j++) {
			found = strcmp(rcpt[j].id_hex, circle[i].id_hex) == 0;
		}
		if (!found) {
			return false;
		}
		n++;
	}
	return n == priv.n;
}

static void private_sos_handler(struct k_work *work)
{
	int64_t now = k_uptime_get();
	k_mutex_lock(&alert_lock, K_FOREVER);
	if (same_sos()) {
		ar_priv_restart(&priv, now);
		printk("[Alertam] private SOS re-triggered: %d undelivered retried now\n",
		       ar_priv_count(&priv, AR_RCPT_PENDING) + ar_priv_count(&priv, AR_RCPT_SENT));
	} else {
		/* New SOS: snapshot the circle and the text, one messageID each */
		int n = 0;
		for (int i = 0; i < CIRCLE_MAX; i++) {
			if (!circle[i].used || bcw_lookup_peer(circle[i].id_hex, rcpt[n].id) != 0) {
				continue;
			}
			snprintk(rcpt[n].name, sizeof(rcpt[n].name), "%s", circle[i].name);
			snprintk(rcpt[n].id_hex, sizeof(rcpt[n].id_hex), "%s", circle[i].id_hex);
			bcw_new_message_id(rcpt[n].msg_id);
			n++;
		}
		ar_priv_start(&priv, now, n);
		strcpy(priv_text, sos_text);
		if (n == 0) {
			printk("[Alertam] private SOS: circle is empty (use 'circle add <nick>')\n");
		} else if (!can_send()) {
			printk("[Alertam] private SOS to %d recipient(s) pending (%s)\n", n, why_not());
		} else {
			printk("[Alertam] private SOS to %d recipient(s)\n", n);
		}
	}
	k_mutex_unlock(&alert_lock);
	k_work_reschedule_for_queue(ble_q, &retry_work, K_NO_WAIT);
}

/* Delivered ACK / read receipt from bitchat_wire (BLE work queue) */
static void on_delivered(const uint8_t peer_id[8], const char *msg_id)
{
	int64_t now = k_uptime_get();
	k_mutex_lock(&alert_lock, K_FOREVER);
	for (int i = 0; i < priv.n; i++) {
		if (memcmp(rcpt[i].id, peer_id, 8) != 0 || strcmp(rcpt[i].msg_id, msg_id) != 0) {
			continue;
		}
		if (ar_priv_ack(&priv, i, now)) {
			printk("[Alertam] private SOS -> %s: delivered (%u attempt(s), %lld s)\n",
			       rcpt[i].name, priv.r[i].attempts, (now - priv.started) / 1000);
			if (ar_priv_count(&priv, AR_RCPT_DELIVERED) == priv.n) {
				printk("[Alertam] private SOS: all %d recipient(s) delivered\n", priv.n);
			}
			led_confirm();
		}
		break;
	}
	k_mutex_unlock(&alert_lock);
}

void alertam_link_ready(void)
{
	if (!ble_q) {
		return;
	}
	atomic_set(&link_kick, 1);
	k_work_reschedule_for_queue(ble_q, &retry_work, K_NO_WAIT);
}

static K_WORK_DEFINE(public_alert_work, public_alert_handler);
static K_WORK_DEFINE(private_sos_work, private_sos_handler);

/* ---------- LED feedback ---------- */

static void led_blink(int times, int on_ms, int off_ms)
{
	for (int i = 0; i < times; i++) {
		gpio_pin_set_dt(&led, 1);
		k_msleep(on_ms);
		gpio_pin_set_dt(&led, 0);
		if (i + 1 < times) {
			k_msleep(off_ms);
		}
	}
}

/* Short blink when a delivery is first confirmed. Called from the BLE queue,
 * so it must not sleep: the system work queue turns the LED off. */
static void led_off_handler(struct k_work *work)
{
	gpio_pin_set_dt(&led, 0);
}
static K_WORK_DELAYABLE_DEFINE(led_off_work, led_off_handler);

static void led_confirm(void)
{
	gpio_pin_set_dt(&led, 1);
	k_work_reschedule(&led_off_work, K_MSEC(200));
}

/* ---------- button thread ---------- */

static void button_thread(void *a, void *b, void *c)
{
	struct gesture_state st;
	const struct gesture_cfg cfg = GESTURE_CFG_DEFAULT;
	gesture_init(&st);

	while (1) {
		bool pressed = gpio_pin_get_dt(&btn_ext) > 0 || gpio_pin_get_dt(&btn_boot) > 0;
		enum gesture g = gesture_update(&st, &cfg, pressed, k_uptime_get_32());

		switch (g) {
		case GESTURE_LONG:
			printk("[Button] long press -> PUBLIC alert\n");
			k_work_submit_to_queue(ble_q, &public_alert_work);
			led_blink(1, 1500, 0);
			break;
		case GESTURE_DOUBLE:
			printk("[Button] double tap -> PRIVATE SOS\n");
			k_work_submit_to_queue(ble_q, &private_sos_work);
			led_blink(3, 120, 120);
			break;
		case GESTURE_SINGLE:
			printk("[Button] single tap (no action)\n");
			break;
		default:
			break;
		}
		k_msleep(POLL_MS);
	}
}

/* ---------- persistence (alertam_store.c) ---------- */

static void circle_save(const struct shell *sh)
{
	struct arec_member m[CIRCLE_MAX];
	int n = 0;
	for (int i = 0; i < CIRCLE_MAX; i++) {
		if (circle[i].used) {
			memcpy(m[n].name, circle[i].name, sizeof(m[n].name));
			memcpy(m[n].id_hex, circle[i].id_hex, sizeof(m[n].id_hex));
			n++;
		}
	}
	if (astore_save_circle(m, n) != 0) {
		shell_warn(sh, "Circle NOT saved to flash (kept in RAM until reboot)");
	}
}

static void persisted_load(void)
{
	struct arec_member m[CIRCLE_MAX];
	int n = astore_load_circle(m, CIRCLE_MAX);
	for (int i = 0; i < n; i++) {
		circle[i].used = true;
		memcpy(circle[i].name, m[i].name, sizeof(circle[i].name));
		memcpy(circle[i].id_hex, m[i].id_hex, sizeof(circle[i].id_hex));
	}
	const char *text = astore_sos();
	if (text) {
		strncpy(sos_text, text, sizeof(sos_text) - 1);
	}
	printk("[Alertam] Loaded %d circle member(s), SOS text %s\n", n,
	       text ? "from flash" : "default");
}

K_THREAD_STACK_DEFINE(button_stack, 1536);
static struct k_thread button_tid;

int alertam_init(struct k_work_q *q, alertam_links_fn links_fn)
{
	ble_q = q;
	links_ready = links_fn;
	bcw_set_delivered_cb(on_delivered);
	persisted_load();

	if (!gpio_is_ready_dt(&btn_ext) || !gpio_is_ready_dt(&btn_boot) || !gpio_is_ready_dt(&led)) {
		printk("[Alertam] GPIO not ready\n");
		return -ENODEV;
	}
	gpio_pin_configure_dt(&btn_ext, GPIO_INPUT);
	gpio_pin_configure_dt(&btn_boot, GPIO_INPUT);
	gpio_pin_configure_dt(&led, GPIO_OUTPUT_INACTIVE);

	k_thread_create(&button_tid, button_stack, K_THREAD_STACK_SIZEOF(button_stack),
			button_thread, NULL, NULL, NULL, 7, 0, K_NO_WAIT);
	k_thread_name_set(&button_tid, "alertam_btn");
	printk("[Alertam] Buttons ready: D1 + BOOT (hold 2 s = public, double tap = private SOS)\n");
	return 0;
}

/* ---------- shell ---------- */

static int cmd_sos_text(const struct shell *sh, size_t argc, char **argv)
{
	if (argc < 2) {
		shell_print(sh, "SOS text: \"%s\"", sos_text);
		return 0;
	}
	size_t pos = 0;
	for (size_t a = 1; a < argc && pos < sizeof(sos_text) - 1; a++) {
		int w = snprintk(sos_text + pos, sizeof(sos_text) - pos, "%s%s", a > 1 ? " " : "", argv[a]);
		if (w < 0) {
			break;
		}
		pos = MIN(pos + (size_t)w, sizeof(sos_text) - 1);
	}
	shell_print(sh, "SOS text set: \"%s\"", sos_text);
	if (astore_save_sos(sos_text) != 0) {
		shell_warn(sh, "SOS text NOT saved to flash");
	}
	return 0;
}

static int cmd_sos_public(const struct shell *sh, size_t argc, char **argv)
{
	k_work_submit_to_queue(ble_q, &public_alert_work);
	return 0;
}

static int cmd_sos_private(const struct shell *sh, size_t argc, char **argv)
{
	k_work_submit_to_queue(ble_q, &private_sos_work);
	return 0;
}

static int cmd_sos_status(const struct shell *sh, size_t argc, char **argv)
{
	int64_t now = k_uptime_get();
	k_mutex_lock(&alert_lock, K_FOREVER);
	shell_print(sh, "Links ready: %d, clock %s", links_ready ? links_ready() : 0,
		    bcw_clock_synced() ? "synced" : "NOT synced");
	if (pub.state == AR_PUB_IDLE) {
		shell_print(sh, "PUBLIC: idle");
	} else {
		shell_print(sh, "PUBLIC: %s for %lld s, %u write(s), %u packet(s)%s \"%s\"",
			    ar_pub_state_name(pub.state), (now - pub.started) / 1000, pub.writes,
			    pub.builds, ar_pub_fresh(&pub, now) ? " (re-broadcasting)" : "", pub_text);
		if (pub.state == AR_PUB_SENT) {
			shell_print(sh, "  ends in %lld s",
				    (pub.first_sent + AR_LIFETIME_MS - now) / 1000);
		}
	}
	if (priv.n == 0) {
		shell_print(sh, "PRIVATE: none");
	} else {
		shell_print(sh, "PRIVATE: %s, started %lld s ago, %d/%d delivered \"%s\"",
			    priv.active ? "active" : "done", (now - priv.started) / 1000,
			    ar_priv_count(&priv, AR_RCPT_DELIVERED), priv.n, priv_text);
		for (int i = 0; i < priv.n; i++) {
			const struct ar_rcpt *r = &priv.r[i];
			bool waiting = r->state == AR_RCPT_PENDING || r->state == AR_RCPT_SENT;
			char next[40] = "";

			if (waiting) {
				snprintk(next, sizeof(next), ", next in %lld s",
					 (long long)(MAX(0, r->next - now) / 1000));
			}
			shell_print(sh, "  %-12s %s  %s, %u attempt(s), %u failure(s)%s",
				    rcpt[i].name, rcpt[i].id_hex, ar_rcpt_state_name(r->state),
				    r->attempts, r->failures, next);
		}
	}
	k_mutex_unlock(&alert_lock);
	return 0;
}

static int cmd_sos_cancel(const struct shell *sh, size_t argc, char **argv)
{
	k_mutex_lock(&alert_lock, K_FOREVER);
	ar_pub_stop(&pub);
	ar_priv_stop(&priv);
	k_mutex_unlock(&alert_lock);
	printk("[Alertam] alerts cancelled from the shell\n");
	return 0;
}

static int cmd_circle_add(const struct shell *sh, size_t argc, char **argv)
{
	uint8_t id[8];
	if (argc < 2 || bcw_lookup_peer(argv[1], id) != 0) {
		shell_error(sh, "Unknown peer (needs a nickname from 'list' or a 16-hex peer ID)");
		return -ENOENT;
	}
	char hex[17];
	for (int i = 0; i < 8; i++) {
		snprintk(hex + 2 * i, 3, "%02x", id[i]);
	}
	int free_slot = -1;
	for (int i = 0; i < CIRCLE_MAX; i++) {
		if (circle[i].used && strcmp(circle[i].id_hex, hex) == 0) {
			shell_print(sh, "%s is already in the circle", argv[1]);
			return 0;
		}
		if (!circle[i].used && free_slot < 0) {
			free_slot = i;
		}
	}
	if (free_slot < 0) {
		shell_error(sh, "Circle is full (%d)", CIRCLE_MAX);
		return -ENOMEM;
	}
	circle[free_slot].used = true;
	strncpy(circle[free_slot].name, argv[1], sizeof(circle[free_slot].name) - 1);
	memcpy(circle[free_slot].id_hex, hex, sizeof(hex));
	shell_print(sh, "Added %s (%s) to the circle", argv[1], hex);
	circle_save(sh);
	return 0;
}

static int cmd_circle_del(const struct shell *sh, size_t argc, char **argv)
{
	for (int i = 0; argc >= 2 && i < CIRCLE_MAX; i++) {
		if (circle[i].used && (strcmp(circle[i].name, argv[1]) == 0 ||
				       strcmp(circle[i].id_hex, argv[1]) == 0)) {
			circle[i].used = false;
			shell_print(sh, "Removed %s", argv[1]);
			circle_save(sh);
			return 0;
		}
	}
	shell_error(sh, "Not in the circle");
	return -ENOENT;
}

static int cmd_circle_list(const struct shell *sh, size_t argc, char **argv)
{
	int n = 0;
	for (int i = 0; i < CIRCLE_MAX; i++) {
		if (circle[i].used) {
			shell_print(sh, "  %s  %s", circle[i].id_hex, circle[i].name);
			n++;
		}
	}
	shell_print(sh, "%d member(s) (saved in flash)", n);
	return 0;
}

static int cmd_sos_buttons(const struct shell *sh, size_t argc, char **argv)
{
	/* Sample both buttons for 5 s and report raw levels / presses seen */
	int ext_pressed = 0, boot_pressed = 0;
	for (int i = 0; i < 500; i++) {
		ext_pressed += gpio_pin_get_dt(&btn_ext) > 0;
		boot_pressed += gpio_pin_get_dt(&btn_boot) > 0;
		k_msleep(10);
	}
	shell_print(sh, "5 s sample (10 ms): D1 pressed %d/500, BOOT pressed %d/500",
		    ext_pressed, boot_pressed);
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_sos,
	SHELL_CMD(buttons, NULL, "Sample button levels for 5 s (wiring check)", cmd_sos_buttons),
	SHELL_CMD(text, NULL, "[text] - Show/set the alert text", cmd_sos_text),
	SHELL_CMD(public, NULL, "Fire the public alert (same as long press)", cmd_sos_public),
	SHELL_CMD(private, NULL, "Fire the private SOS (same as double tap)", cmd_sos_private),
	SHELL_CMD(status, NULL, "Active alerts and per-recipient delivery state", cmd_sos_status),
	SHELL_CMD(cancel, NULL, "Stop retrying all active alerts", cmd_sos_cancel),
	SHELL_SUBCMD_SET_END
);
SHELL_CMD_REGISTER(sos, &sub_sos, "Alertam alerts", NULL);

SHELL_STATIC_SUBCMD_SET_CREATE(sub_circle,
	SHELL_CMD(add, NULL, "<nick|peer-id> - Add to the private SOS circle", cmd_circle_add),
	SHELL_CMD(del, NULL, "<nick|peer-id> - Remove", cmd_circle_del),
	SHELL_CMD(list, NULL, "List circle members", cmd_circle_list),
	SHELL_SUBCMD_SET_END
);
SHELL_CMD_REGISTER(circle, &sub_circle, "Pre-approved private SOS circle", NULL);
