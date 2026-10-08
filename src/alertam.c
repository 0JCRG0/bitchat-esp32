/*
 * alertam.c - Alertam panic-button behavior. See alertam.h.
 */
#include "alertam.h"

#include <string.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/shell/shell.h>
#include <zephyr/sys/printk.h>

#include "bitchat_wire.h"
#include "gesture.h"

#define CIRCLE_MAX 5
#define POLL_MS 10

static const struct gpio_dt_spec btn_ext = GPIO_DT_SPEC_GET(DT_ALIAS(alertam_button), gpios);
static const struct gpio_dt_spec btn_boot = GPIO_DT_SPEC_GET(DT_ALIAS(alertam_boot_button), gpios);
static const struct gpio_dt_spec led = GPIO_DT_SPEC_GET(DT_ALIAS(led0), gpios);

static struct k_work_q *ble_q;
static alertam_public_fn send_public;

static char sos_text[200] = "SOS - Alertam: necesito ayuda";

static struct {
	bool used;
	char name[24];  /* nickname at the time it was added */
	char id_hex[17];
} circle[CIRCLE_MAX];

/* ---------- alerts (run on the BLE work queue) ---------- */

static void public_alert_handler(struct k_work *work)
{
	int ret = send_public(sos_text);
	printk("[Alertam] PUBLIC alert %s: \"%s\"\n",
	       ret == 0 ? "sent" : "NOT sent (no phone in range)", sos_text);
}

static void private_sos_handler(struct k_work *work)
{
	int n = 0, ok = 0;
	for (int i = 0; i < CIRCLE_MAX; i++) {
		if (!circle[i].used) {
			continue;
		}
		n++;
		/* one failing member must not block the others */
		int ret = bcw_send_private(circle[i].id_hex, sos_text);
		printk("[Alertam] private SOS -> %s (%s): %s\n", circle[i].name, circle[i].id_hex,
		       ret == 0 ? "sent/queued" : "failed");
		ok += ret == 0;
	}
	if (n == 0) {
		printk("[Alertam] private SOS: circle is empty (use 'circle add <nick>')\n");
	} else {
		printk("[Alertam] private SOS: %d/%d recipients\n", ok, n);
	}
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

K_THREAD_STACK_DEFINE(button_stack, 1536);
static struct k_thread button_tid;

int alertam_init(struct k_work_q *q, alertam_public_fn public_fn)
{
	ble_q = q;
	send_public = public_fn;

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
	return 0;
}

static int cmd_circle_del(const struct shell *sh, size_t argc, char **argv)
{
	for (int i = 0; argc >= 2 && i < CIRCLE_MAX; i++) {
		if (circle[i].used && (strcmp(circle[i].name, argv[1]) == 0 ||
				       strcmp(circle[i].id_hex, argv[1]) == 0)) {
			circle[i].used = false;
			shell_print(sh, "Removed %s", argv[1]);
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
	shell_print(sh, "%d member(s) (RAM only, lost on reboot)", n);
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
