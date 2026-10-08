/*
 * alertam_store.c - Alertam state persisted in flash. See alertam_store.h.
 */
#include "alertam_store.h"

#include <errno.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/settings/settings.h>
#include <zephyr/shell/shell.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/reboot.h>
#include <psa/crypto.h>

#include "../lib/monocypher/monocypher.h"
#include "bitchat_wire.h"

#define SUBTREE "alertam"

static bool ready;

/* Values seen by the settings loader at boot (and kept in sync on save) */
static uint8_t id_rec[AREC_ID_LEN];
static bool have_id;
static char nick[bitchat_NICKNAME_LEN];
static char sos[200];
static uint8_t circle_rec[AREC_CIRCLE_CAP];
static int circle_len;

static int read_str(settings_read_cb read_cb, void *cb_arg, size_t len, char *buf, size_t cap)
{
	if (len == 0 || len >= cap) {
		return -EINVAL;
	}
	ssize_t n = read_cb(cb_arg, buf, len);
	if (n != (ssize_t)len) {
		buf[0] = '\0';
		return -EIO;
	}
	buf[n] = '\0';
	return 0;
}

static int h_set(const char *name, size_t len, settings_read_cb read_cb, void *cb_arg)
{
	const char *next;

	if (settings_name_steq(name, "id", &next) && !next) {
		if (len != sizeof(id_rec) || read_cb(cb_arg, id_rec, len) != (ssize_t)len) {
			return -EINVAL;
		}
		have_id = true;
		return 0;
	}
	if (settings_name_steq(name, "nick", &next) && !next) {
		return read_str(read_cb, cb_arg, len, nick, sizeof(nick));
	}
	if (settings_name_steq(name, "sos", &next) && !next) {
		return read_str(read_cb, cb_arg, len, sos, sizeof(sos));
	}
	if (settings_name_steq(name, "circle", &next) && !next) {
		if (len > sizeof(circle_rec) || read_cb(cb_arg, circle_rec, len) != (ssize_t)len) {
			circle_len = 0;
			return -EINVAL;
		}
		circle_len = (int)len;
		return 0;
	}
	return -ENOENT;
}

SETTINGS_STATIC_HANDLER_DEFINE(alertam, SUBTREE, NULL, h_set, NULL, NULL);

int astore_init(void)
{
	int ret = settings_subsys_init();
	if (ret == 0) {
		ret = settings_load_subtree(SUBTREE);
	}
	ready = ret == 0;
	if (!ready) {
		printk("[Store] settings init failed (%d): nothing will persist\n", ret);
	}
	return ret;
}

static int save(const char *key, const void *val, size_t len)
{
	if (!ready) {
		return -ENODEV;
	}
	char full[24];
	snprintk(full, sizeof(full), SUBTREE "/%s", key);
	int ret = settings_save_one(full, val, len);
	if (ret) {
		printk("[Store] save %s failed (%d)\n", full, ret);
	}
	return ret;
}

/* ---------- identity ---------- */

static int identity_new(struct bitchat_identity *id)
{
	uint8_t noise_priv[32], seed[32];
	if (psa_generate_random(noise_priv, sizeof(noise_priv)) != PSA_SUCCESS ||
	    psa_generate_random(seed, sizeof(seed)) != PSA_SUCCESS) {
		return -EIO;
	}
	arec_id_encode(id_rec, noise_priv, seed);
	have_id = true;
	int ret = bcw_identity_init_from(id, noise_priv, seed);
	crypto_wipe(noise_priv, sizeof(noise_priv));
	crypto_wipe(seed, sizeof(seed));
	if (ret) {
		return ret;
	}
	/* a failed save is not fatal: the identity still works until reboot */
	(void)save("id", id_rec, sizeof(id_rec));
	return 0;
}

int astore_identity_load(struct bitchat_identity *id, bool *created)
{
	uint8_t noise_priv[32], seed[32];

	*created = false;
	if (have_id && arec_id_decode(id_rec, sizeof(id_rec), noise_priv, seed) == 0) {
		int ret = bcw_identity_init_from(id, noise_priv, seed);
		crypto_wipe(noise_priv, sizeof(noise_priv));
		crypto_wipe(seed, sizeof(seed));
		return ret;
	}
	*created = true;
	return identity_new(id);
}

int astore_identity_regenerate(struct bitchat_identity *id)
{
	return identity_new(id);
}

/* ---------- nickname / SOS text / circle ---------- */

const char *astore_nick(void)
{
	return nick[0] ? nick : NULL;
}

int astore_save_nick(const char *name)
{
	strncpy(nick, name, sizeof(nick) - 1);
	nick[sizeof(nick) - 1] = '\0';
	return save("nick", nick, strlen(nick));
}

const char *astore_sos(void)
{
	return sos[0] ? sos : NULL;
}

int astore_save_sos(const char *text)
{
	strncpy(sos, text, sizeof(sos) - 1);
	sos[sizeof(sos) - 1] = '\0';
	return save("sos", sos, strlen(sos));
}

int astore_load_circle(struct arec_member *m, int max)
{
	if (circle_len == 0) {
		return 0;
	}
	int n = arec_circle_decode(circle_rec, (size_t)circle_len, m, max);
	if (n < 0) {
		printk("[Store] circle record malformed, ignored\n");
		return 0;
	}
	return n;
}

int astore_save_circle(const struct arec_member *m, int n)
{
	int len = arec_circle_encode(circle_rec, sizeof(circle_rec), m, n);
	if (len < 0) {
		return -EINVAL;
	}
	circle_len = len;
	return save("circle", circle_rec, (size_t)len);
}

/* ---------- factory reset ---------- */

static int cmd_alertam_reset(const struct shell *sh, size_t argc, char **argv)
{
	static const char *const keys[] = { "id", "nick", "circle", "sos" };

	if (argc < 2 || strcmp(argv[1], "confirm") != 0) {
		shell_print(sh, "Wipes identity (new peer ID), nickname, circle and SOS text, then reboots.");
		shell_print(sh, "Type 'alertam reset confirm' to proceed.");
		return -EINVAL;
	}
	int fails = 0;
	for (size_t i = 0; i < ARRAY_SIZE(keys); i++) {
		char full[24];
		snprintk(full, sizeof(full), SUBTREE "/%s", keys[i]);
		fails += ready && settings_delete(full) != 0;
	}
	shell_print(sh, "[Store] factory reset %s, rebooting...", fails ? "had errors" : "done");
	k_msleep(200);
	sys_reboot(SYS_REBOOT_COLD);
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_alertam,
	SHELL_CMD(reset, NULL, "confirm - Factory reset: wipe saved identity/circle/SOS text, reboot",
		  cmd_alertam_reset),
	SHELL_SUBCMD_SET_END
);
SHELL_CMD_REGISTER(alertam, &sub_alertam, "Alertam device settings", NULL);
