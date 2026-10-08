/*
 * alertam_record.c - flash record encoding. See alertam_record.h.
 */
#include "alertam_record.h"

#include <string.h>

void arec_id_encode(uint8_t out[AREC_ID_LEN], const uint8_t noise_priv[32],
		    const uint8_t ed_seed[32])
{
	out[0] = AREC_VERSION;
	memcpy(out + 1, noise_priv, 32);
	memcpy(out + 33, ed_seed, 32);
}

int arec_id_decode(const uint8_t *in, size_t len, uint8_t noise_priv[32], uint8_t ed_seed[32])
{
	if (len != AREC_ID_LEN || in[0] != AREC_VERSION) {
		return -1;
	}
	memcpy(noise_priv, in + 1, 32);
	memcpy(ed_seed, in + 33, 32);
	return 0;
}

static int is_hex(char c)
{
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

int arec_circle_encode(uint8_t *out, size_t cap, const struct arec_member *m, int n)
{
	if (n < 0 || n > AREC_CIRCLE_MAX || cap < 2) {
		return -1;
	}
	size_t pos = 0;
	out[pos++] = AREC_VERSION;
	out[pos++] = (uint8_t)n;
	for (int i = 0; i < n; i++) {
		size_t nl = strnlen(m[i].name, AREC_NAME_LEN - 1);
		if (strlen(m[i].id_hex) != 16 || pos + 17 + nl > cap) {
			return -1;
		}
		memcpy(out + pos, m[i].id_hex, 16);
		pos += 16;
		out[pos++] = (uint8_t)nl;
		memcpy(out + pos, m[i].name, nl);
		pos += nl;
	}
	return (int)pos;
}

int arec_circle_decode(const uint8_t *in, size_t len, struct arec_member *m, int max)
{
	if (len < 2 || in[0] != AREC_VERSION || in[1] > AREC_CIRCLE_MAX) {
		return -1;
	}
	int n = in[1];
	size_t pos = 2;
	int out = 0;
	for (int i = 0; i < n; i++) {
		if (pos + 17 > len) {
			return -1;
		}
		const uint8_t *hex = in + pos;
		size_t nl = in[pos + 16];
		pos += 17;
		if (nl > AREC_NAME_LEN - 1 || pos + nl > len) {
			return -1;
		}
		for (int k = 0; k < 16; k++) {
			if (!is_hex((char)hex[k])) {
				return -1;
			}
		}
		if (out < max) {
			memcpy(m[out].id_hex, hex, 16);
			m[out].id_hex[16] = '\0';
			memcpy(m[out].name, in + pos, nl);
			m[out].name[nl] = '\0';
			out++;
		}
		pos += nl;
	}
	return pos == len ? out : -1;
}
