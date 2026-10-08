/* Host test for src/alertam_record.c (flash record encoding).
 * cc -O2 -Wall test_store.c ../src/alertam_record.c -o /tmp/test_store && /tmp/test_store */
#include <stdio.h>
#include <string.h>
#include "../src/alertam_record.h"

static int fails;

#define CHECK(cond, what) do { \
	if (!(cond)) { printf("FAIL: %s\n", what); fails++; } else { printf("ok   %s\n", what); } \
} while (0)

int main(void)
{
	/* identity round trip */
	uint8_t np[32], seed[32], rec[AREC_ID_LEN], np2[32], seed2[32];
	for (int i = 0; i < 32; i++) {
		np[i] = (uint8_t)i;
		seed[i] = (uint8_t)(0xA0 + i);
	}
	arec_id_encode(rec, np, seed);
	CHECK(arec_id_decode(rec, sizeof(rec), np2, seed2) == 0 &&
	      memcmp(np, np2, 32) == 0 && memcmp(seed, seed2, 32) == 0, "id round trip");
	CHECK(arec_id_decode(rec, sizeof(rec) - 1, np2, seed2) < 0, "id short record rejected");
	rec[0] = 99;
	CHECK(arec_id_decode(rec, sizeof(rec), np2, seed2) < 0, "id bad version rejected");

	/* circle round trip, incl. empty and full with max-length names */
	struct arec_member m[AREC_CIRCLE_MAX], out[AREC_CIRCLE_MAX];
	uint8_t buf[AREC_CIRCLE_CAP];
	memset(m, 0, sizeof(m));
	for (int i = 0; i < AREC_CIRCLE_MAX; i++) {
		snprintf(m[i].id_hex, sizeof(m[i].id_hex), "%016x", 0xabc0 + i);
		memset(m[i].name, 'a' + i, AREC_NAME_LEN - 1);
	}
	strcpy(m[0].name, "anon8907");

	int len = arec_circle_encode(buf, sizeof(buf), m, 0);
	CHECK(len == 2 && arec_circle_decode(buf, (size_t)len, out, AREC_CIRCLE_MAX) == 0,
	      "empty circle");

	len = arec_circle_encode(buf, sizeof(buf), m, AREC_CIRCLE_MAX);
	int n = arec_circle_decode(buf, (size_t)len, out, AREC_CIRCLE_MAX);
	int same = n == AREC_CIRCLE_MAX;
	for (int i = 0; same && i < n; i++) {
		same = strcmp(m[i].id_hex, out[i].id_hex) == 0 && strcmp(m[i].name, out[i].name) == 0;
	}
	CHECK(len > 0 && len <= AREC_CIRCLE_CAP && same, "full circle round trip (max names)");

	CHECK(arec_circle_decode(buf, (size_t)len, out, 2) == 2, "decode clamps to max");
	CHECK(arec_circle_decode(buf, (size_t)len - 1, out, AREC_CIRCLE_MAX) < 0, "truncated rejected");
	CHECK(arec_circle_encode(buf, sizeof(buf), m, AREC_CIRCLE_MAX + 1) < 0, "too many rejected");
	CHECK(arec_circle_encode(buf, 20, m, 2) < 0, "small buffer rejected");
	buf[2] = 'Z';
	CHECK(arec_circle_decode(buf, (size_t)len, out, AREC_CIRCLE_MAX) < 0, "non-hex id rejected");
	strcpy(m[1].id_hex, "abc");
	CHECK(arec_circle_encode(buf, sizeof(buf), m, 2) < 0, "short id rejected");

	printf("%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails, fails == 1 ? "" : "s");
	return fails != 0;
}
