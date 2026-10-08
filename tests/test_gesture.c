/* Host test for src/gesture.c.
 * cc -O2 -Wall test_gesture.c ../src/gesture.c -o /tmp/test_gesture && /tmp/test_gesture */
#include <stdio.h>
#include "../src/gesture.h"

static int fails;

/* Simulate a timeline: list of (level, duration_ms) segments, polled every 10 ms.
 * Returns the gestures seen, in order, as a string like "LD". */
static void run(const char *name, const int *segs, int n, const char *expect)
{
	struct gesture_state s;
	struct gesture_cfg cfg = GESTURE_CFG_DEFAULT;
	char got[16] = "";
	int k = 0;
	uint32_t t = 0;
	gesture_init(&s);
	for (int i = 0; i < n; i += 2) {
		for (int d = 0; d < segs[i + 1]; d += 10, t += 10) {
			enum gesture g = gesture_update(&s, &cfg, segs[i], t);
			if (g != GESTURE_NONE && k < 15) {
				got[k++] = "NSDL"[g];
			}
		}
	}
	got[k] = 0;
	int ok = 1;
	for (int i = 0; ok && (got[i] || expect[i]); i++) {
		ok = got[i] == expect[i];
	}
	printf("%-28s expect %-4s got %-4s %s\n", name, expect, got, ok ? "ok" : "FAIL");
	fails += !ok;
}

int main(void)
{
	int single[]   = {0, 100, 1, 120, 0, 1000};
	int dbl[]      = {0, 100, 1, 120, 0, 200, 1, 120, 0, 1000};
	int slow_two[] = {0, 100, 1, 120, 0, 800, 1, 120, 0, 1000};
	int lng[]      = {0, 100, 1, 2500, 0, 1000};
	int bounce[]   = {0, 100, 1, 10, 0, 10, 1, 10, 0, 10, 1, 150, 0, 1000};
	int glitch[]   = {0, 100, 1, 20, 0, 1000};
	int dbl_hold[] = {0, 100, 1, 120, 0, 200, 1, 3000, 0, 1000};
	int long_then_tap[] = {0, 100, 1, 2500, 0, 200, 1, 120, 0, 1000};

	run("single tap", single, 6, "S");
	run("double tap", dbl, 10, "D");
	run("two slow taps", slow_two, 10, "SS");
	run("long press", lng, 6, "L");
	run("bouncy contact = one tap", bounce, 14, "S");
	run("20 ms glitch ignored", glitch, 6, "");
	run("double then hold = double", dbl_hold, 10, "D");
	run("long then tap", long_then_tap, 10, "LS");
	printf(fails ? "FAILED (%d)\n" : "ALL PASS\n", fails);
	return fails != 0;
}
