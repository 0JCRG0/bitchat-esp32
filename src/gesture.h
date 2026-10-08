/*
 * gesture.h - single-button gesture detection (Alertam)
 *
 * Pure state machine: feed it the raw button level and a millisecond clock,
 * it returns at most one gesture per call. No Zephyr dependencies, so it is
 * unit-tested on the host (tests/test_gesture.c).
 *
 *   LONG   : held >= long_ms               -> public alert
 *   DOUBLE : second press starts within double_ms of the first release
 *                                          -> private SOS to the circle
 *   SINGLE : one short press, no second one in time -> no-op (logged)
 */
#ifndef GESTURE_H
#define GESTURE_H

#include <stdbool.h>
#include <stdint.h>

enum gesture {
	GESTURE_NONE = 0,
	GESTURE_SINGLE,
	GESTURE_DOUBLE,
	GESTURE_LONG,
};

struct gesture_cfg {
	uint32_t debounce_ms; /* level must be stable this long */
	uint32_t long_ms;     /* default 2000 */
	uint32_t double_ms;   /* default 500 */
};

#define GESTURE_CFG_DEFAULT { .debounce_ms = 30, .long_ms = 2000, .double_ms = 500 }

struct gesture_state {
	bool raw;
	bool stable;
	uint32_t raw_since;
	uint32_t down_at;
	uint32_t last_up;
	uint8_t taps;     /* completed short presses waiting for a partner */
	bool consumed;    /* current press already produced a gesture */
};

void gesture_init(struct gesture_state *s);
enum gesture gesture_update(struct gesture_state *s, const struct gesture_cfg *cfg,
			    bool pressed, uint32_t now_ms);
const char *gesture_name(enum gesture g);

#endif /* GESTURE_H */
