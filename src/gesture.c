/*
 * gesture.c - single-button gesture detection (Alertam). See gesture.h.
 */
#include "gesture.h"

#include <string.h>

void gesture_init(struct gesture_state *s)
{
	memset(s, 0, sizeof(*s));
}

const char *gesture_name(enum gesture g)
{
	switch (g) {
	case GESTURE_SINGLE: return "single";
	case GESTURE_DOUBLE: return "double";
	case GESTURE_LONG:   return "long";
	default:             return "none";
	}
}

enum gesture gesture_update(struct gesture_state *s, const struct gesture_cfg *cfg,
			    bool pressed, uint32_t now)
{
	/* Debounce: accept a new level only after it has been stable */
	if (pressed != s->raw) {
		s->raw = pressed;
		s->raw_since = now;
	}
	bool edge = false;
	if (s->raw != s->stable && now - s->raw_since >= cfg->debounce_ms) {
		s->stable = s->raw;
		edge = true;
	}

	if (edge && s->stable) {
		/* press */
		s->down_at = now;
		s->consumed = false;
		if (s->taps == 1 && now - s->last_up <= cfg->double_ms) {
			s->taps = 0;
			s->consumed = true; /* don't let this press also become LONG */
			return GESTURE_DOUBLE;
		}
		s->taps = 0;
		return GESTURE_NONE;
	}

	if (edge && !s->stable) {
		/* release */
		if (!s->consumed) {
			s->taps = 1;
			s->last_up = now;
		}
		s->consumed = false;
		return GESTURE_NONE;
	}

	if (s->stable && !s->consumed && now - s->down_at >= cfg->long_ms) {
		s->consumed = true;
		s->taps = 0;
		return GESTURE_LONG;
	}

	if (!s->stable && s->taps == 1 && now - s->last_up > cfg->double_ms) {
		s->taps = 0;
		return GESTURE_SINGLE;
	}
	return GESTURE_NONE;
}
