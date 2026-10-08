/*
 * alertam.h - Alertam panic-button behavior on top of bitchat
 *
 * Buttons (D1 external + on-board BOOT, see the board overlay in boards/) feed the
 * gesture detector:
 *   long press (>= 2 s) -> public alert: signed BitChat public message
 *   double tap          -> private SOS: Noise-encrypted PM to each circle member
 *   single tap          -> nothing (accidental-press guard)
 * The on-board LED confirms which alert fired, and blinks briefly when a delivery
 * is first confirmed. Alerts are retried until delivered (see alert_retry.h);
 * 'sos status' shows where they are.
 */
#ifndef ALERTAM_H
#define ALERTAM_H

#include <zephyr/kernel.h>

/* Number of links a packet can be written to right now */
typedef int (*alertam_links_fn)(void);

int alertam_init(struct k_work_q *ble_q, alertam_links_fn links_ready);

/* A link just became usable (subscribed + announced) or the clock just got
 * synced: deliver pending alerts now. Call from the BLE work queue. */
void alertam_link_ready(void);

#endif /* ALERTAM_H */
