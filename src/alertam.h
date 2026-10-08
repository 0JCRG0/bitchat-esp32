/*
 * alertam.h - Alertam panic-button behavior on top of bitchat
 *
 * Buttons (D1 external + on-board BOOT, see the board overlay in boards/) feed the
 * gesture detector:
 *   long press (>= 2 s) -> public alert: signed BitChat public message
 *   double tap          -> private SOS: Noise-encrypted PM to each circle member
 *   single tap          -> nothing (accidental-press guard)
 * The on-board LED confirms which alert fired.
 */
#ifndef ALERTAM_H
#define ALERTAM_H

#include <zephyr/kernel.h>

/* Broadcasts a public message on every link; runs on the BLE work queue. */
typedef int (*alertam_public_fn)(const char *text);

int alertam_init(struct k_work_q *ble_q, alertam_public_fn send_public);

#endif /* ALERTAM_H */
