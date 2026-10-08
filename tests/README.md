# Host tests

`test_noise.c` checks `src/noise_xx.c` against the two Noise XX vectors that ship with
the BitChat app (`bitchatTests/Noise/NoiseTestVectors.json`, copied to `noise_vectors.json`)
and exercises BitChat's transport framing (4-byte BE nonce prefix, replay window, tamper).

    cd tests
    cc -O2 -Wall test_noise.c ../src/noise_xx.c ../lib/monocypher/monocypher.c -o /tmp/test_noise && /tmp/test_noise

`test_alert_retry.c` covers the Alertam retry / re-broadcast scheduling in `src/alert_retry.c`
(public alert pending → first write, stale rebuild, re-broadcast window, lifetime; private SOS
backoff, per-recipient ACK, one recipient failing while another delivers).

    cc -O2 -Wall test_alert_retry.c ../src/alert_retry.c -o /tmp/test_alert_retry && /tmp/test_alert_retry
