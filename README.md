![bitchat-esp32](bitchat-esp32.png)

# bitchat-esp32

A minimal implementation of bitchat for use on ESP32-C6 based devices. This
firmware can monitor bitchat messages, geohash, perform Bitchat protocol 
diagnostics and handshakes for end-to-end encrypted chat. The terminal is used
over UART, type "help" for instructions. 

## Build

This firmware is tested on a Seeed Studio XIAO ESP32C6 but can be ported
to other ESP32-C6 devices providing you supply a board overlay and modify
the build steps.

To build this project, you need to download the Zephyr SDK, have ESP-IDF toolchain
installed and Python3 available:

1. Download `zephyr-sdk-minimal.7z` and extract it to the root of this repository
2. Run `.\setup_env.ps1` to configure the environment and locate your toolchain.
3. `.\build.bat all` to compile & flash Zephyr OS and bitchat application.

The build system will create Zephyr OS and use esptool to construct a flash bin
file with the OS and application installed. It will then detect any ESP32-C6 device
and flash the firmware and run monitor tool. You can run `.\build.bat build` and
similar steps for each process separately. 

## Example

```
I (40) soc_init: ESP Simple boot
I (40) soc_init: compile time Jan 22 2026 13:13:44
I (41) soc_init: chip revision: v0.2
I (41) flash_init: SPI Speed      : 80MHz
I (43) flash_init: SPI Mode       : DIO
I (47) flash_init: SPI Flash Size : 8MB
I (50) boot: DRAM       : lma=00000020h vma=40800000h size=12fd0h ( 77776)
I (56) boot: DRAM       : lma=00012ff8h vma=40812fe0h size=02980h ( 10624)
I (62) boot: IROM       : lma=00020000h vma=42800000h size=0d054h ( 53332)
I (68) boot: IROM       : lma=00030000h vma=42000000h size=5f82ch (391212)
I (86) boot: libc heap size 218 kB.
I (86) spi_flash: detected chip: generic
I (87) spi_flash: flash io: dio

[BT] Controller ready after 100 ms
[BT] Controller ready, starting services
[BLE] Stealth mode - advertising disabled (scan-only)
[Scan] Starting active scan for peers...
[BLE] Scanning started (mesh discovery)
[BLE] Bluetooth ready

=== bitchat IRC Mode Ready ===
Joined: #bluetooth as izllza6
Mode: +s (stealth), +e (encrypted)

Available Commands (type 'help' or press Tab for full list):
  Core:
    status               - Show system status and connections
    list                 - List discovered peers with keys
    send <msg>           - Send message to current channel
    messages             - View message history
    privmsg <id> <msg>   - Send private message

  Identity:
    nick <name>          - Change nickname
    keys generate        - Generate new identity keypairs
    keys show            - Show public keys

  Security:
    stealth <on|off>     - Toggle stealth mode (monitor/participate)
    privacy <on|off>     - Toggle cover traffic
    debug <on|off>       - Noise XX/BitChat packet dissector

  Bluetooth:
    btle info            - Show connection details
    btle scan <on|off>   - Control BLE scanning
    btle debug <on|off>  - Toggle bluetooth debugging

bitchat> debug on
*** Protocol Debug ON
    Will show detailed packet analysis for handshakes and messages
bitchat> stealth
Usage: stealth <on|off>
  ON:  Monitor-only mode (invisible to peers, no handshake) - DEFAULT
  OFF: Full peer mode (visible, requires Noise XX handshake)

Current status: ON (monitoring only)
[Mesh] BitChat peer found: 45:94:67:55:98:33 (random) (RSSI -70) - scheduling connect
[Mesh] Connecting to 45:94:67:55:98:33 (random)...
[Mesh] Connection initiated successfully
[Mesh] Connected: 45:94:67:55:98:33 (random) (peers: 1)
[Scan] Connection established (scan continues in background)
[MTU] Exchange successful: MTU=508 for 45:94:67:55:98:33 (random)
[GATT] Discovered bitchat char handle: 0x00bf
[GATT] Subscription CCC write complete (notifications enabled)
[GATT] Waiting for incoming handshake from peer...
[GATT] Stealth mode - listening only

[PKT] len=164 type=MSG ttl=7 ts=1769109372454 flags=0x02 payload=78
      sender=0xee6f7ff7e7533f58
      0000  01 08 61 6e 6f 6e 61 6e  6f 6e 02 20 fa 0a d7 61  |..anonanon. ...a|
      0010  21 99 03 59 b9 38 87 61  47 db c0 33 d9 2c da 23  |!..Y.8.aG..3.,.#|
      0020  54 2c 6e 43 76 db b8 77  6c df ec 4d 03 20 5b 4b  |T,nCv..wl..M. [K|
      0030  65 ce 88 80 a3 d6 9b b7  2a 03 4c e9 b5 27 7d 1e  |e.......*.L..'}.|
      0040  ee 88 41 c3 72 db 0c 3b  d9 f1 9e 8c 98 52        |..A.r..;.....R|

[PKT] len=164 type=MSG ttl=7 ts=1769109372521 flags=0x02 payload=78
      sender=0xee6f7ff7e7533f58
      0000  01 08 61 6e 6f 6e 61 6e  6f 6e 02 20 fa 0a d7 61  |..anonanon. ...a|
      0010  21 99 03 59 b9 38 87 61  47 db c0 33 d9 2c da 23  |!..Y.8.aG..3.,.#|
      0020  54 2c 6e 43 76 db b8 77  6c df ec 4d 03 20 5b 4b  |T,nCv..wl..M. [K|
      0030  65 ce 88 80 a3 d6 9b b7  2a 03 4c e9 b5 27 7d 1e  |e.......*.L..'}.|
      0040  ee 88 41 c3 72 db 0c 3b  d9 f1 9e 8c 98 52        |..A.r..;.....R|
[GATT] Unsubscribed (handle was 0x00bf)
[Mesh] Disconnected: 45:94:67:55:98:33 (random) (reason 8, peers: 0)
[Scan] Restarting scan (no connections)
bitchat> debug off
*** Protocol Debug OFF
bitchat> stealth off
[BLE] Advertising started (non-stealth mode)
[00:00:50.998,000] <inf> bitchat_crypto: Noise session initialized (ID: 0x13e1, initiator)
[00:00:50.999,000] <inf> bitchat_crypto: Sent handshake message 1 (e)
*** Stealth mode OFF - initiated handshakes with 1 peer(s)
[RX] Encrypted type=33 len=18 from 0xee6f7ff7e7533f58
  Hex: 01000107020004000001800300047c86af80
[ACK] type=2 from 0xee6f7ff7e7533f58 (anonanon): hacker fantastic says hello
bitchat> list

=== Discovered Peers ===

Peer #1:
  Session ID: 0xee6f7ff7e7533f58
  Nickname:   anonanon
  Channel:    #bluetooth
  BT Address: 6C:CC:FC:E9:C2:8B (random)
  Status:     CONNECTED
  Last seen:  74 sec ago
  Noise Key (X25519):
    5b4b65ce 8880a3d6 9bb72a03 4ce9b527
    7d1eee88 41c372db 0c3bd9f1 9e8c9852

Total: 1 peer(s)
bitchat> status

=== bitchat Status ===
Nickname: izllza6
Channel: #bluetooth
Privacy traffic: OFF
E2EE: ON
Stealth mode: OFF (full handshake, visible)

=== Connections ===
Active connections: 1
  [0] 6C:CC:FC:E9:C2:8B (random) READY

=== Statistics ===
Messages sent: 0
Messages received: 0

=== Identity Keys ===
Noise public key:
  13a470b6 92ddd551 3db2a2d0 554ca733
  7d1d7ea8 22621f7d d566052d 7cb21003
Sign public key:
  0d53c42b 4953e6b4 1584c795 cb748514
  ca00d2bc 301083e2 d296dcad 7afa254f
[RX] Encrypted type=33 len=19 from 0xee6f7ff7e7533f58
  Hex: 01000107020004000002000300050ab6c39880
```

##  WARNING

This code is experimental, incomplete and under active development subject to sudden
changes. 

https://hacker.house

# License

These files are available under the 3-clause BSD license.
