# LunarCore

Multi-protocol mesh firmware for ESP32-S3 LoRa devices.

## Protocols

- MeshCore
- Meshtastic
- RNode/KISS (Reticulum)

Protocol is auto-detected from the first bytes over serial or BLE.

## Hardware

Supported boards:

- Heltec WiFi LoRa 32 V3 (ESP32-S3 + SX1262)
- Seeed XIAO ESP32S3 + Wio-SX1262

## Flash (prebuilt)

Download `lunarcore-esp32s3.bin` from [Releases](../../releases).

```bash
pip install esptool
esptool.py --chip esp32s3 -p PORT write_flash 0x0 lunarcore-esp32s3.bin
```

## Build from source

```bash
espup install
. ~/export-esp.sh
cargo build --release --features board-heltec
espflash flash target/xtensa-esp32s3-espidf/release/lunarcore --monitor
```

To build for the Seeed XIAO ESP32S3 + Wio-SX1262:

```bash
cargo build --release --features board-xiao-wio
```

## Repeater

Enabled by default. Relays MeshCore packets when no app is connected. Disable with `AT+REPEATER=0`.

## License

MIT
