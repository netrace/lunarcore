// This module defines pin mappings for supported boards.

pub trait BoardPins {
    const NAME: &'static str;
    const SPI_MOSI: i32;
    const SPI_MISO: i32;
    const SPI_SCK: i32;
    const LORA_NSS: i32;
    const LORA_RST: i32;
    const LORA_BUSY: i32;
    const LORA_DIO1: i32;
    const LED: i32;
    const VEXT: Option<i32>;
    const BATTERY_ADC: Option<i32>;
    const I2C_SDA: Option<i32>;
    const I2C_SCL: Option<i32>;
    const OLED_RST: Option<i32>;
}

pub mod heltec {
    use super::BoardPins;

    pub struct HeltecV3;

    impl BoardPins for HeltecV3 {
        const NAME: &'static str = "Heltec WiFi LoRa 32 V3";
        const SPI_MOSI: i32 = 10;
        const SPI_MISO: i32 = 11;
        const SPI_SCK: i32 = 9;
        const LORA_NSS: i32 = 8;
        const LORA_RST: i32 = 12;
        const LORA_BUSY: i32 = 13;
        const LORA_DIO1: i32 = 14;
        const LED: i32 = 35;
        const VEXT: Option<i32> = Some(36);
        const BATTERY_ADC: Option<i32> = Some(1);
        const I2C_SDA: Option<i32> = Some(17);
        const I2C_SCL: Option<i32> = Some(18);
        const OLED_RST: Option<i32> = Some(21);
    }
}

pub mod xiao_wio {
    use super::BoardPins;

    pub struct XiaoWio;

    impl BoardPins for XiaoWio {
        const NAME: &'static str = "Seeed XIAO ESP32S3 + Wio-SX1262";
        const SPI_MOSI: i32 = 9;
        const SPI_MISO: i32 = 8;
        const SPI_SCK: i32 = 7;
        const LORA_NSS: i32 = 3;
        const LORA_RST: i32 = 1;
        const LORA_BUSY: i32 = 0;
        const LORA_DIO1: i32 = 2;
        const LED: i32 = 21;
        const VEXT: Option<i32> = None;
        const BATTERY_ADC: Option<i32> = None;
        const I2C_SDA: Option<i32> = None;
        const I2C_SCL: Option<i32> = None;
        const OLED_RST: Option<i32> = None;
    }
}

#[cfg(feature = "board-heltec")]
pub type SelectedBoard = heltec::HeltecV3;

#[cfg(all(feature = "board-xiao-wio", not(feature = "board-heltec")))]
pub type SelectedBoard = xiao_wio::XiaoWio;
