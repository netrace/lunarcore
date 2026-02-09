// This module defines the BoardPins trait and the heltec and xiao_wio modules.

pub trait BoardPins {
    const SPI: i32;
    const LORA: i32;
    const LED: i32;
    const BATTERY_ADC: i32;
    const I2C: i32;
    const UART: i32;
}

pub mod heltec {
    // Implementation for heltec specific pins
}

pub mod xiao_wio {
    // Implementation for xiao_wio specific pins
}