/// Board pin configuration trait
/// This trait defines the required methods for configuring board pins.
pub trait BoardPinConfiguration {
    /// Configures a specific pin as input.
    fn configure_pin_as_input(&self, pin: u8);

    /// Configures a specific pin as output.
    fn configure_pin_as_output(&self, pin: u8);

    /// Sets the value for a specific output pin.
    fn set_output_pin_value(&self, pin: u8, value: bool);

    /// Reads the value of a specific input pin.
    fn read_input_pin_value(&self, pin: u8) -> bool;
}