# Physical-Firmware Safety Limit Overrides

## Description
This mitigation enforces hardware-level safety constraints on Building Energy Management System (BEMS) controlled appliances—specifically HVAC compressors, heaters, and electrical circuits—to prevent unsafe operating conditions that could be induced by erroneous or malicious software commands from an LLM-based AI agent. Safety limits are implemented in physical protection circuits (e.g., thermal cutoffs, current limiters) or in firmware embedded in device microcontrollers, ensuring they cannot be bypassed by higher-layer software, including the AI agent’s action module.

## Effect
When a threat event occurs—such as the AI agent issuing an over-temperature setpoint, excessive electrical load command, or continuous compressor operation leading to equipment damage—the mitigation intervenes independently of the software control loop.  
- **HVAC Systems:** Compressor lockout timers and high-pressure cutout switches physically interrupt power if unsafe pressures or temperatures are detected, preventing coil freeze or overheat.  
- **Heaters:** Thermal fuses or firmware-enforced maximum duty cycles limit surface temperatures to safe levels, irrespective of software-set points.  
- **Electrical Systems:** Circuit breakers or solid-state current limiters trip when load exceeds safe ratings, even if the AI agent commands additional device activation.  
The safety layer operates as a final guardrail, ensuring that even if the AI agent’s perception or brain modules are compromised or erroneous, physical systems remain within manufacturer-defined safe operating envelopes.

## Implementation
Implementation requires a layered approach: firmware-based logic in device controllers, and physical safety components. Below is an example declarative configuration for a firmware safety module in an HVAC controller, using a pseudo-configuration format that could be deployed to an embedded system.

```yaml
# safety_limits.yaml
safety_profiles:
  - device_type: "compressor"
    parameters:
      max_continuous_run_time: "15 minutes"
      min_off_time_between_cycles: "5 minutes"
      max_allowed_suction_pressure: "100 psi"
      max_allowed_discharge_temperature: "280 °F"
    actions:
      on_violation: "hardware_lockout"
      reset_condition: "manual_reset"

  - device_type: "electric_heater"
    parameters:
      max_element_temperature: "150 °C"
      max_duty_cycle_per_hour: "75%"
      overcurrent_threshold: "20 A"
    actions:
      on_violation: "cut_power_via_relay"
      reset_condition: "cooldown_below_50C"

  - device_type: "general_circuit"
    parameters:
      max_current: "15 A"
      max_voltage: "240 V"
      arc_fault_detection: "enabled"
    actions:
      on_violation: "trip_circuit_breaker"
      reset_condition: "manual_restart"
