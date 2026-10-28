#include "stl/sensors.h"

#include <cmath>

namespace stl {

namespace {
constexpr std::int32_t HEATER_SETPOINT_MC = 15000;   // 15.0 C
constexpr std::int32_t PASSIVE_FLOOR_MC = -20000;    // -20.0 C
constexpr std::int32_t NOMINAL_BUS_MV = 28000;       // 28.0 V
}  // namespace

SensorModel::SensorModel(std::uint32_t seed) noexcept
    : rng_state_((seed == 0U) ? 0x1234567U : seed),
      elapsed_us_(0U),
      mode_(Mode::Boot),
      heater_on_(true),
      tm_rate_hz_(2U),
      battery_temp_mc_(5000),
      payload_temp_mc_(2000),
      bus_voltage_mv_(NOMINAL_BUS_MV),
      bus_current_ma_(1200),
      spin_phase_(0.0) {
    for (std::size_t i = 0U; i < 3U; ++i) {
        gyro_[i] = 0;
        accel_[i] = 0;
        mag_[i] = 0;
    }
}

std::uint32_t SensorModel::next_rand() noexcept {
    std::uint32_t x = rng_state_;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    rng_state_ = x;
    return x;
}

std::int32_t SensorModel::noise(std::int32_t amplitude) noexcept {
    if (amplitude <= 0) {
        return 0;
    }
    const std::uint32_t r = next_rand();
    const std::int32_t span = (amplitude * 2) + 1;
    return static_cast<std::int32_t>(r % static_cast<std::uint32_t>(span)) - amplitude;
}

void SensorModel::step(std::uint64_t dt_us) noexcept {
    elapsed_us_ += dt_us;
    const double dt_s = static_cast<double>(dt_us) / 1e6;

    // --- thermal: first-order lag toward the setpoint the heater implies ----
    const std::int32_t target =
        heater_on_ ? HEATER_SETPOINT_MC : PASSIVE_FLOOR_MC;
    const double tau_s = 60.0;
    const double alpha = dt_s / tau_s;

    battery_temp_mc_ += static_cast<std::int32_t>(
        (static_cast<double>(target - battery_temp_mc_) * alpha));
    battery_temp_mc_ += noise(15);

    payload_temp_mc_ += static_cast<std::int32_t>(
        (static_cast<double>((target - 3000) - payload_temp_mc_) * alpha));
    payload_temp_mc_ += noise(20);

    // --- power: load depends on mode and heater -----------------------------
    std::int32_t load_ma = 800;
    if (mode_ == Mode::Nominal) {
        load_ma += 600;
    }
    if (heater_on_) {
        load_ma += 450;
    }
    if (mode_ == Mode::Safe) {
        load_ma = 500 + (heater_on_ ? 450 : 0);
    }
    bus_current_ma_ = load_ma + noise(25);

    // Bus sags slightly under load; enough structure to see a real
    // relationship in the plots rather than independent noise channels.
    bus_voltage_mv_ = NOMINAL_BUS_MV - ((bus_current_ma_ - 800) / 4) + noise(40);

    // --- attitude: slow spin about Z with cross-axis coupling ---------------
    const double rate_z = (mode_ == Mode::Safe) ? 0.35 : 0.12;  // rad/s
    spin_phase_ += rate_z * dt_s;
    if (spin_phase_ > (2.0 * M_PI)) {
        spin_phase_ -= (2.0 * M_PI);
    }

    gyro_[0] = static_cast<std::int32_t>(std::sin(spin_phase_) * 8000.0) + noise(120);
    gyro_[1] = static_cast<std::int32_t>(std::cos(spin_phase_) * 6000.0) + noise(120);
    gyro_[2] = static_cast<std::int32_t>(rate_z * 1e6) + noise(200);

    // Microgravity with small disturbances.
    accel_[0] = noise(300);
    accel_[1] = noise(300);
    accel_[2] = 9810 + noise(400);  // micro-g; nonzero so the axis is visible

    // Magnetic field rotates with the vehicle.
    mag_[0] = static_cast<std::int32_t>(std::cos(spin_phase_) * 25000.0) + noise(300);
    mag_[1] = static_cast<std::int32_t>(std::sin(spin_phase_) * 25000.0) + noise(300);
    mag_[2] = -42000 + noise(300);
}

void SensorModel::sample_housekeeping(Housekeeping& out) const noexcept {
    out.mode = static_cast<std::uint8_t>(mode_);
    out.heater_on = heater_on_ ? 1U : 0U;
    out.telemetry_rate_hz = tm_rate_hz_;
    out.bus_voltage_mv = bus_voltage_mv_;
    out.bus_current_ma = bus_current_ma_;
    out.battery_temp_mc = battery_temp_mc_;
    out.payload_temp_mc = payload_temp_mc_;
    out.uptime_s = uptime_s();
}

void SensorModel::sample_attitude(Attitude& out) const noexcept {
    for (std::size_t i = 0U; i < 3U; ++i) {
        out.gyro[i] = gyro_[i];
        out.accel[i] = accel_[i];
        out.mag[i] = mag_[i];
    }
}

}  // namespace stl
