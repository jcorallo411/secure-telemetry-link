// Simulated vehicle sensor model.
//
// Deterministic given a seed, so a replayed test produces an identical
// telemetry stream. That matters for the cross-implementation vectors and it
// makes a failing test reproducible, which a wall-clock-driven random model
// would not be.

#ifndef STL_SENSORS_H
#define STL_SENSORS_H

#include <cstdint>

#include "stl/protocol.h"

namespace stl {

class SensorModel {
public:
    explicit SensorModel(std::uint32_t seed) noexcept;

    // Advances the simulation by dt microseconds.
    void step(std::uint64_t dt_us) noexcept;

    void sample_housekeeping(Housekeeping& out) const noexcept;
    void sample_attitude(Attitude& out) const noexcept;

    void set_mode(Mode m) noexcept { mode_ = m; }
    void set_heater(bool on) noexcept { heater_on_ = on; }
    void set_tm_rate(std::uint16_t hz) noexcept { tm_rate_hz_ = hz; }

    Mode mode() const noexcept { return mode_; }
    bool heater_on() const noexcept { return heater_on_; }
    std::uint16_t tm_rate_hz() const noexcept { return tm_rate_hz_; }
    std::uint32_t uptime_s() const noexcept {
        return static_cast<std::uint32_t>(elapsed_us_ / 1000000ULL);
    }

private:
    // xorshift32. Not cryptographic, and never used for anything that needs to
    // be: this is sensor noise only. Key material comes from the OS CSPRNG in
    // tools/gen_keys.py.
    std::uint32_t next_rand() noexcept;
    std::int32_t noise(std::int32_t amplitude) noexcept;

    std::uint32_t rng_state_;
    std::uint64_t elapsed_us_;

    Mode mode_;
    bool heater_on_;
    std::uint16_t tm_rate_hz_;

    std::int32_t battery_temp_mc_;
    std::int32_t payload_temp_mc_;
    std::int32_t bus_voltage_mv_;
    std::int32_t bus_current_ma_;

    std::int32_t gyro_[3];
    std::int32_t accel_[3];
    std::int32_t mag_[3];

    double spin_phase_;
};

}  // namespace stl

#endif  // STL_SENSORS_H
