// Flight computer: generates authenticated telemetry, accepts authenticated
// commands, and reports link health.
//
// Usage:
//   flight_computer [--keys PATH] [--bind-port N] [--peer-port N]
//                   [--peer-host H] [--seed N] [--duration SEC] [--quiet]

#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

#include "stl/counter_store.h"
#include "stl/keys.h"
#include "stl/protocol.h"
#include "stl/secure_link.h"
#include "stl/sensors.h"
#include "stl/udp.h"

namespace {

volatile std::sig_atomic_t g_stop = 0;

void on_signal(int) { g_stop = 1; }

std::uint64_t now_us() noexcept {
    timespec ts;
    (void)clock_gettime(CLOCK_REALTIME, &ts);
    return (static_cast<std::uint64_t>(ts.tv_sec) * 1000000ULL) +
           (static_cast<std::uint64_t>(ts.tv_nsec) / 1000ULL);
}

struct Config {
    const char* keys_path = "keys/stl_keys.bin";
    const char* counter_path = "state/flight_tx.ctr";
    const char* bind_host = "127.0.0.1";
    const char* peer_host = "127.0.0.1";
    std::uint16_t bind_port = 50001U;
    std::uint16_t peer_port = 50002U;
    std::uint32_t seed = 0xC0FFEEU;
    int duration_s = 0;  // 0 = run until interrupted
    bool quiet = false;
};

bool parse_args(int argc, char** argv, Config& cfg) {
    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        const bool has_next = (i + 1) < argc;

        if ((std::strcmp(a, "--keys") == 0) && has_next) {
            cfg.keys_path = argv[++i];
        } else if ((std::strcmp(a, "--counter-file") == 0) && has_next) {
            cfg.counter_path = argv[++i];
        } else if ((std::strcmp(a, "--bind-port") == 0) && has_next) {
            cfg.bind_port = static_cast<std::uint16_t>(std::atoi(argv[++i]));
        } else if ((std::strcmp(a, "--peer-port") == 0) && has_next) {
            cfg.peer_port = static_cast<std::uint16_t>(std::atoi(argv[++i]));
        } else if ((std::strcmp(a, "--peer-host") == 0) && has_next) {
            cfg.peer_host = argv[++i];
        } else if ((std::strcmp(a, "--seed") == 0) && has_next) {
            cfg.seed = static_cast<std::uint32_t>(std::strtoul(argv[++i], nullptr, 0));
        } else if ((std::strcmp(a, "--duration") == 0) && has_next) {
            cfg.duration_s = std::atoi(argv[++i]);
        } else if (std::strcmp(a, "--quiet") == 0) {
            cfg.quiet = true;
        } else {
            std::fprintf(stderr, "unknown or incomplete argument: %s\n", a);
            return false;
        }
    }
    return true;
}

void log_line(bool quiet, const char* fmt, ...) {
    if (quiet) {
        return;
    }
    va_list args;
    va_start(args, fmt);
    std::vfprintf(stdout, fmt, args);
    va_end(args);
    std::fflush(stdout);
}

}  // namespace

int main(int argc, char** argv) {
    Config cfg;
    if (!parse_args(argc, argv, cfg)) {
        return 2;
    }

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    stl::KeySet keys;
    const char* err = nullptr;
    if (!stl::load_keys(cfg.keys_path, keys, &err)) {
        std::fprintf(stderr, "[FC] key load failed: %s\n", err);
        return 1;
    }

    // The transmit counter must survive a reboot, or the ground station's
    // replay window will reject all telemetry after a restart.
    stl::CounterStore counters;
    if (!counters.open(cfg.counter_path, &err)) {
        std::fprintf(stderr, "[FC] counter store failed: %s\n", err);
        std::fprintf(stderr, "[FC] (create the directory, e.g. mkdir -p state)\n");
        return 1;
    }

    // Flight signs telemetry with K_TM and verifies commands with K_TC.
    stl::SecureLink link(keys.tm, keys.tc, stl::PacketType::Telemetry);
    link.attach_counter_store(&counters);
    link.enable_freshness_check(true);

    stl::UdpSocket sock;
    if (!sock.bind(cfg.bind_host, cfg.bind_port, &err)) {
        std::fprintf(stderr, "[FC] bind failed: %s\n", err);
        return 1;
    }
    if (!sock.set_peer(cfg.peer_host, cfg.peer_port, &err)) {
        std::fprintf(stderr, "[FC] peer setup failed: %s\n", err);
        return 1;
    }

    stl::SensorModel sensors(cfg.seed);
    sensors.set_mode(stl::Mode::Nominal);

    log_line(cfg.quiet, "[FC] up. tm->%s:%u  rx on %s:%u  rate=%uHz\n",
             cfg.peer_host, cfg.peer_port, cfg.bind_host, cfg.bind_port,
             sensors.tm_rate_hz());

    std::uint8_t tx_buf[stl::MAX_FRAME_SIZE];
    std::uint8_t rx_buf[stl::MAX_FRAME_SIZE];
    std::uint8_t payload[stl::MAX_USER_DATA];

    const std::uint64_t start_us = now_us();
    std::uint64_t last_tm_us = start_us;
    std::uint64_t last_sim_us = start_us;

    auto send_event = [&](std::uint8_t severity, const char* msg) {
        const std::size_t msg_len = std::strlen(msg);
        const std::size_t capped =
            (msg_len > stl::MAX_EVENT_MESSAGE) ? stl::MAX_EVENT_MESSAGE : msg_len;
        payload[0] = severity;
        payload[1] = static_cast<std::uint8_t>(capped);
        std::memcpy(payload + 2, msg, capped);
        const std::size_t n =
            link.seal(stl::APID_TM_EVENT, payload, stl::EVENT_HEADER_SIZE + capped,
                      now_us(), tx_buf, sizeof(tx_buf));
        if (n > 0U) {
            (void)sock.send(tx_buf, n);
        }
    };

    send_event(0U, "flight computer online");

    while (g_stop == 0) {
        const std::uint64_t t = now_us();

        if (cfg.duration_s > 0) {
            // The sign check above guarantees the value is positive; the
            // intermediate cast to unsigned makes that explicit to the
            // compiler rather than silencing the warning with a pragma.
            const std::uint64_t limit_us =
                static_cast<std::uint64_t>(static_cast<unsigned int>(cfg.duration_s)) *
                1000000ULL;
            if ((t - start_us) >= limit_us) {
                break;
            }
        }

        // ---- advance the simulation --------------------------------------
        sensors.step(t - last_sim_us);
        last_sim_us = t;

        // ---- transmit telemetry when due ---------------------------------
        const std::uint64_t period_us = 1000000ULL / sensors.tm_rate_hz();
        if ((t - last_tm_us) >= period_us) {
            last_tm_us = t;

            stl::Housekeeping hk;
            sensors.sample_housekeeping(hk);
            stl::encode_housekeeping(hk, payload);
            std::size_t n = link.seal(stl::APID_TM_HOUSEKEEPING, payload,
                                      stl::HOUSEKEEPING_PAYLOAD_SIZE, t, tx_buf,
                                      sizeof(tx_buf));
            if (n > 0U) {
                (void)sock.send(tx_buf, n);
            }

            stl::Attitude att;
            sensors.sample_attitude(att);
            stl::encode_attitude(att, payload);
            n = link.seal(stl::APID_TM_ATTITUDE, payload,
                          stl::ATTITUDE_PAYLOAD_SIZE, t, tx_buf, sizeof(tx_buf));
            if (n > 0U) {
                (void)sock.send(tx_buf, n);
            }
        }

        // ---- receive commands --------------------------------------------
        const long got = sock.recv_timeout(rx_buf, sizeof(rx_buf), 5);
        if (got < 0) {
            continue;  // timeout or socket error
        }
        // got == 0 is a zero-length datagram, which is a real frame an
        // attacker can send. It goes through the parser like anything else so
        // that it is rejected *and counted*.

        stl::ReceivedFrame frame;
        const stl::ParseResult pr =
            link.open(rx_buf, static_cast<std::size_t>(got), now_us(), frame);

        if (pr != stl::ParseResult::Ok) {
            // Rejections are logged locally and counted, but nothing is sent
            // back. Replying would hand an attacker an oracle telling them
            // exactly which of their guesses got further.
            log_line(cfg.quiet, "[FC] REJECT %-20s (%ld bytes)\n",
                     stl::parse_result_name(pr), got);
            continue;
        }

        if (frame.header.apid != stl::APID_TC_COMMAND) {
            log_line(cfg.quiet, "[FC] authenticated frame on unexpected APID 0x%03X\n",
                     frame.header.apid);
            continue;
        }

        stl::Command cmd;
        if (!stl::decode_command(frame.payload, frame.payload_len, cmd)) {
            log_line(cfg.quiet, "[FC] REJECT BAD_PAYLOAD_LENGTH\n");
            continue;
        }

        // ---- execute ------------------------------------------------------
        stl::AckStatus status = stl::AckStatus::Accepted;
        const stl::Mode mode = sensors.mode();
        const bool in_safe = (mode == stl::Mode::Safe);

        switch (cmd.command_id) {
            case stl::CMD_NOOP:
                break;

            case stl::CMD_PING:
                break;

            case stl::CMD_SET_MODE: {
                if (cmd.arg_len != 1U) {
                    status = stl::AckStatus::RejectedBadArgument;
                } else if (cmd.args[0] > static_cast<std::uint8_t>(stl::Mode::Safe)) {
                    status = stl::AckStatus::RejectedBadArgument;
                } else {
                    sensors.set_mode(static_cast<stl::Mode>(cmd.args[0]));
                }
                break;
            }

            case stl::CMD_SET_TM_RATE: {
                if (in_safe) {
                    status = stl::AckStatus::RejectedInvalidInMode;
                } else if (cmd.arg_len != 2U) {
                    status = stl::AckStatus::RejectedBadArgument;
                } else {
                    const std::uint16_t hz = stl::load_be16(cmd.args);
                    if ((hz < stl::MIN_TM_RATE_HZ) || (hz > stl::MAX_TM_RATE_HZ)) {
                        status = stl::AckStatus::RejectedBadArgument;
                    } else {
                        sensors.set_tm_rate(hz);
                    }
                }
                break;
            }

            case stl::CMD_SET_HEATER: {
                if (in_safe) {
                    status = stl::AckStatus::RejectedInvalidInMode;
                } else if ((cmd.arg_len != 1U) || (cmd.args[0] > 1U)) {
                    status = stl::AckStatus::RejectedBadArgument;
                } else {
                    sensors.set_heater(cmd.args[0] == 1U);
                }
                break;
            }

            case stl::CMD_SAFE_MODE: {
                sensors.set_mode(stl::Mode::Safe);
                sensors.set_tm_rate(1U);
                sensors.set_heater(true);
                break;
            }

            default:
                status = stl::AckStatus::RejectedUnknownCommand;
                break;
        }

        log_line(cfg.quiet, "[FC] CMD 0x%04X args=%u -> %s\n", cmd.command_id,
                 cmd.arg_len, (status == stl::AckStatus::Accepted) ? "ACCEPTED" : "REJECTED");

        // ---- acknowledge ---------------------------------------------------
        stl::CommandAck ack;
        ack.command_id = cmd.command_id;
        ack.frame_counter = frame.header.frame_counter;
        ack.status = static_cast<std::uint8_t>(status);
        stl::encode_command_ack(ack, payload);
        const std::size_t n =
            link.seal(stl::APID_TM_COMMAND_ACK, payload,
                      stl::COMMAND_ACK_PAYLOAD_SIZE, now_us(), tx_buf, sizeof(tx_buf));
        if (n > 0U) {
            (void)sock.send(tx_buf, n);
        }

        if (cmd.command_id == stl::CMD_SAFE_MODE) {
            send_event(2U, "entered SAFE mode by command");
        }
    }

    send_event(0U, "flight computer shutting down");

    const stl::LinkStats& s = link.stats();
    std::fprintf(stdout,
                 "\n[FC] link statistics\n"
                 "  accepted       %llu\n"
                 "  malformed      %llu\n"
                 "  auth failures  %llu\n"
                 "  replay rejects %llu\n"
                 "  stale rejects  %llu\n"
                 "  unknown apid   %llu\n"
                 "  frames sent    %u\n",
                 static_cast<unsigned long long>(s.accepted),
                 static_cast<unsigned long long>(s.malformed),
                 static_cast<unsigned long long>(s.auth_failures),
                 static_cast<unsigned long long>(s.replay_rejects),
                 static_cast<unsigned long long>(s.stale_rejects),
                 static_cast<unsigned long long>(s.unknown_apid),
                 link.tx_frame_counter());
    return 0;
}
