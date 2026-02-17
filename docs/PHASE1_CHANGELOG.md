# SecureSeaHorse SIEM — Phase 1 Changelog

## Version 1.1.0 — Production Robustness

### Summary

Phase 1 delivers four infrastructure upgrades that transform SecureSeaHorse from a prototype into a production-ready system. All changes are backward-compatible with v1.0.1 config files and the on-wire protocol is unchanged.

---

### 1. Dynamic Thread Pool (`server.cpp`, `server_protocol.h`)

**Problem:** The server used a fixed `ThreadPool(4)` — hardcoded at compile time with no way to tune for hardware or workload.

**Solution:** Replaced with `DynamicThreadPool` that auto-scales between configurable `min` and `max` bounds.

**How it works:**

- **Min workers** (default 2) are always alive, eliminating cold-start latency.
- **Scale-up:** A monitor thread runs every 500ms. When pending tasks > 0 and all workers are busy, it spawns up to 4 new workers per cycle (capped at `pool_max`).
- **Scale-down:** Workers that sit idle longer than `pool_idle_timeout_s` (default 30s) self-terminate — but never below `pool_min`.
- **Diagnostics:** A background thread logs pool stats (active/total/pending) every 30s.

**Config keys (server.conf):**

```
pool_min            = 2
pool_max            = 32
pool_idle_timeout_s = 30
```

**Files changed:** `server_protocol.h` (new `DynamicThreadPool` class), `server.cpp` (replaced `ThreadPool pool(4)`)

---

### 2. Exponential Backoff (`client.cpp`, `client_protocol.h`)

**Problem:** The client retried failed connections with a fixed 2-second sleep — creating reconnect storms and wasting resources during extended outages.

**Solution:** Implemented `ExponentialBackoff` with full jitter (per AWS best practices).

**How it works:**

- **Formula:** `delay = random(0, min(base * 2^attempt, max))`
- **Default base:** 1000ms (1 second)
- **Default cap:** 60000ms (60 seconds)
- **Jitter:** Full uniform randomization prevents thundering-herd reconnection spikes across a fleet.
- **Reset:** Backoff resets to attempt 0 after a successful TLS handshake.
- **Signal-aware sleep:** The backoff delay is slept in 100ms increments so the client responds to `SIGINT`/`SIGTERM` within 100ms even during a long backoff.

**Config keys (client.conf):**

```
backoff_base_ms = 1000
backoff_max_ms  = 60000
```

**Files changed:** `client_protocol.h` (new `ExponentialBackoff` class), `client.cpp` (connection loop rewritten)

---

### 3. CLI Argument Parsing (`client.cpp`, `server.cpp`, both headers)

**Problem:** Config file paths were hardcoded. No way to specify alternate configs without editing source.

**Solution:** Cross-platform CLI parser (no external dependencies — works on MSVC, GCC, Clang).

**Usage — Client:**

```bash
./ssh_client --help
./ssh_client --config /etc/seahorse/client.conf
./ssh_client -c custom.conf --set server_ip=10.0.0.5 --set port=9999
./ssh_client --version
```

**Usage — Server:**

```bash
./ssh_server --help
./ssh_server --config /etc/seahorse/server.conf
./ssh_server -c custom.conf --set port=9999 --set pool_max=64
./ssh_server --version
```

**Key behaviors:**

- `-c` / `--config <path>` overrides the default config file location.
- `-s` / `--set <key=value>` overrides individual config values (CLI wins over file).
- `-h` / `--help` prints usage and exits.
- `-v` / `--version` prints version and exits.
- Unknown arguments are reported to stderr but don't crash.

**Files changed:** `client_protocol.h` (new `CliArgs`, `parse_client_cli`, `print_client_usage`), `server_protocol.h` (same for server), `client.cpp` (`main()` updated), `server.cpp` (`main()` updated)

---

### 4. Async Logger with Rotation (both headers, both `.cpp` files)

**Problem:** `SimpleLogger` wrote synchronously under a mutex — blocking the calling thread on every log call. No rotation meant unbounded log growth.

**Solution:** Replaced with `AsyncLogger` — a lock-free-producer, single-consumer async logger with size-based rotation.

**How it works:**

- **Non-blocking writes:** `log()` pushes to an in-memory queue and returns immediately. A dedicated background thread batch-drains the queue and writes to disk.
- **Batch processing:** The worker swaps the entire queue in one lock, then writes the batch outside the lock — minimizing contention.
- **Size-based rotation:** When the log file exceeds `log_max_bytes`, it rotates: `server.log` → `server.log.1`, `server.log.1` → `server.log.2`, etc., up to `log_max_files`.
- **Graceful shutdown:** The destructor signals the worker and blocks until all pending messages are flushed.
- **Console echo:** Still prints to stdout by default (configurable).

**Config keys (both configs):**

```
log_file        = server.log   # or client.log
log_max_bytes   = 10485760     # 10 MB
log_max_files   = 5            # Keep 5 rotated files
```

**Files changed:** `client_protocol.h` and `server_protocol.h` (new `AsyncLogger` class), `client.cpp` and `server.cpp` (replaced `SimpleLogger` with `std::unique_ptr<AsyncLogger>`)

---

### Migration Guide from v1.0.1

1. **Drop-in replacement:** Copy the four new source files over the old ones. No changes to `CMakeLists.txt` required (no new library dependencies).

2. **Config files are backward-compatible:** All new keys have sensible defaults. Your existing `client.conf` and `server.conf` will work unchanged.

3. **To use new features**, add the new config keys shown above. Or use CLI:
   ```bash
   ./ssh_server --set pool_min=4 --set pool_max=64
   ```

4. **Logger output format** is unchanged: `[2026-02-10 14:30:00] [INFO] message`. Rotated files get numeric suffixes (`.1`, `.2`, etc.).

5. **No protocol changes:** The on-wire binary format (`PacketHeader` + `RawTelemetry`) is identical. v1.1.0 clients talk to v1.0.1 servers and vice versa.

---

### Additional Improvements (minor)

- Added `SO_REUSEADDR` on server socket to prevent "address already in use" after restart.
- `AppConfig::get()` and `get_int()` are now `const`-qualified.
- Added `AppConfig::get_size()` for `size_t` values and `AppConfig::set()` for runtime overrides.
- Logger is now a `unique_ptr` — destroyed explicitly before OpenSSL cleanup to guarantee flush ordering.
