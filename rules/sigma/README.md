# Sample Sigma rules (v5.2 groundwork)

These files exercise the subset implemented in `server/src/sigma_engine.h`.
They are original examples written for SecureSeaHorse, not copies of
community rules, and they are not a detection pack for production use.

Load them with `SigmaEngine::load_directory("rules/sigma")` (or any other
directory of `.yml` / `.yaml` files). The existing keyword-list samples
under `server/config/sigma/` remain valid and are covered by the same
loader.

Supported syntax is documented at the top of `sigma_engine.h` and in the
PR draft for `feature/sigma-rules`.
