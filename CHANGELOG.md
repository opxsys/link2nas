# Changelog

## [1.3.0] - 2025-12-30

### Added
- Modular architecture (web service + scheduler service)
- APScheduler-based background processing
- Chrome extension support
- Status page and health endpoints
- Centralized configuration via environment variables

### Changed
- Secure configuration handling (no secrets in logs or repr)
- Systemd services split (web / scheduler)

### Security
- Secrets fully externalized to `.env`
- Safe `Settings.__repr__` implementation
