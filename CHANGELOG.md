# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-11-24

### Changed

- `Announce` joins the topic of every live invite, because kolo-swarm no longer caps topics by default (`MaxTopics` 0; it was 16, and `Announce` waited for a free topic). With a `MaxTopics` cap set on the swarm, a `Join` past it fails at once and `Announce` retries that topic with backoff from 1s to 1 minute, as before. No code changed, only the docs and a doc comment. Requires kolo-swarm v0.1.1.

## [0.1.0] - 2026-11-20

### Added

- First release of kolo-invite.
