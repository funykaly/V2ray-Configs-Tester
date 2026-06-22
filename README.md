# ProxyHarvest Sentinel

ProxyHarvest Sentinel is a Go-first CLI that collects proxy configs from subscription feeds and Telegram channels, normalizes many protocol formats, tests them with Xray or sing-box when possible, scores their security posture, measures latency and download speed, and exports categorized output files that can optionally be synced to GitHub.


## What The Runtime Does

- Scrapes enabled `subscription` and `telegram` sources from `config.json`.
- Extracts raw links plus embedded `json://<base64-json>` payloads from plain text, HTML, or base64-encoded source bodies.
- Parses and normalizes protocols such as `vmess`, `vless`, `trojan`, `ss`, `socks`, `http`, `hysteria`, `hysteria2`, `tuic`, `wireguard`, `ssh`, `shadowtls`, `naive`, and more.
- Deduplicates records by `host:port`.
- Runs connectivity checks, active security probes, geo lookup, and speed measurement.
- Writes categorized output files by country, protocol, security level, and speed bucket.
- Optionally syncs exported text files to a GitHub repository.

## Recommended Subscription Feed
 
The file below is the main output of this project. It is generated through continuous collection, analysis, and testing of configurations from 29 different public sources. Only configurations that successfully pass the project’s connection, security, and performance tests are included in this file:
 
```json
https://raw.githubusercontent.com/funykaly/V2ray-Tester/refs/heads/main/configs/all_secure.txt
```
 
To help identify clean and healthy Cloudflare IPs, this testing tool uses Cloudflare-based speed tests as part of its validation process.
 
Also note that if a configuration name does not include a speed value , it means that the IP is not clean. It has been rejected by Cloudflare
 
 
**Note:** If this subscription has not been updated for a long time, it usually means the testing server is temporarily unavailable due to maintenance, updates, or operational reasons. Since the ProxyHarvest Sentinel project is fully open-source, users can run the project themselves following the provided instructions to generate an up-to-date and personalized list of healthy and secure configurations.


## How Scraping Works

1. The runtime loads `config.json` and creates missing runtime paths.
2. Each enabled source is fetched independently.
3. Subscription sources try their configured `links` in order.
4. Telegram sources first scrape `https://t.me/s/<channel>`.
5. If Telegram web scraping is not enough and Telegram API credentials are configured, `telegram_auth_helper.py` is used as the fallback collector through Telethon.
6. Each fetched payload is hashed. Unchanged sources are skipped to avoid unnecessary re-parse work.
7. `extractProxyLinks()` decodes HTML entities, handles base64-only payloads, splits concatenated links, and converts outbound JSON documents into `json://...` records when possible.
8. `parseProxy()` normalizes protocol aliases, transport names, and stream-security modes before records enter state.

## Validation And Testing Pipeline

### Hard reject stage

Before any live testing, the runtime rejects obviously bad records such as:

- blank authentication on protocols that require it
- private or loopback hosts
- invalid ports
- placeholder host or SNI values
- suspicious injection payloads in host/path/SNI-like fields
- obsolete Shadowsocks ciphers
- malformed `reality` configs with missing public key

### Protocol test plan

The runtime chooses one of three strategies per record:

- Live connectivity test with `Xray` for protocols like `vmess`, `vless`, `trojan`, `ss`, `socks`, `http`, `tor`, and `direct`
- Live connectivity test with `sing-box` for protocols like `hysteria`, `hysteria2`, `tuic`, and `ssh`
- Core validation or synthetic validation for protocols/features that are not safe or practical to live-dial in the bundled flow

### TCP precheck

If `probes.enable_tcp_precheck` is enabled, TCP-based candidates are batch-checked with a fast TCP dial before expensive core startup. This is mainly a throughput optimization for large queues.

## Security Testing Model

Security evaluation is split into two layers:

- Static scoring with `scoreSecurity()`
- Active network probes with `runActiveSecurityProbes()`

Static scoring starts from a fixed score and subtracts penalties for risky patterns such as:

- missing TLS or Reality
- disabled certificate verification
- missing SNI, ALPN, TLS fingerprint, or remote DNS declarations
- deprecated transports like `mkcp`
- weak credentials
- dynamic DNS hosts
- admin-oriented ports
- protocol-specific issues such as legacy Shadowsocks or weak SSR settings

Active probes are run through the tested proxy after ping success. The default public snapshot includes checks against endpoints such as:

- Google and Cloudflare `generate_204`
- Microsoft `connecttest.txt`
- Cloudflare trace
- Cloudflare and Google DoH endpoints

Critical active findings can reject a config entirely.

## Speed Test Model

Speed measurement starts only after the initial connectivity probe succeeds.

- The runtime downloads from configured `probes.speed_urls`.
- The amount of data is bounded by `probes.speed_test_bytes`.
- Results are stored as `speed_mbps`.
- Exported files are bucketed into `fast`, `medium`, and `slow` using `probes.fast_speed_mbps` and `probes.medium_speed_mbps`.
- `fallback_probe_urls` and `use_all_probe_urls` control whether only the first probe URL is used or multiple probe URLs are attempted.

## Configuration Overview

The runtime config lives in `config.json`. A safe starter file is included as `config.example.json`.

### `sources`

- `subscription`: a named list of URL feeds
- `telegram`: a named Telegram channel source
- `enabled`: controls whether a source participates in collection

Example:

```json
{
  "sources": [
    {
      "name": "sample-subscription-1",
      "type": "subscription",
      "enabled": false,
      "links": ["https://example.com/subscription-1.txt"]
    },
    {
      "name": "sample-subscription-2",
      "type": "subscription",
      "enabled": false,
      "links": ["https://example.com/subscription-2.txt"]
    },
    {
      "name": "sample-telegram-1",
      "type": "telegram",
      "enabled": false,
      "channel": "public_channel_one"
    },
    {
      "name": "sample-telegram-2",
      "type": "telegram",
      "enabled": false,
      "channel": "public_channel_two"
    }
  ]
}
```

### `telegram`

- `api_id` and `api_hash` are only needed for Telegram API fallback
- `session_name` controls the local Telethon session filename
- `use_web_only` disables API fallback when `true`

### `github`

- `enabled` toggles export sync
- `token` and `repository` are required for push
- `branch` and `base_path` control the destination path layout
- `sync_every_minutes` applies to long-running mode

### `schedule`

- `source_check_every_minutes` controls refresh cadence in `daemon`
- `retest_every_hours` controls when already-tested records become due again

### `probes`

- `timeout_seconds` is the base network timeout
- `per_config_timeout_ms` caps each config test
- `core_startup_wait_ms` defines how long the runtime waits for a local core to become ready
- `ping_urls`, `speed_urls`, `proxy_ip_urls`, `geo_lookup_urls`, and `proxy_geo_urls` define network probes
- `security_probes` defines active security checks and penalties
- `enable_proxy_geo_lookup` toggles outbound IP geo lookup
- `local_geo_db` and `local_geo_city_db` point to optional MaxMind databases

### `cores`

- `xray_path` and `singbox_path` point to local core binaries
- If they are missing, `check`, `once`, or `daemon` can bootstrap them from official releases

### `paths`

These define where state and export files are written. `writeOutputs()` removes and recreates export directories on each full rewrite, so do not point them at shared or important folders.

## Commands

| Command | Purpose |
| --- | --- |
| `go run . init` | Create default runtime paths and config skeleton |
| `go run . check` | Run startup diagnostics, source reachability, core bootstrap, GitHub/Telegram checks |
| `go run . once` | Collect, parse, test, export, and optionally sync one full cycle |
| `go run . daemon` | Keep refreshing sources and testing pending configs continuously |
| `go run . reindex` | Rebuild export files from saved state without refetching sources |
| `go run . telegram-login` | Run interactive Telethon login for Telegram API fallback |
| `go run . menu` | Open the terminal UI when running interactively |

## Test Coverage

`main_test.go` covers core runtime behavior such as:

- extraction of concatenated and HTML-escaped links
- protocol parsing and normalization
- Xray and sing-box config generation/validation flows
- extended transport and security parameter preservation
- security scoring expectations
- structural validation for non-live protocols
- TCP precheck batching behavior

Recommended local command:

```powershell
go test ./...
```

## Quick Start

```powershell
Copy-Item config.example.json config.json
go run . init
go run . check
go run . once
```

Then edit `config.json` with your own sources, credentials, output paths, and GitHub sync settings.
