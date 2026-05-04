# v2raysub

Vercel serverless API for decrypting built-in subscription payload.

## Endpoints

- `GET /api/decrypt`
  - Default: returns decrypted plain text (node lines)
- `GET /api/decrypt?format=json`
  - Returns parsed details in JSON
- `GET /api/mihomo`
  - Returns FlClash/Mihomo YAML config with proxies, groups, and rules
- `GET /api/mihomo?format=json`
  - Returns JSON with parsed proxies and raw YAML
- `GET /api/health`
  - Health check

## Query Params

- `url`: single source URL
- `urls`: multiple source URLs, comma-separated
- `region`: `cn` (default) or `en`
- `ua`: custom User-Agent for fetching source
- `format`: `text` (default, for `/api/decrypt`) | `yaml` (default, for `/api/mihomo`) | `json`
- `fronting`: (mihomo only) fronting host domain to switch all proxy server addresses to (e.g. `cf.090227.xyz`)

If neither `url` nor `urls` is given, default built-in source list is used.

## Environment Variables (optional)

- `SUB_URLS`: comma-separated default source URLs
- `SUB_REGION`: default `cn` or `en` (used when `SUB_URLS` is not set)
- `SUB_USER_AGENT`: default User-Agent

## Example

```txt
/api/decrypt
/api/decrypt?format=json
/api/decrypt?url=https://bannedbook.github.io/fanqiang/vsp-en.py
/api/mihomo
/api/mihomo?fronting=cf.090227.xyz
```
