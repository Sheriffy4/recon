# Fake Payload Directory

This directory contains fake payloads used for DPI bypass attacks.

## Directory Structure

```
payloads/
├── bundled/          # Pre-bundled payloads from zapret
│   ├── index.json    # Payload metadata and mappings
│   └── *.bin         # Binary payload files
└── captured/         # User-captured payloads
    └── *.bin         # Captured ClientHello and other payloads
```

## Bundled Payloads

The `bundled/` directory contains pre-captured payloads from the zapret project:

### TLS ClientHello Payloads
- `tls_clienthello_www_google_com.bin` - Google (652 bytes)
- `tls_clienthello_vk_com.bin` - VK.com (517 bytes)
- `tls_clienthello_iana_org.bin` - IANA.org (517 bytes)

### QUIC Initial Payloads
- `quic_initial_google_com.bin` - Google (1357 bytes)
- `quic_initial_www_google_com.bin` - Google WWW (1200 bytes)
- `quic_initial_vk_com.bin` - VK.com (1357 bytes)

### HTTP Payloads
- `http_iana_org.bin` - IANA.org HTTP request (418 bytes)

## Captured Payloads

The `captured/` directory is for user-captured payloads using the `cli.py payload capture` command.

## Usage

Payloads are automatically loaded by the PayloadManager and can be referenced in strategies:

```python
from recon.core.payload import PayloadManager

manager = PayloadManager(
    payload_dir=Path("recon/data/payloads/captured"),
    bundled_dir=Path("recon/data/payloads/bundled")
)

# Get a TLS payload for google.com
payload = manager.get_payload(PayloadType.TLS_CLIENTHELLO, domain="google.com")
```

## CDN Mappings

The index.json file includes CDN mappings for domains like:
- googlevideo.com → www.google.com
- ytimg.com → www.google.com
- youtube.com → www.google.com

This allows the system to use google.com payloads for YouTube CDN domains.
