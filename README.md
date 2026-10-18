# SecureWipe Enterprise v2.0

Industry-grade secure data wiping and verification system for IT asset disposal, ITAD operations, and compliance with NIST SP 800-88, DoD 5220.22-M, ISO 27001, GDPR Article 17, R2, and eStewards standards.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                 Electron Desktop UI (React)              │
│  Dashboard · Drive Grid · Wipe Wizard · Certificates    │
└─────────────────────┬───────────────────────────────────┘
                      │ HTTPS + JWT (localhost)
┌─────────────────────▼───────────────────────────────────┐
│              Go Backend Orchestrator                    │
│  REST API · Job Queue · Auth/MFA · Cert Generation      │
│  Audit Log · ITAM Integration · SSE Progress            │
└─────────────────────┬───────────────────────────────────┘
                      │ subprocess JSON IPC
┌─────────────────────▼───────────────────────────────────┐
│           Rust Wipe Engine (wipe-engine)                │
│  Algorithms · HPA/DCO · io_uring · Verification        │
│  ATA/NVMe Commands · Merkle Tree · Sector Retry         │
└─────────────────────┬───────────────────────────────────┘
                      │ ioctl / SG_IO / NVMe Admin
                   Block Devices (/dev/sd*, /dev/nvme*)
```

## Supported Wipe Algorithms

| Algorithm | Standard | Description |
|-----------|----------|-------------|
| `zero-fill` | NIST Clear (HDD) | Single overwrite with 0x00 |
| `random-1pass` | — | Single overwrite with CSPRNG |
| `dod-3pass` | DoD 5220.22-M | 0x00 → 0xFF → random |
| `nist-clear` | NIST SP 800-88 Rev.1 | Multi-pass overwrite (recommended for HDDs) |
| `ata-secure-erase` | ATA/ATAPI-8 | Hardware-native ATA SECURITY ERASE UNIT |
| `ata-enhanced-erase` | ATA/ATAPI-8 | Enhanced variant (purges remapped sectors) |
| `nvme-crypto-erase` | NVMe 1.4 | Cryptographic erasure via NVMe Sanitize |
| `nvme-block-erase` | NVMe 1.4 | Block erase via NVMe Sanitize |
| `encrypt-then-delete` | NIST Purge (SSD) | AES-256-GCM encrypt full drive, zeroize key |
| `nist-purge` | NIST SP 800-88 Rev.1 | Hardware purge (ATA/NVMe) + verification |

## Requirements

### Build Dependencies
- **Rust** 1.78+ (stable)
- **Go** 1.22+
- **Node.js** 20+ and npm 10+
- **OpenSSL** 3.x (for certificate signing)

### Runtime Requirements
- **Linux** 5.10+ (kernel; 5.1+ for io_uring)
- Root privileges (raw disk I/O)
- **SQLite** 3.35+ (embedded, local mode)
- **PostgreSQL** 14+ (optional, enterprise mode)

## Installation

### 1. Clone and build the Rust wipe engine

```bash
cd wipe-engine
cargo build --release --features io_uring_support
# Binary: wipe-engine/target/release/wipe-engine
```

### 2. Build the Go backend

```bash
cd backend
go mod download
go build -o ../bin/securewipe-backend ./...
```

### 3. Build the Electron UI

```bash
cd ui
npm install
npm run electron:build:linux   # or :mac, :win
```

### 4. Initial setup

```bash
# Generate signing keys for certificates
openssl ecparam -name prime256v1 -genkey -noout -out backend/keys/signing.key.pem
openssl ec -in backend/keys/signing.key.pem -pubout -out backend/keys/signing.pub.pem

# Set environment variables (or use config file)
export SECUREWIPE_JWT_SECRET="$(openssl rand -hex 32)"
export SECUREWIPE_SIGNING_KEY="backend/keys/signing.key.pem"
export SECUREWIPE_DATA_DIR="/var/lib/securewipe"

# Start backend (or use the Electron app which launches it automatically)
./bin/securewipe-backend
```

## Configuration

Configuration via environment variables or `/etc/securewipe/config.yaml`:

| Variable | Default | Description |
|----------|---------|-------------|
| `SECUREWIPE_PORT` | `18443` | HTTPS listen port |
| `SECUREWIPE_DATA_DIR` | `./data` | Data directory (SQLite, certs, keys) |
| `SECUREWIPE_DB_URL` | SQLite | PostgreSQL DSN for enterprise mode |
| `SECUREWIPE_JWT_SECRET` | required | HS256 JWT signing secret |
| `SECUREWIPE_SIGNING_KEY` | required | Path to ECDSA P-256 PEM private key |
| `SECUREWIPE_MAX_JOBS` | `20` | Maximum concurrent wipe jobs |
| `SECUREWIPE_WIPE_ENGINE` | `./bin/wipe-engine` | Path to wipe engine binary |
| `SECUREWIPE_LOG_LEVEL` | `info` | Logging level (debug/info/warn/error) |

### ITAM integration (optional)

```yaml
itam:
  provider: servicenow  # or: sccm, intune, generic
  base_url: https://your-instance.service-now.com
  username: securewipe-svc
  password: "${ITAM_PASSWORD}"
```

## Usage

### Desktop App (recommended)

Launch the Electron app as root:
```bash
sudo ./SecureWipe\ Enterprise.AppImage
# or on macOS: sudo open SecureWipeEnterprise.app
```

### CLI (for automation / scripting)

```bash
# List all detected drives
sudo ./bin/wipe-engine list

# Check HPA/DCO status
sudo ./bin/wipe-engine check-hpa /dev/sda

# Wipe a single drive
sudo ./bin/wipe-engine wipe /dev/sda \
  --algorithm nist-clear \
  --verify auto \
  --disable-hpa \
  --operator "jsmith" \
  --job-id "$(uuidgen)"

# Verify a previously wiped drive
sudo ./bin/wipe-engine verify /dev/sda --pattern zeros --mode full
```

### API (for integration)

```bash
# Authenticate
TOKEN=$(curl -s -X POST https://localhost:18443/api/v1/session \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"changeme","totp_code":"123456"}' \
  | jq -r .token)

# List drives
curl -s -k -H "Authorization: Bearer $TOKEN" \
  https://localhost:18443/api/v1/drives | jq

# Start a wipe job
curl -s -k -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"device_path":"/dev/sda","algorithm":"nist-clear","verification":"auto"}' \
  https://localhost:18443/api/v1/jobs | jq

# Stream job progress (SSE)
curl -s -k -H "Authorization: Bearer $TOKEN" \
  https://localhost:18443/api/v1/jobs/<JOB_ID>/progress
```

## Security Model

- **Authentication**: JWT (HS256, 8h expiry) + mandatory TOTP MFA
- **Authorization**: Role-based (Admin, Operator, Auditor) with PostgreSQL RLS
- **Certificate integrity**: ECDSA-P256/SHA256 (JWS) + Merkle tree over 4MB chunks
- **Audit log**: Append-only with SHA-256 hash chain (tamper-evident)
- **Transport**: TLS 1.3 (HTTPS, self-signed for localhost IPC)
- **Memory safety**: Rust engine uses `zeroize` for all key material
- **No telemetry**: Completely air-gappable, no outbound connections required

## Compliance Mapping

| Standard | Coverage |
|----------|----------|
| NIST SP 800-88 Rev.1 | Clear (HDD), Purge (SSD/NVMe), Destroy |
| DoD 5220.22-M | 3-pass overwrite with verification |
| ISO 27001 A.8.3.2 | Media disposal controls |
| GDPR Art. 17 | Right to erasure — certified proof |
| R2:2013 | Electronics recycler standard |
| eStewards | e-Steward certified process |

## Stress Testing

```bash
# Run full 20-drive stress test (requires 20 test block devices)
cd tests
./stress-test.sh --drives 20 --algorithm nist-clear --verify sampled

# Generate mock block devices for testing without real hardware
./setup-test-devices.sh --count 20 --size 1G

# Run verification-only benchmark
./bench-verify.sh --device /dev/sda --iterations 3
```

See `tests/README.md` for detailed test matrix documentation.

## Certificate Format

Each completed wipe produces a tamper-proof certificate:

```json
{
  "certificate_id": "SW-2025-001234",
  "issued_at": "2025-10-15T14:23:01Z",
  "device": {
    "serial": "WXC1A2B3C4D5",
    "model": "WDC WD40EZRZ-00GXCB0",
    "capacity_gb": 4000.787,
    "interface": "SATA"
  },
  "wipe": {
    "algorithm": "nist-clear",
    "verification": "sampled",
    "passes_completed": 3,
    "bad_sectors": 0,
    "duration_seconds": 14832.5,
    "throughput_mb_s": 138.4
  },
  "merkle_root": "a3f8b2c1d4e9...",
  "compliance_standards": ["NIST SP 800-88 Rev.1", "ISO 27001"],
  "operator": "jsmith",
  "signature": "eyJhbGciOiJFUzI1NiIsImtpZCI6..."
}
```

## License

Proprietary — All rights reserved. See `LICENSE.md`.
