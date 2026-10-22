# ota_device_update

Device-specific OTA firmware updates for **ESP32-S3 + Quectel EC200U** over cellular,
with a Node.js/SQLite server that decides per device (IMEI) which firmware it runs.
Derived from `dlms_client/ota_update.ino` (same modem, pins and field fixes).

```
firmware/ota_device_update/   Arduino sketch (ESP32 core 3.x)
server/                       Express + better-sqlite3 OTA server, admin API, dashboard
```

## How a device decides what to run

1. Device pinned to a version → gets exactly that release (downgrades allowed).
2. Otherwise → the current release of its channel (`stable` / `beta`), upgrades only.
3. Target == running version → no update.

New devices register themselves by IMEI and wait for an admin to approve them in the
dashboard (see [Automatic registration](#automatic-registration)). They join `stable`.

## Automatic registration

A device without a key gets one from the server automatically. You don't need to type
`SET secret=` on it.

1. At boot the device reads its IMEI (`AT+GSN`), makes a P-256 key pair (kept in NVS
   until it has a key) and sends `POST /ota/register {device_id, current_ver, pub}`.
2. It appears under **Devices → Awaiting approval**, and the Overview shows a banner. It
   asks again every 10 min (`REGISTER_POLL_SEC`).
3. An admin opens the device and clicks **Approve** (bulk approve works too). Before
   approving, check that the **key fingerprint** matches `GET_STATUS` on the device
   (`reg=pending fp=xxxxxxxx`), or that you trust where the request came from.
4. On its next request the device receives its key, encrypted with
   `AES-256-GCM(SHA256(ECDH(device, server) ‖ IMEI))`. It saves the key and starts
   normal checks.

| `REGISTRATION_MODE` | Behaviour |
|---|---|
| `approval` (default) | new devices wait for an admin |
| `auto` | approved immediately (lab or factory use only) |
| `off` | `/ota/register` refused; only manually provisioned keys work |

The old `AUTO_REGISTER=false` still means `off`.

**Setup:** the firmware must contain the server's registration public key. Run this on
the OTA server:

```bash
cd server && npm run pubkey
```

Paste the printed `#define SERVER_REG_PUBKEY_HEX "04…"` line into `firmware/…/config.h`
and build. The private key is `server/data/server_reg_key.pem`, created on first start.
**Back it up.** Without it, firmware built with the old public key can no longer register.
Devices that already have a key keep working.

Security notes:

- The device key never crosses the network in clear. A reply decrypts only on the device
  that made the request, and only if it came from the real server.
- If a device that is already approved sends a *different* key (its NVS was erased, or
  someone is spoofing its IMEI), it shows up as awaiting approval with a "new key"
  warning. The working device is not locked out in the meantime.
- **Reject** blocks a new device. Delete it to let it ask again.
- At most `REGISTER_MAX_PENDING` (500) devices can wait at once, and each IMEI can ask at
  most once every 20 s.
- Manual `SET secret=` still works as a fallback, as before.

## Protocol

| Call | Signed surface (HMAC-SHA256, key = device key) |
|---|---|
| `POST /ota/check` `{device_id, current_ver, ts, sig}` | `imei\|current_ver\|ts` |
| reply `{update_available, version, size, md5, download_token, check_interval_s, reason, sig}` | `imei\|ts\|version\|size\|md5\|download_token` (verified by the device) |
| `GET /ota/firmware?device_id=&token=` | one-time token, 10 min, bound to device + release |
| `POST /ota/report` `{device_id, version, status, detail, ts, sig}` | `imei\|version\|status\|ts` |
| `POST /ota/register` `{device_id, current_ver, pub}` → `{status:"pending", retry_s}` or `{status:"approved", iv, ct, tag}` | unsigned; the key in the reply is encrypted for `pub` (see above) |

- **Device key** = `HMAC_SHA256(MASTER_SECRET, IMEI)` as 64 lowercase hex chars; the device
  uses that hex string's ASCII bytes as its HMAC key. The server stores no per-device keys.
- `ts` comes from the EC200U network clock (`AT+CCLK?`, NITZ); the server accepts ±300 s
  and rejects reused signatures.
- The signed reply means a rogue server (e.g. one set via `SET host=`) cannot push an image,
  and an old genuine offer cannot be replayed to force a downgrade.
- Report statuses: `downloading`, `flashed`, `md5_fail`, `failed`, `running`. After rebooting
  into a new image the device reports `running` (or `failed` if it booted another version).
- Transport is plain TCP (as in dlms_client); integrity comes from the HMACs + MD5.

## Server

```bash
cd server
npm install
cp .env.example .env       # set MASTER_SECRET (>=16 chars) and ADMIN_TOKEN (>=12 chars)
npm run user:add -- <you> --role admin   # once: first dashboard admin (asks for password)
npm start                  # dashboard at http://<host>:<PORT>/
npm test                   # unit + end-to-end + auth tests
```

### Dashboard

Sign in at `http://<host>:<PORT>/` with a dashboard user. Pages: **Overview** (fleet stats,
versions in the field, channels), **Devices** (search, filters, bulk channel/pin/enable,
per-device detail + key + history), **Releases** (upload with progress), **History**
(filter by device / event / user), **Users** (admins only), **Account** (change password).

| Role | Can |
|---|---|
| `admin` | everything, including device keys and user management |
| `viewer` | read-only; never sees device keys |

- Users live in SQLite (`server/data/ota.db`); passwords are scrypt-hashed (min 10 chars).
- Session cookie is HttpOnly + SameSite=Strict (+ Secure over HTTPS); it ends after
  8 h idle or 24 h total, or on logout. 5 wrong passwords lock that username for 15 min.
- Locked out / forgot the admin password: `npm run user:add -- <name> --role admin --reset`.
- Every admin action is in History with the user who did it.
- Behind nginx with HTTPS on the same host: set `TRUST_PROXY=loopback` in `.env`.

Optional `.env` keys: `SESSION_IDLE_SEC`, `SESSION_MAX_SEC`, `LOGIN_MAX_FAILS`,
`LOGIN_LOCK_SEC`, `COOKIE_SECURE` (auto/always/never), `TRUST_PROXY`.

### API for scripts

`ADMIN_TOKEN` still works as an admin API key (`Authorization: Bearer $ADMIN_TOKEN`) for
scripts; the browser does not use it. Endpoints: see the header of
`server/src/routes/admin.js`. Typical release:

```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" -F version=1.1.0 -F notes="fix X" -F file=@ota_device_update_1.1.0.bin http://localhost:3000/api/releases
```

Then point a channel at it or pin individual devices in the dashboard. Uploads must be
ESP32 app images (first byte `0xE9`) with a `MAJOR.MINOR.PATCH` version.

Device key for provisioning: device page **Show key** (admins), or

```bash
node tools/device-key.js 868123456789012
```

## Firmware

Board: ESP32S3 Dev Module, 16 MB flash, partition `app3M_fat9M_16MB` (two 3 MB OTA slots).

```bash
arduino-cli compile --fqbn "esp32:esp32:esp32s3:USBMode=hwcdc,CDCOnBoot=cdc,FlashMode=qio,FlashSize=16M,PartitionScheme=app3M_fat9M_16MB,PSRAM=opi" firmware/ota_device_update
```

Release checklist: bump `FW_VERSION` in `config.h`, build, upload the `.bin` with the same
version string.

### Commissioning (USB serial, 115200)

With automatic registration nothing is needed beyond approving the device in the
dashboard. To provision manually instead:

```
GET_STATUS                              # shows the IMEI and reg=<state> fp=<fingerprint>
SET host=65.20.77.137 port=8080 secret=<64-hex device key>
CHECK_OTA
```

Other keys: `interval=<s>` (local default, the server's `check_interval_s` wins),
`apn=<apn>`. Over BLE (service `6e400001-…`, write RX `…0002`, notify TX `…0003`,
name `OTA-<last 6 IMEI digits>`) the same commands work, but once a key is provisioned
`SET` also needs `auth=<current device key>`.

### Checks run

- At boot (5 s after the modem attaches), then every `check_interval_s` (default 24 h).
- Retries after 15 min on network or download failure.
- On `CHECK_OTA` from serial or BLE.

Put your product logic in `app_setup()` / `app_loop()` in `ota_device_update.ino`.

### Download speed

The UART runs at 9600 baud, the same as dlms_client, which gives about 1 KB/s. At that rate a
660 KB image takes around 11 minutes. If the module is set to 115200
(`AT+IPR=115200;&W`), set `MODEM_BAUD` to 115200 in `config.h`.

## Not in v1 (by decision)

These were left out on purpose:

- ECDSA-signed images
- Bootloader rollback
- Resumable downloads
- Group or staged rollouts
- TLS
