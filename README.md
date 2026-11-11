# fidoinv

A small command-line tool to take inventory of FIDO2 USB security keys.
Plug in one token at a time, run `fidoinv inventory`, and it appends that
token's details and passkeys to a CSV file.

It uses Yubico's [python-fido2](https://github.com/Yubico/python-fido2)
library (2.x), which works with any FIDO2/CTAP2 token, not just YubiKeys.

What it can read from a token:

* **Device info** (`getInfo`): AAGUID and model name, CTAP versions, extensions,
  options, firmware version, PIN retries left, free passkey slots, plus USB
  vendor/product ids, product name and serial (when the token reports one).
* **Passkeys** (resident / discoverable credentials), using CTAP 2.1 credential
  management (or the `credentialMgmtPreview` version on older firmware): site
  (RP id and name), user name, display name, user id, credential id, public key,
  credProtect level, and whether a largeBlob key exists. Needs the token's PIN.
* **TOTP account names** (optional, `--totp`): YubiKey OATH issuer/account names,
  and OnlyKey slot labels. **Secrets are never read or exported.**

It can also **delete** a passkey from a token, after a typed confirmation.

## Install

Python 3.10 or newer is required.

### Windows (PowerShell)

```powershell
cd C:\sd\fidoinv
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .
# optional, for --totp on YubiKeys / OnlyKeys:
pip install yubikey-manager onlykey
```

If PowerShell refuses to run `Activate.ps1`, run
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once.

### Windows (Command Prompt / batch)

```bat
cd C:\sd\fidoinv
python -m venv .venv
.venv\Scripts\activate.bat
pip install -e .
pip install yubikey-manager onlykey
```

In a `.bat` file, use `call .venv\Scripts\activate.bat` so the script continues
after activating.

### conda

```
conda create -n fidoinv python=3.12
conda activate fidoinv
pip install -e .
pip install yubikey-manager onlykey
```

(`pip` inside the conda env is the reliable way; `fido2` and `onlykey` are not
all on conda's default channel.) Remove with `conda env remove -n fidoinv`.

### Linux

```bash
cd ~/sd/fidoinv
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
pip install yubikey-manager onlykey      # optional
```

Your user needs access to the token's `/dev/hidraw*` device. Most distros ship
FIDO udev rules (`libfido2-1`, `libu2f-udev`, or `fido2-tools` packages). If
`fidoinv list` finds nothing, add a rule like this to
`/etc/udev/rules.d/70-fido.rules` (one line per USB vendor id, see `lsusb`):

```
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="1050", TAG+="uaccess"
```

then `sudo udevadm control --reload-rules && sudo udevadm trigger` and replug.
YubiKey OATH (`--totp`) also needs `pcscd` running (`sudo apt install pcscd`).

`.venv` only holds Python and packages; it is safe to delete it and reinstall.

## Windows: run as Administrator

Windows only lets the browser (through its WebAuthn API) talk to FIDO tokens
without elevation. Any other program, including this one, `ykman fido` and the
vendor tools, must run **as Administrator** to reach a FIDO token directly.
Open PowerShell or Command Prompt with *Run as administrator*. If you forget,
`fidoinv` says "No FIDO device found (or access denied)" and reminds you.
(YubiKey TOTP listing goes over the smart-card interface and does not need it.)

## Usage

```
fidoinv list                                   # connected FIDO devices, numbered
fidoinv info [--device N] [--json]             # getInfo + USB details
fidoinv inventory --label NAME [--out keys.csv] [--totp] [--device N]
fidoinv delete --rp SITE (--user NAME | --cred-id ID | --all-for-rp) [--yes] [--device N]
fidoinv update-aaguids                         # download a fuller AAGUID->model list
```

You can also run it as `python -m fidoinv ...`.

Typical session, one token at a time:

```
fidoinv inventory --label yubikey-blue --totp
fidoinv inventory --label solo-tap
fidoinv inventory --label feitian-k9
```

Each run asks for the token's FIDO2 PIN (typed hidden; it is never stored or
logged) and appends to `keys.csv` (created with a header if it does not exist).
If several tokens are plugged in, `fidoinv list` shows their numbers and you
pick one with `--device N`.

Deleting:

```
fidoinv delete --rp github.com --user roger
```

lists the matching passkeys and only deletes them if you type `yes`
(`--yes` skips the question). The credential id from the CSV works too:
`--cred-id <credential_id>`. Deleting from the token does not remove the passkey
from the website's account settings; remove it there as well.

## CSV columns

| column | meaning |
|---|---|
| timestamp | when the row was written (local time with UTC offset) |
| token_label | the `--label` you gave |
| record_type | `device` (one per run), `passkey`, or `totp` |
| product_name | USB product string |
| model | model name looked up from the AAGUID (blank if unknown) |
| aaguid | authenticator model id |
| usb_serial | USB serial string, if the token reports one (many don't) |
| rp_id | site / relying party id (for `totp`: the issuer or OnlyKey slot) |
| rp_name | site name stored with the passkey |
| user_name | account name (for `totp`: the account / label) |
| user_display_name | display name |
| user_id | user handle, hex |
| credential_id | credential id, base64url (use with `delete --cred-id`) |
| cose_alg | signature algorithm, e.g. `ES256 (-7)`, `EdDSA (-8)` |
| public_key | public key as base64 SubjectPublicKeyInfo DER (a PEM body on one line) |
| public_key_cose | the raw COSE key, base64url CBOR |
| cred_protect | credProtect level (1 uvOptional, 2 uvOptionalWithCredentialIDList, 3 uvRequired) |
| large_blob_key | `yes` if the credential has a largeBlob key |
| note | device summary, or why something could not be listed |

If the token has no credential management (or no PIN set, or is U2F only), the
run still appends its `device` row with the reason in `note`.

An example file is in `examples/keys.example.csv`. Real `*.csv` output is in
`.gitignore`: it lists your accounts, so keep it private.

## Limitations

* **Only resident (discoverable) credentials can be listed.** Ordinary
  second-factor (U2F / non-resident FIDO2) registrations are not stored on the
  token, so nothing about them can be read. Your site list for those has to come
  from the sites' security settings.
* **Private keys can never be extracted**, by design. Public keys, credential
  ids and user info are what is available.
* **TOTP secrets are not exported** (the tokens don't allow reading them anyway).
  Only account names are listed, and only where a documented protocol exists.
* Credential management needs CTAP 2.1 (`credMgmt`) or the 2.1 preview
  (`FIDO_2_1_PRE` + `credentialMgmtPreview`) on the token, and a PIN set.
* Fingerprint-only tokens still need their PIN for credential management here.

## Brand support (researched November 2026; not yet tested on hardware)

| Token | Passkey listing / delete (credMgmt) | TOTP / OATH account names | Notes |
|---|---|---|---|
| **YubiKey** (5 series, Bio, Security Key) | Yes, firmware 5.2+ (preview on 5.2-5.6, CTAP 2.1 on 5.7+). Older firmware: no. [1] | **Yes**, `--totp` via `yubikey-manager` (OATH applet over CCID). Asks for the OATH password if one is set. [2] | |
| **OnlyKey** | Yes, firmware 2.1.1+ supports resident keys (max 12); CTAP 2.1, `onlykey-cli credential ls/rm` does the same. [3][4] | Partial: no OATH listing protocol; `--totp` reads **slot labels** with `onlykey-cli getlabels` (slots hold passwords, TOTP, or both). [5] | |
| **Solo 1 / Solo Tap (v1)** | Yes, firmware 4.0.0+ (adds credential management + credProtect). [6][7] | None: Solo v1 has no TOTP applet. | |
| **Thetis** (FIDO2 / Pro) | Yes per vendor: Chrome's "Manage security keys" and the Thetis Windows Key Manager list/delete passkeys (standard CTAP). Exact firmware cutoff unknown. [8][9] | No: TOTP lives in a Thetis-specific applet used by Thetis Key Manager / Thetis Authenticator; protocol not published. [8][10] | |
| **TrustKey** (T110/T120, G310/G320) | Likely (T series hold 150 resident keys; FIDO2 certified) but credMgmt support is **unknown**; run `fidoinv info` to see. [11][12] | No: up to 50 TOTP/HOTP accounts managed only by TrustKey KeyManager; protocol not published. [11] | |
| **Identiv uTrust FIDO2** | Yes on current firmware (CTAP 2.1 listed); older firmware depends on version. AAGUID 73402251-…-3cb6db604b03. [13][14] | No: NFC+ models have OATH TOTP/HOTP managed by uTrust Key Manager (Windows); plain NFC models have none. [14][15] | |
| **Feitian ePass FIDO / BioPass** | Yes on COS 3.3.00+ (Oct 2020 added FIDO_2_1_PRE and credential management); earlier units: no. [16] | No: HOTP/TOTP via FT Authenticator / SK Manager only; no documented Yubico-OATH compatibility. [16][17] | |

`fidoinv info` shows a token's actual `Credential management` support, which
beats any table.

Sources:
1. Yubico, YubiKey 5 FIDO specifics: https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-fido.html
2. Yubico, ykman OATH/FIDO commands: https://docs.yubico.com/software/yubikey/tools/ykman/FIDO_Commands.html
3. OnlyKey docs, OpenSSH / FIDO2 resident keys: https://docs.onlykey.io/openssh/
4. OnlyKey User's Guide (12 resident credentials): https://docs.onlykey.io/usersguide/
5. OnlyKey command-line utility: https://docs.onlykey.io/command-line/
6. SoloKeys solo1 release 4.0.0, "Credential management and credProtect added": https://github.com/solokeys/solo1/releases/tag/4.0.0
7. solo1 `ctap.c` (CTAP_CBOR_CRED_MGMT 0x0A and 0x41): https://github.com/solokeys/solo1/blob/master/fido2/ctap.c
8. Thetis downloads (Key Manager, Chrome tool, Authenticator app): https://thetis.io/pages/downloads
9. Thetis passkey management in Chrome: https://thetis.io/pages/fido2-passkey-credential-management-tool
10. Thetis TOTP guide: https://thetis.io/pages/guide-thetis-key-as-totp-2fa-thetis-authenticator-app
11. TrustKey T series user manual: https://www.trustkeysolutions.com/public/download/444/T%20Series_User%20Manual(T110_T120)_eng_v1.3.pdf
12. U2F Garden, TrustKey T110: https://u2f.garden/keys/trustkey-t110/
13. Identiv uTrust FIDO2 technical manual: https://go.hirschsecure.com/hubfs/44142801/LACS/manual/uTrust_FIDO2_Technical_Manual.pdf
14. U2F Garden, uTrust FIDO2 NFC / NFC+: https://u2f.garden/keys/identiv-utrust-fido2/ , https://u2f.garden/keys/identiv-utrust-fido2-plus/
15. uTrust Key Manager manual: https://www.scm-pc-card.de/media/pdf/64/fa/a8/uTrust_Key_Manager_Software_User_Manual2023.pdf
16. Feitian ePass FIDO firmware history: https://fido.ftsafe.com/products-epass-fido/
17. Feitian SK Manager manual: https://fido.ftsafe.com/feitian-sk-manager-tool-user-manual/

Model names for AAGUIDs come from the community list at
https://github.com/passkeydeveloper/passkey-authenticator-aaguids (largely from
the FIDO Alliance Metadata Service). A subset for the brands above is bundled;
`fidoinv update-aaguids` downloads the full list to a per-user cache.

## Development

```
pip install -e ".[test]"
python -m pytest
```

Tests use fake CTAP objects, so no hardware is needed.

## License

MIT
