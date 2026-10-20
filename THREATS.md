# TrustVault Security Threat Model & Defense Architecture (THREATS.md)

> *"A document is reachable only by someone who was granted it. You can prove who reached it, including attempts refused. Taking access away works immediately."*

TrustVault treats document sharing as a zero-trust cryptographic and authorization challenge. This document analyzes the adversarial threat landscape, detailing attack vectors, concrete mitigations in the TrustVault codebase, automated test coverage, and knowingly accepted residual risks.

---

## Threat Matrix Overview

| Threat ID | Threat Category | Attack Vector | Mitigated In | Test Coverage |
| :--- | :--- | :--- | :--- | :--- |
| **THR-01** | BOLA / IDOR | Direct URL access to non-granted document UUIDs | `app/security.py:verify_document_access` | `test_unauthorized_user_cannot_read_or_download` |
| **THR-02** | Horizontal Privilege Escalation | Document Owner A attempts to modify or view Document Owner B's files | `app/security.py:verify_document_access` | `test_other_owner_cannot_access_unshared_doc` |
| **THR-03** | Stale Token / URL Reuse | User continues downloading after permission revoked via cached links | `app/routers/documents.py:download_document` | `test_instant_revocation` |
| **THR-04** | Audit Trail Tampering | Rogue actor alters audit database row to hide an exfiltration event | `app/crypto.py:verify_audit_chain` | `test_tampered_audit_record_fails_verification` |
| **THR-05** | Audit Record Deletion / Pruning | Rogue admin deletes log row; hash chain breaks | `app/crypto.py:verify_audit_chain` | `test_broken_hash_chain_link_fails_verification` |
| **THR-06** | MIME Confusion & Disguised Executable | Attacker uploads Windows PE or Linux ELF disguised as `.pdf` | `app/file_validator.py:validate_file_content` | `test_magic_bytes_enforcement_rejects_disguised_executable` |
| **THR-07** | Path Traversal & File Overwrite | Attacker uploads `../../../../etc/passwd` to overwrite server binaries | `app/file_validator.py:sanitize_filename` | `test_path_traversal_filename_sanitization` |
| **THR-08** | Stored XSS via File Content | Browser renders malicious SVG/HTML with active JS in application origin | `app/routers/documents.py:download_document` | Validated via `Content-Disposition: attachment` & `nosniff` headers |
| **THR-09** | Admin Backdoor / Separation of Duty | System Admin inspects confidential employee payroll without ACL grant | `app/security.py:verify_document_access` | `test_admin_cannot_snoop_confidential_document` |
| **THR-10** | Metadata & Search Index Leakage | Unauthenticated or ungranted user learns existence of secret files via search | `app/routers/documents.py:list_documents` | `test_zero_trust_document_listing_isolation` |
| **THR-11** | Physical Disk / Backup Theft | Attacker steals disk volume or database dump to read plaintext files | `app/crypto.py:encrypt_data` | Enforced AES-256-GCM AEAD encryption at rest |
| **THR-12** | Timing Side-Channel Attack | Attacker measures microseconds on password/hash checks to deduce secret | `app/security.py:verify_password` & `app/crypto.py` | `hmac.compare_digest` constant-time verification |
| **THR-13** | Session Invalidation Bypass | User logs out or gets deactivated, but continues using valid JWT | `app/security.py:get_current_user` | `test_token_versioning_instant_revocation_on_logout` |
| **THR-14** | Automated Brute Force / Enumeration | Attacker rapidly probes document IDs to discover valid objects | `app/security.py:record_audit` | `test_repeated_access_refusals_trigger_security_alert` |

---

## Detailed Threat Analyses & Mitigations

### 1. Broken Object-Level Authorization (BOLA / IDOR) (THR-01, THR-02)
* **Attack Scenario**: An authenticated Viewer receives permission for Document `A`. In browser developer tools, they notice the download request `GET /api/documents/{id}/download`. They modify `{id}` to match Document `B` (e.g. `Q3_Executive_Salaries.pdf`) owned by Marcus Chen.
* **Why Traditional Apps Fail**: Traditional apps often check only if a user is logged in (`@login_required`), or check permissions client-side on the frontend button.
* **TrustVault Defense**:
  1. Every single document route (`GET`, `PUT`, `DELETE`, `DOWNLOAD`, `PERMISSIONS`) calls the central zero-trust evaluator `verify_document_access(document_id, user, required_level, db)`.
  2. The database is queried synchronously inside the active transaction:
     ```python
     permission = db.query(DocumentPermission).filter(
         DocumentPermission.document_id == document_id,
         DocumentPermission.user_id == user.id
     ).first()
     ```
  3. If no matching row exists and the user is not the document owner, access is refused immediately (`403 Forbidden`).
  4. The attempt is immediately committed to the tamper-evident audit ledger as `ACCESS_READ: REFUSED`, capturing the actor's user ID, IP address, target resource, and timestamp.
* **Automated Test**: `tests/test_permissions.py::test_unauthorized_user_cannot_read_or_download` and `tests/test_permissions.py::test_other_owner_cannot_access_unshared_doc`.

---

### 2. The Revocation Gap: URL & Token Staleness (THR-03)
* **Attack Scenario**: Sophia (Viewer) is given access to a confidential contract. The company terminates Sophia's contract. The Owner clicks "Revoke Access". However, Sophia previously copied a pre-signed S3 download URL valid for 60 minutes, or holds a JWT claiming `document_access: ["doc_123"]`. She continues downloading the file.
* **Why Traditional Apps Fail**: Cloud-native architectures love offloading file downloads to pre-signed AWS S3 or Google Cloud Storage URLs. Once generated, pre-signed URLs are cryptographically unrevokable until their expiration timeout elapses.
* **TrustVault Defense**:
  1. **Zero Pre-Signed URLs**: TrustVault never issues public or pre-signed storage URLs. Every single file download is strictly brokered by the TrustVault backend stream handler.
  2. **Synchronous Transactional Validation**: When `DELETE /api/documents/{id}/permissions/{user_id}` is invoked, the database record is deleted and committed in the database immediately.
  3. When the user requests `/api/documents/{id}/download`, the authorization query runs *at the exact moment of request execution*. Because the permission row is gone, the request is rejected with `403 Forbidden` with zero latency (0ms delay).
  4. For session-wide revocation, each user record maintains an integer `token_version`. Upon logout or deactivation, `token_version` is incremented, instantly invalidating all active JWTs.
* **Automated Test**: `tests/test_permissions.py::test_instant_revocation` and `tests/test_auth.py::test_token_versioning_instant_revocation_on_logout`.

---

### 3. Audit Trail Tampering, Repudiation & Modification (THR-04, THR-05)
* **Attack Scenario**: A malicious insider or attacker obtains direct SQL access (e.g. database backup restoration, compromised DBA credentials, or SQL injection) and alters audit records:
  - Changing `user_email: "malicious_actor@attacker.com"` to `"innocent_employee@company.com"`.
  - Deleting an audit entry that logged an unauthorized download attempt.
* **Why Traditional Apps Fail**: Standard logging tables (e.g. `audit_logs`) can be updated or deleted silently with standard SQL queries (`UPDATE audit_logs SET ...`). There is no cryptographic proof of chain integrity.
* **TrustVault Defense**:
  1. **Merkle/HMAC Hash Chaining**: Every log row contains:
     - `prev_hash`: SHA-256 hash of the immediate prior row (`0*64` for Genesis block).
     - `record_hash`: `HMAC-SHA256(AUDIT_HMAC_KEY, canonical_payload)`.
  2. The canonical payload strictly binds all identifying fields:
     `{log_id}|{timestamp}|{user_id}|{user_email}|{action}|{target_type}|{target_id}|{status}|{reason}|{ip_address}|{details}|{prev_hash}`.
  3. Changing *any* field in a row (e.g. user_email or timestamp) changes the recalculated HMAC, causing `verify_audit_chain()` to immediately flag `Tampering detected at log entry ID X: signature mismatch`.
  4. Deleting or inserting any row breaks the `prev_hash` pointer of subsequent rows, immediately flagging `Broken chain at log entry ID X`.
  5. The API provides `/api/audit/verify` which verifies the entire ledger from Genesis to tip in real time.
* **Automated Test**: `tests/test_tamper_audit.py::test_tampered_audit_record_fails_verification` and `tests/test_tamper_audit.py::test_broken_hash_chain_link_fails_verification`.

---

### 4. MIME Confusion & Disguised Executable Smuggling (THR-06)
* **Attack Scenario**: An attacker uploads a malicious Windows Portable Executable (`.exe`) or Linux ELF binary renamed to `Quarterly_Report.pdf`, with `Content-Type: application/pdf`. Later, an unsuspecting executive or administrator downloads and executes the binary.
* **TrustVault Defense**:
  1. **Magic Bytes Inspection**: The server reads the raw binary header bytes:
     - PDF files must begin with `b"%PDF-"`.
     - PNG files must begin with `b"\x89PNG\r\n\x1a\n"`.
     - JPEG files must begin with `b"\xff\xd8\xff"`.
     - Office Open XML (DOCX/XLSX) must begin with ZIP magic bytes `b"PK\x03\x04"`.
     - Text files are checked for null bytes `\x00` and forbidden executable headers (`MZ`, `\x7fELF`, `\xca\xfe\xba\xbe`, `#!`).
  2. Files failing magic byte checks are rejected immediately with `400 Bad Request` and logged in the audit trail as `UPLOAD_FAILED: MIME spoofing detected`.
* **Automated Test**: `tests/test_file_upload.py::test_magic_bytes_enforcement_rejects_disguised_executable` and `tests/test_file_upload.py::test_reject_null_bytes_in_text_file`.

---

### 5. Path Traversal & File Overwrite Attacks (THR-07)
* **Attack Scenario**: An attacker uploads a file with a crafted filename containing directory traversal sequences, e.g. `../../../../windows/system32/cmd.exe` or `../../app/main.py`.
* **TrustVault Defense**:
  1. **Filename Sanitization**: `sanitize_filename()` strips all path components (`/` and `\`), removes null bytes, strips leading dots (preventing hidden files like `.env`), and normalizes characters to `[a-zA-Z0-9_.-]`.
  2. **Storage Decoupling**: Uploaded files are **never** stored on disk using their original or sanitized filename! Files are stored using a cryptographically random UUID: `UPLOAD_DIR / f"{uuid.uuid4().hex}.enc"`.
  3. It is physically impossible for an upload to overwrite system files or escape `UPLOAD_DIR`.
* **Automated Test**: `tests/test_file_upload.py::test_path_traversal_filename_sanitization`.

---

### 6. Stored Cross-Site Scripting (XSS) via Uploaded Content (THR-08)
* **Attack Scenario**: An attacker uploads an HTML file or SVG containing `<script>alert(document.cookie)</script>` or JavaScript payload. If the server serves the file with `inline` disposition or missing security headers, the victim's browser executes the script in TrustVault's origin, stealing session tokens.
* **TrustVault Defense**:
  1. **Forced Download Disposition**: All downloads are served with `Content-Disposition: attachment; filename="..."`, forcing the browser to download to disk rather than executing in the browser DOM.
  2. **Strict MIME and Security Headers**:
     - `X-Content-Type-Options: nosniff` (stops browser MIME sniffing).
     - `X-Frame-Options: DENY` (prevents clickjacking and iframe embedding).
     - Strict Content-Security-Policy (CSP) headers applied to all responses.
     - SVG and HTML uploads are disallowed in the file validator whitelist.

---

### 7. Administrator Backdoor & Separation of Duty (THR-09)
* **Attack Scenario**: An IT Administrator with system privileges wants to spy on executive compensation packages (`Q3_Executive_Salaries.pdf`) without the VP of Finance knowing.
* **TrustVault Defense**:
  1. **Zero-Trust Separation of Duty**: In TrustVault, being an Administrator does **not** grant automatic document access.
  2. `verify_document_access()` enforces that only the document Owner and users with an active `DocumentPermission` grant can download file content.
  3. When an Administrator attempts to download a file they were not granted, the server returns `403 Forbidden` and records an audit log alert.
  4. Administrators manage system health, user lifecycle, and audit verification, but cannot snoop confidential payloads.
* **Automated Test**: `tests/test_threats.py::test_admin_cannot_snoop_confidential_document`.

---

### 8. Physical Storage Volume Theft & Plaintext Leakage (THR-11)
* **Attack Scenario**: An attacker gains access to physical server disks, EBS snapshots, or server backup archives.
* **TrustVault Defense**:
  1. **Envelope Encryption at Rest**: Every file stored on disk is encrypted using **AES-256-GCM** (Galois/Counter Mode).
  2. Each file is encrypted with a unique 96-bit cryptographic nonce (`os.urandom(12)`).
  3. The raw file contents on disk are incomprehensible ciphertext.
  4. AES-256-GCM provides authenticated encryption (AEAD): if any ciphertext byte or nonce is modified on disk, decryption fails with `InvalidTag` before any data can be returned.

---

### 9. Metadata & Search Enumeration Isolation (THR-10)
* **Attack Scenario**: Even if an unauthorized user cannot download a file, they can search for "Merger" or "Project Titan" to learn about sensitive ongoing corporate deals from document titles.
* **TrustVault Defense**:
  1. Search queries (`GET /api/documents?search=...`) are filtered at the database query level:
     ```python
     query = query.filter(
         or_(
             Document.owner_id == current_user.id,
             Document.id.in_(granted_doc_ids)
         )
     )
     ```
  2. Documents that the user has not been granted access to **never appear** in search results or listings.
* **Automated Test**: `tests/test_permissions.py::test_zero_trust_document_listing_isolation`.

---

## Knowingly Accepted Risks & Residual Threats

Honesty in threat modeling is paramount. The following trade-offs and residual risks were consciously accepted in this architecture:

### 1. Master Key Storage & Server Host Compromise
* **Accepted Risk**: The `TRUSTVAULT_MASTER_KEY` and `TRUSTVAULT_AUDIT_KEY` are currently supplied via environment variables. If an adversary gains full `root`/administrator access to the running host OS, they can inspect environment memory and decrypt files.
* **Why Accepted**: In a standalone 7-day challenge deployment without a dedicated Hardware Security Module (HSM) or cloud KMS (like AWS KMS or Azure Key Vault), storing keys in environment variables is standard practice.
* **Production Recommendation**: Integrate AWS KMS or HashiCorp Vault with envelope key rotation and per-tenant cryptographic keys.

### 2. Side-Channel Camera / Screenshot Capture
* **Accepted Risk**: Once an authorized user downloads or views a decrypted document on their local screen, TrustVault cannot prevent the user from taking a smartphone photo or screenshot of the monitor.
* **Why Accepted**: DRM screen capture restrictions require proprietary OS client agents (e.g. enterprise MDM) which are outside the scope of a standard web application.

### 3. SQLite Concurrent Write Lock Contention under Extreme Load
* **Accepted Risk**: TrustVault defaults to SQLite with WAL (`Write-Ahead Logging`) mode. While WAL allows unlimited concurrent readers, writes (such as audit log appending) are serialized. Under thousands of concurrent writes per second, SQLite will encounter database lock wait times.
* **Why Accepted**: SQLite WAL mode provides zero-dependency deployment that runs out-of-the-box on any judge's machine. TrustVault supports PostgreSQL simply by setting the `DATABASE_URL` environment variable.

### 4. Ephemeral In-Memory Storage for High-Volume Single-Use Tokens
* **Accepted Risk**: The platform relies on real-time database lookups on every request rather than Redis-cached permission bits. This incurs a database read query per download.
* **Why Accepted**: This deliberate architectural choice guarantees **zero-latency revocation**. Eliminating caching ensures that an access revocation is instantaneous and absolute, with zero cache invalidation lag.
