# TrustVault AI Collaboration Log (PROMPTS.md)

This log records five critical technical intersections during the design and construction of TrustVault where AI assistance was utilized, critically reviewed, and corrected when incorrect or vulnerable solutions were produced.

---

### Entry 1 — October 19, 2026: Pre-Signed URLs vs. Instant Revocation
* **Prompt**:
  > *"How should I implement secure document downloads for authorized users in TrustVault? Provide an implementation pattern for generating temporary download links."*
* **What the AI Produced**:
  The AI suggested generating short-lived pre-signed download URLs (or temporary signed tokens with a 15-minute expiration time) so the frontend could stream files directly without loading the backend server:
  ```python
  # AI's flawed suggestion
  def generate_download_url(document_id: str, user: User):
      token = jwt.encode({"doc_id": document_id, "sub": user.id, "exp": now + timedelta(minutes=15)}, SECRET_KEY)
      return f"/api/documents/direct-download?token={token}"
  ```
* **What Was Wrong With It (Specifically)**:
  This fatally violates **Non-Negotiable Requirement #3**: *"Taking access away works immediately. Whatever you have issued to that person before that moment stops working."*
  If Document Owner Alice grants access to Bob at 10:00, and revokes it at 10:02, Bob's issued download token or pre-signed URL would remain fully valid and operational until 10:15! Bob could copy the link or script a downloader and exfiltrate the confidential file 13 minutes after his access was revoked.
* **What We Did Instead**:
  Rejected all pre-signed and disconnected token schemes. In TrustVault, every file download is mediated synchronously through the backend:
  ```python
  # app/routers/documents.py & app/security.py
  doc, perm_level = verify_document_access(
      document_id=document_id,
      user=current_user,
      required_level="READ",
      db=db,
      request=request
  )
  ```
  The authorization query executes in real time against the active database transaction *at the exact moment of byte streaming*. When an owner revokes access (`DELETE /api/documents/{id}/permissions/{user_id}`), the row is deleted and transaction committed immediately; any subsequent download attempt—even 1 millisecond later—finds no grant and is rejected with `403 Forbidden`.
* **Fix Reference**: See [`app/routers/documents.py`](file:///c:/Users/bandi/Downloads/TrustVault/app/routers/documents.py#L210-L245) and automated test [`tests/test_permissions.py::test_instant_revocation`](file:///c:/Users/bandi/Downloads/TrustVault/tests/test_permissions.py#L65-L100).

---

### Entry 2 — October 20, 2026: Incomplete Canonical Fields in Audit Ledger Chaining
* **Prompt**:
  > *"Write a cryptographic HMAC-SHA256 audit chaining function that connects each audit record to the preceding block."*
* **What the AI Produced**:
  The AI produced a hash calculation function that included only numeric IDs and action strings:
  ```python
  # AI's flawed implementation
  def canonical_log_string(log_id, timestamp, user_id, action, target_type, target_id, status, details, prev_hash):
      return f"{log_id}|{timestamp}|{user_id}|{action}|{target_type}|{target_id}|{status}|{details}|{prev_hash}"
  ```
* **What Was Wrong With It (Specifically)**:
  Notice what the AI omitted: **`user_email`**, **`reason`**, and **`ip_address`** were missing from the canonical hash computation!
  When we ran our automated test suite simulating an attacker modifying database records (`target_log.user_email = "innocent_victim@company.com"`), `verify_audit_chain()` returned `True`! Because `user_email` was not part of the hashed canonical payload, a rogue DBA could change the actor email in the database to frame someone else without breaking the hash chain!
* **What We Did Instead**:
  Expanded `canonical_log_string` and `compute_audit_hash` to deterministically lock every identifying attribute of the actor, network origin, refused reason, and target:
  ```python
  # app/crypto.py
  def canonical_log_string(log_id, timestamp, user_id, user_email, action, target_type, target_id, status, reason, ip_address, details, prev_hash):
      return (
          f"{log_id}|{timestamp}|{user_id or 'ANON'}|{user_email or 'NONE'}|{action}|"
          f"{target_type}|{target_id or 'NONE'}|{status}|{reason or 'NONE'}|"
          f"{ip_address or 'NONE'}|{details}|{prev_hash}"
      )
  ```
  Now, modifying even a single character of `user_email`, `timestamp`, or `reason` causes an HMAC mismatch and flags the exact corrupted row ID.
* **Fix Reference**: See [`app/crypto.py`](file:///c:/Users/bandi/Downloads/TrustVault/app/crypto.py#L37-L75) and automated test [`tests/test_tamper_audit.py::test_tampered_audit_record_fails_verification`](file:///c:/Users/bandi/Downloads/TrustVault/tests/test_tamper_audit.py#L65-L100).

---

### Entry 3 — October 21, 2026: Admin God-Mode Backdoor Violation of Separation of Duty
* **Prompt**:
  > *"Implement the role authorization logic for Document Owner, Administrator, and Viewer."*
* **What the AI Produced**:
  The AI implemented a standard shortcut granting administrators universal access:
  ```python
  # AI's flawed suggestion
  def check_permission(user, document):
      if user.role == "admin":
          return True  # Admins can do anything
      if document.owner_id == user.id:
          return True
      ...
  ```
* **What Was Wrong With It (Specifically)**:
  This destroys zero-trust confidentiality. In real-world enterprises (e.g. banking, healthcare, defence), an IT Administrator or SOC Analyst should **never** have carte-blanche read access to confidential executive salaries, legal contracts, or trade secrets unless explicitly granted access by the document owner. Allowing admins to snoop confidential documents creates a massive insider-threat vector.
* **What We Did Instead**:
  Enforced strict **Separation of Duty**:
  - Administrators have visibility over platform health, user lifecycle, and the audit verification engine.
  - Document *content* access strictly requires ownership or an explicit `DocumentPermission` grant. If an Administrator attempts to call `GET /api/documents/{id}/download` without an explicit grant, the server rejects them with `403 Forbidden` and records an audit log alert.
* **Fix Reference**: See [`app/security.py`](file:///c:/Users/bandi/Downloads/TrustVault/app/security.py#L220-L260) and automated test [`tests/test_threats.py::test_admin_cannot_snoop_confidential_document`](file:///c:/Users/bandi/Downloads/TrustVault/tests/test_threats.py#L10-L35).

---

### Entry 4 — October 22, 2026: Client-Controlled MIME Validation
* **Prompt**:
  > *"Write an upload validation utility to ensure only PDFs and Word documents can be uploaded."*
* **What the AI Produced**:
  The AI suggested checking the file extension and the client-sent `file.content_type`:
  ```python
  # AI's flawed suggestion
  def validate_file(file: UploadFile):
      if file.content_type not in ["application/pdf", "application/msword"]:
          raise HTTPException(400, "Invalid MIME type")
      if not file.filename.endswith((".pdf", ".doc")):
          raise HTTPException(400, "Invalid file extension")
  ```
* **What Was Wrong With It (Specifically)**:
  The `file.content_type` header is supplied by the HTTP client and can be trivial forged (e.g. `curl -F "file=@payload.exe;type=application/pdf"`). An attacker could easily upload a Windows PE `.exe` or Linux ELF binary disguised as a `.pdf`, bypassing this check completely.
* **What We Did Instead**:
  Implemented binary magic bytes inspection in `app/file_validator.py`. The server reads the raw binary header bytes:
  - Validates `%PDF-` signature for PDFs.
  - Validates `PK\x03\x04` for Office Open XML.
  - Validates `\x89PNG\r\n\x1a\n` for PNGs.
  - Explicitly rejects executable binary headers (`MZ`, `\x7fELF`, `\xca\xfe\xba\xbe`, `#!`) even if named `.txt` or `.pdf`.
* **Fix Reference**: See [`app/file_validator.py`](file:///c:/Users/bandi/Downloads/TrustVault/app/file_validator.py#L8-L85) and automated test [`tests/test_file_upload.py::test_magic_bytes_enforcement_rejects_disguised_executable`](file:///c:/Users/bandi/Downloads/TrustVault/tests/test_file_upload.py#L6-L28).

---

### Entry 5 — October 23, 2026: Stateless JWT Invalidation Failure
* **Prompt**:
  > *"How should we handle user sessions and authentication?"*
* **What the AI Produced**:
  The AI suggested using pure stateless JWT tokens with 24-hour expiration and storing nothing in the database for session tracking:
  ```python
  # AI's flawed suggestion
  def get_current_user(token: str):
      payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
      return payload
  ```
* **What Was Wrong With It (Specifically)**:
  Pure stateless JWTs cannot be revoked before expiration. If an employee leaves the company, or an administrator deactivates a compromised account, the user's token continues to work for hours.
* **What We Did Instead**:
  Implemented **JWT Token Versioning**:
  - The `User` database model includes a `token_version` integer.
  - The JWT payload embeds `token_version`.
  - Every authenticated request verifies:
    ```python
    if user.token_version != token_payload.get("token_version"):
        raise HTTPException(401, "Session has been revoked or invalidated.")
    ```
  - When a user logs out, changes password, or is deactivated by an administrator, `token_version` is incremented in the database. All existing tokens across all devices are rendered invalid immediately.
* **Fix Reference**: See [`app/security.py`](file:///c:/Users/bandi/Downloads/TrustVault/app/security.py#L95-L135) and automated test [`tests/test_auth.py::test_token_versioning_instant_revocation_on_logout`](file:///c:/Users/bandi/Downloads/TrustVault/tests/test_auth.py#L42-L68).

---

## Reusable System Prompts & Context Guidelines Used

Throughout development, the following system prompt constraint was enforced in all AI interactions:

```text
SYSTEM ROLE CONTEXT:
You are an expert security engineer reviewing a zero-trust document sharing platform called TrustVault.
NON-NEGOTIABLE PRINCIPLES:
1. Zero client trust: No authorization logic may execute on the client. The server decides every time.
2. Synchronous access decisions: No pre-signed URLs or cached permissions. Taking access away must take effect synchronously with zero lag.
3. Cryptographic tamper-evidence: All audit events must be chained cryptographically via HMAC-SHA256. Any modification to actor, action, status, timestamp, or resource must break verification.
4. Defense in depth: Inspect binary magic bytes, sanitize paths, enforce envelope encryption at rest (AES-256-GCM), and prevent horizontal/vertical privilege escalation.
Always highlight potential security side-effects, bypasses, or race conditions in any code proposed.
```
