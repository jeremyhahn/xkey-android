# Contacts architecture

> **Status: REFERENCE** · Last verified: 2026-10-09
> As-built description of the contact table and the contact import flow in xKey.

## Import a Contact via QR

A user scans another person's QR code to import their public key as a contact,
enabling file encryption and signature verification for that person.

```mermaid
sequenceDiagram
    actor User
    actor Other as Other Person
    participant OApp as Other's xKey
    participant QR as QR Code Display
    participant CMA as ContactManagementActivity
    participant Cam as QR Scanner (CameraX + ML Kit)
    participant DB as ContactDao

    Other->>OApp: Open Contact Management, tap "Export Key"
    OApp->>OApp: Select key to export
    OApp->>OApp: Get public key DER from KeystoreManager
    OApp->>QR: Display QR code
    Note over QR: {"v":1,"type":"xkey-pubkey",<br/>"name":"Other's Key",<br/>"alg":"ES256",<br/>"key":"MFkwEwYH..."}

    User->>CMA: Open Contact Management, tap FAB
    CMA-->>User: Import options bottom sheet
    User->>CMA: Select "Scan QR Code"
    CMA->>Cam: Open camera preview

    User->>Cam: Point at QR code
    Cam->>CMA: Decoded JSON string

    CMA->>CMA: Parse QR payload
    CMA->>CMA: Base64-decode public key
    CMA->>CMA: Compute SHA-256 fingerprint
    CMA-->>User: "Import 'Other's Key' (ES256)?"
    User->>CMA: Confirm import

    CMA->>DB: insert(ContactEntity)
    Note over DB: Unique index on fingerprint<br/>prevents duplicates

    CMA-->>User: "Contact imported successfully"

    Note over User: Can now encrypt files for this contact<br/>and verify their signatures
```

## Entity Details

> **Status: REFERENCE** · Last verified: 2026-08-10
> As-built description of the xKey Room schema. STALE: the migration table stops at v7; `XKeyDatabase.kt` is at version 11. Read the code for v8-v11.

### ContactEntity (`contacts`)

Recipient public keys for file encryption and signature verification. Each
contact stores a DER-encoded public key with a SHA-256 fingerprint for
deduplication (unique index on `public_key_fingerprint`).

## Index Strategy

### contacts

| Index | Columns | Unique | Purpose |
|-------|---------|--------|---------|
| `index_contacts_public_key_fingerprint` | `public_key_fingerprint` | Yes | Deduplication and fingerprint lookup |
| `index_contacts_name` | `name` | No | Search by contact name |
| `index_contacts_algorithm` | `algorithm` | No | Filter by key algorithm |
