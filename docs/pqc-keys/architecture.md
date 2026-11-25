# Post-quantum ML-DSA keys

xKey makes ML-DSA-44, ML-DSA-65 and ML-DSA-87 (FIPS 204) signing keys. Each
key has one of two backings:

- **Software**: generated and used with Bouncy Castle, and stored only wrapped
  by its own non-exportable Android Keystore AES-256-GCM key. Every device
  has it.
- **Hardware**: an Android Keystore key, on devices whose Keystore makes the
  parameter set in the TEE or StrongBox. The Keystore backend is described in
  [hardware.md](hardware.md).

ML-KEM is out of scope: no app path decapsulates (`local.decrypt` is
RSA-OAEP, `local.ecdh` is ECDH, `.xkeyenc` is ECIES), and a wire method only
one side implements is a defect.

## Parameter sets

`crypto/PqcKeys.kt`, `MlDsaParameterSet`:

| Set | COSE | SPKI OID (no parameters) | Public key | Signature |
|-----|------|--------------------------|------------|-----------|
| ML-DSA-44 | -48 | 2.16.840.1.101.3.4.3.17 | 1312 bytes | 2420 bytes |
| ML-DSA-65 | -49 | 2.16.840.1.101.3.4.3.18 | 1952 bytes | 3309 bytes |
| ML-DSA-87 | -50 | 2.16.840.1.101.3.4.3.19 | 2592 bytes | 4627 bytes |

`fromWireName` ignores case, `-` and `_`, so `ML-DSA-65`, `MLDSA65` and
`ml_dsa_65` all name ML-DSA-65. `keySizeBits` for an ML-DSA key is the raw
public key size in bits. Signatures are pure ML-DSA with an empty context,
over the message itself.

## Software key store

`crypto/PqcSoftwareKeyStore.kt` keeps one file per Keystore-style alias:
`filesDir/pqc_keys/<sha256-hex(alias)>.key`, written to a `.tmp` file and
renamed into place. Beside it, `<sha256-hex(alias)>.gen` holds the alias's
generation (an 8-byte long), which delete keeps and advances.

The `.key` file is:

```
"XPQ3" | UTF alias | UTF set name | int len | SPKI DER | UTF wrap key id | int len | sealed
```

The wrap key id is 32 lowercase hex characters (16 random bytes), fresh for
each key. `sealed` is
`KeystoreAeadCipher("xkey_pqc_wrap_" + wrap key id).encrypt(plaintext)`
(AES-256-GCM, IV prepended): every record has its own non-exportable
AndroidKeyStore wrap key (`KeystoreWrapKeyring`). The plaintext is
`int len | alias | int len | set name | int len | SPKI DER | long generation | int auth policy | PKCS#8 private key`.
Records in the earlier `XPQ1` and `XPQ2` formats (never released; `XPQ2`
used one shared `xkey_pqc_wrap` key) do not open and are not migrated.

- Deleting or replacing a key removes its `xkey_pqc_wrap_<id>` key first. A
  record whose wrap key is gone is refused with `PqcKeyRecordException` ("ML-DSA
  key was deleted") before any key is opened, so a copy of the old record put
  back never signs. If the wrap key cannot be removed, the record is written
  back and the delete fails with `IOException`, so the key stays usable.
- A record whose sealed generation is below the alias's `.gen` value is
  refused, as is a record with no `.gen` file.
- `xkey_pqc_wrap` (`PqcSoftwareKeyStore.WRAP_KEY_ALIAS`) seals no record. It
  stays in `KeystoreAeadCipher.INTERNAL_ALIASES`, so a key left under it by an
  earlier build is never listed or deleted as a user key, and tests use it as
  the single injected cipher. `xkey_pqc_wrap_<id>` aliases are internal too.
- No private key byte is written unsealed or logged. Every plaintext copy the
  store makes (the PKCS#8 encoding, the sealed plaintext, the opened
  plaintext) is zeroed after use.
- A record is read only under the alias it names. A file copied under another
  alias is ignored.
- Before it signs, the store checks that the sealed alias, set and public key
  match the record and that the private key is an ML-DSA key of that set whose
  public key is the record's. A record that holds another record's sealed blob
  is refused with `PqcKeyRecordException`.
- The size fields are capped at 64 KiB, and trailing bytes are refused.

The auth policy is the `authDurationSeconds` the key was made with, sealed
with the private key so no caller can drop it: -1 is no user authentication,
0 is per use, and a positive value is a window in seconds. `sign` takes the
time of the caller's last user authentication
(`PqcSoftwareKeyStore.userAuthenticationTime()`, elapsed-realtime) and
refuses with `BiometricRequiredException` before it opens the private key
when that time is missing, in the future, or older than the window (a
per-use key allows 30 seconds, the time between the prompt and the
signature). `local.sign` prompts for every software key whose policy is not
-1, whatever the request's flags, and passes the prompt's time. One store
serves the process: only `PqcSoftwareKeyStore.registerShared` builds one,
and `KeystoreAeadCipher` creates the wrap key under a process-wide lock per
alias, so two first uses never make two wrap keys and orphan a record. A
full sync keeps a row whose record is live (`keyMaterialExists`), and
deleting a row deletes its record.

## Backing rules

`PqcHardware.backend` is the registered `PqcHardwareBackend`.
`PqcHardware.supported()` is the set of parameter sets it reports, and is
empty when no backend is registered.

| Request | Result |
|---------|--------|
| no `keyBacking` | hardware when `supported()` has the set, else software |
| `keyBacking: "software"` | software |
| `keyBacking: "hardware"`, set supported | hardware |
| `keyBacking: "hardware"`, set not supported | `FEATURE_UNAVAILABLE` |
| `keyBacking` not a string, or not `hardware`/`software` | `INVALID_PARAMS` |
| `keyBacking` on a non-ML-DSA algorithm | `INVALID_PARAMS` |
| `exportable: true` with ML-DSA | `INVALID_PARAMS` |
| ML-DSA for a FIDO2 credential | `INVALID_ALGORITHM` |

The backing is checked before the approval prompt and checked again when the
key is made, because the backend can change in between.

`KeystoreManager` routes every general-key path through both backings:

- `generateMlDsaKey`
- `generalKeyExists` and `pqcSoftwareKeyExists`
- `getPublicKeyDER` and `publicKeyDERAt`
- `generalKeySecurityLevel`
- `deleteGeneralKey`
- `signApprovedMlDsa`

A software key reports `securityLevel` `software`. A hardware key reports its
Keystore level. Delete removes the key from either backing and audits it.
`signApprovedMlDsa` runs under the alias gate, and it refuses a key whose
public key changed since approval, or whose set is not the requested set.

## Wire

| Method | ML-DSA behavior |
|--------|-----------------|
| `local.generateKey` | `algorithm` is a name or COSE id (-48, -49, -50); optional `keyBacking`; returns `publicKeyDer` (SPKI) and `securityLevel` |
| `local.sign` | Pure ML-DSA. An `algorithm` that names another set than the key's is `INVALID_ALGORITHM` |
| `local.getPublicKey` | `der` or `pem` SubjectPublicKeyInfo. `ssh` and `cose` are `UNSUPPORTED_FORMAT` |
| `local.deleteKey` | Deletes and audits either backing |
| `local.getCapabilities` | `algorithms` lists the three names. `hardwareAlgorithms` lists the sets the backend makes |
| `local.pivGenerateKey` | `algorithm` `ML-DSA-44/65/87`. Optional `keyBacking`, with the rules above |
| `local.pivSign`, `local.pivListSlots` | Sign with, and report the public key of, either backing of the slot key. The PIV screens also delete it |

PIV slot keys use the slot's alias (`xkey_piv_<slot>`). SP 800-78 has no
ML-DSA algorithm id, so peers name these keys only by wire name (see
[../piv/architecture.md](../piv/architecture.md)).

`PivKeyManager` instances built without a store (the GATT service and the
slot detail screen) use `PqcSoftwareKeyStore.shared`. `XKeyApplication.onCreate`
registers it at process start, next to the Keystore backend, so a slot detail
screen restored alone after process death still finds the software store.

## Dialogs

Key Management lists ML-DSA under Signing and TLS. While an ML-DSA entry is
selected, a Storage spinner shows `KeyCreationAlgorithms.storageOptions(set,
PqcHardware.supported())`: "Hardware" first (the default) when the device
makes the set, then "Software (encrypted with a Keystore key)". If only
software is available, only software is listed. The PIV generate dialog
follows an ML-DSA pick with the same choice, and skips it when software is
the only option. A hardware option never appears for a set the backend does
not report.

## Open questions

- The desktop (go-xkms `xkey/pkg/pairing`) must learn the ML-DSA names,
  `keyBacking` and `hardwareAlgorithms` before it sends or reads them. The
  phone change is additive.
- Bouncy Castle 1.87 keeps the lightweight ML-DSA classes in
  `org.bouncycastle.crypto.{generators,params,signers,util}`. The store uses
  those classes, so it needs no JCA provider and no R8 keep rule. If a later
  version moves them, the JCA fallback and its keep rules apply.
