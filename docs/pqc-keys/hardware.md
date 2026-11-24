# Hardware-backed ML-DSA keys

xKey makes ML-DSA keys in two places: in software (Bouncy Castle, sealed
by a Keystore AES key) on every device, and in the Android Keystore (TEE or
StrongBox) on devices that make them. This page covers the Keystore half,
`crypto/KeystorePqcBackend.kt`, which implements `PqcHardwareBackend` from
`crypto/PqcKeys.kt` and is registered as `PqcHardware.backend` in
`XKeyApplication.onCreate`.

## Platform API

Read from the android-37.0 SDK (`android.jar` and `data/api-versions.xml`):

| Name | Value | Since |
|------|-------|-------|
| `KeyProperties.KEY_ALGORITHM_ML_DSA` | `"ML-DSA"` | API 37 |
| `KeyProperties.KEY_ALGORITHM_ML_DSA_65` | `"ML-DSA-65"` | API 37 |
| `KeyProperties.KEY_ALGORITHM_ML_DSA_87` | `"ML-DSA-87"` | API 37 |
| `NamedParameterSpec.ML_DSA_65`, `ML_DSA_87` | | API 37 |
| `NamedParameterSpec(String)` | | API 33 |
| `KeyInfo.getSecurityLevel()` | | API 31 |

The SDK has no ML-DSA-44 constant and no signature-algorithm constant.
Below API 37 the backend reports nothing and runs no probe.

Unconfirmed until the device test runs on an API 37 device that makes
ML-DSA keys:

- generation as `KeyPairGenerator.getInstance("ML-DSA", "AndroidKeyStore")`
  with `KeyGenParameterSpec.Builder(alias, PURPOSE_SIGN)
  .setAlgorithmParameterSpec(NamedParameterSpec("ML-DSA-<n>"))`. If the
  generic name is refused, the backend asks for `"ML-DSA-65"` or
  `"ML-DSA-87"` by name;
- signing as `Signature.getInstance("ML-DSA")` (pure ML-DSA, empty
  context), which `jcaSignatureAlgorithm` returns for every set;
- ML-DSA-44 in hardware: the probe asks with `NamedParameterSpec("ML-DSA-44")`
  and reports the set only if the key comes back in the TEE or StrongBox.

## The probe

`startProbe` runs once per process, on `Dispatchers.IO` in an
application-lifetime scope that `onCreate` starts and never waits for. For
each set it:

1. generates a throwaway key under `xkey_pqc_probe_ml_dsa_44`,
   `xkey_pqc_probe_ml_dsa_65` or `xkey_pqc_probe_ml_dsa_87` (deleting a
   leftover from a killed process first), in the TEE, with no user
   authentication;
2. checks that the public key is a SubjectPublicKeyInfo with the set's OID
   and size;
3. reads the private key's `KeyInfo.securityLevel`
   (`isInsideSecureHardware` is not needed: the probe only runs on API 37+);
4. deletes the key, in a `finally`, whatever happened.

A set is supported only if its level is `SECURITY_LEVEL_TRUSTED_ENVIRONMENT`
or `SECURITY_LEVEL_STRONGBOX`. Software, unknown, null and any exception
make it unsupported; one failing set does not hide the others. The result
is published once, in an `AtomicReference`.

`supportedParameterSets()` never blocks: it returns the published set,
empty until the probe ends. So the Key Management and PIV dialogs offer no
hardware ML-DSA option, and `keyBacking: "hardware"` is refused, until the
probe has finished.

## Generating

`generate(alias, set, authDurationSeconds, preferStrongBox)` refuses a set
the probe did not report with `UnsupportedAlgorithmException`. Otherwise it
deletes any entry under the alias, generates a `PURPOSE_SIGN` key with the
EC keys' authentication rule (negative: none; zero: every use; positive:
that many seconds, biometric strong), asks StrongBox first when preferred
and falls back to the TEE on any StrongBox refusal, checks the returned
SubjectPublicKeyInfo (OID and size), and returns its DER. It blocks on the
Keystore, so callers run it off the main thread.

## Tests

- `KeystorePqcBackendTest` (JVM, injected SDK level and probe): no probe
  below API 37; only TEE and StrongBox sets are reported; a throwing set
  does not hide others; empty and non-blocking while the probe runs; the
  probe runs once; `generate` refuses unreported sets; the signature name;
  the SPKI check against Bouncy Castle keys of each set.
- `KeystorePqcBackendDeviceTest` (device; skipped below API 37 or when the
  probe finds nothing): the probe keys are gone; for each supported set,
  generate, check the SPKI OID and size, read the KeyInfo level (TEE or
  StrongBox), sign with the Keystore key, check the signature size, verify
  with Bouncy Castle `MLDSASigner` from the SPKI, and delete; a second
  generate replaces the entry; `preferStrongBox` falls back to the TEE.

## Out of scope

Attestation of ML-DSA keys, and ML-KEM.
