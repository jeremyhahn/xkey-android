# 338: Hardware-backed ML-DSA keys in the Android Keystore

## Objective

Offer ML-DSA keys held in the Android Keystore (TEE or StrongBox) next to the
software keys of `docs/plans/338.md`. This branch writes only the Keystore
backend behind the `PqcHardwareBackend` contract in `crypto/PqcKeys.kt` and
registers it at startup; the wire, dialogs and choke points are the parallel
branch's.

## Slices, in order

1. Test commit. `KeystorePqcBackendTest` (JVM): no probe below API 37; only
   TEE and StrongBox sets are reported; empty and non-blocking before the
   probe ends; `generate` refuses an unsupported set; the JCA signature name;
   the SPKI check. `KeystorePqcBackendDeviceTest` (device, skipped where the
   probe finds nothing): generate, KeyInfo level, Keystore sign, Bouncy
   Castle verify from the SPKI, OID and size, delete.
2. `KeystorePqcBackend.kt`: background probe, generate, signature name.
3. `XKeyApplication.onCreate` sets `PqcHardware.backend` and starts the probe
   on an application-lifetime IO scope.
4. Docs: `docs/pqc-keys/hardware.md`.

## Platform API (read from the android-37.0 SDK, platform-37.0_r02)

Read from `android.jar` (javap) and `data/api-versions.xml`:

- `KeyProperties.KEY_ALGORITHM_ML_DSA = "ML-DSA"`, since API 37.0.
- `KeyProperties.KEY_ALGORITHM_ML_DSA_65 = "ML-DSA-65"` and
  `KEY_ALGORITHM_ML_DSA_87 = "ML-DSA-87"`, since API 37.0. There is no
  ML-DSA-44 constant.
- `java.security.spec.NamedParameterSpec.ML_DSA_65` and `ML_DSA_87`, since
  API 37.0 (the class and its `(String)` constructor since API 33).
- `KeyGenParameterSpec.Builder` gains no ML-DSA method: the set goes through
  `setAlgorithmParameterSpec`. `KeyInfo.getSecurityLevel()` exists since 31.
- No signature-algorithm constant is published.

Not in the SDK, so unconfirmed until the device test runs on an API 37
device: that `KeyPairGenerator.getInstance("ML-DSA", "AndroidKeyStore")`
takes `NamedParameterSpec("ML-DSA-<n>")` (the backend falls back to the
per-set name `"ML-DSA-65"`/`"ML-DSA-87"`); that `Signature.getInstance("ML-DSA")`
signs with the key; and whether any device makes ML-DSA-44 (the probe asks
with `NamedParameterSpec("ML-DSA-44")` and reports it only if the key comes
back in TEE or StrongBox).

## Out of scope

- Attestation of ML-DSA keys.
- ML-KEM.
- Probing in StrongBox: the probe asks the TEE; `generate` asks StrongBox
  when preferred and falls back to the TEE.
