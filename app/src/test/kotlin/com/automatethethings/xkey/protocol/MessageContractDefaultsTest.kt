/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */
package com.automatethethings.xkey.protocol

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Constructor defaults and field retention for the `Messages.kt` wire types.
 *
 * The other suites in this package drive the types through `fromJson`/`toJson`.
 * This one covers what those cannot: the value a field takes when the caller
 * omits it, and that a value handed to a constructor is the one the object
 * reports back. Both matter on the wire.
 *
 * Defaults are part of the contract with go-xkms (`xkey/pkg/pairing`), not an
 * implementation detail. `LocalGetPublicKeyParams.format` defaulting to `der`,
 * `LocalSymmetricResult.payloadField` defaulting to `ciphertext`, and
 * `GetInfoResult.supportedAlgorithms` defaulting to the advertised COSE set are
 * each things the desktop reads directly; changing one silently changes what
 * the peer receives.
 *
 * Every case builds an instance the way a handler in `Handler.kt` builds it,
 * once with the optional arguments omitted and once with them supplied, so a
 * default that drifts and a field that is dropped both surface here.
 *
 * Pure JVM: no Android framework types are touched.
 */
class MessageContractDefaultsTest {

    // -------------------------------------------------------------------------
    // Envelope
    // -------------------------------------------------------------------------

    /**
     * `Response` has three constructor arities in the bytecode because both
     * payload slots are optional; a response is built with exactly one of them.
     */
    @Test
    fun `Response defaults both payload slots to absent`() {
        val success = Response(id = 1, result = org.json.JSONObject().put("pong", true))
        assertEquals(1L, success.id)
        assertNull("a success response carries no error", success.error)
        assertTrue(success.isSuccess())

        val failure = Response(id = 2, error = ErrorObject(ErrorCodes.INVALID_PARAMS, "bad"))
        assertEquals(2L, failure.id)
        assertNull("an error response carries no result", failure.result)
        assertTrue(failure.isError())
    }

    // -------------------------------------------------------------------------
    // Base protocol (un-namespaced methods)
    // -------------------------------------------------------------------------

    @Test
    fun `GenerateKeyResult defaults to no attestation and no StrongBox`() {
        val minimal = GenerateKeyResult(publicKey = "cG9uZw==")
        assertEquals("cG9uZw==", minimal.publicKey)
        assertNull("attestation is optional and defaults to absent", minimal.attestation)
        assertFalse("strongBoxBacked defaults to false", minimal.strongBoxBacked)

        val full = GenerateKeyResult(
            publicKey = "cG9uZw==",
            attestation = "YXR0",
            strongBoxBacked = true
        )
        assertEquals("YXR0", full.attestation)
        assertTrue(full.strongBoxBacked)
    }

    @Test
    fun `GetInfoResult defaults to the advertised COSE set and credential ceiling`() {
        val info = GetInfoResult(
            version = "1.0.0",
            deviceName = "Pixel 8",
            hasStrongBox = true,
            hasBiometrics = false,
            credentialCount = 3
        )

        assertEquals("1.0.0", info.version)
        assertEquals("Pixel 8", info.deviceName)
        assertTrue(info.hasStrongBox)
        assertFalse(info.hasBiometrics)
        assertEquals(3, info.credentialCount)
        assertEquals(
            "supportedAlgorithms defaults to the advertised COSE set",
            CoseAlgorithms.SUPPORTED,
            info.supportedAlgorithms
        )
        assertEquals(
            "maxCredentials defaults to the documented ceiling",
            GetInfoResult.DEFAULT_MAX_CREDENTIALS,
            info.maxCredentials
        )
    }

    @Test
    fun `GetInfoResult honours an explicit algorithm set and ceiling`() {
        val info = GetInfoResult(
            version = "1.0.0",
            deviceName = "emulator",
            hasStrongBox = false,
            hasBiometrics = true,
            credentialCount = 0,
            supportedAlgorithms = listOf(CoseAlgorithms.ES256),
            maxCredentials = 8
        )

        assertEquals(listOf(CoseAlgorithms.ES256), info.supportedAlgorithms)
        assertEquals(8, info.maxCredentials)
    }

    @Test
    fun `LoadKeyResult reports an absent key with no public key or algorithm`() {
        val absent = LoadKeyResult(exists = false)
        assertFalse(absent.exists)
        assertNull(absent.publicKey)
        assertNull(absent.algorithm)

        val present = LoadKeyResult(
            exists = true,
            publicKey = "cHVi",
            algorithm = CoseAlgorithms.ES256
        )
        assertTrue(present.exists)
        assertEquals("cHVi", present.publicKey)
        assertEquals(CoseAlgorithms.ES256, present.algorithm)
    }

    // -------------------------------------------------------------------------
    // local.* key management
    // -------------------------------------------------------------------------

    @Test
    fun `LocalGenerateKeyResult defaults softwareBacked to false`() {
        val hardware = LocalGenerateKeyResult(
            keyId = "signing-1",
            publicKey = "ZGVy",
            publicKeyCose = null,
            algorithm = "ES256",
            keySizeBits = 256,
            strongBoxBacked = true
        )

        assertEquals("signing-1", hardware.keyId)
        assertEquals("ZGVy", hardware.publicKey)
        assertNull("a non-FIDO2 key carries no COSE encoding", hardware.publicKeyCose)
        assertEquals("ES256", hardware.algorithm)
        assertEquals(256, hardware.keySizeBits)
        assertTrue(hardware.strongBoxBacked)
        assertFalse("softwareBacked defaults to false", hardware.softwareBacked)

        val software = LocalGenerateKeyResult(
            keyId = "secret-1",
            publicKey = "",
            publicKeyCose = "Y29zZQ==",
            algorithm = "AES256",
            keySizeBits = 256,
            strongBoxBacked = false,
            softwareBacked = true
        )
        assertEquals("Y29zZQ==", software.publicKeyCose)
        assertTrue(software.softwareBacked)
    }

    @Test
    fun `LocalGetPublicKeyParams defaults the export format to der`() {
        val defaulted = LocalGetPublicKeyParams(keyId = "signing-1")
        assertEquals("signing-1", defaulted.keyId)
        assertEquals(ExportFormats.DER, defaulted.format)

        val explicit = LocalGetPublicKeyParams(keyId = "signing-1", format = ExportFormats.SSH)
        assertEquals(ExportFormats.SSH, explicit.format)
    }

    @Test
    fun `LocalSetKeyPolicyParams leaves shareable unset when the peer omits it`() {
        val unset = LocalSetKeyPolicyParams(keyId = "signing-1")
        assertEquals("signing-1", unset.keyId)
        assertNull(
            "an omitted shareable means 'do not change', not 'set to false'",
            unset.shareable
        )

        assertEquals(false, LocalSetKeyPolicyParams("signing-1", shareable = false).shareable)
        assertEquals(true, LocalSetKeyPolicyParams("signing-1", shareable = true).shareable)
    }

    @Test
    fun `KeyInfo defaults every FIDO2 field for a non-passkey`() {
        val plain = KeyInfo(
            keyId = "signing-1",
            keyType = KeyTypes.SIGNING,
            algorithm = "ES256",
            label = "Signing key",
            keySizeBits = 256,
            strongBoxBacked = true,
            shareable = false,
            source = "remote_ble",
            useCount = 4,
            createdAt = 1_700_000_000L,
            lastUsedAt = 1_700_000_500L
        )

        assertEquals("signing-1", plain.keyId)
        assertEquals(KeyTypes.SIGNING, plain.keyType)
        assertEquals("ES256", plain.algorithm)
        assertEquals("Signing key", plain.label)
        assertEquals(256, plain.keySizeBits)
        assertTrue(plain.strongBoxBacked)
        assertFalse(plain.shareable)
        assertEquals("remote_ble", plain.source)
        assertEquals(4L, plain.useCount)
        assertEquals(1_700_000_000L, plain.createdAt)
        assertEquals(1_700_000_500L, plain.lastUsedAt)
        assertNull(plain.rpId)
        assertNull(plain.rpName)
        assertNull(plain.userName)
        assertNull(plain.userDisplayName)
        assertFalse("a non-passkey is not discoverable", plain.isDiscoverable)
        assertEquals("a non-passkey has no signature counter", 0L, plain.signCount)
    }

    // -------------------------------------------------------------------------
    // local.* crypto operations
    // -------------------------------------------------------------------------

    /**
     * go-xkms reads `ciphertext` from an encrypt result and `plaintext` from a
     * decrypt result. The default is the encrypt spelling, so a decrypt handler
     * has to opt in to the other one.
     */
    @Test
    fun `LocalSymmetricResult defaults its payload field to the encrypt spelling`() {
        val encrypt = LocalSymmetricResult(data = "Y2lwaGVy")
        assertEquals("Y2lwaGVy", encrypt.data)
        assertEquals(LocalSymmetricResult.FIELD_CIPHERTEXT, encrypt.payloadField)

        val decrypt = LocalSymmetricResult(
            data = "cGxhaW4=",
            payloadField = LocalSymmetricResult.FIELD_PLAINTEXT
        )
        assertEquals(LocalSymmetricResult.FIELD_PLAINTEXT, decrypt.payloadField)
        assertEquals(
            "the two spellings must not be the same string",
            2,
            setOf(
                LocalSymmetricResult.FIELD_CIPHERTEXT,
                LocalSymmetricResult.FIELD_PLAINTEXT
            ).size
        )
    }

    // -------------------------------------------------------------------------
    // Attestation
    // -------------------------------------------------------------------------

    @Test
    fun `LocalAttestKeyParams and its result carry the challenge nonce end to end`() {
        val nonce = java.util.Base64.getEncoder().encodeToString(byteArrayOf(1, 2, 3, 4))

        val params = LocalAttestKeyParams(keyId = "signing-1", nonce = nonce)
        assertEquals("signing-1", params.keyId)
        assertEquals(nonce, params.nonce)
        assertArrayEquals(byteArrayOf(1, 2, 3, 4), params.getNonceBytes())

        val result = LocalAttestKeyResult(
            certificateChain = listOf("bGVhZg==", "cm9vdA=="),
            securityLevel = "tee",
            nonce = nonce
        )
        assertEquals(listOf("bGVhZg==", "cm9vdA=="), result.certificateChain)
        assertEquals("tee", result.securityLevel)
        assertEquals("the nonce must be echoed unchanged", nonce, result.nonce)
    }

    @Test
    fun `LocalAttestDeviceParams decodes its nonce and the result carries the version 2 proof`() {
        val nonceBytes = ByteArray(32) { (9 - it % 3).toByte() }
        val nonce = java.util.Base64.getEncoder().encodeToString(nonceBytes)
        val params = LocalAttestDeviceParams(
            protocolVersion = 2,
            nonce = nonce,
            purpose = "reattest"
        )
        assertEquals(nonce, params.nonce)
        assertEquals("reattest", params.purpose)
        assertArrayEquals(nonceBytes, params.getNonceBytes())

        val result = LocalAttestDeviceResult(
            protocolVersion = 2,
            format = "android-keystore",
            certificateChain = listOf("bGVhZg=="),
            securityLevel = "strongbox",
            nonce = nonce,
            purpose = "reattest",
            signature = "c2ln",
            signatureAlgorithm = "ES256",
            bootState = 0,
            deviceLocked = true,
            verifiedBootKey = "a2V5",
            verifiedBootHash = "aGFzaA=="
        )
        assertEquals(2, result.protocolVersion)
        assertEquals("android-keystore", result.format)
        assertEquals(listOf("bGVhZg=="), result.certificateChain)
        assertEquals("strongbox", result.securityLevel)
        assertEquals(nonce, result.nonce)
        assertEquals("reattest", result.purpose)
        assertEquals("c2ln", result.signature)
        assertEquals("ES256", result.signatureAlgorithm)
        assertEquals(0, result.bootState)
        assertTrue(result.deviceLocked)
        assertEquals("a2V5", result.verifiedBootKey)
        assertEquals("aGFzaA==", result.verifiedBootHash)
    }

    @Test
    fun `RemoteAttestDeviceParams decodes its nonce for the bridge`() {
        val nonce = java.util.Base64.getEncoder().encodeToString(byteArrayOf(0x0F, 0x10))
        val params = RemoteAttestDeviceParams(nonce = nonce)

        assertEquals(nonce, params.nonce)
        assertArrayEquals(byteArrayOf(0x0F, 0x10), params.getNonceBytes())
    }

    // -------------------------------------------------------------------------
    // Capabilities
    // -------------------------------------------------------------------------

    @Test
    fun `LocalGetCapabilitiesResult defaults its go-xkms identity fields`() {
        val capabilities = LocalGetCapabilitiesResult(
            algorithms = listOf("ES256"),
            keyTypes = listOf(KeyTypes.SIGNING),
            hasStrongBox = true,
            hasBiometrics = false,
            supportsAttestation = true,
            supportsECDH = true,
            supportsSymmetric = true,
            supportsHMAC = false,
            maxKeys = 256
        )

        assertEquals(listOf("ES256"), capabilities.algorithms)
        assertEquals(listOf(KeyTypes.SIGNING), capabilities.keyTypes)
        assertTrue(capabilities.hasStrongBox)
        assertFalse(capabilities.hasBiometrics)
        assertTrue(capabilities.supportsAttestation)
        assertTrue(capabilities.supportsECDH)
        assertTrue(capabilities.supportsSymmetric)
        assertFalse(capabilities.supportsHMAC)
        assertEquals(256, capabilities.maxKeys)
        assertEquals("", capabilities.version)
        assertEquals("", capabilities.deviceName)
        assertEquals(0, capabilities.currentKeyCount)
        assertEquals(
            "every export format this device can produce is advertised by default",
            listOf(ExportFormats.DER, ExportFormats.PEM, ExportFormats.SSH, ExportFormats.COSE),
            capabilities.supportedFormats
        )
    }

    // -------------------------------------------------------------------------
    // FIDO2
    // -------------------------------------------------------------------------

    @Test
    fun `Fido2CredentialInfo keeps the optional user fields nullable`() {
        val sparse = Fido2CredentialInfo(
            credentialId = "cred-2",
            rpId = "example.com",
            rpName = null,
            userId = null,
            userName = null,
            userDisplayName = null,
            isDiscoverable = false,
            createdAt = 0L
        )

        assertNull(sparse.rpName)
        assertNull(sparse.userId)
        assertNull(sparse.userName)
        assertNull(sparse.userDisplayName)
        assertFalse(sparse.isDiscoverable)
    }

    /**
     * WebAuthn defaults user verification to required; a peer that omits the
     * flag must get the safe answer, not the permissive one.
     */
    @Test
    fun `LocalSignFido2AssertionParams defaults user verification to required`() {
        val defaulted = LocalSignFido2AssertionParams(
            credentialId = "cred-1",
            clientDataHash = "aGFzaA==",
            rpId = "example.com"
        )

        assertEquals("cred-1", defaulted.credentialId)
        assertEquals("aGFzaA==", defaulted.clientDataHash)
        assertEquals("example.com", defaulted.rpId)
        assertTrue(defaulted.userVerificationRequired)

        val relaxed = LocalSignFido2AssertionParams(
            credentialId = "cred-1",
            clientDataHash = "aGFzaA==",
            rpId = "example.com",
            userVerificationRequired = false
        )
        assertFalse(relaxed.userVerificationRequired)
    }

    // -------------------------------------------------------------------------
    // Pairing and notifications
    // -------------------------------------------------------------------------

    @Test
    fun `LocalBiometricPendingParams defaults the timeout to thirty seconds`() {
        val defaulted = LocalBiometricPendingParams(operation = "sign", rpName = null)
        assertEquals("sign", defaulted.operation)
        assertNull(defaulted.rpName)
        assertEquals(30, defaulted.timeoutSecs)

        val explicit = LocalBiometricPendingParams("decrypt", "Example", timeoutSecs = 5)
        assertEquals("decrypt", explicit.operation)
        assertEquals("Example", explicit.rpName)
        assertEquals(5, explicit.timeoutSecs)
    }

    // -------------------------------------------------------------------------
    // remote.* bridge parameters
    // -------------------------------------------------------------------------

    @Test
    fun `remote crypto parameters default their optional algorithm and aad`() {
        val encrypt = RemoteEncryptParams(backend = "tpm2", keyId = "k", plaintext = "cA==")
        assertEquals("tpm2", encrypt.backend)
        assertEquals("k", encrypt.keyId)
        assertEquals("cA==", encrypt.plaintext)
        assertNull(encrypt.algorithm)
        assertNull(encrypt.aad)

        val decrypt = RemoteDecryptParams(
            backend = "pkcs11",
            keyId = "k",
            ciphertext = "Yw==",
            algorithm = "AES-256-GCM",
            aad = "YWFk"
        )
        assertEquals("pkcs11", decrypt.backend)
        assertEquals("k", decrypt.keyId)
        assertEquals("Yw==", decrypt.ciphertext)
        assertEquals("AES-256-GCM", decrypt.algorithm)
        assertEquals("YWFk", decrypt.aad)
    }

    @Test
    fun `remote signing and verification parameters default the algorithm override`() {
        val sign = RemoteSignParams(backend = "tpm2", keyId = "k", data = "ZA==")
        assertEquals("tpm2", sign.backend)
        assertEquals("k", sign.keyId)
        assertEquals("ZA==", sign.data)
        assertNull("an omitted algorithm means 'use the key's own'", sign.algorithm)
        assertEquals("ES384", RemoteSignParams("tpm2", "k", "ZA==", "ES384").algorithm)

        val verify = RemoteVerifyParams(backend = "tpm2", keyId = "k", data = "ZA==", signature = "cw==")
        assertEquals("tpm2", verify.backend)
        assertEquals("k", verify.keyId)
        assertEquals("ZA==", verify.data)
        assertEquals("cw==", verify.signature)
        assertNull(verify.algorithm)
        assertEquals(
            "ES256",
            RemoteVerifyParams("tpm2", "k", "ZA==", "cw==", "ES256").algorithm
        )
    }

    /** A zero key size means "the backend's default", not a zero-bit key. */
    @Test
    fun `RemoteGenerateKeyParams defaults the key size to unspecified and the label to absent`() {
        val defaulted = RemoteGenerateKeyParams(backend = "tpm2", keyId = "k", algorithm = "ES256")
        assertEquals("tpm2", defaulted.backend)
        assertEquals("k", defaulted.keyId)
        assertEquals("ES256", defaulted.algorithm)
        assertEquals(0, defaulted.keySizeBits)
        assertNull(defaulted.label)

        val explicit = RemoteGenerateKeyParams("tpm2", "k", "RS256", keySizeBits = 3072, label = "TLS")
        assertEquals(3072, explicit.keySizeBits)
        assertEquals("TLS", explicit.label)
    }

    @Test
    fun `RemoteGetPublicKeyParams defaults the export format to der`() {
        val defaulted = RemoteGetPublicKeyParams(backend = "tpm2", keyId = "k")
        assertEquals("tpm2", defaulted.backend)
        assertEquals("k", defaulted.keyId)
        assertEquals("der", defaulted.format)

        val explicit = RemoteGetPublicKeyParams("tpm2", "k", format = "pem")
        assertEquals("pem", explicit.format)

        val result = RemoteGetPublicKeyResult(publicKey = "ZGVy", format = "der", algorithm = "ES256")
        assertEquals("ZGVy", result.publicKey)
        assertEquals("der", result.format)
        assertEquals("ES256", result.algorithm)
    }

    @Test
    fun `RemoteListKeysParams defaults to an unfiltered listing`() {
        val unfiltered = RemoteListKeysParams(backend = "tpm2")
        assertEquals("tpm2", unfiltered.backend)
        assertNull("an omitted algorithm lists every key", unfiltered.algorithm)

        assertEquals("ES256", RemoteListKeysParams("tpm2", "ES256").algorithm)
    }

    // -------------------------------------------------------------------------
    // IDevID / TCG value types
    // -------------------------------------------------------------------------

    @Test
    fun `IDevIDCertificateInfo defaults isCa to false and the usage lists to absent`() {
        val info = IDevIDCertificateInfo(
            serialNumber = "01",
            issuer = "CN=Issuing CA",
            subject = "CN=device",
            notBefore = 1_700_000_000L,
            notAfter = 1_800_000_000L,
            algorithm = "SHA256withECDSA",
            publicKeyAlgorithm = "EC",
            keySizeBits = 256,
            fingerprint = "aa:bb"
        )

        assertEquals("01", info.serialNumber)
        assertEquals("CN=Issuing CA", info.issuer)
        assertEquals("CN=device", info.subject)
        assertEquals(1_700_000_000L, info.notBefore)
        assertEquals(1_800_000_000L, info.notAfter)
        assertEquals("SHA256withECDSA", info.algorithm)
        assertEquals("EC", info.publicKeyAlgorithm)
        assertEquals(256, info.keySizeBits)
        assertEquals("aa:bb", info.fingerprint)
        assertFalse("a leaf IDevID is not a CA by default", info.isCa)
        assertNull(info.keyUsage)
        assertNull(info.extKeyUsage)
        assertNull(info.hardwareSerial)
    }

    @Test
    fun `IDevIDSubject defaults every attribute to absent`() {
        val empty = IDevIDSubject()

        assertNull(empty.commonName)
        assertNull(empty.organization)
        assertNull(empty.organizationalUnit)
        assertNull(empty.serialNumber)
        assertNull(empty.country)
        assertNull(empty.locality)
        assertNull(empty.province)

        val full = IDevIDSubject(
            commonName = "device-1",
            organization = "Automate The Things",
            organizationalUnit = "Devices",
            serialNumber = "SN-1",
            country = "US",
            locality = "Austin",
            province = "TX"
        )
        assertEquals("device-1", full.commonName)
        assertEquals("Automate The Things", full.organization)
        assertEquals("Devices", full.organizationalUnit)
        assertEquals("SN-1", full.serialNumber)
        assertEquals("US", full.country)
        assertEquals("Austin", full.locality)
        assertEquals("TX", full.province)
    }

    @Test
    fun `LocalGenerateIDevIDCSRParams defaults every field to absent`() {
        val empty = LocalGenerateIDevIDCSRParams()

        assertNull(empty.backend)
        assertNull(empty.keyId)
        assertNull(empty.algorithm)
        assertNull(empty.subject)
        assertNull(empty.csrFormat)

        val full = LocalGenerateIDevIDCSRParams(
            backend = "tpm2",
            keyId = "idevid",
            algorithm = "ES256",
            subject = IDevIDSubject(commonName = "device-1"),
            csrFormat = "der"
        )
        assertEquals("tpm2", full.backend)
        assertEquals("idevid", full.keyId)
        assertEquals("ES256", full.algorithm)
        assertEquals("device-1", full.subject?.commonName)
        assertEquals("der", full.csrFormat)
    }

    @Test
    fun `LocalGenerateIDevIDCSRResult retains the CSR metadata`() {
        val result = LocalGenerateIDevIDCSRResult(
            csr = byteArrayOf(0x30, 0x30),
            csrFormat = "der",
            keyId = "idevid",
            backend = "tpm2",
            algorithm = "ES256"
        )

        assertArrayEquals(byteArrayOf(0x30, 0x30), result.csr)
        assertEquals("der", result.csrFormat)
        assertEquals("idevid", result.keyId)
        assertEquals("tpm2", result.backend)
        assertEquals("ES256", result.algorithm)
        assertNull("the public key is optional", result.publicKey)
    }

    @Test
    fun `LocalStoreIDevIDCertificateParams and its result retain the stored identity`() {
        val params = LocalStoreIDevIDCertificateParams(
            certificate = byteArrayOf(0x30, 0x40),
            keyId = "idevid"
        )
        assertArrayEquals(byteArrayOf(0x30, 0x40), params.certificate)
        assertEquals("idevid", params.keyId)
        assertNull("the chain is optional", params.chain)
        assertNull("the backend is optional", params.backend)

        val stored = LocalStoreIDevIDCertificateResult(stored = true)
        assertTrue(stored.stored)
        assertNull(stored.certificateInfo)
    }

    @Test
    fun `LocalStoreEnrollmentCertsResult defaults both fingerprints to absent`() {
        val minimal = LocalStoreEnrollmentCertsResult(stored = false)
        assertFalse(minimal.stored)
        assertNull(minimal.iakCertFingerprint)
        assertNull(minimal.idevidCertFingerprint)

        val full = LocalStoreEnrollmentCertsResult(
            stored = true,
            iakCertFingerprint = "aa",
            idevidCertFingerprint = "bb"
        )
        assertTrue(full.stored)
        assertEquals("aa", full.iakCertFingerprint)
        assertEquals("bb", full.idevidCertFingerprint)
    }

    @Test
    fun `LocalRequestIDevIDIssuanceParams and its result default their optionals`() {
        val params = LocalRequestIDevIDIssuanceParams(csr = byteArrayOf(0x30))
        assertArrayEquals(byteArrayOf(0x30), params.csr)
        assertNull(params.csrFormat)
        assertNull(params.attestationData)
        assertNull(params.validityDays)

        val failure = LocalRequestIDevIDIssuanceResult(issued = false)
        assertFalse(failure.issued)
        assertNull(failure.certificate)
        assertNull(failure.certificateChain)
        assertNull(failure.certificateInfo)
        assertNull(failure.errorCode)
        assertNull(failure.errorMessage)

        val success = LocalRequestIDevIDIssuanceResult(
            issued = true,
            certificate = byteArrayOf(0x31),
            certificateChain = listOf(byteArrayOf(0x32)),
            errorCode = null,
            errorMessage = null
        )
        assertTrue(success.issued)
        assertArrayEquals(byteArrayOf(0x31), success.certificate)
        assertEquals(1, success.certificateChain?.size)
    }

    @Test
    fun `LocalGetTCGCSRIDevIDResult keeps the IAK and IDevID keys in separate fields`() {
        val result = LocalGetTCGCSRIDevIDResult(
            csr = byteArrayOf(0x30),
            iakPublicKey = byteArrayOf(0x04, 0x10),
            idevidPublicKey = byteArrayOf(0x04, 0x11)
        )

        assertArrayEquals(byteArrayOf(0x30), result.csr)
        assertArrayEquals(byteArrayOf(0x04, 0x10), result.iakPublicKey)
        assertArrayEquals(byteArrayOf(0x04, 0x11), result.idevidPublicKey)
        assertNull(result.ekCert)
        assertNull(result.platformSerial)
        assertNull(result.platformModel)
        assertNull(result.firmwareVersion)
    }

    @Test
    fun `LocalGetIAKPublicKeyResult defaults the DER encoding and the TPM name to absent`() {
        val minimal = LocalGetIAKPublicKeyResult(
            publicKey = byteArrayOf(0x04, 0x20),
            algorithm = "ES256"
        )

        assertArrayEquals(byteArrayOf(0x04, 0x20), minimal.publicKey)
        assertEquals("ES256", minimal.algorithm)
        assertNull(minimal.publicKeyDer)
        assertNull(minimal.name)
    }

    @Test
    fun `LocalGetAttestationQuoteParams defaults the PCR bank to the backend's own`() {
        val defaulted = LocalGetAttestationQuoteParams(
            nonce = byteArrayOf(1, 2),
            pcrIndices = listOf(0, 7)
        )

        assertArrayEquals(byteArrayOf(1, 2), defaulted.nonce)
        assertEquals(listOf(0, 7), defaulted.pcrIndices)
        assertNull(defaulted.pcrBank)
        assertEquals("sha256", LocalGetAttestationQuoteParams(byteArrayOf(1), listOf(0), "sha256").pcrBank)
    }

    @Test
    fun `LocalGetAttestationQuoteResult defaults the event log to absent`() {
        val result = LocalGetAttestationQuoteResult(
            quoted = byteArrayOf(0xFF.toByte()),
            signature = byteArrayOf(0x14),
            pcrValues = mapOf(0 to byteArrayOf(0xA0.toByte())),
            pcrBank = "sha256"
        )

        assertArrayEquals(byteArrayOf(0xFF.toByte()), result.quoted)
        assertArrayEquals(byteArrayOf(0x14), result.signature)
        assertEquals(1, result.pcrValues.size)
        assertNull("the event log is optional", result.eventLog)
        assertEquals("sha256", result.pcrBank)
    }

    @Test
    fun `LocalGetCABundleResult defaults the bundle and root subject to absent`() {
        val minimal = LocalGetCABundleResult(certificates = emptyList(), count = 0)

        assertNull(minimal.bundlePem)
        assertTrue(minimal.certificates.isEmpty())
        assertEquals(0, minimal.count)
        assertNull(minimal.rootSubject)
    }

    @Test
    fun `LocalActivateCredentialParams and its result expose their raw blobs`() {
        val params = LocalActivateCredentialParams(
            credentialBlob = byteArrayOf(1, 2),
            encryptedSecret = byteArrayOf(3, 4)
        )
        assertArrayEquals(byteArrayOf(1, 2), params.credentialBlob)
        assertArrayEquals(byteArrayOf(3, 4), params.encryptedSecret)

        val result = LocalActivateCredentialResult(decryptedSecret = byteArrayOf(5, 6))
        assertArrayEquals(byteArrayOf(5, 6), result.decryptedSecret)
    }

    @Test
    fun `LocalStoreEnrollmentCertsParams defaults its chain to absent`() {
        val params = LocalStoreEnrollmentCertsParams(
            iakCert = byteArrayOf(0x30, 0x60),
            idevidCert = byteArrayOf(0x30, 0x61)
        )

        assertArrayEquals(byteArrayOf(0x30, 0x60), params.iakCert)
        assertArrayEquals(byteArrayOf(0x30, 0x61), params.idevidCert)
        assertNull(params.chain)
    }

    @Test
    fun `LocalGetIDevIDCertificateParams and its result default to no certificate`() {
        assertNull(LocalGetIDevIDCertificateParams().nonce)

        val absent = LocalGetIDevIDCertificateResult(hasCertificate = false)
        assertFalse(absent.hasCertificate)
        assertNull(absent.certificateChain)
        assertNull(absent.nonce)
        assertNull(absent.certificateInfo)
    }
}
