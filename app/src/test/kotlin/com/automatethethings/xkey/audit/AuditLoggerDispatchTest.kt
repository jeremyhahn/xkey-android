/*
 * Copyright (c) 2025 Jeremy Hahn
 * Copyright (c) 2025 Automate The Things, LLC
 *
 * This file is part of xKey.
 *
 * xKey is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */
package com.automatethethings.xkey.audit

import android.util.Log
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkStatic
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.concurrent.atomic.AtomicReference

/**
 * Unit tests for the [AuditLogger] singleton's dispatch layer: every public
 * `log*` helper is exercised and the [AuditLogEntity] it hands to the DAO is
 * asserted field by field (operation type, key/device identity, success flag,
 * error message, duration, and the structured `details` JSON).
 *
 * [AuditLogger.initialize] needs a Room database and is therefore covered by
 * instrumented tests; here the singleton's private `daoRef`/`scopeRef` holders
 * are injected with a mock DAO and an unconfined scope so writes complete
 * synchronously on the calling thread. Both holders are restored to their
 * uninitialized state after each test, so the tests are order independent.
 */
class AuditLoggerDispatchTest {

    private val inserted = mutableListOf<AuditLogEntity>()
    private lateinit var dao: AuditLogDao

    @Suppress("UNCHECKED_CAST")
    private fun <T> holder(name: String): AtomicReference<T?> =
        AuditLogger::class.java.getDeclaredField(name)
            .apply { isAccessible = true }
            .get(AuditLogger) as AtomicReference<T?>

    @Before
    fun setUp() {
        inserted.clear()
        dao = mockk(relaxed = true)
        coEvery { dao.insert(any()) } answers {
            inserted += firstArg<AuditLogEntity>()
            inserted.size.toLong()
        }
        holder<AuditLogDao>("daoRef").set(dao)
        holder<CoroutineScope>("scopeRef").set(CoroutineScope(Dispatchers.Unconfined))
    }

    @After
    fun tearDown() {
        holder<AuditLogDao>("daoRef").set(null)
        holder<CoroutineScope>("scopeRef").set(null)
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /** The single entity written by the call under test. */
    private fun only(): AuditLogEntity {
        assertEquals("expected exactly one audit entry", 1, inserted.size)
        return inserted[0]
    }

    private fun details(entry: AuditLogEntity): JSONObject = JSONObject(entry.details!!)

    // -----------------------------------------------------------------------
    // Wiring
    // -----------------------------------------------------------------------

    @Test
    fun `entries carry a generated timestamp and an unassigned id`() {
        val before = System.currentTimeMillis()
        AuditLogger.logServiceStarted()
        val entry = only()
        assertEquals(0L, entry.id)
        assertTrue(entry.timestamp >= before)
        assertTrue(entry.timestamp <= System.currentTimeMillis())
    }

    @Test
    fun `entries reach the dao in call order`() {
        AuditLogger.logServiceStarted()
        AuditLogger.logBiometricSuccess("unlock")
        AuditLogger.logServiceStopped()
        assertEquals(
            listOf(
                AuditOperationType.SERVICE_STARTED,
                AuditOperationType.BIOMETRIC_SUCCESS,
                AuditOperationType.SERVICE_STOPPED
            ),
            inserted.map { it.operationType }
        )
    }

    @Test
    fun `entries are dropped when the logger is not initialized`() {
        mockkStatic(Log::class)
        try {
            every { Log.w(any<String>(), any<String>()) } returns 0
            holder<AuditLogDao>("daoRef").set(null)
            holder<CoroutineScope>("scopeRef").set(null)
            assertFalse(AuditLogger.isInitialized())

            AuditLogger.logServiceStarted()

            assertTrue("no entry may be written before initialize()", inserted.isEmpty())
        } finally {
            unmockkStatic(Log::class)
        }
    }

    // -----------------------------------------------------------------------
    // Key lifecycle
    // -----------------------------------------------------------------------

    @Test
    fun `logKeyCreated records algorithm and strongBox flag`() {
        AuditLogger.logKeyCreated("k1", "Signing Key", "signing", "ES256")
        var entry = only()
        assertEquals(AuditOperationType.KEY_CREATED, entry.operationType)
        assertEquals("k1", entry.keyId)
        assertEquals("Signing Key", entry.keyLabel)
        assertEquals("signing", entry.keyType)
        assertTrue(entry.success)
        assertEquals("ES256", details(entry).getString("algorithm"))
        assertFalse(details(entry).getBoolean("strongBox"))

        inserted.clear()
        AuditLogger.logKeyCreated("k2", "SB Key", "signing", "ES256", strongBox = true)
        entry = only()
        assertTrue(details(entry).getBoolean("strongBox"))
    }

    @Test
    fun `logKeyDeleted records identity without details`() {
        AuditLogger.logKeyDeleted("k1", "Old Key", "signing")
        val entry = only()
        assertEquals(AuditOperationType.KEY_DELETED, entry.operationType)
        assertEquals("k1", entry.keyId)
        assertEquals("Old Key", entry.keyLabel)
        assertEquals("signing", entry.keyType)
        assertTrue(entry.success)
        assertNull(entry.details)
    }

    @Test
    fun `logKeyUsed records the operation and failure detail`() {
        AuditLogger.logKeyUsed(
            keyId = "k1",
            keyLabel = "Key",
            keyType = "signing",
            operation = "sign",
            success = false,
            errorMessage = "user cancelled",
            durationMs = 17L
        )
        val entry = only()
        assertEquals(AuditOperationType.KEY_USED, entry.operationType)
        assertFalse(entry.success)
        assertEquals("user cancelled", entry.errorMessage)
        assertEquals(17L, entry.durationMs)
        assertEquals("sign", details(entry).getString("operation"))
    }

    @Test
    fun `logKeyAttested omits details when no security level is known`() {
        AuditLogger.logKeyAttested("k1", "Key", "signing")
        var entry = only()
        assertEquals(AuditOperationType.KEY_ATTESTED, entry.operationType)
        assertNull(entry.details)
        assertTrue(entry.success)

        inserted.clear()
        AuditLogger.logKeyAttested("k1", "Key", "signing", securityLevel = "StrongBox", durationMs = 5L)
        entry = only()
        assertEquals("StrongBox", details(entry).getString("securityLevel"))
        assertEquals(5L, entry.durationMs)
    }

    @Test
    fun `logKeySharingChanged records both policies`() {
        AuditLogger.logKeySharingChanged("k1", "Key", "signing", "PRIVATE", "PUBLIC_ONLY")
        val entry = only()
        assertEquals(AuditOperationType.KEY_SHARING_CHANGED, entry.operationType)
        assertEquals("PRIVATE", details(entry).getString("oldPolicy"))
        assertEquals("PUBLIC_ONLY", details(entry).getString("newPolicy"))
    }

    @Test
    fun `logKeyExported records the export format`() {
        AuditLogger.logKeyExported("k1", "Key", "signing", "PEM")
        val entry = only()
        assertEquals(AuditOperationType.KEY_EXPORTED, entry.operationType)
        assertEquals("PEM", details(entry).getString("format"))
        assertTrue(entry.success)
    }

    // -----------------------------------------------------------------------
    // Cryptographic operations
    // -----------------------------------------------------------------------

    @Test
    fun `logSigningRequest carries device identity and algorithm`() {
        AuditLogger.logSigningRequest(
            keyId = "k1",
            keyLabel = "Key",
            keyType = "signing",
            algorithm = "SHA256withECDSA",
            deviceId = "dev-1",
            deviceName = "Laptop",
            durationMs = 12L
        )
        val entry = only()
        assertEquals(AuditOperationType.SIGNING_REQUEST, entry.operationType)
        assertEquals("dev-1", entry.deviceId)
        assertEquals("Laptop", entry.deviceName)
        assertEquals(12L, entry.durationMs)
        assertEquals("SHA256withECDSA", details(entry).getString("algorithm"))
    }

    @Test
    fun `logSigningRequest omits details when the algorithm is unknown`() {
        AuditLogger.logSigningRequest("k1", "Key", "signing", success = false, errorMessage = "boom")
        val entry = only()
        assertNull(entry.details)
        assertFalse(entry.success)
        assertEquals("boom", entry.errorMessage)
    }

    @Test
    fun `logHmacRequest writes HMAC_REQUEST with key, device and algorithm`() {
        AuditLogger.logHmacRequest(
            keyId = "k1",
            keyLabel = "Key",
            keyType = "symmetric",
            algorithm = "HMAC-SHA256",
            deviceId = "dev-1",
            deviceName = "Laptop",
            durationMs = 4L
        )
        val entry = only()
        assertEquals(AuditOperationType.HMAC_REQUEST, entry.operationType)
        assertEquals("k1", entry.keyId)
        assertEquals("dev-1", entry.deviceId)
        assertEquals("Laptop", entry.deviceName)
        assertEquals(4L, entry.durationMs)
        assertTrue(entry.success)
        assertEquals("HMAC-SHA256", details(entry).getString("algorithm"))
    }

    @Test
    fun `logKeyDerivationRequest writes KEY_DERIVATION_REQUEST with key and device`() {
        AuditLogger.logKeyDerivationRequest(
            keyId = "k2",
            keyLabel = "Key",
            keyType = "ecdh",
            algorithm = "ECDH",
            deviceId = "dev-1",
            deviceName = "Laptop",
            durationMs = 7L
        )
        val entry = only()
        assertEquals(AuditOperationType.KEY_DERIVATION_REQUEST, entry.operationType)
        assertEquals("k2", entry.keyId)
        assertEquals("dev-1", entry.deviceId)
        assertEquals("Laptop", entry.deviceName)
        assertEquals(7L, entry.durationMs)
        assertTrue(entry.success)
        assertEquals("ECDH", details(entry).getString("algorithm"))
    }

    @Test
    fun `logKeyDerivationRequest omits details when the algorithm is unknown`() {
        AuditLogger.logKeyDerivationRequest("k2", "Key", "ecdh")
        assertNull(only().details)
    }

    @Test
    fun `logEncryptionRequest records the algorithm`() {
        AuditLogger.logEncryptionRequest("k1", "Key", "secret", algorithm = "AES/GCM/NoPadding")
        val entry = only()
        assertEquals(AuditOperationType.ENCRYPTION_REQUEST, entry.operationType)
        assertEquals("AES/GCM/NoPadding", details(entry).getString("algorithm"))
    }

    @Test
    fun `logDecryptionRequest records failure state`() {
        AuditLogger.logDecryptionRequest(
            "k1", "Key", "secret",
            success = false,
            errorMessage = "tag mismatch",
            durationMs = 3L
        )
        val entry = only()
        assertEquals(AuditOperationType.DECRYPTION_REQUEST, entry.operationType)
        assertFalse(entry.success)
        assertEquals("tag mismatch", entry.errorMessage)
        assertEquals(3L, entry.durationMs)
        assertNull(entry.details)
    }

    // -----------------------------------------------------------------------
    // FIDO2
    // -----------------------------------------------------------------------

    @Test
    fun `logFido2Registration tags the entry as a fido2 key`() {
        AuditLogger.logFido2Registration("cred-1", "webauthn.io", "webauthn.io", userName = "alice")
        val entry = only()
        assertEquals(AuditOperationType.FIDO2_REGISTRATION, entry.operationType)
        assertEquals("fido2", entry.keyType)
        assertEquals("cred-1", entry.keyId)
        assertEquals("webauthn.io", details(entry).getString("rpId"))
        assertEquals("alice", details(entry).getString("userName"))
    }

    @Test
    fun `logFido2Registration omits userName when absent`() {
        AuditLogger.logFido2Registration("cred-1", "rp", "rp.example")
        val json = details(only())
        assertEquals("rp.example", json.getString("rpId"))
        assertFalse(json.has("userName"))
    }

    @Test
    fun `logFido2Authentication records device and failure`() {
        AuditLogger.logFido2Authentication(
            keyId = "cred-1",
            keyLabel = "rp",
            rpId = "rp.example",
            deviceId = "dev-1",
            deviceName = "Phone",
            success = false,
            errorMessage = "no credential"
        )
        val entry = only()
        assertEquals(AuditOperationType.FIDO2_AUTHENTICATION, entry.operationType)
        assertEquals("fido2", entry.keyType)
        assertEquals("dev-1", entry.deviceId)
        assertFalse(entry.success)
        assertEquals("no credential", entry.errorMessage)
        assertEquals("rp.example", details(entry).getString("rpId"))
    }

    // -----------------------------------------------------------------------
    // Pairing and connection
    // -----------------------------------------------------------------------

    @Test
    fun `logPairingApproved records the fingerprint when supplied`() {
        AuditLogger.logPairingApproved("dev-1", "Laptop", fingerprint = "SHA256:abc")
        var entry = only()
        assertEquals(AuditOperationType.PAIRING_APPROVED, entry.operationType)
        assertEquals("dev-1", entry.deviceId)
        assertEquals("Laptop", entry.deviceName)
        assertEquals("SHA256:abc", details(entry).getString("fingerprint"))

        inserted.clear()
        AuditLogger.logPairingApproved("dev-1", "Laptop")
        entry = only()
        assertNull(entry.details)
    }

    @Test
    fun `logPairingDenied records the reason and flags the entry as successful`() {
        AuditLogger.logPairingDenied("dev-1", "Laptop", reason = "user rejected")
        val entry = only()
        assertEquals(AuditOperationType.PAIRING_DENIED, entry.operationType)
        assertEquals("user rejected", details(entry).getString("reason"))
        // NOTE: a denial is recorded with success = true, unlike POLICY_DENIED.
        assertTrue(entry.success)
    }

    @Test
    fun `logDeviceUnpaired records device identity only`() {
        AuditLogger.logDeviceUnpaired("dev-1", "Laptop")
        val entry = only()
        assertEquals(AuditOperationType.DEVICE_UNPAIRED, entry.operationType)
        assertEquals("dev-1", entry.deviceId)
        assertEquals("Laptop", entry.deviceName)
        assertNull(entry.details)
        assertNull(entry.keyId)
    }

    @Test
    fun `logConnectionEstablished records the transport`() {
        AuditLogger.logConnectionEstablished("dev-1", "Laptop", "BLE")
        val entry = only()
        assertEquals(AuditOperationType.CONNECTION_ESTABLISHED, entry.operationType)
        assertEquals("BLE", details(entry).getString("connectionType"))
    }

    @Test
    fun `logConnectionClosed records reason and duration`() {
        AuditLogger.logConnectionClosed("dev-1", "Laptop", reason = "timeout", durationMs = 900L)
        var entry = only()
        assertEquals(AuditOperationType.CONNECTION_CLOSED, entry.operationType)
        assertEquals("timeout", details(entry).getString("reason"))
        assertEquals(900L, entry.durationMs)

        inserted.clear()
        AuditLogger.logConnectionClosed("dev-1", "Laptop")
        entry = only()
        assertNull(entry.details)
        assertNull(entry.durationMs)
    }

    @Test
    fun `logDeviceAttested propagates the failure reason`() {
        AuditLogger.logDeviceAttested("dev-1", "Laptop", success = false, errorMessage = "bad chain")
        val entry = only()
        assertEquals(AuditOperationType.DEVICE_ATTESTED, entry.operationType)
        assertFalse(entry.success)
        assertEquals("bad chain", entry.errorMessage)
        assertNull(entry.details)
    }

    // -----------------------------------------------------------------------
    // Configuration and trust store
    // -----------------------------------------------------------------------

    @Test
    fun `logSettingsChanged records old and new values`() {
        AuditLogger.logSettingsChanged("ble_enabled", oldValue = "false", newValue = "true")
        var json = details(only())
        assertEquals("ble_enabled", json.getString("setting"))
        assertEquals("false", json.getString("oldValue"))
        assertEquals("true", json.getString("newValue"))

        inserted.clear()
        AuditLogger.logSettingsChanged("ble_enabled", newValue = "true")
        json = details(only())
        assertFalse(json.has("oldValue"))
        assertEquals("true", json.getString("newValue"))
    }

    @Test
    fun `logTrustStoreImport records subject, fingerprint and source`() {
        AuditLogger.logTrustStoreImport("CN=Root", "SHA256:aa", "https://ca.example/bundle")
        val entry = only()
        assertEquals(AuditOperationType.TRUST_STORE_IMPORT, entry.operationType)
        val json = details(entry)
        assertEquals("CN=Root", json.getString("subject"))
        assertEquals("SHA256:aa", json.getString("fingerprint"))
        assertEquals("https://ca.example/bundle", json.getString("source"))
    }

    @Test
    fun `logTrustStoreDelete records subject and fingerprint`() {
        AuditLogger.logTrustStoreDelete("CN=Root", "SHA256:aa")
        val json = details(only())
        assertEquals("CN=Root", json.getString("subject"))
        assertEquals("SHA256:aa", json.getString("fingerprint"))
        assertEquals(2, json.length())
    }

    // -----------------------------------------------------------------------
    // Security events
    // -----------------------------------------------------------------------

    @Test
    fun `logBiometricSuccess and logBiometricFailure set opposite success flags`() {
        AuditLogger.logBiometricSuccess("unlock key")
        AuditLogger.logBiometricFailure("unlock key", errorCode = 7)

        assertEquals(2, inserted.size)
        val success = inserted[0]
        assertEquals(AuditOperationType.BIOMETRIC_SUCCESS, success.operationType)
        assertTrue(success.success)
        assertEquals("unlock key", details(success).getString("purpose"))

        val failure = inserted[1]
        assertEquals(AuditOperationType.BIOMETRIC_FAILURE, failure.operationType)
        assertFalse(failure.success)
        assertEquals(7, details(failure).getInt("errorCode"))
    }

    @Test
    fun `logPolicyDenied is recorded as a failure with full context`() {
        AuditLogger.logPolicyDenied(
            keyId = "k1",
            keyLabel = "Key",
            deviceId = "dev-1",
            deviceName = "Laptop",
            reason = "sharing disabled"
        )
        val entry = only()
        assertEquals(AuditOperationType.POLICY_DENIED, entry.operationType)
        assertFalse(entry.success)
        assertEquals("k1", entry.keyId)
        assertEquals("dev-1", entry.deviceId)
        assertEquals("sharing disabled", details(entry).getString("reason"))
    }

    // -----------------------------------------------------------------------
    // Service events
    // -----------------------------------------------------------------------

    @Test
    fun `logServiceStarted has no details`() {
        AuditLogger.logServiceStarted()
        val entry = only()
        assertEquals(AuditOperationType.SERVICE_STARTED, entry.operationType)
        assertTrue(entry.success)
        assertNull(entry.details)
    }

    @Test
    fun `logServiceStopped records an optional reason`() {
        AuditLogger.logServiceStopped("user toggled BLE off")
        var entry = only()
        assertEquals(AuditOperationType.SERVICE_STOPPED, entry.operationType)
        assertEquals("user toggled BLE off", details(entry).getString("reason"))

        inserted.clear()
        AuditLogger.logServiceStopped()
        entry = only()
        assertNull(entry.details)
    }

    // -----------------------------------------------------------------------
    // Certificate operations
    // -----------------------------------------------------------------------

    @Test
    fun `logCertificateIssued records serial, subject and profile`() {
        AuditLogger.logCertificateIssued("0A1B", "CN=alice", "tls-client")
        val entry = only()
        assertEquals(AuditOperationType.CERTIFICATE_ISSUED, entry.operationType)
        val json = details(entry)
        assertEquals("0A1B", json.getString("serialNumber"))
        assertEquals("CN=alice", json.getString("subjectDN"))
        assertEquals("tls-client", json.getString("profile"))
    }

    @Test
    fun `logCertificateRevoked records the numeric CRL reason`() {
        AuditLogger.logCertificateRevoked("0A1B", "CN=alice", reason = 1)
        val entry = only()
        assertEquals(AuditOperationType.CERTIFICATE_REVOKED, entry.operationType)
        assertEquals(1, details(entry).getInt("reason"))
    }

    @Test
    fun `logCSRSigned records serial, subject and profile`() {
        AuditLogger.logCSRSigned("0C0D", "CN=bob", "tls-server")
        val entry = only()
        assertEquals(AuditOperationType.CSR_SIGNED, entry.operationType)
        assertEquals("0C0D", details(entry).getString("serialNumber"))
    }

    @Test
    fun `logCRLGenerated records the entry count`() {
        AuditLogger.logCRLGenerated(3)
        val entry = only()
        assertEquals(AuditOperationType.CRL_GENERATED, entry.operationType)
        assertEquals(3, details(entry).getInt("entryCount"))
    }

    @Test
    fun `logCertificateExported records the format`() {
        AuditLogger.logCertificateExported("0A1B", "CN=alice", "DER")
        val entry = only()
        assertEquals(AuditOperationType.CERTIFICATE_EXPORTED, entry.operationType)
        assertEquals("DER", details(entry).getString("format"))
    }

    // -----------------------------------------------------------------------
    // File and media operations
    // -----------------------------------------------------------------------

    @Test
    fun `logFileSigned records the file name when supplied`() {
        AuditLogger.logFileSigned("k1", "Key", "report.pdf")
        var entry = only()
        assertEquals(AuditOperationType.FILE_SIGNED, entry.operationType)
        assertEquals("k1", entry.keyId)
        assertEquals("report.pdf", details(entry).getString("fileName"))

        inserted.clear()
        AuditLogger.logFileSigned("k1", "Key")
        entry = only()
        assertNull(entry.details)
    }

    @Test
    fun `logFileVerified maps the verified flag onto success`() {
        AuditLogger.logFileVerified("report.pdf", signerCount = 2)
        var entry = only()
        assertEquals(AuditOperationType.FILE_VERIFIED, entry.operationType)
        assertTrue(entry.success)
        assertEquals(2, details(entry).getInt("signerCount"))

        inserted.clear()
        AuditLogger.logFileVerified(verified = false)
        entry = only()
        assertFalse(entry.success)
        assertFalse(details(entry).has("fileName"))
        assertEquals(0, details(entry).getInt("signerCount"))
    }

    @Test
    fun `logFileEncrypted records recipient and file name`() {
        AuditLogger.logFileEncrypted("k1", "SHA256:bb", "secret.txt")
        val entry = only()
        assertEquals(AuditOperationType.FILE_ENCRYPTED, entry.operationType)
        assertEquals("k1", entry.keyId)
        val json = details(entry)
        assertEquals("SHA256:bb", json.getString("recipientFingerprint"))
        assertEquals("secret.txt", json.getString("fileName"))
    }

    @Test
    fun `logFileEncrypted writes an empty details object when nothing is known`() {
        AuditLogger.logFileEncrypted()
        val entry = only()
        assertNull(entry.keyId)
        assertEquals(0, details(entry).length())
    }

    @Test
    fun `logFileDecrypted records the key and optional file name`() {
        AuditLogger.logFileDecrypted("k1", "secret.txt")
        val entry = only()
        assertEquals(AuditOperationType.FILE_DECRYPTED, entry.operationType)
        assertEquals("k1", entry.keyId)
        assertEquals("secret.txt", details(entry).getString("fileName"))
    }

    @Test
    fun `logMediaAutoSigned records the media uri`() {
        AuditLogger.logMediaAutoSigned("k1", "Camera Key", "content://media/1")
        val entry = only()
        assertEquals(AuditOperationType.MEDIA_AUTO_SIGNED, entry.operationType)
        assertEquals("Camera Key", entry.keyLabel)
        assertEquals("content://media/1", details(entry).getString("uri"))
    }

    // -----------------------------------------------------------------------
    // Contacts
    // -----------------------------------------------------------------------

    @Test
    fun `logContactImported records name, fingerprint and source`() {
        AuditLogger.logContactImported("Alice", "SHA256:cc", "qr")
        val entry = only()
        assertEquals(AuditOperationType.CONTACT_IMPORTED, entry.operationType)
        val json = details(entry)
        assertEquals("Alice", json.getString("name"))
        assertEquals("SHA256:cc", json.getString("fingerprint"))
        assertEquals("qr", json.getString("source"))
    }

    @Test
    fun `logContactDeleted records name and fingerprint`() {
        AuditLogger.logContactDeleted("Alice", "SHA256:cc")
        val json = details(only())
        assertEquals("Alice", json.getString("name"))
        assertEquals(2, json.length())
    }

    // -----------------------------------------------------------------------
    // OATH
    // -----------------------------------------------------------------------

    @Test
    fun `logOathCredentialCreated composes the label from issuer and account`() {
        AuditLogger.logOathCredentialCreated("o1", "GitHub", "alice@example.com", "TOTP")
        val entry = only()
        assertEquals(AuditOperationType.OATH_CREDENTIAL_CREATED, entry.operationType)
        assertEquals("o1", entry.keyId)
        assertEquals("GitHub:alice@example.com", entry.keyLabel)
        val json = details(entry)
        assertEquals("GitHub", json.getString("issuer"))
        assertEquals("alice@example.com", json.getString("accountName"))
        assertEquals("TOTP", json.getString("oathType"))
    }

    @Test
    fun `logOathCredentialCreated falls back to the account name without an issuer`() {
        AuditLogger.logOathCredentialCreated("o1", null, "alice@example.com", "HOTP")
        val entry = only()
        assertEquals("alice@example.com", entry.keyLabel)
        assertFalse(details(entry).has("issuer"))
    }

    @Test
    fun `logOathCredentialDeleted and logOathCodeGenerated carry no details`() {
        AuditLogger.logOathCredentialDeleted("o1", "GitHub", "alice")
        AuditLogger.logOathCodeGenerated("o1", null, "alice")

        assertEquals(2, inserted.size)
        assertEquals(AuditOperationType.OATH_CREDENTIAL_DELETED, inserted[0].operationType)
        assertEquals("GitHub:alice", inserted[0].keyLabel)
        assertNull(inserted[0].details)
        assertEquals(AuditOperationType.OATH_CODE_GENERATED, inserted[1].operationType)
        assertEquals("alice", inserted[1].keyLabel)
        assertNull(inserted[1].details)
    }

    @Test
    fun `logOathSyncPerformed records the credential count against the device`() {
        AuditLogger.logOathSyncPerformed("dev-1", "Laptop", 4)
        val entry = only()
        assertEquals(AuditOperationType.OATH_SYNC_PERFORMED, entry.operationType)
        assertEquals("dev-1", entry.deviceId)
        assertEquals(4, details(entry).getInt("credentialCount"))
    }

    // -----------------------------------------------------------------------
    // Co-signing
    // -----------------------------------------------------------------------

    @Test
    fun `logCoSignInitiated records the content hash and witness count`() {
        AuditLogger.logCoSignInitiated("abc123", witnessCount = 2)
        val entry = only()
        assertEquals(AuditOperationType.COSIGN_INITIATED, entry.operationType)
        assertEquals("abc123", details(entry).getString("contentHash"))
        assertEquals(2, details(entry).getInt("witnessCount"))
    }

    @Test
    fun `logCoSignInitiated defaults the witness count to zero`() {
        AuditLogger.logCoSignInitiated("abc123")
        assertEquals(0, details(only()).getInt("witnessCount"))
    }

    @Test
    fun `logCoSignReceived records the signer fingerprint`() {
        AuditLogger.logCoSignReceived("abc123", "SHA256:dd")
        val entry = only()
        assertEquals(AuditOperationType.COSIGN_RECEIVED, entry.operationType)
        assertEquals("SHA256:dd", details(entry).getString("signerFingerprint"))
    }

    // -----------------------------------------------------------------------
    // PIN
    // -----------------------------------------------------------------------

    @Test
    fun `logPinSet distinguishes SO PIN from user PIN`() {
        AuditLogger.logPinSet("SO_PIN")
        AuditLogger.logPinSet("USER_PIN")

        assertEquals(AuditOperationType.PIN_SO_SET, inserted[0].operationType)
        assertEquals("SO_PIN", details(inserted[0]).getString("pinType"))
        assertEquals(AuditOperationType.PIN_USER_SET, inserted[1].operationType)
        assertEquals("USER_PIN", details(inserted[1]).getString("pinType"))
    }

    @Test
    fun `logPinSet treats any non SO_PIN token as a user PIN`() {
        AuditLogger.logPinSet("so_pin")
        assertEquals(AuditOperationType.PIN_USER_SET, only().operationType)
    }

    @Test
    fun `logPinChanged distinguishes SO PIN from user PIN`() {
        AuditLogger.logPinChanged("SO_PIN")
        AuditLogger.logPinChanged("USER_PIN")

        assertEquals(AuditOperationType.PIN_SO_CHANGED, inserted[0].operationType)
        assertEquals(AuditOperationType.PIN_USER_CHANGED, inserted[1].operationType)
    }

    @Test
    fun `pin verification outcomes set the success flag`() {
        AuditLogger.logPinVerificationSuccess("USER_PIN")
        AuditLogger.logPinVerificationFailed("USER_PIN", failedAttempts = 3)

        assertEquals(AuditOperationType.PIN_VERIFICATION_SUCCESS, inserted[0].operationType)
        assertTrue(inserted[0].success)

        assertEquals(AuditOperationType.PIN_VERIFICATION_FAILED, inserted[1].operationType)
        assertFalse(inserted[1].success)
        assertEquals(3, details(inserted[1]).getInt("failedAttempts"))
    }

    @Test
    fun `logPinLockoutTriggered is a failure carrying the lockout deadline`() {
        AuditLogger.logPinLockoutTriggered("USER_PIN", lockoutUntil = 1_700_000_000_000L)
        val entry = only()
        assertEquals(AuditOperationType.PIN_LOCKOUT_TRIGGERED, entry.operationType)
        assertFalse(entry.success)
        assertEquals(1_700_000_000_000L, details(entry).getLong("lockoutUntil"))
    }

    @Test
    fun `logPinLockoutReset is a bare success entry`() {
        AuditLogger.logPinLockoutReset()
        val entry = only()
        assertEquals(AuditOperationType.PIN_LOCKOUT_RESET, entry.operationType)
        assertTrue(entry.success)
        assertNull(entry.details)
    }

    // -----------------------------------------------------------------------
    // PIV
    // -----------------------------------------------------------------------

    @Test
    fun `logPivKeyGenerated namespaces the key id by slot`() {
        AuditLogger.logPivKeyGenerated("9a", "ECCP256")
        val entry = only()
        assertEquals(AuditOperationType.PIV_KEY_GENERATED, entry.operationType)
        assertEquals("piv_9a", entry.keyId)
        assertEquals("piv", entry.keyType)
        val json = details(entry)
        assertEquals("9a", json.getString("slotId"))
        assertEquals("ECCP256", json.getString("algorithm"))
    }

    @Test
    fun `logPivCertImported records the optional subject`() {
        AuditLogger.logPivCertImported("9c", "CN=alice")
        var entry = only()
        assertEquals(AuditOperationType.PIV_CERT_IMPORTED, entry.operationType)
        assertEquals("piv_9c", entry.keyId)
        assertEquals("CN=alice", details(entry).getString("subject"))

        inserted.clear()
        AuditLogger.logPivCertImported("9c")
        entry = only()
        assertFalse(details(entry).has("subject"))
    }

    @Test
    fun `logPivSignRequest propagates failure state`() {
        AuditLogger.logPivSignRequest(
            slotId = "9a",
            algorithm = "SHA256withECDSA",
            success = false,
            errorMessage = "pin required",
            durationMs = 8L
        )
        val entry = only()
        assertEquals(AuditOperationType.PIV_SIGN_REQUEST, entry.operationType)
        assertEquals("piv_9a", entry.keyId)
        assertFalse(entry.success)
        assertEquals("pin required", entry.errorMessage)
        assertEquals(8L, entry.durationMs)
    }

    @Test
    fun `logPivKeyDeleted records the slot`() {
        AuditLogger.logPivKeyDeleted("9d")
        val entry = only()
        assertEquals(AuditOperationType.PIV_KEY_DELETED, entry.operationType)
        assertEquals("piv_9d", entry.keyId)
        assertEquals("piv", entry.keyType)
        assertEquals("9d", details(entry).getString("slotId"))
    }

    // -----------------------------------------------------------------------
    // Desktop backups
    // -----------------------------------------------------------------------

    @Test
    fun `logBackupCreated records the backup id, size and requesting device`() {
        AuditLogger.logBackupCreated("backup-1-1", 42, "aabbcc", "Laptop")
        val entry = only()
        assertEquals(AuditOperationType.BACKUP_CREATED, entry.operationType)
        assertEquals("aabbcc", entry.deviceId)
        assertEquals("Laptop", entry.deviceName)
        assertTrue(entry.success)
        val details = details(entry)
        assertEquals("backup-1-1", details.getString("backupId"))
        assertEquals(42, details.getInt("sizeBytes"))
    }

    @Test
    fun `logBackupRestored records the backup id and size without a device`() {
        AuditLogger.logBackupRestored("backup-2-1", 7, null, null)
        val entry = only()
        assertEquals(AuditOperationType.BACKUP_RESTORED, entry.operationType)
        assertNull(entry.deviceId)
        assertNull(entry.deviceName)
        assertTrue(entry.success)
        val details = details(entry)
        assertEquals("backup-2-1", details.getString("backupId"))
        assertEquals(7, details.getInt("sizeBytes"))
    }
}
