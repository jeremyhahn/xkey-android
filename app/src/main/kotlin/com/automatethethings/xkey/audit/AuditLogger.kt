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

import android.content.Context
import android.util.Log
import androidx.annotation.VisibleForTesting
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicReference

/**
 * Singleton logger for recording security-relevant operations to the audit log.
 *
 * Provides a simple, non-blocking API for logging operations throughout the xKey
 * application. All logging operations are performed asynchronously using coroutines
 * to avoid blocking the calling thread.
 *
 * Features:
 * - Asynchronous, non-blocking logging
 * - Type-safe operation recording with dedicated methods
 * - Automatic timestamp and duration capture
 * - Structured JSON details for additional context
 * - Singleton pattern with thread-safe initialization
 *
 * Usage:
 * ```kotlin
 * // Initialize on application startup
 * AuditLogger.initialize(applicationContext)
 *
 * // Log operations
 * AuditLogger.logKeyCreated(keyId, keyLabel, keyType, "ES256")
 * AuditLogger.logSigningRequest(keyId, keyLabel, keyType, success = true, durationMs = 45)
 * ```
 *
 * The logger uses a SupervisorJob to ensure logging failures don't affect
 * other operations or crash the application.
 */
object AuditLogger {

    private const val TAG = "AuditLogger"

    /**
     * Default retention period: 90 days in milliseconds.
     *
     * `internal` only so the retention tests can apply the same cutoff.
     */
    @VisibleForTesting
    internal const val DEFAULT_RETENTION_MS = 90L * 24 * 60 * 60 * 1000

    /**
     * Maximum number of audit entries to retain.
     *
     * `internal` only so the retention tests can apply the same limit.
     */
    @VisibleForTesting
    internal const val MAX_ENTRIES = 10000

    private val daoRef = AtomicReference<AuditLogDao?>(null)
    private val scopeRef = AtomicReference<CoroutineScope?>(null)

    /**
     * Initialize the audit logger with application context.
     *
     * Must be called once during application startup before any logging operations.
     *
     * @param context Application context for database access.
     */
    fun initialize(context: Context) {
        val existing = daoRef.get()
        if (existing != null) return

        val database = XKeyDatabase.getInstance(context)
        val dao = database.auditLogDao()
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

        if (daoRef.compareAndSet(null, dao)) {
            scopeRef.set(scope)
            // Apply retention policy on startup
            scope.launch {
                try {
                    applyRetentionPolicy(dao)
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to apply retention policy", e)
                }
            }
        }
    }

    /**
     * Check if the logger is initialized.
     *
     * @return True if initialized and ready for logging.
     */
    fun isInitialized(): Boolean = daoRef.get() != null

    // -------------------------------------------------------------------------
    // Key Lifecycle Operations
    // -------------------------------------------------------------------------

    /**
     * Log a key creation event.
     *
     * @param keyId The unique key identifier.
     * @param keyLabel Human-readable key label.
     * @param keyType The key type (e.g., "fido2", "signing").
     * @param algorithm The key algorithm (e.g., "ES256", "AES256").
     * @param strongBox Whether StrongBox hardware was used.
     */
    fun logKeyCreated(
        keyId: String,
        keyLabel: String,
        keyType: String,
        algorithm: String,
        strongBox: Boolean = false
    ) {
        val details = JSONObject().apply {
            put("algorithm", algorithm)
            put("strongBox", strongBox)
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.KEY_CREATED,
                keyId = keyId,
                keyLabel = keyLabel,
                keyType = keyType,
                success = true,
                details = details.toString()
            )
        )
    }

    /**
     * Log a key deletion event.
     *
     * @param keyId The unique key identifier.
     * @param keyLabel Human-readable key label.
     * @param keyType The key type.
     */
    fun logKeyDeleted(keyId: String, keyLabel: String, keyType: String) {
        log(
            AuditLogEntity(
                operationType = AuditOperationType.KEY_DELETED,
                keyId = keyId,
                keyLabel = keyLabel,
                keyType = keyType,
                success = true
            )
        )
    }

    /**
     * Log a generic key usage event.
     *
     * @param keyId The unique key identifier.
     * @param keyLabel Human-readable key label.
     * @param keyType The key type.
     * @param operation Description of the operation.
     * @param success Whether the operation succeeded.
     * @param errorMessage Error message if failed.
     * @param durationMs Operation duration in milliseconds.
     */
    fun logKeyUsed(
        keyId: String,
        keyLabel: String,
        keyType: String,
        operation: String,
        success: Boolean = true,
        errorMessage: String? = null,
        durationMs: Long? = null
    ) {
        val details = JSONObject().apply {
            put("operation", operation)
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.KEY_USED,
                keyId = keyId,
                keyLabel = keyLabel,
                keyType = keyType,
                success = success,
                errorMessage = errorMessage,
                details = details.toString(),
                durationMs = durationMs
            )
        )
    }

    /**
     * Log a key attestation event.
     *
     * @param keyId The unique key identifier.
     * @param keyLabel Human-readable key label.
     * @param keyType The key type.
     * @param securityLevel The attestation security level (e.g., "StrongBox", "TEE").
     * @param success Whether attestation succeeded.
     * @param errorMessage Error message if failed.
     * @param durationMs Operation duration in milliseconds.
     */
    fun logKeyAttested(
        keyId: String,
        keyLabel: String,
        keyType: String,
        securityLevel: String? = null,
        success: Boolean = true,
        errorMessage: String? = null,
        durationMs: Long? = null
    ) {
        val details = securityLevel?.let {
            JSONObject().apply { put("securityLevel", it) }.toString()
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.KEY_ATTESTED,
                keyId = keyId,
                keyLabel = keyLabel,
                keyType = keyType,
                success = success,
                errorMessage = errorMessage,
                details = details,
                durationMs = durationMs
            )
        )
    }

    /**
     * Log a key sharing policy change.
     *
     * @param keyId The unique key identifier.
     * @param keyLabel Human-readable key label.
     * @param keyType The key type.
     * @param oldPolicy The previous sharing policy.
     * @param newPolicy The new sharing policy.
     */
    fun logKeySharingChanged(
        keyId: String,
        keyLabel: String,
        keyType: String,
        oldPolicy: String,
        newPolicy: String
    ) {
        val details = JSONObject().apply {
            put("oldPolicy", oldPolicy)
            put("newPolicy", newPolicy)
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.KEY_SHARING_CHANGED,
                keyId = keyId,
                keyLabel = keyLabel,
                keyType = keyType,
                success = true,
                details = details.toString()
            )
        )
    }

    /**
     * Log a public key export event.
     *
     * @param keyId The unique key identifier.
     * @param keyLabel Human-readable key label.
     * @param keyType The key type.
     * @param format The export format (e.g., "PEM", "DER").
     */
    fun logKeyExported(
        keyId: String,
        keyLabel: String,
        keyType: String,
        format: String
    ) {
        val details = JSONObject().apply {
            put("format", format)
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.KEY_EXPORTED,
                keyId = keyId,
                keyLabel = keyLabel,
                keyType = keyType,
                success = true,
                details = details.toString()
            )
        )
    }

    // -------------------------------------------------------------------------
    // Cryptographic Operations
    // -------------------------------------------------------------------------

    /**
     * Log a signing request.
     *
     * @param keyId The unique key identifier.
     * @param keyLabel Human-readable key label.
     * @param keyType The key type.
     * @param algorithm The signing algorithm used.
     * @param deviceId Remote device ID if applicable.
     * @param deviceName Remote device name if applicable.
     * @param success Whether the operation succeeded.
     * @param errorMessage Error message if failed.
     * @param durationMs Operation duration in milliseconds.
     */
    fun logSigningRequest(
        keyId: String,
        keyLabel: String,
        keyType: String,
        algorithm: String? = null,
        deviceId: String? = null,
        deviceName: String? = null,
        success: Boolean = true,
        errorMessage: String? = null,
        durationMs: Long? = null
    ) {
        val details = algorithm?.let {
            JSONObject().apply { put("algorithm", it) }.toString()
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.SIGNING_REQUEST,
                keyId = keyId,
                keyLabel = keyLabel,
                keyType = keyType,
                deviceId = deviceId,
                deviceName = deviceName,
                success = success,
                errorMessage = errorMessage,
                details = details,
                durationMs = durationMs
            )
        )
    }

    /**
     * Log an encryption request.
     *
     * @param keyId The unique key identifier.
     * @param keyLabel Human-readable key label.
     * @param keyType The key type.
     * @param algorithm The encryption algorithm used.
     * @param deviceId Remote device ID if applicable.
     * @param deviceName Remote device name if applicable.
     * @param success Whether the operation succeeded.
     * @param errorMessage Error message if failed.
     * @param durationMs Operation duration in milliseconds.
     */
    fun logEncryptionRequest(
        keyId: String,
        keyLabel: String,
        keyType: String,
        algorithm: String? = null,
        deviceId: String? = null,
        deviceName: String? = null,
        success: Boolean = true,
        errorMessage: String? = null,
        durationMs: Long? = null
    ) {
        val details = algorithm?.let {
            JSONObject().apply { put("algorithm", it) }.toString()
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.ENCRYPTION_REQUEST,
                keyId = keyId,
                keyLabel = keyLabel,
                keyType = keyType,
                deviceId = deviceId,
                deviceName = deviceName,
                success = success,
                errorMessage = errorMessage,
                details = details,
                durationMs = durationMs
            )
        )
    }

    /**
     * Log a decryption request.
     *
     * @param keyId The unique key identifier.
     * @param keyLabel Human-readable key label.
     * @param keyType The key type.
     * @param algorithm The decryption algorithm used.
     * @param deviceId Remote device ID if applicable.
     * @param deviceName Remote device name if applicable.
     * @param success Whether the operation succeeded.
     * @param errorMessage Error message if failed.
     * @param durationMs Operation duration in milliseconds.
     */
    fun logDecryptionRequest(
        keyId: String,
        keyLabel: String,
        keyType: String,
        algorithm: String? = null,
        deviceId: String? = null,
        deviceName: String? = null,
        success: Boolean = true,
        errorMessage: String? = null,
        durationMs: Long? = null
    ) {
        val details = algorithm?.let {
            JSONObject().apply { put("algorithm", it) }.toString()
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.DECRYPTION_REQUEST,
                keyId = keyId,
                keyLabel = keyLabel,
                keyType = keyType,
                deviceId = deviceId,
                deviceName = deviceName,
                success = success,
                errorMessage = errorMessage,
                details = details,
                durationMs = durationMs
            )
        )
    }

    // -------------------------------------------------------------------------
    // FIDO2/WebAuthn Operations
    // -------------------------------------------------------------------------

    /**
     * Log a FIDO2 credential registration.
     *
     * @param keyId The credential ID.
     * @param keyLabel The RP name or display name.
     * @param rpId The relying party identifier.
     * @param userName The user name associated with the credential.
     * @param success Whether registration succeeded.
     * @param errorMessage Error message if failed.
     * @param durationMs Operation duration in milliseconds.
     */
    fun logFido2Registration(
        keyId: String,
        keyLabel: String,
        rpId: String,
        userName: String? = null,
        success: Boolean = true,
        errorMessage: String? = null,
        durationMs: Long? = null
    ) {
        val details = JSONObject().apply {
            put("rpId", rpId)
            userName?.let { put("userName", it) }
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.FIDO2_REGISTRATION,
                keyId = keyId,
                keyLabel = keyLabel,
                keyType = "fido2",
                success = success,
                errorMessage = errorMessage,
                details = details.toString(),
                durationMs = durationMs
            )
        )
    }

    /**
     * Log a FIDO2 authentication.
     *
     * @param keyId The credential ID.
     * @param keyLabel The RP name or display name.
     * @param rpId The relying party identifier.
     * @param deviceId Remote device ID if applicable.
     * @param deviceName Remote device name if applicable.
     * @param success Whether authentication succeeded.
     * @param errorMessage Error message if failed.
     * @param durationMs Operation duration in milliseconds.
     */
    fun logFido2Authentication(
        keyId: String,
        keyLabel: String,
        rpId: String,
        deviceId: String? = null,
        deviceName: String? = null,
        success: Boolean = true,
        errorMessage: String? = null,
        durationMs: Long? = null
    ) {
        val details = JSONObject().apply {
            put("rpId", rpId)
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.FIDO2_AUTHENTICATION,
                keyId = keyId,
                keyLabel = keyLabel,
                keyType = "fido2",
                deviceId = deviceId,
                deviceName = deviceName,
                success = success,
                errorMessage = errorMessage,
                details = details.toString(),
                durationMs = durationMs
            )
        )
    }

    // -------------------------------------------------------------------------
    // Pairing and Connection Operations
    // -------------------------------------------------------------------------

    /**
     * Log a device pairing approval.
     *
     * @param deviceId The device identifier.
     * @param deviceName The device name.
     * @param fingerprint The device fingerprint for verification.
     */
    fun logPairingApproved(
        deviceId: String,
        deviceName: String,
        fingerprint: String? = null
    ) {
        val details = fingerprint?.let {
            JSONObject().apply { put("fingerprint", it) }.toString()
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.PAIRING_APPROVED,
                deviceId = deviceId,
                deviceName = deviceName,
                success = true,
                details = details
            )
        )
    }

    /**
     * Log a device pairing denial.
     *
     * @param deviceId The device identifier.
     * @param deviceName The device name.
     * @param reason The reason for denial.
     */
    fun logPairingDenied(
        deviceId: String,
        deviceName: String,
        reason: String? = null
    ) {
        val details = reason?.let {
            JSONObject().apply { put("reason", it) }.toString()
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.PAIRING_DENIED,
                deviceId = deviceId,
                deviceName = deviceName,
                success = true,
                details = details
            )
        )
    }

    /**
     * Log a device unpairing.
     *
     * @param deviceId The device identifier.
     * @param deviceName The device name.
     */
    fun logDeviceUnpaired(deviceId: String, deviceName: String) {
        log(
            AuditLogEntity(
                operationType = AuditOperationType.DEVICE_UNPAIRED,
                deviceId = deviceId,
                deviceName = deviceName,
                success = true
            )
        )
    }

    /**
     * Log the per-key sharing grants dropped because a device stopped being
     * paired: unpaired, cleared, or replaced by a re-pairing under a new key
     * (#174). Separate from [logDeviceUnpaired], which fires before the grants
     * are deleted and not at all for an eviction or a clear.
     *
     * @param deviceId The removed device's public key hex.
     * @param droppedGrants The number of `key_sharing_policies` rows deleted.
     */
    fun logPeerGrantsDropped(deviceId: String, droppedGrants: Int) {
        val details = JSONObject().apply {
            put("reason", "peer_unpaired")
            put("droppedGrants", droppedGrants)
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.KEY_SHARING_CHANGED,
                deviceId = deviceId,
                success = true,
                details = details.toString()
            )
        )
    }

    /**
     * Log a connection establishment.
     *
     * @param deviceId The device identifier.
     * @param deviceName The device name.
     * @param connectionType The type of connection (e.g., "BLE", "USB").
     */
    fun logConnectionEstablished(
        deviceId: String,
        deviceName: String,
        connectionType: String
    ) {
        val details = JSONObject().apply {
            put("connectionType", connectionType)
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.CONNECTION_ESTABLISHED,
                deviceId = deviceId,
                deviceName = deviceName,
                success = true,
                details = details.toString()
            )
        )
    }

    /**
     * Log a connection closure.
     *
     * @param deviceId The device identifier.
     * @param deviceName The device name.
     * @param reason The reason for closure (e.g., "user_initiated", "timeout").
     * @param durationMs Connection duration in milliseconds.
     */
    fun logConnectionClosed(
        deviceId: String,
        deviceName: String,
        reason: String? = null,
        durationMs: Long? = null
    ) {
        val details = reason?.let {
            JSONObject().apply { put("reason", it) }.toString()
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.CONNECTION_CLOSED,
                deviceId = deviceId,
                deviceName = deviceName,
                success = true,
                details = details,
                durationMs = durationMs
            )
        )
    }

    /**
     * Log a device attestation verification.
     *
     * @param deviceId The device identifier.
     * @param deviceName The device name.
     * @param success Whether verification succeeded.
     * @param errorMessage Error message if failed.
     */
    fun logDeviceAttested(
        deviceId: String,
        deviceName: String,
        success: Boolean = true,
        errorMessage: String? = null
    ) {
        log(
            AuditLogEntity(
                operationType = AuditOperationType.DEVICE_ATTESTED,
                deviceId = deviceId,
                deviceName = deviceName,
                success = success,
                errorMessage = errorMessage
            )
        )
    }

    /**
     * Log a device enrollment that was refused before any certificate was issued.
     *
     * The refusal is recorded as a failed attestation, as [logDeviceAttested]
     * would, plus the case that classifies it. The case goes in the structured
     * details so refusals can be filtered on it — a device that answered the
     * credential challenge with the wrong secret and one that never answered at
     * all are different findings, and reading them apart must not depend on
     * parsing the message. [detail] is the human-readable half and stays in the
     * error message where every existing reader already looks for it.
     *
     * @param deviceId The device identifier.
     * @param deviceName The device name.
     * @param refusalCase The stable case name, from `EnrollmentRefusal.auditName`.
     * @param detail What specifically failed inside that case.
     */
    fun logDeviceEnrollmentRefused(
        deviceId: String,
        deviceName: String,
        refusalCase: String,
        detail: String
    ) {
        val details = JSONObject().apply {
            put("refusalCase", refusalCase)
            put("detail", detail)
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.DEVICE_ATTESTED,
                deviceId = deviceId,
                deviceName = deviceName,
                success = false,
                errorMessage = detail,
                details = details.toString()
            )
        )
    }

    /**
     * Log that an external CA issued this device a credential.
     *
     * [notAfter] is recorded because it is the re-attestation deadline: the
     * credential's expiry is how the issuing authority states how often it
     * wants fresh proof, so an operator reading the log can see when this
     * device must present itself again.
     *
     * @param caSubject Distinguished name of the issuing authority.
     * @param fingerprint SHA-256 of the issued certificate, hex.
     * @param notAfter Expiry in epoch milliseconds.
     */
    fun logDeviceEnrolled(
        caSubject: String,
        fingerprint: String,
        notAfter: Long
    ) {
        val details = JSONObject().apply {
            put("caSubject", caSubject)
            put("fingerprint", fingerprint)
            put("notAfter", notAfter)
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.DEVICE_ENROLLED,
                success = true,
                details = details.toString()
            )
        )
    }

    // -------------------------------------------------------------------------
    // Configuration Operations
    // -------------------------------------------------------------------------

    /**
     * Log a settings change.
     *
     * @param settingName The name of the setting that was changed.
     * @param oldValue The previous value (as a string).
     * @param newValue The new value (as a string).
     */
    fun logSettingsChanged(
        settingName: String,
        oldValue: String? = null,
        newValue: String
    ) {
        val details = JSONObject().apply {
            put("setting", settingName)
            oldValue?.let { put("oldValue", it) }
            put("newValue", newValue)
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.SETTINGS_CHANGED,
                success = true,
                details = details.toString()
            )
        )
    }

    /**
     * Log a trust store certificate import.
     *
     * @param certSubject The certificate subject.
     * @param certFingerprint The certificate fingerprint.
     * @param source The source URL or file path.
     */
    fun logTrustStoreImport(
        certSubject: String,
        certFingerprint: String,
        source: String
    ) {
        val details = JSONObject().apply {
            put("subject", certSubject)
            put("fingerprint", certFingerprint)
            put("source", source)
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.TRUST_STORE_IMPORT,
                success = true,
                details = details.toString()
            )
        )
    }

    /**
     * Log a trust store certificate deletion.
     *
     * @param certSubject The certificate subject.
     * @param certFingerprint The certificate fingerprint.
     */
    fun logTrustStoreDelete(certSubject: String, certFingerprint: String) {
        val details = JSONObject().apply {
            put("subject", certSubject)
            put("fingerprint", certFingerprint)
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.TRUST_STORE_DELETE,
                success = true,
                details = details.toString()
            )
        )
    }

    // -------------------------------------------------------------------------
    // Security Events
    // -------------------------------------------------------------------------

    /**
     * Log a successful biometric authentication.
     *
     * @param purpose The purpose of the authentication.
     */
    fun logBiometricSuccess(purpose: String) {
        val details = JSONObject().apply {
            put("purpose", purpose)
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.BIOMETRIC_SUCCESS,
                success = true,
                details = details.toString()
            )
        )
    }

    /**
     * Log a failed biometric authentication.
     *
     * @param purpose The purpose of the authentication.
     * @param errorCode The biometric error code.
     */
    fun logBiometricFailure(purpose: String, errorCode: Int) {
        val details = JSONObject().apply {
            put("purpose", purpose)
            put("errorCode", errorCode)
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.BIOMETRIC_FAILURE,
                success = false,
                details = details.toString()
            )
        )
    }

    /**
     * Log a policy denial event.
     *
     * @param keyId The key ID involved (if applicable).
     * @param keyLabel The key label (if applicable).
     * @param deviceId The device ID involved (if applicable).
     * @param deviceName The device name (if applicable).
     * @param reason The reason for denial.
     */
    fun logPolicyDenied(
        keyId: String? = null,
        keyLabel: String? = null,
        deviceId: String? = null,
        deviceName: String? = null,
        reason: String
    ) {
        val details = JSONObject().apply {
            put("reason", reason)
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.POLICY_DENIED,
                keyId = keyId,
                keyLabel = keyLabel,
                deviceId = deviceId,
                deviceName = deviceName,
                success = false,
                details = details.toString()
            )
        )
    }

    // -------------------------------------------------------------------------
    // Service Events
    // -------------------------------------------------------------------------

    /**
     * Log service start event.
     */
    fun logServiceStarted() {
        log(
            AuditLogEntity(
                operationType = AuditOperationType.SERVICE_STARTED,
                success = true
            )
        )
    }

    /**
     * Log service stop event.
     *
     * @param reason The reason for stopping.
     */
    fun logServiceStopped(reason: String? = null) {
        val details = reason?.let {
            JSONObject().apply { put("reason", it) }.toString()
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.SERVICE_STOPPED,
                success = true,
                details = details
            )
        )
    }

    // -------------------------------------------------------------------------
    // Certificate Operations
    // -------------------------------------------------------------------------

    /**
     * Log a certificate issuance event.
     *
     * @param serialNumber The certificate serial number (hex).
     * @param subjectDN The certificate subject distinguished name.
     * @param profile The certificate profile used.
     */
    fun logCertificateIssued(
        serialNumber: String,
        subjectDN: String,
        profile: String
    ) {
        val details = JSONObject().apply {
            put("serialNumber", serialNumber)
            put("subjectDN", subjectDN)
            put("profile", profile)
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.CERTIFICATE_ISSUED,
                success = true,
                details = details.toString()
            )
        )
    }

    /**
     * Log a certificate revocation event.
     *
     * @param serialNumber The certificate serial number (hex).
     * @param subjectDN The certificate subject distinguished name.
     * @param reason The RFC 5280 CRLReason code.
     */
    fun logCertificateRevoked(
        serialNumber: String,
        subjectDN: String,
        reason: Int
    ) {
        val details = JSONObject().apply {
            put("serialNumber", serialNumber)
            put("subjectDN", subjectDN)
            put("reason", reason)
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.CERTIFICATE_REVOKED,
                success = true,
                details = details.toString()
            )
        )
    }

    /**
     * Log a CSR signing event.
     *
     * @param serialNumber The issued certificate serial number (hex).
     * @param subjectDN The certificate subject distinguished name.
     * @param profile The certificate profile used.
     */
    fun logCSRSigned(
        serialNumber: String,
        subjectDN: String,
        profile: String
    ) {
        val details = JSONObject().apply {
            put("serialNumber", serialNumber)
            put("subjectDN", subjectDN)
            put("profile", profile)
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.CSR_SIGNED,
                success = true,
                details = details.toString()
            )
        )
    }

    /**
     * Log a CRL generation event.
     *
     * @param entryCount The number of revoked certificate entries in the CRL.
     */
    fun logCRLGenerated(entryCount: Int) {
        val details = JSONObject().apply {
            put("entryCount", entryCount)
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.CRL_GENERATED,
                success = true,
                details = details.toString()
            )
        )
    }

    /**
     * Log a certificate export event.
     *
     * @param serialNumber The certificate serial number (hex).
     * @param subjectDN The certificate subject distinguished name.
     * @param format The export format (e.g., "PEM", "DER").
     */
    fun logCertificateExported(
        serialNumber: String,
        subjectDN: String,
        format: String
    ) {
        val details = JSONObject().apply {
            put("serialNumber", serialNumber)
            put("subjectDN", subjectDN)
            put("format", format)
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.CERTIFICATE_EXPORTED,
                success = true,
                details = details.toString()
            )
        )
    }

    // -------------------------------------------------------------------------
    // File and Media Operations
    // -------------------------------------------------------------------------

    fun logFileSigned(keyId: String, keyLabel: String, fileName: String? = null) {
        val details = fileName?.let {
            JSONObject().apply { put("fileName", it) }.toString()
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.FILE_SIGNED,
                keyId = keyId,
                keyLabel = keyLabel,
                success = true,
                details = details
            )
        )
    }

    fun logFileVerified(fileName: String? = null, signerCount: Int = 0, verified: Boolean = true) {
        val details = JSONObject().apply {
            fileName?.let { put("fileName", it) }
            put("signerCount", signerCount)
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.FILE_VERIFIED,
                success = verified,
                details = details.toString()
            )
        )
    }

    fun logFileEncrypted(keyId: String? = null, recipientFingerprint: String? = null, fileName: String? = null) {
        val details = JSONObject().apply {
            recipientFingerprint?.let { put("recipientFingerprint", it) }
            fileName?.let { put("fileName", it) }
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.FILE_ENCRYPTED,
                keyId = keyId,
                success = true,
                details = details.toString()
            )
        )
    }

    fun logFileDecrypted(keyId: String, fileName: String? = null) {
        val details = fileName?.let {
            JSONObject().apply { put("fileName", it) }.toString()
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.FILE_DECRYPTED,
                keyId = keyId,
                success = true,
                details = details
            )
        )
    }

    fun logMediaAutoSigned(keyId: String, keyLabel: String, uri: String? = null) {
        val details = uri?.let {
            JSONObject().apply { put("uri", it) }.toString()
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.MEDIA_AUTO_SIGNED,
                keyId = keyId,
                keyLabel = keyLabel,
                success = true,
                details = details
            )
        )
    }

    // -------------------------------------------------------------------------
    // Contact Operations
    // -------------------------------------------------------------------------

    fun logContactImported(name: String, fingerprint: String, source: String) {
        val details = JSONObject().apply {
            put("name", name)
            put("fingerprint", fingerprint)
            put("source", source)
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.CONTACT_IMPORTED,
                success = true,
                details = details.toString()
            )
        )
    }

    fun logContactDeleted(name: String, fingerprint: String) {
        val details = JSONObject().apply {
            put("name", name)
            put("fingerprint", fingerprint)
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.CONTACT_DELETED,
                success = true,
                details = details.toString()
            )
        )
    }

    // -------------------------------------------------------------------------
    // OATH/TOTP Operations
    // -------------------------------------------------------------------------

    fun logOathCredentialCreated(oathId: String, issuer: String?, accountName: String, oathType: String) {
        val details = JSONObject().apply {
            issuer?.let { put("issuer", it) }
            put("accountName", accountName)
            put("oathType", oathType)
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.OATH_CREDENTIAL_CREATED,
                keyId = oathId,
                keyLabel = issuer?.let { "$it:$accountName" } ?: accountName,
                success = true,
                details = details.toString()
            )
        )
    }

    fun logOathCredentialDeleted(oathId: String, issuer: String?, accountName: String) {
        log(
            AuditLogEntity(
                operationType = AuditOperationType.OATH_CREDENTIAL_DELETED,
                keyId = oathId,
                keyLabel = issuer?.let { "$it:$accountName" } ?: accountName,
                success = true
            )
        )
    }

    fun logOathCodeGenerated(oathId: String, issuer: String?, accountName: String) {
        log(
            AuditLogEntity(
                operationType = AuditOperationType.OATH_CODE_GENERATED,
                keyId = oathId,
                keyLabel = issuer?.let { "$it:$accountName" } ?: accountName,
                success = true
            )
        )
    }

    fun logOathSyncPerformed(deviceId: String, deviceName: String, count: Int) {
        val details = JSONObject().apply {
            put("credentialCount", count)
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.OATH_SYNC_PERFORMED,
                deviceId = deviceId,
                deviceName = deviceName,
                success = true,
                details = details.toString()
            )
        )
    }

    // -------------------------------------------------------------------------
    // Co-Signing Operations
    // -------------------------------------------------------------------------

    fun logCoSignInitiated(contentHash: String, witnessCount: Int = 0) {
        val details = JSONObject().apply {
            put("contentHash", contentHash)
            put("witnessCount", witnessCount)
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.COSIGN_INITIATED,
                success = true,
                details = details.toString()
            )
        )
    }

    fun logCoSignReceived(contentHash: String, signerFingerprint: String) {
        val details = JSONObject().apply {
            put("contentHash", contentHash)
            put("signerFingerprint", signerFingerprint)
        }
        log(
            AuditLogEntity(
                operationType = AuditOperationType.COSIGN_RECEIVED,
                success = true,
                details = details.toString()
            )
        )
    }

    // -------------------------------------------------------------------------
    // PIN Operations
    // -------------------------------------------------------------------------

    fun logPinSet(pinType: String) {
        val opType = if (pinType == "SO_PIN") AuditOperationType.PIN_SO_SET else AuditOperationType.PIN_USER_SET
        val details = JSONObject().apply { put("pinType", pinType) }
        log(AuditLogEntity(operationType = opType, success = true, details = details.toString()))
    }

    fun logPinChanged(pinType: String) {
        val opType = if (pinType == "SO_PIN") AuditOperationType.PIN_SO_CHANGED else AuditOperationType.PIN_USER_CHANGED
        val details = JSONObject().apply { put("pinType", pinType) }
        log(AuditLogEntity(operationType = opType, success = true, details = details.toString()))
    }

    fun logPinVerificationSuccess(pinType: String) {
        val details = JSONObject().apply { put("pinType", pinType) }
        log(AuditLogEntity(operationType = AuditOperationType.PIN_VERIFICATION_SUCCESS, success = true, details = details.toString()))
    }

    fun logPinVerificationFailed(pinType: String, failedAttempts: Int) {
        val details = JSONObject().apply {
            put("pinType", pinType)
            put("failedAttempts", failedAttempts)
        }
        log(AuditLogEntity(operationType = AuditOperationType.PIN_VERIFICATION_FAILED, success = false, details = details.toString()))
    }

    fun logPinLockoutTriggered(pinType: String, lockoutUntil: Long) {
        val details = JSONObject().apply {
            put("pinType", pinType)
            put("lockoutUntil", lockoutUntil)
        }
        log(AuditLogEntity(operationType = AuditOperationType.PIN_LOCKOUT_TRIGGERED, success = false, details = details.toString()))
    }

    fun logPinLockoutReset() {
        log(AuditLogEntity(operationType = AuditOperationType.PIN_LOCKOUT_RESET, success = true))
    }

    // -------------------------------------------------------------------------
    // PIV Operations
    // -------------------------------------------------------------------------

    fun logPivKeyGenerated(slotId: String, algorithm: String) {
        val details = JSONObject().apply {
            put("slotId", slotId)
            put("algorithm", algorithm)
        }
        log(AuditLogEntity(operationType = AuditOperationType.PIV_KEY_GENERATED, keyId = "piv_$slotId", keyType = "piv", success = true, details = details.toString()))
    }

    fun logPivCertImported(slotId: String, subject: String? = null) {
        val details = JSONObject().apply {
            put("slotId", slotId)
            subject?.let { put("subject", it) }
        }
        log(AuditLogEntity(operationType = AuditOperationType.PIV_CERT_IMPORTED, keyId = "piv_$slotId", keyType = "piv", success = true, details = details.toString()))
    }

    fun logPivSignRequest(slotId: String, algorithm: String, success: Boolean = true, errorMessage: String? = null, durationMs: Long? = null) {
        val details = JSONObject().apply {
            put("slotId", slotId)
            put("algorithm", algorithm)
        }
        log(AuditLogEntity(operationType = AuditOperationType.PIV_SIGN_REQUEST, keyId = "piv_$slotId", keyType = "piv", success = success, errorMessage = errorMessage, details = details.toString(), durationMs = durationMs))
    }

    fun logPivKeyDeleted(slotId: String) {
        val details = JSONObject().apply { put("slotId", slotId) }
        log(AuditLogEntity(operationType = AuditOperationType.PIV_KEY_DELETED, keyId = "piv_$slotId", keyType = "piv", success = true, details = details.toString()))
    }

    // -------------------------------------------------------------------------
    // Password Vault Operations
    // -------------------------------------------------------------------------
    // Only the entry id and its display name are recorded: never the
    // password, username, URL or notes.

    fun logPasswordCreated(passwordId: String, name: String) =
        logPasswordEdit(AuditOperationType.PASSWORD_CREATED, passwordId, name)

    fun logPasswordDeleted(passwordId: String, name: String) =
        logPasswordEdit(AuditOperationType.PASSWORD_DELETED, passwordId, name)

    private fun logPasswordEdit(type: AuditOperationType, passwordId: String, name: String) {
        val details = JSONObject().apply { put("name", name) }
        log(
            AuditLogEntity(
                operationType = type,
                keyId = passwordId,
                keyLabel = name,
                keyType = "password",
                success = true,
                details = details.toString()
            )
        )
    }

    // -------------------------------------------------------------------------
    // Desktop Backups
    // -------------------------------------------------------------------------

    /**
     * Log a backup a paired desktop stored on the phone. Records the id and
     * size only; the backup bytes never enter the log.
     */
    fun logBackupCreated(backupId: String, sizeBytes: Int, deviceId: String?, deviceName: String?) {
        val details = JSONObject().apply {
            put("backupId", backupId)
            put("sizeBytes", sizeBytes)
        }
        log(AuditLogEntity(operationType = AuditOperationType.BACKUP_CREATED, deviceId = deviceId, deviceName = deviceName, success = true, details = details.toString()))
    }

    /**
     * Log a stored backup a paired desktop fetched from the phone. Records the
     * id and size only; the backup bytes never enter the log.
     */
    fun logBackupRestored(backupId: String, sizeBytes: Int, deviceId: String?, deviceName: String?) {
        val details = JSONObject().apply {
            put("backupId", backupId)
            put("sizeBytes", sizeBytes)
        }
        log(AuditLogEntity(operationType = AuditOperationType.BACKUP_RESTORED, deviceId = deviceId, deviceName = deviceName, success = true, details = details.toString()))
    }

    // -------------------------------------------------------------------------
    // Internal Methods
    // -------------------------------------------------------------------------

    /**
     * Internal method to asynchronously write an audit log entry.
     */
    private fun log(entry: AuditLogEntity) {
        val dao = daoRef.get()
        val scope = scopeRef.get()

        if (dao == null || scope == null) {
            Log.w(TAG, "AuditLogger not initialized, dropping entry: ${entry.operationType}")
            return
        }

        scope.launch {
            try {
                dao.insert(entry)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to insert audit log entry", e)
            }
        }
    }

    /**
     * Apply retention policy by removing old entries and enforcing max count.
     */
    private suspend fun applyRetentionPolicy(dao: AuditLogDao) {
        val cutoffTime = System.currentTimeMillis() - DEFAULT_RETENTION_MS
        val deletedByAge = dao.deleteOlderThan(cutoffTime)
        if (deletedByAge > 0) {
            Log.i(TAG, "Deleted $deletedByAge audit entries older than 90 days")
        }

        val deletedByCount = dao.deleteExceedingCount(MAX_ENTRIES)
        if (deletedByCount > 0) {
            Log.i(TAG, "Deleted $deletedByCount audit entries exceeding max count")
        }
    }
}
