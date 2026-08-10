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
package com.automatethethings.xkey.ca

import android.content.Context
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.automatethethings.xkey.util.getStringOrNull
import org.json.JSONArray
import org.json.JSONObject

/**
 * Represents an enrolled device with its attestation baseline and certificates.
 */
data class EnrolledDevice(
    val deviceId: String,                    // Device identifier (Noise public key fingerprint)
    val publicKeyHex: String,                // Noise static public key

    // EK verification data (for full attestation mode)
    val ekCertificateFingerprint: String? = null,
    val ekCertificateDER: ByteArray? = null,
    val ekVerifiedAt: Long? = null,

    // IAK certificate
    val iakCertificateDER: ByteArray? = null,

    // IDevID certificate
    val idevidCertificateDER: ByteArray? = null,
    val idevidCertificateChain: List<ByteArray>? = null,

    // TLS certificates
    val tlsServerCertificateDER: ByteArray? = null,
    val tlsServerCertificateChain: List<ByteArray>? = null,
    val tlsClientCertificateDER: ByteArray? = null,
    val tlsClientCertificateChain: List<ByteArray>? = null,

    // SSH certificates
    val sshUserCertificate: String? = null,
    val sshHostCertificate: String? = null,

    // Initial attestation quote (baseline)
    val initialQuote: ByteArray? = null,        // TPMS_QUOTE_INFO
    val initialQuoteSignature: ByteArray? = null,
    val initialPCRs: ByteArray? = null,         // PCR values at enrollment
    val initialEventLog: ByteArray? = null,     // TPM event log (optional)
    val enrolledAt: Long,

    // Trust status
    val trustLevel: String,                     // "full-attestation", "android-ca", "external-ca"
    val lastVerifiedAt: Long? = null
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("deviceId", deviceId)
        put("publicKeyHex", publicKeyHex)
        ekCertificateFingerprint?.let { put("ekCertificateFingerprint", it) }
        ekCertificateDER?.let { put("ekCertificateDER", Base64.encodeToString(it, Base64.NO_WRAP)) }
        ekVerifiedAt?.let { put("ekVerifiedAt", it) }
        iakCertificateDER?.let { put("iakCertificateDER", Base64.encodeToString(it, Base64.NO_WRAP)) }
        idevidCertificateDER?.let { put("idevidCertificateDER", Base64.encodeToString(it, Base64.NO_WRAP)) }
        idevidCertificateChain?.let { chain ->
            put("idevidCertificateChain", JSONArray(chain.map { Base64.encodeToString(it, Base64.NO_WRAP) }))
        }
        tlsServerCertificateDER?.let { put("tlsServerCertificateDER", Base64.encodeToString(it, Base64.NO_WRAP)) }
        tlsServerCertificateChain?.let { chain ->
            put("tlsServerCertificateChain", JSONArray(chain.map { Base64.encodeToString(it, Base64.NO_WRAP) }))
        }
        tlsClientCertificateDER?.let { put("tlsClientCertificateDER", Base64.encodeToString(it, Base64.NO_WRAP)) }
        tlsClientCertificateChain?.let { chain ->
            put("tlsClientCertificateChain", JSONArray(chain.map { Base64.encodeToString(it, Base64.NO_WRAP) }))
        }
        sshUserCertificate?.let { put("sshUserCertificate", it) }
        sshHostCertificate?.let { put("sshHostCertificate", it) }
        initialQuote?.let { put("initialQuote", Base64.encodeToString(it, Base64.NO_WRAP)) }
        initialQuoteSignature?.let { put("initialQuoteSignature", Base64.encodeToString(it, Base64.NO_WRAP)) }
        initialPCRs?.let { put("initialPCRs", Base64.encodeToString(it, Base64.NO_WRAP)) }
        initialEventLog?.let { put("initialEventLog", Base64.encodeToString(it, Base64.NO_WRAP)) }
        put("enrolledAt", enrolledAt)
        put("trustLevel", trustLevel)
        lastVerifiedAt?.let { put("lastVerifiedAt", it) }
    }

    companion object {
        private fun decodeChain(obj: JSONObject, key: String): List<ByteArray>? {
            return obj.optJSONArray(key)?.let { arr ->
                (0 until arr.length()).map { i ->
                    Base64.decode(arr.getString(i), Base64.NO_WRAP)
                }
            }
        }

        fun fromJson(obj: JSONObject): EnrolledDevice {
            return EnrolledDevice(
                deviceId = obj.getString("deviceId"),
                publicKeyHex = obj.getString("publicKeyHex"),
                ekCertificateFingerprint = obj.getStringOrNull("ekCertificateFingerprint"),
                ekCertificateDER = obj.getStringOrNull("ekCertificateDER")?.let {
                    Base64.decode(it, Base64.NO_WRAP)
                },
                ekVerifiedAt = if (obj.has("ekVerifiedAt")) obj.getLong("ekVerifiedAt") else null,
                iakCertificateDER = obj.getStringOrNull("iakCertificateDER")?.let {
                    Base64.decode(it, Base64.NO_WRAP)
                },
                idevidCertificateDER = obj.getStringOrNull("idevidCertificateDER")?.let {
                    Base64.decode(it, Base64.NO_WRAP)
                },
                idevidCertificateChain = decodeChain(obj, "idevidCertificateChain"),
                tlsServerCertificateDER = obj.getStringOrNull("tlsServerCertificateDER")?.let {
                    Base64.decode(it, Base64.NO_WRAP)
                },
                tlsServerCertificateChain = decodeChain(obj, "tlsServerCertificateChain"),
                tlsClientCertificateDER = obj.getStringOrNull("tlsClientCertificateDER")?.let {
                    Base64.decode(it, Base64.NO_WRAP)
                },
                tlsClientCertificateChain = decodeChain(obj, "tlsClientCertificateChain"),
                sshUserCertificate = obj.getStringOrNull("sshUserCertificate"),
                sshHostCertificate = obj.getStringOrNull("sshHostCertificate"),
                initialQuote = obj.getStringOrNull("initialQuote")?.let {
                    Base64.decode(it, Base64.NO_WRAP)
                },
                initialQuoteSignature = obj.getStringOrNull("initialQuoteSignature")?.let {
                    Base64.decode(it, Base64.NO_WRAP)
                },
                initialPCRs = obj.getStringOrNull("initialPCRs")?.let {
                    Base64.decode(it, Base64.NO_WRAP)
                },
                initialEventLog = obj.getStringOrNull("initialEventLog")?.let {
                    Base64.decode(it, Base64.NO_WRAP)
                },
                enrolledAt = obj.getLong("enrolledAt"),
                trustLevel = obj.getString("trustLevel"),
                lastVerifiedAt = if (obj.has("lastVerifiedAt")) obj.getLong("lastVerifiedAt") else null
            )
        }
    }

    // ByteArray equals/hashCode
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is EnrolledDevice) return false
        return deviceId == other.deviceId && publicKeyHex == other.publicKeyHex
    }

    override fun hashCode(): Int = deviceId.hashCode()

    /**
     * Check if this device has full attestation data.
     */
    fun hasFullAttestation(): Boolean = ekCertificateDER != null && initialQuote != null

    /**
     * Check if this device has an issued IDevID certificate.
     */
    fun hasIDevIDCertificate(): Boolean = idevidCertificateDER != null

    fun hasTLSServerCertificate(): Boolean = tlsServerCertificateDER != null

    fun hasTLSClientCertificate(): Boolean = tlsClientCertificateDER != null

    fun hasSSHUserCertificate(): Boolean = sshUserCertificate != null

    fun hasSSHHostCertificate(): Boolean = sshHostCertificate != null
}

/**
 * Why a device enrollment was refused.
 *
 * The ceremony in `GattServer` refuses by name rather than warning and
 * continuing, and the record it leaves behind is the only diagnostic that
 * survives the session. A free-text reason makes every refusal look alike, and
 * two of them are not alike at all: [ActivationMismatch] means the device
 * answered the credential challenge with the wrong secret — it does not hold
 * the keys it claims — while [ActivationUnsupported] means no answer was ever
 * obtained. The first is a device that lied or an attack; the second is an
 * interoperability problem to diagnose. They must be distinguishable without
 * reading the message.
 *
 * [detail] stays free text on purpose: it is the human-readable half, and it
 * carries the exception message or the offending value that names the specific
 * failure inside the case.
 */
sealed interface EnrollmentRefusal {

    val detail: String

    /** The enrollment package would not parse or its fields disagreed. */
    data class MalformedPackage(override val detail: String) : EnrollmentRefusal

    /** The EK certificate was absent, expired, or did not chain to a trusted root. */
    data class UntrustedEndorsement(override val detail: String) : EnrollmentRefusal

    /** The device returned the wrong secret: it does not hold the keys it claims. */
    data class ActivationMismatch(override val detail: String) : EnrollmentRefusal

    /** We could not complete the challenge at all — transport, timeout, or refusal. */
    data class ActivationUnsupported(override val detail: String) : EnrollmentRefusal

    /** The quote did not verify, or did not answer the nonce we sent. */
    data class QuoteInvalid(override val detail: String) : EnrollmentRefusal

    /**
     * The signing key was not certified by the attestation key, so nothing
     * shows it lives in the same TPM.
     *
     * Distinct from [ActivationMismatch], which is a device that answered
     * wrongly. Here the device answered everything correctly *about the
     * attestation key*: it holds the endorsement key, it passed activation, its
     * quote verified. What it never showed is that the key it wants certified
     * is inside that TPM at all — the CSR's self-signature proves possession,
     * and a key generated in software is possessed just as fully.
     */
    data class SigningKeyNotCertified(override val detail: String) : EnrollmentRefusal

    /**
     * The stable name of this case.
     *
     * It is what reaches the audit log and what a stored record is read back
     * through, so it is written out here rather than derived from the class
     * name: renaming a case must not silently reclassify records already
     * written.
     */
    val auditName: String
        get() = when (this) {
            is MalformedPackage -> MALFORMED_PACKAGE
            is UntrustedEndorsement -> UNTRUSTED_ENDORSEMENT
            is ActivationMismatch -> ACTIVATION_MISMATCH
            is ActivationUnsupported -> ACTIVATION_UNSUPPORTED
            is QuoteInvalid -> QUOTE_INVALID
            is SigningKeyNotCertified -> SIGNING_KEY_NOT_CERTIFIED
        }

    companion object {
        const val MALFORMED_PACKAGE = "malformed-package"
        const val UNTRUSTED_ENDORSEMENT = "untrusted-endorsement"
        const val ACTIVATION_MISMATCH = "activation-mismatch"
        const val ACTIVATION_UNSUPPORTED = "activation-unsupported"
        const val QUOTE_INVALID = "quote-invalid"
        const val SIGNING_KEY_NOT_CERTIFIED = "signing-key-not-certified"

        /**
         * Rebuilds a refusal from the [auditName] and [detail] it was stored
         * with, or null for a name this build does not know — a record written
         * by a newer build must not crash the screen reading it.
         */
        fun of(auditName: String, detail: String): EnrollmentRefusal? = when (auditName) {
            MALFORMED_PACKAGE -> MalformedPackage(detail)
            UNTRUSTED_ENDORSEMENT -> UntrustedEndorsement(detail)
            ACTIVATION_MISMATCH -> ActivationMismatch(detail)
            ACTIVATION_UNSUPPORTED -> ActivationUnsupported(detail)
            QUOTE_INVALID -> QuoteInvalid(detail)
            SIGNING_KEY_NOT_CERTIFIED -> SigningKeyNotCertified(detail)
            else -> null
        }
    }
}

/**
 * The last refusal recorded for a device.
 *
 * A refused device is by definition not enrolled, so this cannot hang off
 * [EnrolledDevice]; it is kept beside the enrollment list under the device id
 * the ceremony refused, which is the same Noise public key the paired-device
 * screens are keyed on.
 */
data class EnrollmentRefusalRecord(
    val deviceId: String,
    val deviceName: String,
    val refusal: EnrollmentRefusal,
    val refusedAt: Long
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("deviceId", deviceId)
        put("deviceName", deviceName)
        put("case", refusal.auditName)
        put("detail", refusal.detail)
        put("refusedAt", refusedAt)
    }

    companion object {
        /** Null when the stored case is not one this build knows. */
        fun fromJson(obj: JSONObject): EnrollmentRefusalRecord? {
            val refusal = EnrollmentRefusal.of(
                obj.optString("case"),
                obj.optString("detail")
            ) ?: return null
            return EnrollmentRefusalRecord(
                deviceId = obj.getString("deviceId"),
                deviceName = obj.optString("deviceName"),
                refusal = refusal,
                refusedAt = obj.optLong("refusedAt")
            )
        }
    }
}

/**
 * Result of quote verification against baseline.
 */
sealed class QuoteVerificationResult {
    data class Valid(val pcrDrift: List<Int>) : QuoteVerificationResult()
    data class Invalid(val reason: String) : QuoteVerificationResult()
    data object NotEnrolled : QuoteVerificationResult()
}

/**
 * Repository for storing enrolled device data with attestation baselines.
 *
 * Uses EncryptedSharedPreferences for secure storage.
 */
class EnrolledDeviceRepository(context: Context) {

    private val prefs = EncryptedSharedPreferences.create(
        context,
        PREFS_NAME,
        MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    /**
     * Enroll a device with its attestation baseline.
     */
    fun enroll(device: EnrolledDevice) {
        val devices = getAllDevices().toMutableList()
        // Remove existing if re-enrolling
        devices.removeAll { it.deviceId == device.deviceId }
        devices.add(device)
        saveDevices(devices)
        // A device that has just been certified is no longer refused; leaving
        // the old record would show a stale reason beside a valid certificate.
        clearRefusal(device.deviceId)
    }

    /**
     * Get an enrolled device by its device ID.
     */
    fun getDevice(deviceId: String): EnrolledDevice? {
        return getAllDevices().find { it.deviceId == deviceId }
    }

    /**
     * Get an enrolled device by its public key hex.
     */
    fun getDeviceByPublicKey(publicKeyHex: String): EnrolledDevice? {
        return getAllDevices().find { it.publicKeyHex == publicKeyHex }
    }

    /**
     * Check if a device is enrolled.
     */
    fun isEnrolled(deviceId: String): Boolean {
        return getAllDevices().any { it.deviceId == deviceId }
    }

    /**
     * Update the last verification time for a device.
     */
    fun updateLastVerified(deviceId: String) {
        val devices = getAllDevices().toMutableList()
        val idx = devices.indexOfFirst { it.deviceId == deviceId }
        if (idx >= 0) {
            devices[idx] = devices[idx].copy(lastVerifiedAt = System.currentTimeMillis())
            saveDevices(devices)
        }
    }

    /**
     * Update IDevID certificate for an enrolled device.
     */
    fun updateIDevIDCertificate(
        deviceId: String,
        certificateDER: ByteArray,
        chain: List<ByteArray>?
    ) {
        val devices = getAllDevices().toMutableList()
        val idx = devices.indexOfFirst { it.deviceId == deviceId }
        if (idx >= 0) {
            devices[idx] = devices[idx].copy(
                idevidCertificateDER = certificateDER,
                idevidCertificateChain = chain
            )
            saveDevices(devices)
        }
    }

    /**
     * Update TLS server certificate for an enrolled device.
     */
    fun updateTLSServerCertificate(
        deviceId: String,
        certificateDER: ByteArray,
        chain: List<ByteArray>?
    ) {
        val devices = getAllDevices().toMutableList()
        val idx = devices.indexOfFirst { it.deviceId == deviceId }
        if (idx >= 0) {
            devices[idx] = devices[idx].copy(
                tlsServerCertificateDER = certificateDER,
                tlsServerCertificateChain = chain
            )
            saveDevices(devices)
        }
    }

    /**
     * Update TLS client certificate for an enrolled device.
     */
    fun updateTLSClientCertificate(
        deviceId: String,
        certificateDER: ByteArray,
        chain: List<ByteArray>?
    ) {
        val devices = getAllDevices().toMutableList()
        val idx = devices.indexOfFirst { it.deviceId == deviceId }
        if (idx >= 0) {
            devices[idx] = devices[idx].copy(
                tlsClientCertificateDER = certificateDER,
                tlsClientCertificateChain = chain
            )
            saveDevices(devices)
        }
    }

    /**
     * Update SSH user certificate for an enrolled device.
     */
    fun updateSSHUserCertificate(deviceId: String, certificate: String) {
        val devices = getAllDevices().toMutableList()
        val idx = devices.indexOfFirst { it.deviceId == deviceId }
        if (idx >= 0) {
            devices[idx] = devices[idx].copy(sshUserCertificate = certificate)
            saveDevices(devices)
        }
    }

    /**
     * Update SSH host certificate for an enrolled device.
     */
    fun updateSSHHostCertificate(deviceId: String, certificate: String) {
        val devices = getAllDevices().toMutableList()
        val idx = devices.indexOfFirst { it.deviceId == deviceId }
        if (idx >= 0) {
            devices[idx] = devices[idx].copy(sshHostCertificate = certificate)
            saveDevices(devices)
        }
    }

    /**
     * Remove an enrolled device.
     */
    fun removeDevice(deviceId: String) {
        val devices = getAllDevices().toMutableList()
        devices.removeAll { it.deviceId == deviceId }
        saveDevices(devices)
        clearRefusal(deviceId)
    }

    // -------------------------------------------------------------------------
    // Enrollment refusals
    // -------------------------------------------------------------------------

    /**
     * Records [record] as the reason this device holds no certificate,
     * replacing any earlier refusal for the same device: only the most recent
     * attempt describes the state the device is in now.
     */
    fun recordRefusal(record: EnrollmentRefusalRecord) {
        val refusals = getAllRefusals().toMutableList()
        refusals.removeAll { it.deviceId == record.deviceId }
        refusals.add(record)
        saveRefusals(refusals)
    }

    /** The most recent refusal for [deviceId], or null if it was never refused. */
    fun lastRefusal(deviceId: String): EnrollmentRefusalRecord? =
        getAllRefusals().find { it.deviceId == deviceId }

    /** Forgets any refusal recorded for [deviceId]. */
    fun clearRefusal(deviceId: String) {
        val refusals = getAllRefusals().toMutableList()
        if (refusals.removeAll { it.deviceId == deviceId }) {
            saveRefusals(refusals)
        }
    }

    /** Every refusal on record, newest attempt per device. */
    fun getAllRefusals(): List<EnrollmentRefusalRecord> {
        val jsonStr = prefs.getString(KEY_REFUSALS, null) ?: return emptyList()
        return try {
            val arr = JSONArray(jsonStr)
            (0 until arr.length()).mapNotNull {
                EnrollmentRefusalRecord.fromJson(arr.getJSONObject(it))
            }
        } catch (e: Exception) {
            emptyList()
        }
    }

    /**
     * Get all enrolled devices.
     */
    fun getAllDevices(): List<EnrolledDevice> {
        val jsonStr = prefs.getString(KEY_DEVICES, null) ?: return emptyList()
        return try {
            val arr = JSONArray(jsonStr)
            (0 until arr.length()).map { EnrolledDevice.fromJson(arr.getJSONObject(it)) }
        } catch (e: Exception) {
            emptyList()
        }
    }

    /**
     * Clear all enrolled devices.
     */
    fun clear() {
        prefs.edit().remove(KEY_DEVICES).remove(KEY_REFUSALS).apply()
    }

    /**
     * Get count of enrolled devices.
     */
    fun getDeviceCount(): Int = getAllDevices().size

    private fun saveDevices(devices: List<EnrolledDevice>) {
        val arr = JSONArray()
        devices.forEach { arr.put(it.toJson()) }
        prefs.edit().putString(KEY_DEVICES, arr.toString()).apply()
    }

    private fun saveRefusals(refusals: List<EnrollmentRefusalRecord>) {
        val arr = JSONArray()
        refusals.forEach { arr.put(it.toJson()) }
        prefs.edit().putString(KEY_REFUSALS, arr.toString()).apply()
    }

    companion object {
        private const val PREFS_NAME = "xkey_enrolled_devices"
        private const val KEY_DEVICES = "enrolled_devices"
        private const val KEY_REFUSALS = "enrollment_refusals"
    }
}
