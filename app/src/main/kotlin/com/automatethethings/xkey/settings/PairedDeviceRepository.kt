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
package com.automatethethings.xkey.settings

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.util.getStringOrNull
import org.json.JSONArray
import org.json.JSONObject

/**
 * Data class representing a paired desktop/laptop device.
 */
data class PairedDeviceData(
    val publicKeyHex: String,
    val deviceName: String,
    val pairedAt: Long,
    // BLE address for phone-initiated connections (stored during pairing)
    val bleAddress: String? = null,
    // Attestation tracking
    val lastAttestationTime: Long? = null,
    val bootHashHex: String? = null,           // verifiedBootHash from RootOfTrust
    val bootStateVerified: Boolean = false,
    val securityLevel: String? = null,         // "software", "tee", "strongbox"
    val deviceFingerprint: String? = null,     // SHA256 of attestation root cert
    // Per-device settings
    val requireAttestationForKeyUse: Boolean = false,
    val requireAttestationForKeyAttestation: Boolean = true,
    val attestationGracePeriodMinutes: Int = 5,  // Default 5 minutes
    // Connection tracking
    val lastConnectedAt: Long? = null,
    val connectionCount: Long = 0,
    // IDevID certificate fields - for Phase 5 certificate verification
    val idevidCertificateDER: ByteArray? = null,     // The IDevID certificate (DER encoded)
    val idevidCertificateChain: List<ByteArray>? = null,  // Certificate chain (DER encoded)
    val idevidVerifiedAt: Long? = null,              // When IDevID was verified
    val idevidTrustLevel: String? = null,            // "android-ca", "external-ca", "untrusted"
    val idevidSubjectDN: String? = null,             // Certificate subject DN
    val idevidNotAfter: Long? = null                 // Certificate expiry timestamp
) {
    /**
     * Returns true if this device has a verified IDevID certificate.
     */
    fun hasVerifiedIDevID(): Boolean = idevidCertificateDER != null && idevidTrustLevel != null

    /**
     * Returns true if the IDevID certificate has expired.
     * Returns true if no expiry is set (conservative default).
     */
    fun isIDevIDExpired(): Boolean {
        val notAfter = idevidNotAfter ?: return true
        return System.currentTimeMillis() > notAfter
    }

    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("publicKeyHex", publicKeyHex)
            put("deviceName", deviceName)
            put("pairedAt", pairedAt)
            bleAddress?.let { put("bleAddress", it) }
            lastAttestationTime?.let { put("lastAttestationTime", it) }
            bootHashHex?.let { put("bootHashHex", it) }
            put("bootStateVerified", bootStateVerified)
            securityLevel?.let { put("securityLevel", it) }
            deviceFingerprint?.let { put("deviceFingerprint", it) }
            put("requireAttestationForKeyUse", requireAttestationForKeyUse)
            put("requireAttestationForKeyAttestation", requireAttestationForKeyAttestation)
            put("attestationGracePeriodMinutes", attestationGracePeriodMinutes)
            lastConnectedAt?.let { put("lastConnectedAt", it) }
            put("connectionCount", connectionCount)
            // IDevID certificate fields
            idevidCertificateDER?.let {
                put("idevidCertificateDER", Base64.encodeToString(it, Base64.NO_WRAP))
            }
            idevidCertificateChain?.let { chain ->
                val chainArray = JSONArray()
                for (cert in chain) {
                    chainArray.put(Base64.encodeToString(cert, Base64.NO_WRAP))
                }
                put("idevidCertificateChain", chainArray)
            }
            idevidVerifiedAt?.let { put("idevidVerifiedAt", it) }
            idevidTrustLevel?.let { put("idevidTrustLevel", it) }
            idevidSubjectDN?.let { put("idevidSubjectDN", it) }
            idevidNotAfter?.let { put("idevidNotAfter", it) }
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PairedDeviceData

        if (publicKeyHex != other.publicKeyHex) return false
        if (deviceName != other.deviceName) return false
        if (pairedAt != other.pairedAt) return false
        if (bleAddress != other.bleAddress) return false
        if (lastAttestationTime != other.lastAttestationTime) return false
        if (bootHashHex != other.bootHashHex) return false
        if (bootStateVerified != other.bootStateVerified) return false
        if (securityLevel != other.securityLevel) return false
        if (deviceFingerprint != other.deviceFingerprint) return false
        if (requireAttestationForKeyUse != other.requireAttestationForKeyUse) return false
        if (requireAttestationForKeyAttestation != other.requireAttestationForKeyAttestation) return false
        if (attestationGracePeriodMinutes != other.attestationGracePeriodMinutes) return false
        if (lastConnectedAt != other.lastConnectedAt) return false
        if (connectionCount != other.connectionCount) return false
        if (idevidCertificateDER != null) {
            if (other.idevidCertificateDER == null) return false
            if (!idevidCertificateDER.contentEquals(other.idevidCertificateDER)) return false
        } else if (other.idevidCertificateDER != null) return false
        if (idevidCertificateChain != null) {
            if (other.idevidCertificateChain == null) return false
            if (idevidCertificateChain.size != other.idevidCertificateChain.size) return false
            for (i in idevidCertificateChain.indices) {
                if (!idevidCertificateChain[i].contentEquals(other.idevidCertificateChain[i])) return false
            }
        } else if (other.idevidCertificateChain != null) return false
        if (idevidVerifiedAt != other.idevidVerifiedAt) return false
        if (idevidTrustLevel != other.idevidTrustLevel) return false
        if (idevidSubjectDN != other.idevidSubjectDN) return false
        if (idevidNotAfter != other.idevidNotAfter) return false

        return true
    }

    override fun hashCode(): Int {
        var result = publicKeyHex.hashCode()
        result = 31 * result + deviceName.hashCode()
        result = 31 * result + pairedAt.hashCode()
        result = 31 * result + (bleAddress?.hashCode() ?: 0)
        result = 31 * result + (lastAttestationTime?.hashCode() ?: 0)
        result = 31 * result + (bootHashHex?.hashCode() ?: 0)
        result = 31 * result + bootStateVerified.hashCode()
        result = 31 * result + (securityLevel?.hashCode() ?: 0)
        result = 31 * result + (deviceFingerprint?.hashCode() ?: 0)
        result = 31 * result + requireAttestationForKeyUse.hashCode()
        result = 31 * result + requireAttestationForKeyAttestation.hashCode()
        result = 31 * result + attestationGracePeriodMinutes
        result = 31 * result + (lastConnectedAt?.hashCode() ?: 0)
        result = 31 * result + connectionCount.hashCode()
        result = 31 * result + (idevidCertificateDER?.contentHashCode() ?: 0)
        result = 31 * result + (idevidCertificateChain?.fold(0) { acc, bytes ->
            31 * acc + bytes.contentHashCode()
        } ?: 0)
        result = 31 * result + (idevidVerifiedAt?.hashCode() ?: 0)
        result = 31 * result + (idevidTrustLevel?.hashCode() ?: 0)
        result = 31 * result + (idevidSubjectDN?.hashCode() ?: 0)
        result = 31 * result + (idevidNotAfter?.hashCode() ?: 0)
        return result
    }

    companion object {
        fun fromJson(obj: JSONObject): PairedDeviceData {
            // Parse IDevID certificate chain if present
            val chainArray = obj.optJSONArray("idevidCertificateChain")
            val chain: List<ByteArray>? = if (chainArray != null) {
                (0 until chainArray.length()).map { idx ->
                    Base64.decode(chainArray.getString(idx), Base64.NO_WRAP)
                }
            } else {
                null
            }

            // Parse IDevID certificate DER if present
            val certDerBase64 = obj.getStringOrNull("idevidCertificateDER")
            val certDer: ByteArray? = if (certDerBase64 != null && certDerBase64.isNotEmpty()) {
                Base64.decode(certDerBase64, Base64.NO_WRAP)
            } else {
                null
            }

            return PairedDeviceData(
                publicKeyHex = obj.getString("publicKeyHex"),
                deviceName = obj.getString("deviceName"),
                pairedAt = obj.getLong("pairedAt"),
                bleAddress = obj.getStringOrNull("bleAddress"),
                lastAttestationTime = if (obj.has("lastAttestationTime")) obj.getLong("lastAttestationTime") else null,
                bootHashHex = obj.getStringOrNull("bootHashHex"),
                bootStateVerified = obj.optBoolean("bootStateVerified", false),
                securityLevel = obj.getStringOrNull("securityLevel"),
                deviceFingerprint = obj.getStringOrNull("deviceFingerprint"),
                requireAttestationForKeyUse = obj.optBoolean("requireAttestationForKeyUse", false),
                requireAttestationForKeyAttestation = obj.optBoolean("requireAttestationForKeyAttestation", true),
                attestationGracePeriodMinutes = obj.optInt("attestationGracePeriodMinutes", 5),
                lastConnectedAt = if (obj.has("lastConnectedAt")) obj.getLong("lastConnectedAt") else null,
                connectionCount = obj.optLong("connectionCount", 0),
                idevidCertificateDER = certDer,
                idevidCertificateChain = chain,
                idevidVerifiedAt = if (obj.has("idevidVerifiedAt")) obj.getLong("idevidVerifiedAt") else null,
                idevidTrustLevel = obj.getStringOrNull("idevidTrustLevel"),
                idevidSubjectDN = obj.getStringOrNull("idevidSubjectDN"),
                idevidNotAfter = if (obj.has("idevidNotAfter")) obj.getLong("idevidNotAfter") else null
            )
        }
    }
}

class PairedDeviceRepository(context: Context) {

    private val prefs: SharedPreferences

    init {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        prefs = EncryptedSharedPreferences.create(
            context,
            PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    fun isDeviceKnown(publicKeyHex: String): Boolean {
        return getAllDevices().any { it.publicKeyHex == publicKeyHex }
    }

    fun getDevice(publicKeyHex: String): PairedDeviceData? {
        return getAllDevices().find { it.publicKeyHex == publicKeyHex }
    }

    @Synchronized
    fun addDevice(publicKeyHex: String, deviceName: String, bleAddress: String? = null) {
        val devices = getAllDevices().toMutableList()
        // Remove stale entries for this device. A re-pairing device will have a new Noise
        // static key, so we match by publicKeyHex, BLE address, OR device name to ensure
        // the old entry is replaced rather than duplicated.
        devices.removeAll {
            it.publicKeyHex == publicKeyHex ||
                (bleAddress != null && it.bleAddress == bleAddress) ||
                it.deviceName == deviceName
        }
        devices.add(PairedDeviceData(
            publicKeyHex = publicKeyHex,
            deviceName = deviceName,
            pairedAt = System.currentTimeMillis(),
            bleAddress = bleAddress
        ))
        saveDevices(devices)
    }

    @Synchronized
    fun updateDeviceBleAddress(publicKeyHex: String, bleAddress: String) {
        val devices = getAllDevices().toMutableList()
        val idx = devices.indexOfFirst { it.publicKeyHex == publicKeyHex }
        if (idx >= 0) {
            devices[idx] = devices[idx].copy(bleAddress = bleAddress)
            saveDevices(devices)
        }
    }

    @Synchronized
    fun removeDevice(publicKeyHex: String) {
        val devices = getAllDevices().toMutableList()
        val deviceToRemove = devices.find { it.publicKeyHex == publicKeyHex }
        devices.removeAll { it.publicKeyHex == publicKeyHex }
        saveDevices(devices)

        // Log device unpairing
        if (deviceToRemove != null) {
            AuditLogger.logDeviceUnpaired(
                deviceId = publicKeyHex,
                deviceName = deviceToRemove.deviceName
            )
        }
    }

    @Synchronized
    fun getAllDevices(): List<PairedDeviceData> {
        val jsonStr = prefs.getString(KEY_DEVICES, null) ?: return emptyList()
        return try {
            val arr = JSONArray(jsonStr)
            (0 until arr.length()).map { PairedDeviceData.fromJson(arr.getJSONObject(it)) }
        } catch (e: Exception) {
            emptyList()
        }
    }

    @Synchronized
    fun clear() {
        prefs.edit().remove(KEY_DEVICES).apply()
    }

    @Synchronized
    fun updateDeviceSettings(
        publicKeyHex: String,
        requireAttestationForKeyUse: Boolean,
        requireAttestationForKeyAttestation: Boolean,
        attestationGracePeriodMinutes: Int
    ) {
        val devices = getAllDevices().toMutableList()
        val idx = devices.indexOfFirst { it.publicKeyHex == publicKeyHex }
        if (idx >= 0) {
            devices[idx] = devices[idx].copy(
                requireAttestationForKeyUse = requireAttestationForKeyUse,
                requireAttestationForKeyAttestation = requireAttestationForKeyAttestation,
                attestationGracePeriodMinutes = attestationGracePeriodMinutes
            )
            saveDevices(devices)
        }
    }

    @Synchronized
    fun updateDeviceAttestation(
        publicKeyHex: String,
        bootHashHex: String,
        securityLevel: String,
        bootStateVerified: Boolean,
        deviceFingerprint: String
    ) {
        val devices = getAllDevices().toMutableList()
        val idx = devices.indexOfFirst { it.publicKeyHex == publicKeyHex }
        if (idx >= 0) {
            devices[idx] = devices[idx].copy(
                lastAttestationTime = System.currentTimeMillis(),
                bootHashHex = bootHashHex,
                securityLevel = securityLevel,
                bootStateVerified = bootStateVerified,
                deviceFingerprint = deviceFingerprint
            )
            saveDevices(devices)
        }
    }

    /**
     * Updates the IDevID certificate data for a paired device.
     *
     * @param publicKeyHex The device's public key hex identifier
     * @param certificateDER The IDevID certificate in DER encoding
     * @param certificateChain Optional certificate chain in DER encoding
     * @param trustLevel The trust level: "android-ca", "external-ca", or "untrusted"
     * @param subjectDN The certificate subject distinguished name
     * @param notAfter The certificate expiry timestamp in milliseconds
     */
    @Synchronized
    fun updateDeviceIDevID(
        publicKeyHex: String,
        certificateDER: ByteArray,
        certificateChain: List<ByteArray>?,
        trustLevel: String,
        subjectDN: String,
        notAfter: Long
    ) {
        val devices = getAllDevices().toMutableList()
        val idx = devices.indexOfFirst { it.publicKeyHex == publicKeyHex }
        if (idx >= 0) {
            devices[idx] = devices[idx].copy(
                idevidCertificateDER = certificateDER,
                idevidCertificateChain = certificateChain,
                idevidVerifiedAt = System.currentTimeMillis(),
                idevidTrustLevel = trustLevel,
                idevidSubjectDN = subjectDN,
                idevidNotAfter = notAfter
            )
            saveDevices(devices)
        }
    }

    @Synchronized
    fun recordConnection(publicKeyHex: String) {
        val devices = getAllDevices().toMutableList()
        val idx = devices.indexOfFirst { it.publicKeyHex == publicKeyHex }
        if (idx >= 0) {
            devices[idx] = devices[idx].copy(
                lastConnectedAt = System.currentTimeMillis(),
                connectionCount = devices[idx].connectionCount + 1
            )
            saveDevices(devices)
        }
    }

    private fun saveDevices(devices: List<PairedDeviceData>) {
        val arr = JSONArray()
        for (device in devices) {
            arr.put(device.toJson())
        }
        prefs.edit().putString(KEY_DEVICES, arr.toString()).apply()
    }

    companion object {
        private const val PREFS_NAME = "xkey_paired_devices"
        private const val KEY_DEVICES = "paired_devices"
    }
}
