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
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.storage.dao.KeySharingPolicyDao
import com.automatethethings.xkey.util.getStringOrNull
import java.io.IOException
import java.util.concurrent.CopyOnWriteArraySet
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
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
    val deviceFingerprint: String? = null,     // SHA256 of the phone's OWN attested leaf SPKI, captured at pairing; echoed on reconnect (#93)
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

class PairedDeviceRepository internal constructor(private val prefs: SharedPreferences) {

    constructor(context: Context) : this(openPrefs(context))

    fun isDeviceKnown(publicKeyHex: String): Boolean {
        return getAllDevices().any { it.publicKeyHex == publicKeyHex }
    }

    fun getDevice(publicKeyHex: String): PairedDeviceData? {
        return getAllDevices().find { it.publicKeyHex == publicKeyHex }
    }

    fun addDevice(publicKeyHex: String, deviceName: String, bleAddress: String? = null) {
        var stillPending = false
        val evicted = synchronized(storeLock) {
            val devices = getAllDevices().toMutableList()
            // Remove stale entries for this device. A re-pairing device will have a new Noise
            // static key, so we match by publicKeyHex, BLE address, OR device name to ensure
            // the old entry is replaced rather than duplicated.
            val evicted = devices.filter {
                it.publicKeyHex == publicKeyHex ||
                    (bleAddress != null && it.bleAddress == bleAddress) ||
                    it.deviceName == deviceName
            }
            devices.removeAll(evicted)
            devices.add(PairedDeviceData(
                publicKeyHex = publicKeyHex,
                deviceName = deviceName,
                pairedAt = System.currentTimeMillis(),
                bleAddress = bleAddress
            ))
            val evictedKeys = evicted.map { it.publicKeyHex }.filter { it != publicKeyHex }
            saveDevices(devices, revoke = evictedKeys)
            stillPending = publicKeyHex in readPending()
            evictedKeys
        }
        // A stale entry replaced under a different key is no longer paired:
        // a live session with it must not outlive the record. Listeners run
        // outside the store's lock, so one that takes a transport lock can
        // never deadlock against a send that reads the store.
        notifyRemoved(evicted)
        // A key re-paired while its earlier revocation never committed: retry
        // it now, not only at the next start. Until it commits, the request
        // handler refuses SELECTED_PEERS for this key.
        if (stillPending) notifyRevocationPending(publicKeyHex)
    }

    fun updateDeviceBleAddress(publicKeyHex: String, bleAddress: String) = synchronized(storeLock) {
        val devices = getAllDevices().toMutableList()
        val idx = devices.indexOfFirst { it.publicKeyHex == publicKeyHex }
        if (idx >= 0) {
            devices[idx] = devices[idx].copy(bleAddress = bleAddress)
            saveDevices(devices)
        }
    }

    /**
     * Removes the device paired under [publicKeyHex] and tells every
     * [PairedDeviceRemovalListener] about it, so a transport tears down a live
     * session with that peer (#59). Listeners are told even when no record
     * matched: the record may already be gone while a session still runs.
     * They are told after the record is gone and outside the store's lock.
     */
    fun removeDevice(publicKeyHex: String) {
        synchronized(storeLock) {
            val devices = getAllDevices().toMutableList()
            val deviceToRemove = devices.find { it.publicKeyHex == publicKeyHex }
            devices.removeAll { it.publicKeyHex == publicKeyHex }
            saveDevices(devices, revoke = listOf(publicKeyHex))

            // Log device unpairing
            if (deviceToRemove != null) {
                AuditLogger.logDeviceUnpaired(
                    deviceId = publicKeyHex,
                    deviceName = deviceToRemove.deviceName
                )
            }
        }
        notifyRemoved(listOf(publicKeyHex))
    }

    fun getAllDevices(): List<PairedDeviceData> = synchronized(storeLock) {
        val jsonStr = prefs.getString(KEY_DEVICES, null) ?: return@synchronized emptyList()
        try {
            val arr = JSONArray(jsonStr)
            (0 until arr.length()).map { PairedDeviceData.fromJson(arr.getJSONObject(it)) }
        } catch (e: Exception) {
            emptyList()
        }
    }

    fun clear() {
        val removed = synchronized(storeLock) {
            val removed = getAllDevices().map { it.publicKeyHex }
            prefs.edit()
                .remove(KEY_DEVICES)
                .remove(KEY_PAIRINGS)
                .recordRevocations(removed)
                .apply()
            storeChangeCount.value++
            removed
        }
        notifyRemoved(removed)
    }

    /**
     * Send-time revalidation (#59): throws [PeerNotPairedException] unless
     * [publicKeyHex], a session's authenticated remote static key, is still
     * paired. A transport calls it before it encrypts a phone-initiated
     * request, so a refused send consumes no nonce and writes nothing.
     */
    fun requirePaired(publicKeyHex: String?) {
        if (publicKeyHex == null || !isDeviceKnown(publicKeyHex)) {
            throw PeerNotPairedException(publicKeyHex)
        }
    }

    fun updateDeviceSettings(
        publicKeyHex: String,
        requireAttestationForKeyUse: Boolean,
        requireAttestationForKeyAttestation: Boolean,
        attestationGracePeriodMinutes: Int
    ) = synchronized(storeLock) {
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

    fun updateDeviceAttestation(
        publicKeyHex: String,
        bootHashHex: String,
        securityLevel: String,
        bootStateVerified: Boolean,
        deviceFingerprint: String? = null
    ) = synchronized(storeLock) {
        val devices = getAllDevices().toMutableList()
        val idx = devices.indexOfFirst { it.publicKeyHex == publicKeyHex }
        if (idx >= 0) {
            devices[idx] = devices[idx].copy(
                lastAttestationTime = System.currentTimeMillis(),
                bootHashHex = bootHashHex,
                securityLevel = securityLevel,
                bootStateVerified = bootStateVerified,
                // The reconnect binding is the phone's OWN attested-key SPKI,
                // captured at pairing (see updateDeviceFingerprint). A null here
                // preserves it: verifying the PEER's attestation (`remote.attestDevice`)
                // must not overwrite the phone's own reconnect fingerprint.
                deviceFingerprint = deviceFingerprint ?: devices[idx].deviceFingerprint
            )
            saveDevices(devices)
        }
    }

    /**
     * Records the phone's OWN attested-key fingerprint against a paired peer —
     * the value the peer stored at pairing and byte-compares on reconnect,
     * mixing it into the Noise prologue (#93, docs/12). It is
     * `AttestedKeyFingerprint.hexOf(leaf)` over the leaf the phone returned to
     * the desktop's `local.attestDevice` at pairing time, so the phone echoes
     * exactly what the desktop verified. No-op for an unknown peer.
     */
    fun updateDeviceFingerprint(publicKeyHex: String, deviceFingerprint: String) = synchronized(storeLock) {
        val devices = getAllDevices().toMutableList()
        val idx = devices.indexOfFirst { it.publicKeyHex == publicKeyHex }
        if (idx >= 0) {
            devices[idx] = devices[idx].copy(deviceFingerprint = deviceFingerprint)
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
    fun updateDeviceIDevID(
        publicKeyHex: String,
        certificateDER: ByteArray,
        certificateChain: List<ByteArray>?,
        trustLevel: String,
        subjectDN: String,
        notAfter: Long
    ) = synchronized(storeLock) {
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

    fun recordConnection(publicKeyHex: String) = synchronized(storeLock) {
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

    /**
     * Keys whose sharing grants are still to be dropped (#174), each tagged
     * with the generation of the removal that queued it: written in the same
     * prefs edit that removes the pairing, so the two persist or vanish
     * together, and cleared by [completeRevocation] only once the delete for
     * that generation has committed. Replayed at app start.
     *
     * Also every key with a grant write in flight, or interrupted, that was
     * checked against a pairing which has since ended: its row may already be
     * in the table, so the key is treated as revoking until the write is
     * finished and its revocation recorded ([writeGrant]).
     */
    fun pendingRevocations(): Set<String> = synchronized(storeLock) {
        // currentPairing, not the raw pairings map: a key paired before #174
        // has no entry there but is paired at generation 0, and an unpaired
        // key (null) never matches a marker.
        readPending().keys + readGrantWrites()
            .filter { (key, generation) -> currentPairing(key) != generation }
            .map { it.first }
    }

    fun isRevocationPending(publicKeyHex: String): Boolean = publicKeyHex in pendingRevocations()

    /** The generation of [publicKeyHex]'s pending revocation, or null if none is pending. */
    fun pendingRevocationGeneration(publicKeyHex: String): Long? =
        synchronized(storeLock) { readPending()[publicKeyHex] }

    /**
     * Called once [publicKeyHex]'s sharing grants are deleted for [generation].
     * A no-op, returning false, when that generation is no longer the pending
     * one: the revocation already completed, or a later removal replaced it.
     *
     * Durable before visible: the entry is cleared with commit(), under
     * [storeLock], which every reader of the pending set takes. So no grant
     * writer sees the revocation as done before the acknowledgment is on
     * disk, and a crash cannot leave a pending entry that the next start's
     * replay would use to delete a grant approved after completion.
     *
     * @throws IOException if the write did not reach disk; the entry is put
     *   back and stays pending.
     */
    fun completeRevocation(publicKeyHex: String, generation: Long): Boolean = synchronized(storeLock) {
        val pending = readPending()
        if (pending[publicKeyHex] != generation) return@synchronized false
        val written = prefs.edit()
            .putStringSet(KEY_PENDING_REVOCATIONS, encodePending(pending - publicKeyHex))
            .commit()
        if (!written) {
            prefs.edit().putStringSet(KEY_PENDING_REVOCATIONS, encodePending(pending)).apply()
            throw IOException("Acknowledging a grant revocation did not reach disk")
        }
        storeChangeCount.value++
        true
    }

    /**
     * The pairing generation of [publicKeyHex], or null if it is not paired.
     * Each pairing of a key gets a new one; a key paired again while still
     * paired keeps its pairing. Devices paired before #174 have 0.
     */
    fun pairingGeneration(publicKeyHex: String): Long? = synchronized(storeLock) { currentPairing(publicKeyHex) }

    /**
     * Runs [write], which inserts a sharing grant for [publicKeyHex], bound to
     * the key's current pairing (#174). Every grant writer goes through here.
     *
     * Refused, returning false without running [write], when the key is not
     * paired or a revocation of it is pending. Otherwise a marker naming the
     * key and its pairing generation is committed before [write] runs and
     * cleared after it. While the marker names a pairing that has ended, the
     * key counts as revoking ([pendingRevocations]), so a row the write left
     * authorizes nothing. If the pairing ended while [write] ran, a
     * revocation of the key is recorded when it finishes, in the same commit
     * that clears the marker, and the grant cleanup deletes the row; the call
     * returns false. A marker an ended process left behind is settled the
     * same way by [recoverInterruptedGrantWrites].
     */
    suspend fun writeGrant(publicKeyHex: String, write: suspend () -> Unit): Boolean {
        val marker = synchronized(storeLock) {
            val generation = currentPairing(publicKeyHex) ?: return false
            if (publicKeyHex in pendingRevocations()) return false
            val marker = publicKeyHex to generation
            if (grantWritesInFlight.merge(marker, 1, Int::plus) == 1) {
                val written = prefs.edit()
                    .putStringSet(KEY_GRANT_WRITES, encodeGenerations(readGrantWrites() + marker))
                    .commit()
                if (!written) {
                    grantWritesInFlight.remove(marker)
                    prefs.edit().putStringSet(KEY_GRANT_WRITES, encodeGenerations(readGrantWrites() - marker)).apply()
                    return false
                }
            }
            marker
        }
        var stale = true
        try {
            write()
        } finally {
            stale = finishGrantWrite(marker)
        }
        return !stale
    }

    /** Clears [marker]; true, with a revocation recorded, if its pairing ended. */
    private fun finishGrantWrite(marker: Pair<String, Long>): Boolean {
        val (publicKeyHex, generation) = marker
        val stale = synchronized(storeLock) {
            val stale = currentPairing(publicKeyHex) != generation || publicKeyHex in readPending()
            val left = grantWritesInFlight.merge(marker, -1) { count, minus -> (count + minus).takeIf { it > 0 } }
            val edit = prefs.edit()
            if (left == null) edit.putStringSet(KEY_GRANT_WRITES, encodeGenerations(readGrantWrites() - marker))
            if (stale) edit.recordRevocations(listOf(publicKeyHex))
            // On a failed commit the marker stays and the key keeps counting
            // as revoking; the next start settles it.
            if (!edit.commit()) Log.e(TAG, "Finishing a grant write did not reach disk")
            stale
        }
        if (stale) notifyRevocationPending(publicKeyHex)
        return stale
    }

    /**
     * Settles the grant writes an ended process left unfinished: one whose
     * pairing is still current stands; any other may have left a row for an
     * ended pairing, so the key's revocation is recorded. Run at app start.
     */
    fun recoverInterruptedGrantWrites() = synchronized(storeLock) {
        val markers = readGrantWrites().filter { it !in grantWritesInFlight }
        if (markers.isEmpty()) return@synchronized
        val pending = readPending()
        val stale = markers.filter { (key, generation) -> currentPairing(key) != generation || key in pending }
        val written = prefs.edit()
            .putStringSet(KEY_GRANT_WRITES, encodeGenerations(readGrantWrites() - markers.toSet()))
            .recordRevocations(stale.map { it.first }.distinct())
            .commit()
        if (!written) Log.e(TAG, "Settling interrupted grant writes did not reach disk")
    }

    /** Call under [storeLock]. */
    private fun currentPairing(publicKeyHex: String): Long? {
        if (getAllDevices().none { it.publicKeyHex == publicKeyHex }) return null
        return readPairings()[publicKeyHex] ?: 0L
    }

    /** Call under [storeLock]. */
    private fun readPairings(): Map<String, Long> = decodeGenerations(prefs.getStringSet(KEY_PAIRINGS, null)).toMap()

    /** Call under [storeLock]. */
    private fun readGrantWrites(): Set<Pair<String, Long>> =
        decodeGenerations(prefs.getStringSet(KEY_GRANT_WRITES, null)).toSet()

    private fun encodeGenerations(markers: Set<Pair<String, Long>>): Set<String> =
        markers.map { (key, generation) -> "$key$GENERATION_SEPARATOR$generation" }.toSet()

    private fun decodeGenerations(entries: Set<String>?): List<Pair<String, Long>> =
        entries.orEmpty().map { entry ->
            val at = entry.lastIndexOf(GENERATION_SEPARATOR)
            if (at < 0) {
                entry to 0L
            } else {
                entry.substring(0, at) to (entry.substring(at + 1).toLongOrNull() ?: 0L)
            }
        }

    /** Call under [storeLock]. */
    private fun readPending(): Map<String, Long> =
        decodeGenerations(prefs.getStringSet(KEY_PENDING_REVOCATIONS, null)).toMap()

    private fun encodePending(pending: Map<String, Long>): Set<String> =
        pending.map { (key, generation) -> "$key$GENERATION_SEPARATOR$generation" }.toSet()

    /** Call under [storeLock]: adds [keys] to the pending set, each under a fresh generation. */
    private fun SharedPreferences.Editor.recordRevocations(keys: Collection<String>): SharedPreferences.Editor {
        if (keys.isEmpty()) return this
        var generation = prefs.getLong(KEY_REVOCATION_GENERATION, 0L)
        val pending = readPending().toMutableMap()
        for (key in keys) pending[key] = ++generation
        // Under storeLock: a reader woken by this blocks until the edit is applied.
        storeChangeCount.value++
        return putStringSet(KEY_PENDING_REVOCATIONS, encodePending(pending))
            .putLong(KEY_REVOCATION_GENERATION, generation)
    }

    /**
     * Call under [storeLock]. Writes the device list and, in the same edit,
     * the pairing generations: a key that was not paired gets a new one, a
     * key that stays paired keeps its own, a key that left loses it.
     */
    private fun saveDevices(devices: List<PairedDeviceData>, revoke: Collection<String> = emptyList()) {
        val arr = JSONArray()
        for (device in devices) {
            arr.put(device.toJson())
        }
        val wasPaired = getAllDevices().map { it.publicKeyHex }.toSet()
        val before = readPairings()
        var counter = prefs.getLong(KEY_PAIRING_GENERATION, 0L)
        val pairings = devices.map { it.publicKeyHex }.distinct().associateWith { key ->
            when {
                key !in wasPaired -> ++counter
                else -> before[key] ?: 0L
            }
        }
        prefs.edit()
            .putString(KEY_DEVICES, arr.toString())
            .putStringSet(KEY_PAIRINGS, encodeGenerations(pairings.toList().toSet()))
            .putLong(KEY_PAIRING_GENERATION, counter)
            .recordRevocations(revoke)
            .apply()
        storeChangeCount.value++
    }

    private fun notifyRevocationPending(publicKeyHex: String) {
        for (listener in removalListeners) {
            try {
                listener.onRevocationPending(publicKeyHex)
            } catch (e: Exception) {
                Log.e(TAG, "Removal listener failed", e)
            }
        }
    }

    private fun notifyRemoved(publicKeysHex: List<String>) {
        for (publicKeyHex in publicKeysHex) {
            for (listener in removalListeners) {
                try {
                    listener.onDeviceRemoved(publicKeyHex)
                } catch (e: Exception) {
                    Log.e(TAG, "Removal listener failed", e)
                }
            }
        }
    }

    companion object {
        private const val TAG = "PairedDeviceRepository"
        private const val PREFS_NAME = "xkey_paired_devices"
        private const val KEY_DEVICES = "paired_devices"
        private const val KEY_PENDING_REVOCATIONS = "pending_grant_revocations"
        private const val KEY_REVOCATION_GENERATION = "grant_revocation_generation"
        private const val KEY_PAIRINGS = "pairing_generations"
        private const val KEY_PAIRING_GENERATION = "pairing_generation"
        private const val KEY_GRANT_WRITES = "grant_writes"
        private const val GENERATION_SEPARATOR = '@'

        /**
         * Guards every read-modify-write of the store. Process-wide: the
         * Activity, the services and the grant cleanup each build their own
         * repository over the same prefs, so a per-instance lock would let
         * one write back a set another has changed since it read it.
         */
        private val storeLock = Any()

        private val storeChangeCount = MutableStateFlow(0L)

        /**
         * Changes whenever the paired devices change or a revocation is
         * queued or completed, in any repository instance: a screen that
         * shows the devices or their pending state rereads them on each value.
         */
        val storeChanges: StateFlow<Long> = storeChangeCount.asStateFlow()

        /** Grant writes running in this process, by key and pairing generation. Guarded by [storeLock]. */
        private val grantWritesInFlight = HashMap<Pair<String, Long>, Int>()

        /**
         * Process-wide: the Activity that unpairs a device and the service
         * that holds its session each build their own repository.
         */
        private val removalListeners = CopyOnWriteArraySet<PairedDeviceRemovalListener>()

        fun addRemovalListener(listener: PairedDeviceRemovalListener) {
            removalListeners.add(listener)
        }

        fun removeRemovalListener(listener: PairedDeviceRemovalListener) {
            removalListeners.remove(listener)
        }

        private fun openPrefs(context: Context): SharedPreferences {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()

            return EncryptedSharedPreferences.create(
                context,
                PREFS_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
        }
    }
}

/**
 * Told the public key of every device that stops being paired: unpaired,
 * cleared, or replaced by a re-pairing under a new key. Called on the thread
 * that changed the store, often the main thread, after the record is gone and
 * outside the store's lock, so it must not block.
 */
fun interface PairedDeviceRemovalListener {
    fun onDeviceRemoved(publicKeyHex: String)

    /**
     * [publicKeyHex] was paired again while an earlier removal's grant
     * revocation is still pending (#174). Not a removal: the device stays
     * paired. Same threading as [onDeviceRemoved].
     */
    fun onRevocationPending(publicKeyHex: String) {}
}

/**
 * Drops the per-key sharing grants of every device that stops being paired
 * (#174). Without it a desktop that re-pairs under the same static key would
 * get its old `SELECTED_PEERS` grants back, since access control reads
 * `key_sharing_policies` by peer key alone.
 *
 * Registered once at app start ([com.automatethethings.xkey.XKeyApplication]).
 * The repository holds no database handle, so the delete runs here, on
 * [scope] (the app passes an IO scope): [onDeviceRemoved] must not block the
 * thread that changed the store. Only the peer's policy rows go; keys and
 * their sharing policy (`ALL_PEERS`, `PRIVATE`, `SELECTED_PEERS`) are
 * untouched. [policyDao] and [repository] are resolved on [scope], so
 * registering the listener opens neither the database nor the prefs.
 *
 * Durable: the repository records each removed key as a pending revocation
 * together with the removal. A key leaves that set only after its delete
 * commits, so a delete that failed, or never ran because the process died,
 * is retried by [replayPending] at the next start, or as soon as the key is
 * paired again.
 */
class PairedDeviceGrantCleanup(
    private val policyDao: () -> KeySharingPolicyDao,
    private val repository: () -> PairedDeviceRepository,
    private val scope: CoroutineScope
) : PairedDeviceRemovalListener {

    /**
     * One peer's job. [requested] and [wake] record a request that arrived
     * while the job ran, so a failure does not lose it.
     */
    private class Job {
        /** Guarded by [inFlight]. */
        var requested = false
        val wake = Channel<Unit>(Channel.CONFLATED)
    }

    /** Peer key to its one in-flight job. Guarded by itself. */
    private val inFlight = HashMap<String, Job>()

    override fun onDeviceRemoved(publicKeyHex: String) = revoke(publicKeyHex)

    override fun onRevocationPending(publicKeyHex: String) = revoke(publicKeyHex)

    /** Retries every revocation a previous process left pending. */
    fun replayPending() {
        scope.launch {
            val pending = try {
                repository().recoverInterruptedGrantWrites()
                repository().pendingRevocations()
            } catch (e: Exception) {
                Log.e(TAG, "Reading pending grant revocations failed", e)
                return@launch
            }
            for (publicKeyHex in pending) revoke(publicKeyHex)
        }
    }

    /**
     * At most one job per peer. A request while one runs is recorded on it:
     * the job rereads the pending generation before it ends, and a job that
     * failed and is backing off retries at once.
     */
    private fun revoke(publicKeyHex: String) {
        val job = Job()
        synchronized(inFlight) {
            inFlight[publicKeyHex]?.let { running ->
                running.requested = true
                running.wake.trySend(Unit)
                return
            }
            inFlight[publicKeyHex] = job
        }
        scope.launch { drain(publicKeyHex, job) }
            .invokeOnCompletion { release(publicKeyHex, job) }
    }

    private fun release(publicKeyHex: String, job: Job) {
        synchronized(inFlight) {
            if (inFlight[publicKeyHex] === job) inFlight.remove(publicKeyHex)
        }
    }

    /**
     * Deletes the peer's grants for the pending generation and acknowledges
     * that generation only. With nothing pending the job is a no-op, so a
     * stale or duplicate job never deletes grants approved after the
     * revocation completed.
     *
     * A failure leaves the entry pending and retries after a backoff that
     * doubles from [BASE_BACKOFF_MS] up to [MAX_BACKOFF_MS]. After
     * [MAX_FAILURES] failures in a row the job ends; the entry is retried at
     * the next start or re-pairing. A request that arrived since the last
     * attempt cuts the backoff short and resets the count.
     */
    private suspend fun drain(publicKeyHex: String, job: Job) {
        var failures = 0
        while (true) {
            // Each exit decision and the job's release are one step under
            // inFlight's lock, the lock revoke() takes: a request that lands
            // after it finds no job and starts one.
            val generation = synchronized(inFlight) {
                // A request since the last attempt, even one that woke this
                // job from its backoff, renews the failure budget.
                if (job.requested) failures = 0
                job.requested = false
                job.wake.tryReceive()
                val pending = try {
                    repository().pendingRevocationGeneration(publicKeyHex)
                } catch (e: Exception) {
                    Log.e(TAG, "Reading a pending grant revocation failed", e)
                    null
                }
                if (pending == null) {
                    release(publicKeyHex, job)
                    return
                }
                pending
            }
            try {
                val dropped = policyDao().clearPoliciesForPeer(publicKeyHex)
                // Audited as soon as the rows are gone: a failed acknowledgment
                // is retried, and the retry deletes nothing.
                if (dropped > 0) {
                    AuditLogger.logPeerGrantsDropped(deviceId = publicKeyHex, droppedGrants = dropped)
                }
                repository().completeRevocation(publicKeyHex, generation)
                failures = 0
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "Dropping sharing grants for a removed device failed", e)
                val requested = synchronized(inFlight) {
                    failures = if (job.requested) 1 else failures + 1
                    if (failures > MAX_FAILURES) {
                        release(publicKeyHex, job)
                        return
                    }
                    job.requested
                }
                val backoff = (BASE_BACKOFF_MS shl (failures - 1)).coerceAtMost(MAX_BACKOFF_MS)
                if (!requested) withTimeoutOrNull(backoff) { job.wake.receive() }
            }
        }
    }

    private companion object {
        const val TAG = "PairedDeviceGrantCleanup"
        const val BASE_BACKOFF_MS = 1_000L
        const val MAX_BACKOFF_MS = 60_000L
        const val MAX_FAILURES = 8
    }
}

/**
 * A phone-initiated send was refused because the session's peer is no longer
 * paired (#59). Nothing was encrypted or written. An [IOException], so
 * [com.automatethethings.xkey.remote.MessageSender] callers keep their contract.
 */
class PeerNotPairedException(val publicKeyHex: String?) :
    IOException("Peer ${publicKeyHex?.take(16) ?: "(unknown)"} is not paired")
