// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under AGPL-3.0 (see LICENSE) or a commercial license.
// Contact licensing@automatethethings.com for commercial licensing options.

package com.automatethethings.xkey.sync

import android.content.Context
import android.util.Log
import com.automatethethings.xkey.crypto.Base32
import com.automatethethings.xkey.crypto.SyncCodec
import com.automatethethings.xkey.oath.OathRepository
import com.automatethethings.xkey.oath.OathSecretManager
import com.automatethethings.xkey.password.FilePasswordVaultFactorStore
import com.automatethethings.xkey.password.PasswordRepository
import com.automatethethings.xkey.password.PasswordVault
import com.automatethethings.xkey.settings.SyncStateRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.truststore.TrustStoreRepository
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.URLEncoder

/**
 * Single source of truth for bidirectional store synchronization. Owns the
 * gather (export local items as DTOs) and merge (import incoming items) logic
 * for the trust store, OATH credentials, and passwords, plus sync status.
 *
 * Both directions delegate here so neither duplicates the reconciliation logic:
 *  - inbound  `local.sync*`  (laptop -> phone): the RequestHandler merges the
 *    laptop's items and returns the phone's via [gatherCertificates] etc.
 *  - outbound `remote.sync*` (phone -> laptop):
 *    [com.automatethethings.xkey.remote.RemoteSyncClient] sends the phone's
 *    items and merges the laptop's reply back in.
 *
 * DTO field names match the go-xkms pairing contract
 * (`pkg/pairing/protocol_sync.go`: SyncCertificate / SyncOATHCredential /
 * SyncPassword).
 *
 * [passwordRepository] opens the password store; the default is the app
 * database's, under the Keystore cipher.
 */
class SyncEngine(
    private val context: Context,
    private val passwordRepository: () -> PasswordRepository = {
        PasswordRepository(XKeyDatabase.getInstance(context).passwordDao())
    }
) {

    /** Result of merging incoming certificates. */
    data class CertCounts(val added: Int, val skipped: Int)

    /** Result of merging incoming OATH credentials or passwords. */
    data class ItemCounts(val added: Int, val updated: Int, val skipped: Int)

    private val db by lazy { XKeyDatabase.getInstance(context) }

    // --- Trust store ---

    /** Exports the phone's trust store certificates as [SyncCertificate] JSON. */
    suspend fun gatherCertificates(): JSONArray {
        val repo = TrustStoreRepository(context)
        val out = JSONArray()
        for (ca in repo.getAllCertificates()) {
            val der = repo.getCertificateDER(ca.fingerprint) ?: continue
            out.put(JSONObject().apply {
                put("pem", SyncCodec.derToPem(der))
                put("fingerprint", ca.fingerprint)
                put("source", ca.source)
            })
        }
        return out
    }

    /** Imports incoming certificates, skipping ones already present. */
    suspend fun mergeCertificates(incoming: JSONArray): CertCounts {
        val repo = TrustStoreRepository(context)
        var added = 0
        var skipped = 0
        for (i in 0 until incoming.length()) {
            val obj = incoming.optJSONObject(i) ?: continue
            val fingerprint = obj.optString("fingerprint", "")
            if (fingerprint.isNotEmpty() && repo.hasCertificate(fingerprint)) {
                skipped++
                continue
            }
            val der = SyncCodec.pemToDer(obj.optString("pem", ""))
            if (der == null) {
                skipped++
                continue
            }
            val label = obj.optString("purpose", "").ifBlank { "sync" }
            if (repo.importCertificate(der, label) != null) added++ else skipped++
        }
        return CertCounts(added, skipped)
    }

    // --- OATH ---

    /** Exports the phone's OATH credentials (Base32 secrets) as JSON. */
    suspend fun gatherOath(): JSONArray {
        val secretManager = OathSecretManager()
        val out = JSONArray()
        for (cred in db.oathCredentialDao().getAll()) {
            val secretBytes = secretManager.decryptSecret(cred.secretEncrypted)
            out.put(JSONObject().apply {
                put("id", cred.oathId)
                put("name", cred.oathId)
                put("issuer", cred.issuer ?: JSONObject.NULL)
                put("account_name", cred.accountName)
                put("secret", Base32.encode(secretBytes))
                put("type", cred.oathType.lowercase())
                put("algorithm", cred.algorithm)
                put("digits", cred.digits)
                put("period", cred.periodSeconds)
                put("counter", cred.counter)
            })
        }
        return out
    }

    /** Imports/updates incoming OATH credentials. */
    suspend fun mergeOath(incoming: JSONArray): ItemCounts {
        val secretManager = OathSecretManager()
        val oathRepo = OathRepository(db.oathCredentialDao(), secretManager)
        var added = 0
        var updated = 0
        var skipped = 0
        for (i in 0 until incoming.length()) {
            val obj = incoming.optJSONObject(i) ?: continue
            val id = obj.optString("id", "").ifBlank { obj.optString("name", "") }
            val secret = obj.optString("secret", "")
            val accountName = obj.optString("account_name", "")
            if (id.isEmpty() || secret.isEmpty() || accountName.isEmpty()) {
                skipped++
                continue
            }
            val existed = db.oathCredentialDao().getByOathId(id) != null
            val type = obj.optString("type", "totp").lowercase()
            val issuer = obj.optString("issuer", "").ifBlank { null }
            val uri = otpauthUri(
                type = type,
                issuer = issuer,
                accountName = accountName,
                secret = secret,
                algorithm = obj.optString("algorithm", "SHA1"),
                digits = obj.optInt("digits", 6),
                period = obj.optInt("period", 30),
                counter = if (type == "hotp") obj.optLong("counter", 0) else null
            )
            oathRepo.importFromUri(uri)
            if (existed) updated++ else added++
        }
        return ItemCounts(added, updated, skipped)
    }

    // --- Passwords ---

    /**
     * Exports the phone's password entries as [SyncPassword] JSON.
     *
     * @throws com.automatethethings.xkey.password.PasswordStoreLockedException
     *   if the password vault is locked.
     */
    suspend fun gatherPasswords(): JSONArray = passwordSync().gather()

    /**
     * Imports/updates incoming password entries.
     *
     * @throws com.automatethethings.xkey.password.PasswordStoreLockedException
     *   if the password vault is locked; nothing is written.
     */
    suspend fun mergePasswords(incoming: JSONArray): ItemCounts = passwordSync().merge(incoming)

    private fun passwordSync() = PasswordSync(
        passwordRepository(),
        FilePasswordVaultFactorStore(File(context.filesDir, PasswordVault.FACTOR_DIR))
    )

    // --- Status ---

    /** This device's stable identifier for sync attribution. */
    @Suppress("HardwareIds")
    fun deviceId(): String =
        android.provider.Settings.Secure.getString(
            context.contentResolver, android.provider.Settings.Secure.ANDROID_ID
        ) ?: "unknown"

    /**
     * Per-store SHA-256 checksums so a peer can detect changes cheaply.
     *
     * Not behind the password vault's lock: the password checksum covers only
     * entry IDs and update times, read without decrypting any password, and
     * yields one digest.
     */
    suspend fun storeChecksums(): JSONObject {
        val passwords = passwordRepository().listWithoutSecrets()
        val trustRepo = TrustStoreRepository(context)
        return JSONObject().apply {
            put("oath", SyncCodec.storeChecksum(db.oathCredentialDao().getAll().map { "${it.oathId}:${it.counter}" }))
            put("passwords", SyncCodec.storeChecksum(passwords.map { "${it.passwordId}:${it.updatedAt}" }))
            put("trust_store", SyncCodec.storeChecksum(trustRepo.getAllCertificates().map { it.fingerprint }))
        }
    }

    /** Last successful sync time as RFC 3339, or "" if never synced. */
    suspend fun lastSyncRfc3339(): String {
        val lastSync = SyncStateRepository(context).getLastSyncMillis()
        return if (lastSync > 0) SyncCodec.toRfc3339(lastSync) else ""
    }

    /** Records the current time as the last successful sync. */
    suspend fun markSynced() {
        try {
            SyncStateRepository(context).setLastSyncMillis()
        } catch (e: Exception) {
            Log.w(TAG, "Failed to record sync time", e)
        }
    }

    private companion object {
        const val TAG = "SyncEngine"
    }
}

/**
 * The `otpauth://` URI ([Key Uri Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format))
 * that [SyncEngine.mergeOath] hands to `OathRepository.importFromUri` for a
 * synced OATH credential. The issuer and account are percent-encoded
 * (RFC 3986, a space as `%20`) in the label and the `issuer` parameter.
 * [counter] is written for HOTP only (non-null).
 */
internal fun otpauthUri(
    type: String,
    issuer: String?,
    accountName: String,
    secret: String,
    algorithm: String,
    digits: Int,
    period: Int,
    counter: Long?
): String = buildString {
    val encodedIssuer = issuer?.let(::percentEncode)
    append("otpauth://$type/")
    if (encodedIssuer != null) append("$encodedIssuer:")
    append(percentEncode(accountName))
    append("?secret=$secret")
    if (encodedIssuer != null) append("&issuer=$encodedIssuer")
    append("&algorithm=$algorithm")
    append("&digits=$digits")
    append("&period=$period")
    if (counter != null) append("&counter=$counter")
}

/**
 * Uses the charset-name overload: `URLEncoder.encode(String, Charset)` is
 * API 33, above minSdk 28, and throws NoSuchMethodError below it.
 */
private fun percentEncode(value: String): String =
    URLEncoder.encode(value, Charsets.UTF_8.name()).replace("+", "%20")
