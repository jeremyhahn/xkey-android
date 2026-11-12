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
package com.automatethethings.xkey.storage

import android.util.Log
import androidx.annotation.VisibleForTesting
import com.automatethethings.xkey.crypto.FileEncryptor
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.SoftwareKeyStore
import com.automatethethings.xkey.remote.SharePermissionLedger
import com.automatethethings.xkey.storage.dao.CredentialMetadataDao
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.dao.deleteKeyAndMaterial
import com.automatethethings.xkey.storage.entity.CredentialMetadataEntity
import com.automatethethings.xkey.storage.entity.KeyEntity
import java.security.KeyStore
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import javax.crypto.SecretKey

/**
 * Synchronizes key metadata across Android Keystore, credential_metadata table,
 * and the unified keys table.
 *
 * Ensures all keys are discoverable in the Key Management UI by:
 * 1. Copying FIDO2 credentials from credential_metadata into the keys table,
 *    skipping any whose Keystore key is gone (step 3 would remove them again)
 * 2. Discovering orphaned Keystore entries not tracked in any table
 * 3. Removing stale keys table entries whose Keystore keys no longer exist
 *
 * @param keystoreManager Manager for Android Keystore operations.
 * @param credentialDao DAO for the credential_metadata table.
 * @param keyDao DAO for the unified keys table.
 */
class KeyStoreSyncManager(
    private val keystoreManager: KeystoreManager,
    private val credentialDao: CredentialMetadataDao,
    private val keyDao: KeyDao
) {
    companion object {
        private const val TAG = "KeyStoreSyncManager"
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val KEY_ALIAS_PREFIX = "xkey_credential_"
        private const val KEY_ALIAS_PREFIX_GENERAL = "xkey_key_"

        private const val ROOT_CA_ALIAS = "xkey_root_ca"
        private const val INTERMEDIATE_CA_ALIAS = "xkey_intermediate_ca"
        private val CA_ALIASES = setOf(ROOT_CA_ALIAS, INTERMEDIATE_CA_ALIAS)

        /**
         * FileEncryptor's per-operation agreement keys. They live for one
         * encryption and are deleted after it, so they never get a key row.
         */
        private const val EPHEMERAL_ALIAS_PREFIX = KEY_ALIAS_PREFIX_GENERAL + FileEncryptor.EPHEMERAL_KEY_PREFIX

        /**
         * The Keystore aliases [discoverKeystoreEntries] maps to key ID
         * [keyId], in [KeystoreManager.resolveKeystoreAlias]'s order. The ID
         * itself is an alias only when it is a CA alias or carries neither
         * xKey prefix: `xkey_key_a` is discovered as key `a`, never as key
         * `xkey_key_a`.
         */
        fun keystoreAliasesOf(keyId: String): List<String> {
            val raw = keyId in CA_ALIASES ||
                !(keyId.startsWith(KEY_ALIAS_PREFIX) || keyId.startsWith(KEY_ALIAS_PREFIX_GENERAL))
            return listOfNotNull(KEY_ALIAS_PREFIX + keyId, KEY_ALIAS_PREFIX_GENERAL + keyId, keyId.takeIf { raw })
        }

        /** Alias prefixes used by Android framework libraries (must not be deleted). */
        private val SYSTEM_KEY_PREFIXES = listOf(
            "_androidx_",       // AndroidX Security Crypto (master key for EncryptedSharedPreferences)
            "AndroidKeyStore",  // Android platform internal keys
        )
    }

    /**
     * Performs a full sync of all key sources.
     *
     * Safe to call multiple times -- uses INSERT OR REPLACE so existing
     * entries are updated rather than duplicated.
     *
     * @return The total number of keys in the keys table after sync.
     */
    suspend fun syncAll(): Int {
        Log.d(TAG, "Starting full key sync")

        val syncedFromCredentials = syncCredentialMetadata()
        val discoveredFromKeystore = discoverKeystoreEntries()
        val removedStale = removeStaleEntries()

        val total = keyDao.countAll()
        Log.d(TAG, "Sync complete: $syncedFromCredentials from credentials, " +
                "$discoveredFromKeystore discovered in keystore, " +
                "$removedStale stale removed, $total total keys")
        return total
    }

    /**
     * Copies FIDO2 credentials from credential_metadata into the keys table.
     *
     * For each credential in credential_metadata that does NOT have a
     * matching entry in the keys table, creates a KeyEntity with
     * source="local" and keyType="fido2".
     *
     * A credential whose Android Keystore key no longer exists is skipped
     * rather than written: [removeStaleEntries] would delete it again later in
     * the same [syncAll], so inserting it only churns the table and inflates
     * the reported count with rows that do not survive the sync.
     *
     * @return Number of credentials synced, all of which survive this sync.
     */
    private suspend fun syncCredentialMetadata(): Int {
        val credentials = credentialDao.getAll()
        var synced = 0
        var skipped = 0

        for (cred in credentials) {
            if (keyDao.exists(cred.credentialId)) continue

            if (keystoreManager.resolveKeystoreAlias(cred.credentialId) == null) {
                skipped++
                Log.d(TAG, "Skipped credential with no Keystore key: ${cred.credentialId}")
                continue
            }

            keyDao.insert(mapCredentialToKeyEntity(cred))
            synced++
            Log.d(TAG, "Synced credential to keys: ${cred.credentialId} (${cred.rpId})")
        }

        Log.d(TAG, "Synced $synced credentials from credential_metadata, " +
                "$skipped skipped with no Keystore key")
        return synced
    }

    /**
     * Discovers keys in Android Keystore that are not tracked in the keys table.
     *
     * Enumerates ALL aliases in the Keystore (not just xKey-prefixed ones)
     * to provide a comprehensive view of all keys on the device.
     *
     * @return Number of keys discovered.
     */
    @VisibleForTesting
    internal suspend fun discoverKeystoreEntries(): Int {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER)
        keyStore.load(null)

        var discovered = 0

        for (alias in keyStore.aliases()) {
            if (alias.startsWith(EPHEMERAL_ALIAS_PREFIX)) continue
            val (keyId, isFido2, isCA) = when {
                alias in CA_ALIASES -> {
                    Triple(alias, false, true)
                }
                alias.startsWith(KEY_ALIAS_PREFIX) -> {
                    Triple(alias.removePrefix(KEY_ALIAS_PREFIX), true, false)
                }
                alias.startsWith(KEY_ALIAS_PREFIX_GENERAL) -> {
                    Triple(alias.removePrefix(KEY_ALIAS_PREFIX_GENERAL), false, false)
                }
                else -> {
                    // Non-xKey key - use full alias as keyId
                    Triple(alias, false, false)
                }
            }

            if (!keyDao.exists(keyId)) {
                val entity = buildKeyEntityFromKeystore(keyStore, alias, keyId, isFido2, isCA)
                if (entity != null) {
                    keyDao.insert(entity)
                    discovered++
                    Log.d(TAG, "Discovered key in keystore: $keyId (alias=$alias)")
                }
            }
        }

        Log.d(TAG, "Discovered $discovered keys in keystore")
        return discovered
    }

    /**
     * Removes keys table entries for local keys whose Keystore entries no longer exist.
     *
     * Only removes entries with local sources (not "xkmsd" remote references).
     *
     * @return Number of stale entries removed.
     */
    private suspend fun removeStaleEntries(): Int {
        val localKeys = keyDao.getAll().filter { it.source != "xkmsd" }
        var removed = 0

        for (key in localKeys) {
            val alias = keystoreManager.resolveKeystoreAlias(key.keyId)
            if (alias == null) {
                SharePermissionLedger.revoking(key.keyId) { keyDao.deleteByKeyId(key.keyId) }
                removed++
                Log.d(TAG, "Removed stale key entry: ${key.keyId}")
            }
        }

        Log.d(TAG, "Removed $removed stale entries")
        return removed
    }

    /**
     * Builds a KeyEntity from a Keystore entry by inspecting the key's
     * certificate and properties.
     */
    private fun buildKeyEntityFromKeystore(
        keyStore: KeyStore,
        alias: String,
        keyId: String,
        isFido2: Boolean,
        isCA: Boolean = false
    ): KeyEntity? {
        return try {
            val cert = keyStore.getCertificate(alias)
            val publicKey = cert?.publicKey

            val (algorithm, keySizeBits) = when (publicKey) {
                is ECPublicKey -> {
                    val bitLength = publicKey.params.order.bitLength()
                    val algo = when {
                        bitLength <= 256 -> "ES256"
                        bitLength <= 384 -> "ES384"
                        else -> "ES512"
                    }
                    algo to bitLength
                }
                is RSAPublicKey -> {
                    val bits = publicKey.modulus.bitLength()
                    "RS256" to bits
                }
                else -> {
                    // Could be a SecretKey (AES/HMAC) - no certificate
                    val key = try {
                        keyStore.getKey(alias, null)
                    } catch (e: Exception) {
                        // Key may require auth - still track it
                        null
                    }
                    when (key) {
                        is SecretKey -> {
                            val algo = key.algorithm
                            when {
                                algo.contains("AES", ignoreCase = true) -> "AES256" to 256
                                algo.contains("HMAC", ignoreCase = true) -> "HMAC-SHA256" to 256
                                else -> "Unknown" to 0
                            }
                        }
                        null -> {
                            // Key exists but we can't read it (auth required, etc.)
                            // Still create an entry with minimal info
                            "Unknown" to 0
                        }
                        else -> return null
                    }
                }
            }

            val keyType = when {
                isCA -> "ca"
                isFido2 -> "fido2"
                algorithm.startsWith("AES") -> "secret"
                algorithm.startsWith("HMAC") -> "hmac"
                algorithm == "Unknown" -> "signing"
                else -> "signing"
            }

            // Detect system/framework keys by alias pattern
            val isSystemKey = isCA || SYSTEM_KEY_PREFIXES.any { prefix ->
                alias.startsWith(prefix)
            }

            // Generate a user-friendly label
            val label = when {
                isCA -> {
                    val x509 = cert as? java.security.cert.X509Certificate
                    val cn = x509?.subjectX500Principal?.name
                        ?.split(",")
                        ?.firstOrNull { it.trimStart().startsWith("CN=") }
                        ?.substringAfter("CN=")
                        ?.trim()
                    cn ?: if (alias == ROOT_CA_ALIAS) "Root CA" else "Intermediate CA"
                }
                isFido2 -> "FIDO2 Credential"
                isSystemKey -> "System: $alias"
                alias.startsWith(KEY_ALIAS_PREFIX_GENERAL) -> keyId
                else -> alias
            }

            KeyEntity(
                keyId = keyId,
                keyType = keyType,
                algorithm = algorithm,
                label = label,
                publicKeyDer = publicKey?.encoded,
                keySizeBits = keySizeBits,
                strongBoxBacked = false, // Can't reliably determine from existing key
                biometricRequired = true, // Default assumption
                source = "local",
                createdAt = System.currentTimeMillis(), // Actual creation time not available from Keystore
                isSystemKey = isSystemKey
            )
        } catch (e: Exception) {
            Log.w(TAG, "Failed to read keystore entry: $alias", e)
            null
        }
    }

    /**
     * Maps a CredentialMetadataEntity to a KeyEntity.
     */
    private fun mapCredentialToKeyEntity(cred: CredentialMetadataEntity): KeyEntity {
        return KeyEntity(
            keyId = cred.credentialId,
            keyType = "fido2",
            algorithm = "ES256",
            label = cred.rpName.ifEmpty { cred.rpId },
            publicKeyCose = cred.publicKeyCose,
            keySizeBits = 256,
            biometricRequired = true,
            source = "local",
            createdAt = cred.createdAt,
            lastUsedAt = cred.lastUsedAt,
            rpId = cred.rpId,
            rpName = cred.rpName,
            userId = cred.userId,
            userName = cred.userName,
            userDisplayName = cred.userDisplayName,
            isDiscoverable = cred.isDiscoverable,
            signCount = cred.signCount
        )
    }
}

/**
 * Deletes the key behind one key row [key], as the key list and the key
 * detail screen do: its material, then its row, inside one
 * [SharePermissionLedger] revoke of the row's key ID ([deleteKeyAndMaterial]).
 *
 * The row's ID names exactly one key, and only its material is removed: the
 * software key of that ID if [softwareKeys] holds one, else the Keystore
 * entry [KeyStoreSyncManager] discovers under that ID. Never
 * [KeystoreManager.resolveKeystoreAlias], which reads `xkey_key_a` as the
 * alias of hardware key `a`: software key `xkey_key_a` and hardware key `a`
 * can both exist, and deleting the first must leave the second.
 *
 * @return Number of rows deleted.
 */
suspend fun KeyDao.deleteKeyRow(
    key: KeyEntity,
    keystoreManager: KeystoreManager,
    softwareKeys: SoftwareKeyStore
): Int = deleteKeyAndMaterial(key.keyId) {
    if (key.source == "xkmsd") return@deleteKeyAndMaterial
    if (softwareKeys.contains(key.keyId)) {
        softwareKeys.delete(key.keyId)
    } else {
        KeyStoreSyncManager.keystoreAliasesOf(key.keyId).firstOrNull { keystoreManager.deleteByAlias(it) }
    }
}
