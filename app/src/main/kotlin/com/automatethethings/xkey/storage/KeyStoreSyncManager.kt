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
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.piv.PIV_KEYSTORE_ALIAS_PREFIX
import com.automatethethings.xkey.storage.dao.CredentialMetadataDao
import com.automatethethings.xkey.storage.dao.KeyDao
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
 * PIV slot keys (`xkey_piv_*`) are not general keys: they belong to
 * [com.automatethethings.xkey.piv.PivKeyManager] and its `piv_slots` rows, so
 * they are never listed here, where the key management screen could delete
 * them behind those rows.
 *
 * @param keystoreManager Manager for Android Keystore operations.
 * @param credentialDao DAO for the credential_metadata table.
 * @param keyDao DAO for the unified keys table.
 * @param keyPolicyStore The store whose deletion tombstones the sync
 *   honours ([KeyPolicyStore.insertDiscovered]): material whose delete is
 *   still owed is not discovered.
 */
class KeyStoreSyncManager(
    private val keystoreManager: KeystoreManager,
    private val credentialDao: CredentialMetadataDao,
    private val keyDao: KeyDao,
    private val keyPolicyStore: KeyPolicyStore
) {
    companion object {
        private const val TAG = "KeyStoreSyncManager"
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val KEY_ALIAS_PREFIX = "xkey_credential_"
        private const val KEY_ALIAS_PREFIX_GENERAL = "xkey_key_"

        private const val ROOT_CA_ALIAS = "xkey_root_ca"
        private const val INTERMEDIATE_CA_ALIAS = "xkey_intermediate_ca"
        private val CA_ALIASES = setOf(ROOT_CA_ALIAS, INTERMEDIATE_CA_ALIAS)

        /** Alias prefixes used by Android framework libraries (must not be deleted). */
        private val SYSTEM_KEY_PREFIXES = listOf(
            "_androidx_",       // AndroidX Security Crypto (master key for EncryptedSharedPreferences)
            "AndroidKeyStore",  // Android platform internal keys
        )

        /**
         * Whether the Keystore entry [alias] is protected from a user delete:
         * every alias but a user key's (KeystoreManager.userKeyAliases), so
         * the app's own keys (xkey_seal_store_key,
         * xkey_password_encryption_key, the CA keys) and framework keys are
         * listed as system keys. A delete of one is refused
         * ([InternalKeyException]) with nothing deleted (#255 review).
         */
        fun isProtectedAlias(alias: String): Boolean {
            val userKey = when {
                alias.startsWith(KEY_ALIAS_PREFIX) -> alias.removePrefix(KEY_ALIAS_PREFIX)
                alias.startsWith(KEY_ALIAS_PREFIX_GENERAL) -> alias.removePrefix(KEY_ALIAS_PREFIX_GENERAL)
                else -> return true
            }
            return alias !in com.automatethethings.xkey.crypto.KeystoreManager.userKeyAliases(userKey) ||
                SYSTEM_KEY_PREFIXES.any { alias.startsWith(it) }
        }
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

            if (!track(mapCredentialToKeyEntity(cred))) {
                skipped++
                continue
            }
            synced++
            Log.d(TAG, "Synced credential to keys: ${cred.credentialId} (${cred.rpId})")
        }

        Log.d(TAG, "Synced $synced credentials from credential_metadata, " +
                "$skipped skipped with no Keystore key")
        return synced
    }

    /**
     * The sync's one key row insert (#193 r9, r10, r11): a key id whose row
     * was deleted while its material delete is still owed (a tombstone) is
     * never listed again, from a credential or from the Keystore, with
     * default metadata; the replay deletes its material. The tombstone
     * check and the insert are one step under the key's material lock
     * ([KeyPolicyStore.insertDiscovered]), so a delete running meanwhile
     * is never undone. Returns whether [entity] was inserted.
     */
    private suspend fun track(entity: KeyEntity): Boolean =
        keyPolicyStore.insertDiscovered(entity.keyId) { keyDao.insert(entity) }

    /**
     * Discovers keys in Android Keystore that are not tracked in the keys table.
     *
     * Enumerates ALL aliases in the Keystore (not just xKey-prefixed ones)
     * to provide a comprehensive view of all keys on the device.
     *
     * @return Number of keys discovered.
     */
    private suspend fun discoverKeystoreEntries(): Int {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER)
        keyStore.load(null)

        var discovered = 0

        for (alias in keyStore.aliases()) {
            if (alias.startsWith(PIV_KEYSTORE_ALIAS_PREFIX)) continue
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
                if (entity != null && track(entity)) {
                    discovered++
                    Log.d(TAG, "Discovered key in keystore: $keyId (alias=$alias)")
                }
            } else if (isProtectedAlias(alias)) {
                // A row an earlier sync listed as a deletable user key.
                keyDao.getByKeyId(keyId)?.takeIf { !it.isSystemKey }?.let {
                    keyDao.update(it.copy(isSystemKey = true))
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
     * A PIV slot alias listed by an earlier sync is removed as well, because
     * [KeystoreManager.resolveKeystoreAlias] never resolves a raw PIV alias.
     *
     * @return Number of stale entries removed.
     */
    private suspend fun removeStaleEntries(): Int {
        val localKeys = keyDao.getAll().filter { it.source != "xkmsd" }
        var removed = 0

        for (key in localKeys) {
            // Classify by the resolved alias, never the logical id: a general
            // key "xkey_piv_x" lives at xkey_key_xkey_piv_x and resolves, while
            // a raw PIV slot alias row never resolves and so is removed here.
            if (keystoreManager.resolveKeystoreAlias(key.keyId) == null) {
                keyDao.deleteByKeyId(key.keyId)
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

            val isSystemKey = isCA || isProtectedAlias(alias)

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
