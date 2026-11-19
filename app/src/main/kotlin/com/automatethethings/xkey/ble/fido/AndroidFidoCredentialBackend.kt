/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
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
package com.automatethethings.xkey.ble.fido

import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.credential.PasskeySignCounter
import com.automatethethings.xkey.crypto.BiometricException
import com.automatethethings.xkey.crypto.BiometricHelper
import com.automatethethings.xkey.crypto.BiometricLockoutException
import com.automatethethings.xkey.crypto.BiometricRequiredException
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.UserCancelledException
import com.automatethethings.xkey.protocol.SharePermission
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.storage.dao.CredentialMetadataDao
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.CredentialMetadataEntity
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.security.SecureRandom
import java.util.Base64

/** Raises the phone's user verification prompt for a BLE ceremony. */
interface FidoUserPrompt {
    /** Whether a biometric or device credential is enrolled and a prompt can be shown. */
    val available: Boolean

    suspend fun verify(rpId: String, registering: Boolean): UserCheck

    /**
     * Ask the owner which of [accounts] (each a passkey's display name and
     * user name) signs in to [rpId]. Returns its index, or null when the
     * owner declines or no prompt can be shown.
     */
    suspend fun chooseAccount(rpId: String, accounts: List<String>): Int?

    /**
     * Sign with the passkey [keyId], whose Keystore alias is [keyAlias],
     * behind a prompt bound to that one signature, for a key Keystore lets
     * sign only right after its own authentication (a per-operation passkey).
     * Signs inside Keystore. [signedData] is called once, when this
     * signature's turn on the shared prompt queue has come, and its result is
     * what is signed.
     *
     * @throws com.automatethethings.xkey.crypto.UserCancelledException and the
     *   other biometric failures when the user does not approve.
     */
    suspend fun signWithKey(keyId: String, keyAlias: String, rpId: String, signedData: suspend () -> ByteArray): ByteArray
}

/**
 * The phone's passkeys for the FIDO BLE authenticator.
 *
 * A BLE client is not a paired xkey desktop: it has no Noise static key, so
 * [SharePermission] sees no peer. Only passkeys shared with all peers are
 * offered; private passkeys and passkeys shared with selected peers are never
 * listed or signed with. The policy is read again under the signing path, so a
 * passkey made private while its prompt was open is refused.
 *
 * The counter comes from the one [PasskeySignCounter] the credential provider
 * and the JSON-RPC phone backend share, and the key signs inside Keystore.
 */
class AndroidFidoCredentialBackend(
    private val keyDao: KeyDao,
    private val credentialDao: CredentialMetadataDao,
    private val sharePermission: SharePermission,
    private val signCounter: PasskeySignCounter,
    private val keystoreManager: KeystoreManager,
    private val userPrompt: FidoUserPrompt?,
    private val settings: () -> BiometricSettingsData
) : FidoCredentialBackend {

    override val userVerificationAvailable: Boolean
        get() = userPrompt?.available == true

    override val strictUserVerification: Boolean
        get() = settings().strictUserVerification

    override suspend fun credentials(rpId: String): List<FidoCredential> =
        offered(rpId).map { (entity, id) ->
            FidoCredential(
                id = id,
                rpId = rpId,
                userHandle = entity.userId?.let { decodeBase64(it) },
                userName = entity.userName,
                userDisplayName = entity.userDisplayName,
                discoverable = entity.isDiscoverable
            )
        }

    /**
     * The one map between stored passkeys and wire credential IDs: each
     * passkey for [rpId] the sharing policy shows a BLE client, with the ID
     * the client sees ([wireId] of its stored key ID). Listing and signing
     * both go through here, so a wire ID always leads back to the key ID
     * exactly as the database and Keystore hold it. Two stored IDs that
     * would reach the client as the same bytes are both left out.
     */
    private suspend fun offered(rpId: String): List<Pair<KeyEntity, ByteArray>> {
        val all = keyDao.getFido2ByRpId(rpId)
            .filter { it.keyType == KeyTypeFido2 && it.rpId == rpId && shared(it) }
            .map { it to wireId(it.keyId) }
        return all.filter { (_, id) -> all.count { it.second.contentEquals(id) } == 1 }
    }

    override suspend fun checkUser(rpId: String, registering: Boolean): UserCheck {
        val prompt = userPrompt ?: return UserCheck.UNAVAILABLE
        if (!prompt.available) return UserCheck.UNAVAILABLE
        return prompt.verify(rpId, registering)
    }

    override suspend fun chooseCredential(rpId: String, candidates: List<FidoCredential>): FidoCredential? {
        val prompt = userPrompt ?: return null
        if (!prompt.available) return null
        val index = prompt.chooseAccount(rpId, candidates.mapIndexed { i, c -> accountName(c, i) }) ?: return null
        return candidates.getOrNull(index)
    }

    override suspend fun sign(
        credential: FidoCredential,
        authenticatorData: (signCount: Long) -> ByteArray,
        clientDataHash: ByteArray
    ): SignedAssertion {
        // The stored key ID, never one re-encoded from the wire ID: stored IDs
        // come padded, in standard base64 or not in base64 at all.
        val keyId = offered(credential.rpId).singleOrNull { it.second.contentEquals(credential.id) }?.first?.keyId
        val entity = keyId?.let { keyDao.getByKeyId(it) }
        if (keyId == null || entity == null || entity.keyType != KeyTypeFido2 ||
            entity.rpId != credential.rpId || !shared(entity)
        ) {
            throw FidoRefusedException(Ctap2.ERR_NO_CREDENTIALS, "Passkey is gone or no longer shared")
        }
        // The counter is read and authenticatorData built only once this
        // assertion's signing turn has come, so no other assertion for the
        // passkey, over BLE or from the credential provider, signs a later
        // count before this one.
        var count = 0L
        var authData = ByteArray(0)
        val signature = signInKeystore(entity, credential.rpId) {
            count = signCounter.next(keyId)
            authData = authenticatorData(count)
            authData + clientDataHash
        }
        releasable(keyId, credential.rpId)
        Log.i(TAG, "Signed a CTAP2 assertion over BLE, rpId=${credential.rpId}, signCount=$count")
        runCatching {
            AuditLogger.logFido2Authentication(
                keyId = keyId,
                keyLabel = entity.rpName ?: entity.label,
                rpId = credential.rpId
            )
        }
        return SignedAssertion(authData, signature)
    }

    /**
     * Every BLE registration runs under [registration], the one lock in the
     * process: two clients registering the same account at once replace one
     * another in turn, never both insert beside the old passkey, nor each
     * remove the other's.
     */
    override suspend fun create(request: CredentialRequest): NewCredential =
        registration.withLock { createLocked(request) }

    private suspend fun createLocked(request: CredentialRequest): NewCredential {
        val rawId = ByteArray(CREDENTIAL_ID_BYTES).also { SecureRandom().nextBytes(it) }
        val keyId = encodeId(rawId)
        // Not auth-bound: the phone's prompt gates every use, as on the
        // JSON-RPC path, and an auth-bound key could not sign after it.
        val cose = keystoreManager.generateKeyWithAuthDuration(
            credentialId = keyId,
            authDurationSeconds = -1,
            requireStrongBox = false
        )
        val userId = encodeId(request.userHandle)
        val rpName = request.rpName ?: request.rpId
        // The passkeys this one replaces, then its key row, then the metadata
        // the credential provider lists. Any failure, a cancellation (the
        // client disconnected or sent CANCEL) included, removes the new
        // passkey and leaves the old ones untouched.
        val replaced = try {
            // The discoverable passkeys this client could see for the same
            // account. One the sharing policy hides from BLE clients is never
            // touched.
            val old = if (request.discoverable) {
                keyDao.getFido2ByRpId(request.rpId).filter {
                    it.keyId != keyId && it.keyType == KeyTypeFido2 && it.rpId == request.rpId &&
                        it.isDiscoverable && sameUser(it.userId, request.userHandle) && shared(it)
                }
            } else {
                emptyList()
            }
            keyDao.insert(
                KeyEntity(
                    keyId = keyId,
                    keyType = KeyTypeFido2,
                    algorithm = "ES256",
                    label = rpName,
                    publicKeyCose = cose,
                    keySizeBits = 256,
                    biometricRequired = false,
                    authDurationSeconds = -1,
                    exportable = false,
                    shareable = false,
                    source = "local",
                    createdAt = System.currentTimeMillis(),
                    rpId = request.rpId,
                    rpName = rpName,
                    userId = userId,
                    userName = request.userName,
                    userDisplayName = request.userDisplayName,
                    isDiscoverable = request.discoverable,
                    signCount = 0,
                    // Made by a BLE client, which has no paired identity: shared
                    // with all peers so that client can use it again.
                    sharingPolicy = SharingPolicyType.ALL_PEERS
                )
            )
            credentialDao.insert(
                CredentialMetadataEntity(
                    credentialId = keyId,
                    rpId = request.rpId,
                    rpName = rpName,
                    userId = userId,
                    userName = request.userName ?: "",
                    userDisplayName = request.userDisplayName ?: request.userName ?: "",
                    publicKeyCose = cose,
                    signCount = 0,
                    isDiscoverable = request.discoverable
                )
            )
            old
        } catch (e: Throwable) {
            withContext(NonCancellable) { remove(keyId) }
            throw e
        }
        // Only now that the new passkey is whole are the old ones removed, all
        // their rows in one transaction. When those rows will not go, none
        // does: the registration fails and the new passkey is removed, so the
        // client and the credential provider see the passkeys they had.
        withContext(NonCancellable) {
            try {
                delete(replaced.map { it.keyId })
            } catch (e: Throwable) {
                Log.w(TAG, "The replaced passkeys could not be removed; the registration fails, rpId=${request.rpId}", e)
                remove(keyId)
                throw e
            }
        }
        Log.i(TAG, "Created a passkey over BLE, rpId=${request.rpId}")
        runCatching {
            AuditLogger.logFido2Registration(
                keyId = keyId,
                keyLabel = rpName,
                rpId = request.rpId,
                userName = request.userName ?: ""
            )
        }
        return NewCredential(rawId, cose)
    }

    /**
     * The one signing path for BLE assertions. [signedData] makes
     * `authenticatorData || clientDataHash`, unhashed: every Keystore signature
     * here is SHA256withECDSA, which hashes it once, as WebAuthn expects. It is
     * called only on this signature's turn on the shared prompt queue (the
     * turn the credential provider signs in), so counters are signed in the
     * order they are read.
     *
     * A per-operation passkey (auth duration 0), or any key Keystore will not
     * use without fresh authentication, signs behind a prompt bound to this
     * signature, as the credential provider signs it. A declined or
     * impossible prompt is a refusal, never a signature.
     */
    private suspend fun signInKeystore(
        entity: KeyEntity,
        rpId: String,
        signedData: suspend () -> ByteArray
    ): ByteArray {
        if (entity.authDurationSeconds != PER_OPERATION) {
            try {
                return BiometricHelper.inOneTurn("fidoBleAssertion") {
                    keystoreManager.signWithoutBiometric(credentialId = entity.keyId, dataHash = signedData())
                }
            } catch (e: BiometricRequiredException) {
                // Auth-bound after all: fall through to the key-bound prompt,
                // which reads the next count (the one read here is a gap).
            } catch (e: BiometricException) {
                throw FidoRefusedException(Ctap2.ERR_OPERATION_DENIED, "No signing turn came")
            }
        }
        val prompt = userPrompt?.takeIf { it.available }
            ?: throw FidoRefusedException(Ctap2.ERR_OPERATION_DENIED, "This passkey needs a prompt bound to its key")
        // The alias the key really has: a passkey local.generateKey made lives
        // under xkey_key_<id>, one the credential provider made under
        // xkey_credential_<id>. The signing activity is told which.
        val alias = keystoreManager.resolveKeystoreAlias(entity.keyId)
            ?: throw FidoRefusedException(Ctap2.ERR_NO_CREDENTIALS, "The passkey's key is not in Keystore")
        return try {
            prompt.signWithKey(entity.keyId, alias, rpId, signedData)
        } catch (e: CancellationException) {
            // The client went away or sent CANCEL: never a refusal (a
            // CancellationException is an IllegalStateException).
            throw e
        } catch (e: UserCancelledException) {
            throw FidoRefusedException(Ctap2.ERR_OPERATION_DENIED, "The user declined the passkey's prompt")
        } catch (e: BiometricLockoutException) {
            throw FidoRefusedException(Ctap2.ERR_OPERATION_DENIED, "Biometrics are locked out")
        } catch (e: BiometricException) {
            throw FidoRefusedException(Ctap2.ERR_OPERATION_DENIED, "The passkey's prompt failed")
        } catch (e: IllegalStateException) {
            throw FidoRefusedException(Ctap2.ERR_OPERATION_DENIED, "No prompt can be shown")
        }
    }

    /**
     * The last check before a signature leaves the phone, run after every
     * signature on either path: the prompt can stay up for as long as the
     * user takes, and the passkey may have been made private, shared with
     * selected peers only, or deleted meanwhile. Then the signature is
     * dropped and the client gets CTAP2_ERR_OPERATION_DENIED.
     */
    private suspend fun releasable(keyId: String, rpId: String) {
        val now = keyDao.getByKeyId(keyId)
        if (now == null || now.keyType != KeyTypeFido2 || now.rpId != rpId || !shared(now)) {
            throw FidoRefusedException(Ctap2.ERR_OPERATION_DENIED, "Passkey sharing changed while it signed")
        }
    }

    private suspend fun shared(entity: KeyEntity): Boolean = sharePermission.canShare(entity, null)

    /**
     * Delete the passkeys [keyIds] from all three places they live: their
     * metadata rows (what the credential provider lists) and key rows, all in
     * one transaction, then their Keystore keys. The keys go only once the
     * rows are gone, so no row ever points at a key that is gone. Throws when
     * the rows will not go, and then every row and key stays.
     */
    private suspend fun delete(keyIds: List<String>) {
        if (keyIds.isEmpty()) return
        keyDao.deletePasskeyRows(keyIds)
        keyIds.forEach { runCatching { keystoreManager.deleteKey(it) } }
    }

    /** Roll back the new passkey [keyId]: [delete], logged rather than thrown when its rows stay. */
    private suspend fun remove(keyId: String) {
        try {
            delete(listOf(keyId))
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.w(TAG, "A passkey row could not be deleted; its Keystore key stays", e)
        }
    }

    /** A stored base64 user ID and a wire user handle name the same user when their bytes match. */
    private fun sameUser(storedUserId: String?, userHandle: ByteArray): Boolean =
        storedUserId?.let { decodeBase64(it) }?.contentEquals(userHandle) == true

    private companion object {
        const val TAG = "FidoBleBackend"
        const val KeyTypeFido2 = "fido2"
        const val CREDENTIAL_ID_BYTES = 32

        /** The one lock every BLE registration in the process runs under. */
        val registration = Mutex()

        /** Auth duration of a key that authenticates for each use. */
        const val PER_OPERATION = 0

        fun encodeId(raw: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(raw)

        /**
         * How the chooser names a passkey: its display name and user name,
         * either alone when the other is missing or the same, else its place.
         */
        fun accountName(credential: FidoCredential, index: Int): String {
            val display = credential.userDisplayName?.takeIf { it.isNotBlank() }
            val name = credential.userName?.takeIf { it.isNotBlank() }
            return when {
                display != null && name != null && display != name -> "$display ($name)"
                display != null -> display
                name != null -> name
                else -> "Account ${index + 1}"
            }
        }

        /**
         * The credential ID a BLE client sees for a stored key ID: its bytes
         * when the stored ID is base64 (URL-safe or standard, padded or not),
         * else the stored ID's own UTF-8 bytes. Never null, so every stored
         * passkey can be offered.
         */
        fun wireId(keyId: String): ByteArray = decodeBase64(keyId) ?: keyId.toByteArray(Charsets.UTF_8)

        /** Base64 in either alphabet, padded or not; null for anything else. */
        fun decodeBase64(text: String): ByteArray? {
            val bare = text.trimEnd('=')
            if (bare.isEmpty() || text.length - bare.length > 2) return null
            val decoder = when {
                bare.all { it.isLetterOrDigitAscii() || it == '-' || it == '_' } -> Base64.getUrlDecoder()
                bare.all { it.isLetterOrDigitAscii() || it == '+' || it == '/' } -> Base64.getDecoder()
                else -> return null
            }
            return try {
                decoder.decode(bare)
            } catch (e: IllegalArgumentException) {
                null
            }
        }

        private fun Char.isLetterOrDigitAscii(): Boolean = this in 'A'..'Z' || this in 'a'..'z' || this in '0'..'9'
    }
}
