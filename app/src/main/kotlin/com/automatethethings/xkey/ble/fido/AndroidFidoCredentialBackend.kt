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
import com.automatethethings.xkey.crypto.ApprovedKeyChangedException
import com.automatethethings.xkey.crypto.BiometricException
import com.automatethethings.xkey.crypto.BiometricHelper
import com.automatethethings.xkey.crypto.BiometricLockoutException
import com.automatethethings.xkey.crypto.BiometricRequiredException
import com.automatethethings.xkey.crypto.KeyNotFoundException
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.UserCancelledException
import com.automatethethings.xkey.crypto.GeneratedKeyDiscard
import com.automatethethings.xkey.crypto.UserKeyKind
import com.automatethethings.xkey.protocol.Fido2WireIds.decodeBase64
import com.automatethethings.xkey.protocol.Fido2WireIds.wireId
import com.automatethethings.xkey.protocol.KeyIdReservations
import com.automatethethings.xkey.protocol.SharePermission
import com.automatethethings.xkey.protocol.isSameKeyAs
import com.automatethethings.xkey.protocol.storedKeyLockId
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.storage.dao.CredentialMetadataDao
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.CredentialMetadataEntity
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.security.SecureRandom
import java.util.Base64

/**
 * A passkey as it was listed to a BLE client, read under its stored-key lock
 * before the account chooser, the user check or any signing turn: its [row],
 * the [rpId] asked for, the one Keystore [alias] every signature uses, and the
 * public key under exactly that alias. It travels on [FidoCredential.selection]
 * to signing, which signs with this key only.
 */
private class SelectedPasskey(
    val row: KeyEntity,
    val rpId: String,
    val alias: String,
    val publicKeyDer: ByteArray
) : FidoCredentialSelection

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
    // Unused: a passkey's metadata row is written with its key row in one
    // KeyDao transaction (completePasskeyRegistration) and deleted with it.
    @Suppress("UNUSED_PARAMETER") credentialDao: CredentialMetadataDao,
    private val sharePermission: SharePermission,
    private val signCounter: PasskeySignCounter,
    private val keystoreManager: KeystoreManager,
    private val userPrompt: FidoUserPrompt?,
    private val settings: () -> BiometricSettingsData,
    private val pendingKeyDeletions: PendingKeyDeletions
) : FidoCredentialBackend {

    override val userVerificationAvailable: Boolean
        get() = userPrompt?.available == true

    override val strictUserVerification: Boolean
        get() = settings().strictUserVerification

    /**
     * The one list every candidate is built from: the allowList match, the
     * discoverable list, the account chooser and the excludeList check in
     * [Ctap2Authenticator] all read it. Each credential is snapshotted
     * before it is built, and one without a snapshot (its row gone or no
     * longer shared since [offered], or its key not in Keystore) is left
     * out, so a passkey that cannot sign is never a candidate: it neither
     * shadows a usable one in an allowList nor is offered on discovery.
     */
    override suspend fun credentials(rpId: String): List<FidoCredential> =
        offered(rpId).mapNotNull { (entity, id) ->
            val selection = snapshot(entity.keyId, rpId) ?: return@mapNotNull null
            FidoCredential(
                id = id,
                rpId = rpId,
                userHandle = selection.row.userId?.let { decodeBase64(it) },
                userName = selection.row.userName,
                userDisplayName = selection.row.userDisplayName,
                discoverable = selection.row.isDiscoverable,
                selection = selection
            )
        }

    /**
     * The passkey [keyId] as it is now, read under its stored-key lock: its
     * row, alias and public key, the snapshot signing compares against. Null
     * when it is no longer an offered passkey or its key is not in Keystore;
     * [credentials] then leaves it out, and [sign] refuses a credential
     * without one.
     */
    private suspend fun snapshot(keyId: String, rpId: String): SelectedPasskey? = withStoredKey(keyId) {
        val row = keyDao.getByKeyId(keyId)?.takeIf { usable(it, rpId) && shared(it) }
        row?.let {
            try {
                select(it, rpId)
            } catch (e: FidoRefusedException) {
                null
            }
        }
    }

    /**
     * The one map between stored passkeys and wire credential IDs: each
     * passkey for [rpId] the sharing policy shows a BLE client, with the ID
     * the client sees ([wireId] of its stored key ID). Listing and signing
     * both go through here, so a wire ID always leads back to the key ID
     * exactly as the database and Keystore hold it. Two stored IDs that
     * would reach the client as the same bytes are both left out, and so is
     * every passkey this backend cannot sign with ([usable]), so one never
     * shadows a usable passkey in the same allowList. A registration that did
     * not complete has no rows at all
     * ([KeyDao.completePasskeyRegistration]), here or for any other reader.
     */
    private suspend fun offered(rpId: String): List<Pair<KeyEntity, ByteArray>> {
        val all = keyDao.getFido2ByRpId(rpId)
            .filter { usable(it, rpId) && shared(it) }
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
        // The passkey as it was listed, before the account chooser and the
        // user check: only this key signs, and only while it is still this
        // passkey (signSelected). Its stored key ID, never one re-encoded from
        // the wire ID: stored IDs come padded, in standard base64 or not in
        // base64 at all.
        val selected = (credential.selection as? SelectedPasskey)
            ?.takeIf { it.rpId == credential.rpId && wireId(it.row.keyId).contentEquals(credential.id) }
            ?: throw FidoRefusedException(Ctap2.ERR_NO_CREDENTIALS, "Passkey is gone or no longer shared")
        val keyId = selected.row.keyId
        val entity = keyDao.getByKeyId(keyId)
        if (entity == null || !usable(entity, credential.rpId) || !shared(entity)) {
            throw FidoRefusedException(Ctap2.ERR_NO_CREDENTIALS, "Passkey is gone or no longer shared")
        }
        // The counter is read and authenticatorData built only once this
        // assertion's signing turn has come, so no other assertion for the
        // passkey, over BLE or from the credential provider, signs a later
        // count before this one.
        var count = 0L
        var authData = ByteArray(0)
        val signature = signInKeystore(selected) {
            count = signCounter.next(keyId)
            authData = authenticatorData(count)
            authData + clientDataHash
        }
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
        retryPendingKeyDeletions()
        val rawId = ByteArray(CREDENTIAL_ID_BYTES).also { SecureRandom().nextBytes(it) }
        val keyId = encodeId(rawId)
        // Recorded before its key is made, and forgotten once the passkey is
        // whole: a registration that stops before then, a process death
        // included, leaves a Keystore key no row owns, which a later retry
        // deletes. Without the record nothing is made.
        pendingKeyDeletions.addRegistration(keyId)
        // Not auth-bound: the phone's prompt gates every use, as on the
        // JSON-RPC path, and an auth-bound key could not sign after it.
        val cose = try {
            withStoredKey(keyId) {
                keystoreManager.generateKeyWithAuthDuration(
                    credentialId = keyId,
                    authDurationSeconds = -1,
                    requireStrongBox = false
                )
            }
        } catch (e: Throwable) {
            forget(keyId)
            throw e
        }
        // StrongBox is preferred, with the TEE as the fallback; the row
        // records the level the key was really made at, read from its
        // KeyInfo. A level that cannot be read fails the registration and
        // drops the new key: it is never guessed.
        val securityLevel = try {
            withStoredKey(keyId) { keystoreManager.credentialSecurityLevel(keyId) } ?: throw KeyNotFoundException(keyId)
        } catch (e: Throwable) {
            withContext(NonCancellable) { dropNewKey(keyId) }
            throw e
        }
        val userId = encodeId(request.userHandle)
        val rpName = request.rpName ?: request.rpId
        // The passkeys this one replaces, read and read again before anything
        // is written. Any failure here, a cancellation (the client
        // disconnected or sent CANCEL) included, removes the new key and
        // leaves the old passkeys untouched.
        // Each replaced passkey's key as recorded: its ID and the namespace
        // its row's key lives in, read before the rows go.
        var replacedKeys = emptyList<PendingKey>()
        val replaced = try {
            // The discoverable passkeys this client could see for the same
            // account. One the sharing policy hides from BLE clients is never
            // touched.
            val old = if (request.discoverable) {
                keyDao.getFido2ByRpId(request.rpId).filter { replaceable(it, request, keyId) }
            } else {
                emptyList()
            }
            // Read again right before they go: a passkey made private, shared
            // with selected peers only, or changed since the lookup is no
            // longer this client's to replace, and stays. The rows as read
            // here are what the delete matches, so a policy change after this
            // read keeps the passkey too.
            val stillReplaceable = old.mapNotNull { candidate ->
                keyDao.getByKeyId(candidate.keyId)?.takeIf { replaceable(it, request, keyId) }
            }
            // The last point a cancellation stops the registration.
            currentCoroutineContext().ensureActive()
            // Their keys are recorded before their rows go, so a key whose
            // deletion throws, or whose process dies first, is deleted by a
            // later retry. Without the record no old passkey goes. Each is
            // recorded under the alias its row's key really lives at: a
            // passkey local.generateKey made has a general key, not a
            // credential one.
            replacedKeys = stillReplaceable.map { PendingKey(it.keyId, keyKindOf(it)) }
            if (replacedKeys.isNotEmpty()) pendingKeyDeletions.add(replacedKeys)
            stillReplaceable
        } catch (e: Throwable) {
            withContext(NonCancellable) { dropNewKey(keyId) }
            throw e
        }
        // The one point the new passkey becomes whole: its key row and the
        // metadata the credential provider lists are written, and the old
        // passkeys' rows deleted (each only while its sharing policy is still
        // the one read above), in one transaction. Until it commits no reader
        // anywhere sees the new passkey; when it throws nothing was written
        // and the old passkeys stay. It runs to its end once begun, and a
        // cancellation that comes meanwhile never undoes a committed passkey.
        var committed: List<String>? = null
        try {
            withContext(NonCancellable) {
                committed = keyDao.completePasskeyRegistration(
                    // Made by a BLE client, which has no paired identity:
                    // shared with all peers so that client can use it again.
                    FidoKeyRows.passkey(
                        keyId = keyId,
                        label = rpName,
                        publicKeyCose = cose,
                        rpId = request.rpId,
                        rpName = rpName,
                        userId = userId,
                        userName = request.userName,
                        userDisplayName = request.userDisplayName,
                        discoverable = request.discoverable,
                        createdAt = System.currentTimeMillis(),
                        policy = SharingPolicyType.ALL_PEERS,
                        securityLevel = securityLevel
                    ),
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
                    ),
                    replaced
                )
            }
        } catch (e: Throwable) {
            // Thrown on the way out of a commit that succeeded: only a
            // cancellation that came meanwhile, which a whole passkey outlives.
            if (committed == null) {
                Log.w(TAG, "The new passkey could not be stored; the registration fails, rpId=${request.rpId}", e)
                // Their rows stay and own their keys.
                replaced.forEach { forget(it.keyId) }
                withContext(NonCancellable) { dropNewKey(keyId) }
                throw e
            }
        }
        val removed = committed.orEmpty()
        // Whole: its row owns its key now. The old passkeys whose rows went
        // lose their keys; one whose policy changed since the read keeps its
        // rows, and they own its key. None of this fails the registration,
        // and a cancellation that came during the commit does not stop it.
        // Each key goes only while no row owns its ID, checked under its
        // stored-key lock: a passkey made again under the ID over JSON-RPC
        // since the commit keeps its key.
        forget(keyId)
        (replaced.map { it.keyId } - removed.toSet()).forEach { forget(it) }
        withContext(NonCancellable) {
            replacedKeys.filter { it.keyId in removed }.forEach { key ->
                try {
                    deleteUnownedKey(key)
                } catch (e: Exception) {
                    Log.w(TAG, "A replaced passkey's Keystore key could not be deleted or recorded", e)
                }
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
     * The passkey [entity] as the client chose it, read before any prompt or
     * signing turn: its row, the one Keystore alias every signature of this
     * assertion uses ([KeystoreManager.keyRowAlias], resolved once, here),
     * and the public key under exactly that alias. [signSelected] signs only
     * while all three still hold.
     */
    private fun select(entity: KeyEntity, rpId: String): SelectedPasskey {
        val alias = keystoreManager.keyRowAlias(entity.keyId, KeyTypeFido2, entity.publicKeyDer)
        val publicKeyDer = keystoreManager.publicKeyDERAt(alias)
            ?: throw FidoRefusedException(Ctap2.ERR_NO_CREDENTIALS, "The passkey's key is not in Keystore")
        return SelectedPasskey(entity, rpId, alias, publicKeyDer)
    }

    /**
     * The one signing path for BLE assertions. [signedData] makes
     * `authenticatorData || clientDataHash`, unhashed: every Keystore signature
     * here is SHA256withECDSA, which hashes it once, as WebAuthn expects. It is
     * called only on this signature's turn on the shared prompt queue (the
     * turn the credential provider signs in), so counters are signed in the
     * order they are read.
     *
     * Which prompt a passkey whose key will not sign silently takes is
     * decided in one place, [reauthentication], as RequestHandler's
     * signWithBiometric decides it:
     *
     * - a per-operation passkey (auth duration 0), or any other key Keystore
     *   will not use without fresh authentication, signs behind a prompt
     *   bound to this signature ([signBehindKeyBoundPrompt]), as the
     *   credential provider signs it;
     * - a time-window passkey (auth duration above 0) whose window closed,
     *   say while this assertion waited behind another approval, takes a
     *   fresh generic authentication and signs again inside the new window.
     *   A key-bound prompt cannot unlock it: its signing activity's
     *   Signature.initSign fails on the expired key before any prompt.
     *
     * A declined or impossible prompt is a refusal, never a signature. Every
     * path signs through [signSelected], with [selected]'s alias only.
     */
    private suspend fun signInKeystore(
        selected: SelectedPasskey,
        signedData: suspend () -> ByteArray
    ): ByteArray {
        val reauthentication = reauthentication(selected.row)
        if (selected.row.authDurationSeconds == PER_OPERATION) {
            return signBehindKeyBoundPrompt(selected, signedData)
        }
        try {
            return signSilently(selected, signedData)
        } catch (e: BiometricRequiredException) {
            // The key wants fresh authentication after all (the count read
            // here is a gap).
        }
        return when (reauthentication) {
            Reauthentication.KEY_BOUND -> signBehindKeyBoundPrompt(selected, signedData)
            Reauthentication.GENERIC -> {
                reauthenticate(selected)
                try {
                    signSilently(selected, signedData)
                } catch (e: BiometricRequiredException) {
                    throw FidoRefusedException(
                        Ctap2.ERR_OPERATION_DENIED,
                        "The passkey's authentication window closed again before it signed"
                    )
                }
            }
        }
    }

    /** The prompt a passkey whose key will not sign silently takes. */
    private enum class Reauthentication { GENERIC, KEY_BOUND }

    /**
     * The one choice of prompt kind for a BLE signature, by the passkey's
     * auth duration, as RequestHandler's signWithBiometric makes it: a
     * time-window key takes a generic prompt, every other key one bound to
     * its signature.
     */
    private fun reauthentication(row: KeyEntity): Reauthentication =
        if (row.authDurationSeconds > 0) Reauthentication.GENERIC else Reauthentication.KEY_BOUND

    /**
     * A signature without a prompt, on this assertion's own queue turn,
     * inside the key's authentication window (or for a key that needs none).
     *
     * @throws BiometricRequiredException when Keystore wants fresh
     *   authentication first; every other failure is a refusal.
     */
    private suspend fun signSilently(
        selected: SelectedPasskey,
        signedData: suspend () -> ByteArray
    ): ByteArray = try {
        signSelected(selected, signedData) { checkedData ->
            BiometricHelper.inOneTurn("fidoBleAssertion") {
                keystoreManager.signApproved(
                    alias = selected.alias,
                    approvedPublicKeyDer = selected.publicKeyDer,
                    data = checkedData(),
                    jcaAlgorithm = SIGNING_JCA_ALGORITHM
                )
            }
        }
    } catch (e: BiometricRequiredException) {
        throw e
    } catch (e: ApprovedKeyChangedException) {
        throw FidoRefusedException(Ctap2.ERR_OPERATION_DENIED, "The passkey's key changed while it signed")
    } catch (e: KeyNotFoundException) {
        throw FidoRefusedException(Ctap2.ERR_OPERATION_DENIED, "The passkey's key went while it signed")
    } catch (e: BiometricException) {
        throw FidoRefusedException(Ctap2.ERR_OPERATION_DENIED, "No signing turn came")
    }

    /**
     * A fresh generic authentication for a time-window passkey, which opens
     * its Keystore window again. Anything but a verified user is a refusal.
     */
    private suspend fun reauthenticate(selected: SelectedPasskey) {
        val prompt = userPrompt?.takeIf { it.available }
            ?: throw FidoRefusedException(Ctap2.ERR_OPERATION_DENIED, "This passkey needs a prompt to sign")
        if (prompt.verify(selected.rpId, registering = false) != UserCheck.VERIFIED) {
            throw FidoRefusedException(Ctap2.ERR_OPERATION_DENIED, "The user declined the passkey's prompt")
        }
    }

    /**
     * A signature behind a prompt bound to it, for a key Keystore lets sign
     * only right after its own authentication.
     */
    private suspend fun signBehindKeyBoundPrompt(
        selected: SelectedPasskey,
        signedData: suspend () -> ByteArray
    ): ByteArray {
        val prompt = userPrompt?.takeIf { it.available }
            ?: throw FidoRefusedException(Ctap2.ERR_OPERATION_DENIED, "This passkey needs a prompt bound to its key")
        return try {
            // The signing activity is told the selected alias, the one whose
            // public key was read: a passkey local.generateKey made lives under
            // xkey_key_<id>, one the credential provider made under
            // xkey_credential_<id>.
            signSelected(selected, signedData) { checkedData ->
                prompt.signWithKey(selected.row.keyId, selected.alias, selected.rpId, checkedData)
            }
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
     * The one revalidate-and-sign step, for both signing paths. [sign] makes
     * the signature from the data it is handed, which is [signedData] made
     * only once [selected] is checked again ([stillSelected]); the signature
     * is checked again after it, before it leaves the phone.
     *
     * All of it runs holding the stored key's lock ([storedKeyLockId]), the
     * one local.deleteKey and the JSON-RPC approval path take, so no deletion
     * there, and no key made again under the same id, lands between the check
     * and the signature. The lock is taken before the prompt queue's turn,
     * never inside it, on every path that holds both, so no two holders wait
     * on each other. A passkey deleted and made again under its id by any
     * transport while the prompt or the signing turn waits is a new row with
     * a new key under the alias, and is refused.
     */
    private suspend fun signSelected(
        selected: SelectedPasskey,
        signedData: suspend () -> ByteArray,
        sign: suspend (checkedData: suspend () -> ByteArray) -> ByteArray
    ): ByteArray = withStoredKey(selected.row.keyId) {
        val signature = sign {
            stillSelected(selected)
            signedData()
        }
        stillSelected(selected)
        signature
    }

    /**
     * Whether [selected] is still the passkey chosen and still offered: its
     * row the same key ([isSameKeyAs]: same row, key material and sharing
     * policy revision), an ES256 passkey for its RP, shared with a BLE client,
     * and the key under its alias still the one read. The prompt can stay up
     * for as long as the user takes, and the passkey may have been made
     * private, deleted, or deleted and made again meanwhile. Then nothing is
     * signed, or the signature is dropped, and the client gets
     * CTAP2_ERR_OPERATION_DENIED.
     */
    private suspend fun stillSelected(selected: SelectedPasskey) {
        val now = keyDao.getByKeyId(selected.row.keyId)
        val same = now != null && now.isSameKeyAs(selected.row) && usable(now, selected.rpId) && shared(now) &&
            keystoreManager.publicKeyDERAt(selected.alias)?.contentEquals(selected.publicKeyDer) == true
        if (!same) {
            throw FidoRefusedException(Ctap2.ERR_OPERATION_DENIED, "The passkey changed or its sharing changed while it signed")
        }
    }

    private suspend fun shared(entity: KeyEntity): Boolean = sharePermission.canShare(entity, null)

    /**
     * Whether [entity] is a discoverable passkey this BLE client could see
     * for [request]'s account, other than the new passkey [newKeyId], and so
     * one the registration replaces. One the sharing policy hides from BLE
     * clients, or one this backend cannot sign with, is never touched.
     */
    private suspend fun replaceable(entity: KeyEntity, request: CredentialRequest, newKeyId: String): Boolean =
        entity.keyId != newKeyId && usable(entity, request.rpId) &&
            entity.isDiscoverable && sameUser(entity.userId, request.userHandle) && shared(entity)

    /**
     * Whether [entity] is a passkey for [rpId] this backend can sign with:
     * a fido2 row whose algorithm is the one both signing paths use, ES256
     * (SHA256withECDSA on a P-256 key). `local.generateKey` can store fido2
     * rows of other algorithms (ES384, ES512, RSA); a BLE client is never
     * offered one, so none can be signed with the wrong algorithm or shadow
     * a usable passkey.
     */
    private fun usable(entity: KeyEntity, rpId: String): Boolean =
        entity.keyType == KeyTypeFido2 && entity.rpId == rpId &&
            entity.algorithm.equals(SIGNING_ALGORITHM, ignoreCase = true)

    /**
     * Drop the Keystore key of a registration that failed before its rows
     * were written: no row owns it. [deleteKey] deletes it or keeps it
     * recorded for a retry; when even the record fails it is logged, never
     * thrown over the registration's own failure.
     */
    private suspend fun dropNewKey(keyId: String) {
        try {
            deleteUnownedKey(PendingKey(keyId, UserKeyKind.CREDENTIAL))
        } catch (e: Exception) {
            Log.w(TAG, "A failed registration's Keystore key could not be deleted or recorded", e)
        }
    }

    /**
     * The one lock every BLE step that reads, signs with or deletes the key
     * material of the passkey [keyId] runs under: the stored key's lock
     * ([storedKeyLockId]), the one local.generateKey and local.deleteKey take.
     * It is not reentrant: [block] never takes it again.
     */
    private suspend fun <T> withStoredKey(keyId: String, block: suspend () -> T): T =
        KeyIdReservations.process.withKeyLock(storedKeyLockId(keyId), block)

    /**
     * The one way this backend removes a passkey's Keystore key, [key]'s
     * alias in its own namespace: under [withStoredKey], and only while no
     * row owns its ID. A row there now,
     * one completed by a registration or made again under the ID by another
     * transport, owns the key, which stays; only the record is dropped.
     */
    private suspend fun deleteUnownedKey(key: PendingKey) = withStoredKey(key.keyId) {
        if (keyDao.getByKeyId(key.keyId) != null) forget(key.keyId) else deleteKey(key)
    }

    /**
     * The namespace [entity]'s key lives in: a general key when its row's
     * alias ([KeystoreManager.keyRowAlias]) is the general one, as for a
     * fido2 key local.generateKey made, else a credential.
     */
    private fun keyKindOf(entity: KeyEntity): UserKeyKind =
        if (keystoreManager.keyRowAlias(entity.keyId, KeyTypeFido2, entity.publicKeyDer) ==
            KeystoreManager.userKeyAlias(entity.keyId, UserKeyKind.GENERAL)
        ) UserKeyKind.GENERAL else UserKeyKind.CREDENTIAL

    /**
     * Deletes a Keystore key, for a passkey with no row left; called only
     * from [deleteUnownedKey]. A deletion that throws or reports
     * [GeneratedKeyDiscard.FAILED] is kept in [pendingKeyDeletions] for
     * [retryPendingKeyDeletions], never discarded; one whose key is now gone
     * (deleted, or absent already) is forgotten. Throws only when a failed
     * deletion cannot be recorded. A record whose namespace is not known
     * deletes the key under its ID in every namespace
     * ([PendingKey.candidates]) and is forgotten only once none failed.
     */
    private fun deleteKey(key: PendingKey) {
        val outcomes = key.candidates.map { kind ->
            try {
                keystoreManager.deleteKey(key.keyId, kind)
            } catch (e: Exception) {
                Log.w(TAG, "A passkey's Keystore key could not be deleted", e)
                GeneratedKeyDiscard.FAILED
            }
        }
        if (GeneratedKeyDiscard.FAILED in outcomes) {
            Log.w(TAG, "A passkey's Keystore key is still there; it is kept for a later retry")
            pendingKeyDeletions.add(listOf(key))
            return
        }
        try {
            pendingKeyDeletions.remove(key)
        } catch (e: Exception) {
            Log.w(TAG, "A pending Keystore deletion record could not be cleared", e)
        }
    }

    /**
     * Retry every Keystore deletion [pendingKeyDeletions] records, a
     * registration's included. Runs under [registration], the lock every
     * deletion and registration here runs under, so none is in flight
     * meanwhile. A key a row still points at is never deleted: that row owns
     * it, and its record is dropped. A registration's rows exist only once it
     * is whole ([KeyDao.completePasskeyRegistration]), so a recorded
     * registration with rows completed and is kept; one without lost only
     * its key. A retry that fails again stays recorded for the next
     * registration, and never fails this one.
     */
    private suspend fun retryPendingKeyDeletions() {
        val recorded = try {
            // A registration's key is the credential key it made.
            pendingKeyDeletions.all() +
                pendingKeyDeletions.registrations().map { PendingKey(it, UserKeyKind.CREDENTIAL) }
        } catch (e: Exception) {
            Log.w(TAG, "Pending Keystore deletions could not be read; they stay recorded", e)
            emptySet()
        }
        for (key in recorded) {
            try {
                deleteUnownedKey(key)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.w(TAG, "A pending Keystore deletion could not be retried; it stays recorded", e)
            }
        }
    }

    /** Drop [keyId]'s record. A record left behind is harmless: a retry deletes no key a row owns. */
    private fun forget(keyId: String) {
        try {
            pendingKeyDeletions.remove(keyId)
        } catch (e: Exception) {
            Log.w(TAG, "A pending Keystore deletion record could not be cleared", e)
        }
    }

    /** A stored base64 user ID and a wire user handle name the same user when their bytes match. */
    private fun sameUser(storedUserId: String?, userHandle: ByteArray): Boolean =
        storedUserId?.let { decodeBase64(it) }?.contentEquals(userHandle) == true

    private companion object {
        const val TAG = "FidoBleBackend"
        const val KeyTypeFido2 = "fido2"
        const val CREDENTIAL_ID_BYTES = 32

        /** The one algorithm a BLE assertion signs with, on either signing path. */
        const val SIGNING_ALGORITHM = "ES256"

        /** [SIGNING_ALGORITHM] as Keystore signs it. */
        const val SIGNING_JCA_ALGORITHM = "SHA256withECDSA"

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
    }
}
