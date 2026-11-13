/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */
package com.automatethethings.xkey.ui

import android.util.Log
import com.automatethethings.xkey.settings.PairedDeviceData
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.storage.KeyPolicyStore
import com.automatethethings.xkey.storage.entity.SharingPolicyType as StoredPolicy
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * The peer list of [KeySharingBottomSheet] for one key: every paired device,
 * whether it holds a grant, and whether the user may change that.
 *
 * Read from the `key_sharing_policies` rows and the paired-device store
 * themselves, so a change made elsewhere (a grant cleanup, another screen, a
 * device pairing while the sheet is open) reaches the sheet.
 *
 * A peer whose grant revocation is still pending (#174: unpaired, then
 * paired again before the cleanup finished) is shown unselected and not
 * selectable, whatever rows it still has, and a grant for it is refused:
 * the cleanup would delete it. The list updates when the revocation
 * completes. A grant is bound to the pairing it was checked against
 * ([PairedDeviceRepository.writeGrant]): one that lands after that pairing
 * ended authorizes nothing and is deleted.
 *
 * The grant protocol commits prefs synchronously, so it runs on
 * [ioDispatcher], never on the sheet's Main caller. Grants, withdrawals and
 * key-wide policy changes ([setKeyPolicy]) take one lock, which is FIFO,
 * before that switch, so they land in the order the user made them: a later
 * withdrawal or clear always follows an earlier grant. A grant carries the
 * pairing generation its caller read when the user acted, before that wait
 * (#193).
 *
 * Those edits run in [editScope], which outlives the sheet: one queued
 * behind another sheet's grant still lands when its sheet is dismissed.
 *
 * A key's policy and its grant rows are written only through
 * [KeyPolicyStore], each change in one transaction bound to the key row the
 * caller read (#193): a failure is returned to the caller, never retried in
 * memory, and a failed narrowing leaves its denial in the key's policy row,
 * where the request handler enforces it.
 */
class KeySharingPeers(
    private val keyId: String,
    private val store: KeyPolicyStore,
    private val repository: PairedDeviceRepository,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val editScope: CoroutineScope = acceptedEdits
) {

    /** One row of the list. [selectable] is false while the row must not be changed. */
    data class Peer(
        val device: PairedDeviceData,
        val allowed: Boolean,
        val selectable: Boolean
    )

    /** The list, again on every change to this key's grant rows, its policy row, the paired devices or the pending revocations and withdrawals. */
    fun peers(): Flow<List<Peer>> =
        combine(store.observeGrants(keyId), store.observePolicy(keyId), PairedDeviceRepository.storeChanges, pendingWithdrawals) { policies, row, _, withdrawn ->
            val pending = repository.pendingRevocations()
            val allowed = policies.filter { it.allowed }.map { it.peerPublicKeyHex }.toSet()
            repository.getAllDevices().map { device ->
                val revoking = device.publicKeyHex in pending
                Peer(
                    device,
                    allowed = !revoking && device.publicKeyHex in allowed &&
                        (keyId to device.publicKeyHex) !in withdrawn && row?.enforced != StoredPolicy.PRIVATE,
                    selectable = !revoking && !KeyPolicyStore.refusesGrants(row)
                )
            }
        }

    /**
     * Grants or withdraws [peerPublicKeyHex]'s access to the key. Returns
     * false if a grant does not stand: refused before anything was written
     * (the peer is not paired, or its revocation is pending), or written for
     * a pairing that ended meanwhile, which the grant cleanup then deletes.
     * A grant is also refused while the key's policy row denies every peer
     * or still owes a grant clear ([KeyPolicyStore.grant]). Withdrawing is
     * always allowed, and stands even if its write fails ([withdraw]).
     *
     * [pairing] is the peer's [PairedDeviceRepository.pairingGeneration] read
     * when the user acted, before any wait (#193): a grant is refused if the
     * peer was not paired then, or that pairing ended before the grant's turn.
     */
    suspend fun setAllowed(peerPublicKeyHex: String, allowed: Boolean, pairing: Long?): Boolean {
        val entry = keyId to peerPublicKeyHex
        if (allowed) {
            if (pairing == null) return false
            return accepted {
                val granted = withContext(ioDispatcher) {
                    try {
                        repository.writeGrant(peerPublicKeyHex, pairing) { store.grant(keyId, peerPublicKeyHex) }
                    } catch (e: KeyPolicyStore.GrantRefusedException) {
                        false
                    }
                }
                // The later choice stands: an earlier failed withdrawal is not retried over it.
                if (granted) settle { it.first == keyId && it.second == peerPublicKeyHex }
                granted
            }
        }
        accepted { withdraw(entry) { store.removeGrant(keyId, peerPublicKeyHex) } }
        return true
    }

    /**
     * Stores the key's sharing [policy] for its key row [instance], in the
     * same order as grants, withdrawals and local.setKeyPolicy: the
     * companion's [setKeyPolicy], in this sheet's [editScope].
     */
    suspend fun setKeyPolicy(policy: SharingPolicyType, instance: Long): Boolean =
        setKeyPolicy(keyId, store, policy, instance, editScope)

    /** Runs [edit] under the edits lock in [editScope] ([accepted] in the companion). */
    private suspend fun <T> accepted(edit: suspend () -> T): T = accepted(editScope, edit)

    /**
     * Runs [write], a withdrawal, under the edits lock already held. Its
     * caller may be gone (the sheet was dismissed), so a failure is handled
     * here, not left in an abandoned Deferred: [entry] is recorded as a
     * pending withdrawal, which denies the peer ([isWithdrawalPending]) from
     * that moment, and [write] is retried in [editScope] until it lands, or
     * until the key row it was made for is gone or replaced (#193).
     */
    private suspend fun withdraw(entry: Pair<String, String>, write: suspend () -> Unit) {
        try {
            write()
            settle { it == entry }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "Withdrawing key access failed; the peer is denied until a retry lands", e)
            val token = Any()
            // Unbound if the key row cannot be read: a retried removal only
            // ever deletes a grant, so it fails closed on a recreated key.
            val instance = try {
                store.instance(keyId)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                null
            }
            pendingWithdrawals.update { it + (entry to token) }
            editScope.launch {
                retry({ pendingWithdrawals.value[entry] === token }) {
                    if (instance == null || store.instance(keyId) == instance) write()
                    pendingWithdrawals.update { if (it[entry] === token) it - entry else it }
                }
            }
        }
    }

    companion object {
        private const val TAG = "KeySharingPeers"

        private const val FIRST_RETRY_MS = 1_000L
        private const val MAX_RETRY_MS = 60_000L

        /** Orders every grant, withdrawal and policy change, across all sheets and local.setKeyPolicy. */
        private val edits = Mutex()

        /**
         * Outlives every sheet: an edit the user made lands after its sheet is
         * gone. Not [Dispatchers.IO]: an edit starts undispatched on its
         * caller's thread, and a `withContext(Dispatchers.IO)` inside a scope
         * already on IO would not leave that thread (#193).
         */
        private val acceptedEdits = CoroutineScope(SupervisorJob() + Dispatchers.Default)

        /**
         * Withdrawals (key, peer) whose write failed and is being retried,
         * each with the token of its retry. Held for the life of the
         * process, as the retries are.
         */
        private val pendingWithdrawals = MutableStateFlow<Map<Pair<String, String>, Any>>(emptyMap())

        /**
         * True while a withdrawal of [peerPublicKeyHex]'s access to [keyId]
         * has failed to persist and is being retried: the stored rows still
         * say otherwise, and must not authorize the peer (#174).
         */
        fun isWithdrawalPending(keyId: String, peerPublicKeyHex: String?): Boolean =
            peerPublicKeyHex != null && (keyId to peerPublicKeyHex) in pendingWithdrawals.value

        /**
         * Stores [keyId]'s sharing [policy] for its key row [instance]
         * ([KeyPolicyStore.setPolicy]), in the same order as every grant and
         * withdrawal. Every writer of a key's policy goes through here, the
         * sheet and local.setKeyPolicy alike. Leaving
         * [SharingPolicyType.SELECTED_PEERS] clears every grant row of the
         * key in the same transaction, under that order, so a grant the user
         * made earlier lands first and is cleared, never after the clear.
         *
         * Nothing is retried: a failure is logged and returned as false, and
         * the caller reports it. A failed narrowing leaves its denial in the
         * key's policy row, enforced until a later change lands; an edit of
         * a key row deleted or replaced since [instance] was read is refused.
         *
         * @return true once the change is stored, false if it was refused.
         */
        suspend fun setKeyPolicy(
            keyId: String,
            store: KeyPolicyStore,
            policy: SharingPolicyType,
            instance: Long,
            editScope: CoroutineScope = acceptedEdits
        ): Boolean =
            accepted(editScope) {
                try {
                    // The grant rows are gone: no per-peer withdrawal of the key is outstanding.
                    if (store.setPolicy(keyId, instance, StoredPolicy.valueOf(policy.name))) settle { it.first == keyId }
                    true
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Log.e(TAG, "Storing the key's sharing policy failed; it was refused", e)
                    false
                }
            }

        /**
         * Deletes [keyId] with its policy row and grant rows
         * ([KeyPolicyStore.deleteKey]) under the edits lock, and drops its
         * pending withdrawals: no retry of an edit of the deleted key lands
         * on one generated again under its id (#193). Throws if the delete
         * failed. Returns whether a key was deleted.
         */
        suspend fun forgetKey(keyId: String, store: KeyPolicyStore): Boolean =
            accepted(acceptedEdits) {
                store.deleteKey(keyId).also { settle { it.first == keyId } }
            }

        /**
         * Runs [edit] under the edits lock in [editScope], not the caller's
         * scope: a sheet dismissed while its edit waits behind another grant
         * stops waiting for the answer, but the edit still lands. Started
         * undispatched, so it joins the lock's queue before this call returns
         * to its caller, in the order the user acted.
         */
        private suspend fun <T> accepted(editScope: CoroutineScope, edit: suspend () -> T): T =
            editScope.async(start = CoroutineStart.UNDISPATCHED) { edits.withLock { edit() } }.await()

        /**
         * Retries [attempt] under the edits lock, with a growing delay, until it
         * lands or [current] turns false because a later edit settled or
         * replaced what it writes: the user's later choice is never undone by an
         * earlier one's retry.
         */
        private suspend fun retry(current: () -> Boolean, attempt: suspend () -> Unit) {
            var wait = FIRST_RETRY_MS
            while (true) {
                delay(wait)
                val done = edits.withLock {
                    if (!current()) return@withLock true
                    try {
                        attempt()
                        true
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        Log.e(TAG, "Retrying a sharing edit failed; it stays enforced", e)
                        false
                    }
                }
                if (done) return
                wait = (wait * 2).coerceAtMost(MAX_RETRY_MS)
            }
        }

        /** Drops the pending withdrawals [which] selects: a later edit landed over them. */
        private fun settle(which: (Pair<String, String>) -> Boolean) {
            pendingWithdrawals.update { pending -> pending.filterKeys { !which(it) } }
        }
    }
}
