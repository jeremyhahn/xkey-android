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
import com.automatethethings.xkey.storage.dao.KeySharingPolicyDao
import com.automatethethings.xkey.storage.entity.KeySharingPolicy
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
 * pairing generation read when the user acted, before that wait.
 *
 * Those edits run in [editScope], which outlives the sheet: one queued
 * behind another sheet's grant still lands when its sheet is dismissed.
 */
class KeySharingPeers(
    private val keyId: String,
    private val policyDao: KeySharingPolicyDao,
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

    /** The list, again on every change to this key's policy rows, the paired devices or the pending revocations and withdrawals. */
    fun peers(): Flow<List<Peer>> =
        combine(policyDao.getPoliciesForKey(keyId), PairedDeviceRepository.storeChanges, pendingWithdrawals) { policies, _, withdrawn ->
            val pending = repository.pendingRevocations()
            val allowed = policies.filter { it.allowed }.map { it.peerPublicKeyHex }.toSet()
            repository.getAllDevices().map { device ->
                val revoking = device.publicKeyHex in pending
                Peer(
                    device,
                    allowed = !revoking && device.publicKeyHex in allowed && !withdrawn.denies(keyId, device.publicKeyHex),
                    selectable = !revoking
                )
            }
        }

    /**
     * Grants or withdraws [peerPublicKeyHex]'s access to the key. Returns
     * false if a grant does not stand: refused before anything was written
     * (the peer is not paired, or its revocation is pending), or written for
     * a pairing that ended meanwhile, which the grant cleanup then deletes.
     * Withdrawing is always allowed, and stands even if its write fails
     * ([withdraw]).
     */
    suspend fun setAllowed(peerPublicKeyHex: String, allowed: Boolean): Boolean {
        val entry = keyId to peerPublicKeyHex
        if (allowed) {
            // The pairing the user approved, read before any wait: a grant
            // still queued when that pairing ends is refused, never written
            // for a later pairing of the same key.
            val pairing = repository.pairingOf(peerPublicKeyHex) ?: return false
            return accepted {
                val granted = withContext(ioDispatcher) {
                    repository.writeGrant(peerPublicKeyHex, pairing) {
                        policyDao.setPolicy(KeySharingPolicy(keyId = keyId, peerPublicKeyHex = peerPublicKeyHex, allowed = true))
                    }
                }
                // The later choice stands: an earlier failed withdrawal is not retried over it.
                if (granted) settle { it.first == keyId && it.second == peerPublicKeyHex }
                granted
            }
        }
        accepted { withdraw(entry) { policyDao.removePolicy(keyId, peerPublicKeyHex) } }
        return true
    }

    /**
     * Stores the key's sharing [policy] through [persist], in the same order
     * as grants and withdrawals. Leaving [SharingPolicyType.SELECTED_PEERS]
     * clears every per-peer row under that order too, so a grant the user
     * made earlier lands first and is cleared, never after the clear. A
     * Private policy is a withdrawal from every peer and stands even if its
     * write fails ([withdraw]).
     */
    suspend fun setKeyPolicy(policy: SharingPolicyType, persist: suspend () -> Unit) {
        accepted {
            when (policy) {
                SharingPolicyType.PRIVATE -> withdraw(keyId to ANY_PEER) {
                    persist()
                    policyDao.clearPoliciesForKey(keyId)
                }
                SharingPolicyType.ALL_PEERS -> {
                    persist()
                    policyDao.clearPoliciesForKey(keyId)
                    settle { it.first == keyId }
                }
                SharingPolicyType.SELECTED_PEERS -> {
                    persist()
                    settle { it == keyId to ANY_PEER }
                }
            }
        }
    }

    /**
     * Runs [edit] under the edits lock in [editScope], not the caller's
     * scope: a sheet dismissed while its edit waits behind another grant
     * stops waiting for the answer, but the edit still lands. Started
     * undispatched, so it joins the lock's queue before this call returns
     * to its caller, in the order the user acted.
     */
    private suspend fun <T> accepted(edit: suspend () -> T): T =
        editScope.async(start = CoroutineStart.UNDISPATCHED) { edits.withLock { edit() } }.await()

    /**
     * Runs [write], a withdrawal, under the edits lock already held. Its
     * caller may be gone (the sheet was dismissed), so a failure is handled
     * here, not left in an abandoned Deferred: [entry] is recorded as a
     * pending withdrawal, which denies the peer ([isWithdrawalPending]) from
     * that moment, and [write] is retried in [editScope] until it lands.
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
            pendingWithdrawals.update { it + (entry to token) }
            editScope.launch { retry(entry, token, write) }
        }
    }

    /**
     * Retries [write] under the edits lock, with a growing delay, until it
     * lands or a later edit settled [entry] (a grant, another policy, or a
     * newer failure with its own retry): the user's later choice is never
     * undone by an earlier one's retry.
     */
    private suspend fun retry(entry: Pair<String, String>, token: Any, write: suspend () -> Unit) {
        var wait = FIRST_RETRY_MS
        while (true) {
            delay(wait)
            val done = edits.withLock {
                if (pendingWithdrawals.value[entry] !== token) return@withLock true
                try {
                    write()
                    pendingWithdrawals.update { if (it[entry] === token) it - entry else it }
                    true
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Log.e(TAG, "Retrying a withdrawal failed; the peer stays denied", e)
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

    companion object {
        private const val TAG = "KeySharingPeers"

        /** Stands for every peer of a key in a pending Private policy. Never a public key's hex. */
        private const val ANY_PEER = "*"

        private const val FIRST_RETRY_MS = 1_000L
        private const val MAX_RETRY_MS = 60_000L

        /** Orders every grant and withdrawal, across all sheets. */
        private val edits = Mutex()

        /** Outlives every sheet: an edit the user made lands after its sheet is gone. */
        private val acceptedEdits = CoroutineScope(SupervisorJob() + Dispatchers.IO)

        /**
         * Withdrawals (key, peer) and Private policies (key, [ANY_PEER]) whose
         * write failed and is being retried, each with the token of its
         * retry. Held for the life of the process, as the retries are.
         */
        private val pendingWithdrawals = MutableStateFlow<Map<Pair<String, String>, Any>>(emptyMap())

        private fun Map<Pair<String, String>, Any>.denies(keyId: String, peerPublicKeyHex: String?): Boolean =
            (keyId to ANY_PEER) in this || (peerPublicKeyHex != null && (keyId to peerPublicKeyHex) in this)

        /**
         * True while a withdrawal of [peerPublicKeyHex]'s access to [keyId],
         * or a Private policy for [keyId], has failed to persist and is being
         * retried: the stored rows and policy still say otherwise, and must
         * not authorize the peer (#174).
         */
        fun isWithdrawalPending(keyId: String, peerPublicKeyHex: String?): Boolean =
            pendingWithdrawals.value.denies(keyId, peerPublicKeyHex)
    }
}
