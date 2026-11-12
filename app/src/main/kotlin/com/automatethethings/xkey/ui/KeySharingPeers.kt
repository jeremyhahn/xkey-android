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
 * pairing generation read when the user acted, before that wait.
 *
 * Those edits run in [editScope], which outlives the sheet: one queued
 * behind another sheet's grant still lands when its sheet is dismissed.
 *
 * A policy change is recorded as the key's pending intent before it is
 * written, and stays recorded until the policy and the row clear it owes
 * have both landed; a failure is logged and retried ([setKeyPolicy]). While
 * it is pending the request handler enforces it, not the stored policy
 * ([enforcedPolicy]), so a narrowing whose write fails denies at once.
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

    /** The list, again on every change to this key's policy rows, the paired devices or the pending revocations, withdrawals and policy intents. */
    fun peers(): Flow<List<Peer>> =
        combine(policyDao.getPoliciesForKey(keyId), PairedDeviceRepository.storeChanges, pendingWithdrawals, keyIntents) { policies, _, withdrawn, intents ->
            val pending = repository.pendingRevocations()
            val allowed = policies.filter { it.allowed }.map { it.peerPublicKeyHex }.toSet()
            val intent = intents[keyId]
            repository.getAllDevices().map { device ->
                val revoking = device.publicKeyHex in pending
                Peer(
                    device,
                    allowed = !revoking && device.publicKeyHex in allowed &&
                        (keyId to device.publicKeyHex) !in withdrawn && intent?.enforced != SharingPolicyType.PRIVATE,
                    selectable = !revoking && intent?.refusesGrants != true
                )
            }
        }

    /**
     * Grants or withdraws [peerPublicKeyHex]'s access to the key. Returns
     * false if a grant does not stand: refused before anything was written
     * (the peer is not paired, or its revocation is pending), or written for
     * a pairing that ended meanwhile, which the grant cleanup then deletes.
     * A grant is also refused while the key's pending policy intent enforces
     * Private or still owes a row clear: that intent's retry would delete it.
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
                if (keyIntents.value[keyId]?.refusesGrants == true) return@accepted false
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
     * as grants, withdrawals and local.setKeyPolicy: the companion's
     * [setKeyPolicy], in this sheet's [editScope].
     */
    suspend fun setKeyPolicy(policy: SharingPolicyType, persist: suspend () -> Unit) =
        setKeyPolicy(keyId, policyDao, policy, editScope, persist)

    /** Runs [edit] under the edits lock in [editScope] ([accepted] in the companion). */
    private suspend fun <T> accepted(edit: suspend () -> T): T = accepted(editScope, edit)

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
            editScope.launch {
                retry({ pendingWithdrawals.value[entry] === token }) {
                    write()
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

        /** Outlives every sheet: an edit the user made lands after its sheet is gone. */
        private val acceptedEdits = CoroutineScope(SupervisorJob() + Dispatchers.IO)

        /**
         * Withdrawals (key, peer) whose write failed and is being retried,
         * each with the token of its retry. Held for the life of the
         * process, as the retries are.
         */
        private val pendingWithdrawals = MutableStateFlow<Map<Pair<String, String>, Any>>(emptyMap())

        /** Each key's policy change not yet landed ([setKeyPolicy]), for the life of the process. */
        private val keyIntents = MutableStateFlow<Map<String, KeyIntent>>(emptyMap())

        /**
         * True while a withdrawal of [peerPublicKeyHex]'s access to [keyId]
         * has failed to persist and is being retried, or a Private change
         * of [keyId] (or a Selected Peers one still owing its row clear) has
         * not landed: the stored rows and policy still say otherwise, and
         * must not authorize the peer (#174).
         */
        fun isWithdrawalPending(keyId: String, peerPublicKeyHex: String?): Boolean =
            keyIntents.value[keyId]?.enforced == SharingPolicyType.PRIVATE ||
                (peerPublicKeyHex != null && (keyId to peerPublicKeyHex) in pendingWithdrawals.value)

        /**
         * The policy to enforce for [keyId] instead of the stored one while
         * a change of it has not landed, or null to use the stored policy.
         */
        fun enforcedPolicy(keyId: String): StoredPolicy? =
            keyIntents.value[keyId]?.enforced?.let { StoredPolicy.valueOf(it.name) }

        /**
         * Stores [keyId]'s sharing [policy] through [persist], in the same
         * order as every grant and withdrawal. Every writer of a key's
         * policy goes through here, the sheet and local.setKeyPolicy alike:
         * an older change's retry is superseded by a later change from
         * either, never landed over it. Leaving
         * [SharingPolicyType.SELECTED_PEERS] clears every per-peer row
         * under that order too, so a grant the user made earlier lands
         * first and is cleared, never after the clear.
         *
         * The change is first recorded as the key's pending [KeyIntent],
         * replacing an older one: Selected Peers takes over a row clear the
         * older intent still owed, so returning to Selected starts empty.
         * Its caller may be gone (the sheet was dismissed), so a failure is
         * handled here: logged, and retried in [editScope] until the intent
         * lands or a newer one replaces it. Until then the intent is
         * enforced ([enforcedPolicy]): a narrowing to Private or Selected
         * Peers denies from the moment it is accepted, whatever is stored.
         */
        suspend fun setKeyPolicy(
            keyId: String,
            policyDao: KeySharingPolicyDao,
            policy: SharingPolicyType,
            editScope: CoroutineScope = acceptedEdits,
            persist: suspend () -> Unit
        ) {
            accepted(editScope) {
                val token = Any()
                keyIntents.update { intents ->
                    val older = intents[keyId]
                    intents + (keyId to KeyIntent(
                        policy = policy,
                        persist = persist,
                        clearRows = policy != SharingPolicyType.SELECTED_PEERS || older?.clearRows == true,
                        carried = older?.enforced,
                        token = token
                    ))
                }
                try {
                    land(keyId, policyDao, token)
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Log.e(TAG, "Storing the key's sharing policy failed; it is enforced until a retry lands", e)
                    editScope.launch {
                        retry({ keyIntents.value[keyId]?.token === token }) { land(keyId, policyDao, token) }
                    }
                }
            }
        }

        /**
         * Lands [keyId]'s intent [token] under the edits lock already held:
         * the row clear it owes first (after which no per-peer withdrawal of
         * the key is outstanding), then its policy. The intent is dropped only
         * after both; a step that throws leaves it, minus what already landed.
         */
        private suspend fun land(keyId: String, policyDao: KeySharingPolicyDao, token: Any) {
            val intent = keyIntents.value[keyId]?.takeIf { it.token === token } ?: return
            if (intent.clearRows) {
                policyDao.clearPoliciesForKey(keyId)
                keyIntents.update { intents ->
                    val current = intents[keyId]
                    if (current?.token === token) intents + (keyId to current.copy(clearRows = false)) else intents
                }
                settle { it.first == keyId }
            }
            intent.persist()
            keyIntents.update { intents -> if (intents[keyId]?.token === token) intents - keyId else intents }
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

    /**
     * A key's accepted policy change: [policy] and its [persist], whether
     * the key's rows must still be cleared, and what the intent it replaced
     * enforced ([carried]). [token] identifies its retry.
     */
    private data class KeyIntent(
        val policy: SharingPolicyType,
        val persist: suspend () -> Unit,
        val clearRows: Boolean,
        val carried: SharingPolicyType?,
        val token: Any
    ) {
        /**
         * Private denies every peer, and so does Selected Peers while the
         * old rows it must clear could still authorize; once cleared, the
         * rows decide. All Peers widens nothing until it lands: it enforces
         * what the intent it replaced enforced.
         */
        val enforced: SharingPolicyType?
            get() = when (policy) {
                SharingPolicyType.PRIVATE -> SharingPolicyType.PRIVATE
                SharingPolicyType.SELECTED_PEERS -> if (clearRows) SharingPolicyType.PRIVATE else SharingPolicyType.SELECTED_PEERS
                SharingPolicyType.ALL_PEERS -> carried
            }

        /** A grant written now would be deleted by this intent's row clear, or denied by its Private. */
        val refusesGrants: Boolean
            get() = clearRows || enforced == SharingPolicyType.PRIVATE
    }
}
