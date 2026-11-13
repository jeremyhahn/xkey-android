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
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
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
    private val instance: Long,
    private val store: KeyPolicyStore,
    private val repository: PairedDeviceRepository,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val editScope: CoroutineScope = acceptedEdits
) {

    /**
     * One row of the list. [selectable] is false while the row must not be
     * changed. [unsaved] is true while the peer's withdrawal is held only in
     * the process ([Outcome.UNSAVED]), whichever sheet made it (#193 r8).
     */
    data class Peer(
        val device: PairedDeviceData,
        val allowed: Boolean,
        val selectable: Boolean,
        val unsaved: Boolean = false
    )

    /**
     * The list, again on every change to this key's key row, grant rows,
     * policy row, the paired devices or the pending revocations and
     * obligations. Bound to the key row [instance] (#193 r9): once the key is
     * deleted or replaced under its id, no peer is shown allowed or
     * selectable, so a stale sheet never shows the replacement's grants.
     */
    fun peers(): Flow<List<Peer>> =
        combine(
            store.observeInstance(keyId),
            store.observeGrants(keyId),
            store.observePolicy(keyId),
            PairedDeviceRepository.storeChanges,
            pendingObligations
        ) { current, policies, row, _, owed ->
            val live = current == instance
            val pending = repository.pendingRevocations()
            val allowed = if (live) policies.filter { it.allowed }.map { it.peerPublicKeyHex }.toSet() else emptySet()
            val bound = row?.takeIf { it.keyInstance == instance }
            // Only this key row's obligations: one of a key replaced under the id denies nothing here (#193 r8).
            val mine = owed.filterKeys { it.keyId == keyId && it.instance == instance }
            val withdrawals = mine.filterKeys { it.peer != null }.mapKeys { it.key.peer }
            val policyHeld = mine.keys.any { it.peer == null }
            repository.getAllDevices().map { device ->
                val revoking = device.publicKeyHex in pending
                val withdrawal = withdrawals[device.publicKeyHex]
                Peer(
                    device,
                    allowed = !revoking && device.publicKeyHex in allowed && !policyHeld &&
                        withdrawal == null && bound?.enforced != StoredPolicy.PRIVATE,
                    selectable = live && !revoking && !policyHeld && !KeyPolicyStore.refusesGrants(bound),
                    unsaved = withdrawal?.saved == false
                )
            }
        }

    /**
     * True once the key row this list was opened for is deleted or replaced
     * under its id (#193 r9): the sheet dismisses itself, and every edit it
     * makes meanwhile is refused as [Outcome.STALE].
     */
    val stale: Flow<Boolean> = store.observeInstance(keyId).map { it != instance }.distinctUntilChanged()

    /**
     * True while a policy denial for this key row is held only in the
     * process, its writes failed, whichever sheet made it (#193 r9): shown
     * until its retry stores it durably.
     */
    val policyUnsaved: Flow<Boolean> =
        pendingObligations.map { owed -> owed.any { (k, v) -> k.keyId == keyId && k.instance == instance && k.peer == null && !v.saved } }
            .distinctUntilChanged()

    /**
     * Grants or withdraws [peerPublicKeyHex]'s access to the key. Returns
     * false if a grant does not stand: refused before anything was written
     * (the peer is not paired, or its revocation is pending), or written for
     * a pairing that ended meanwhile, which the grant cleanup then deletes.
     * A grant is also refused while the key's policy row denies every peer
     * or still owes a grant clear ([KeyPolicyStore.grant]). Withdrawing is
     * always allowed, and is enforced even if its write fails ([withdraw]);
     * it returns false if neither its delete nor the denial it then owes
     * could be stored durably.
     *
     * [pairing] is the peer's [PairedDeviceRepository.pairingGeneration] read
     * when the user acted, before any wait (#193): a grant is refused if the
     * peer was not paired then, or that pairing ended before the grant's turn.
     */
    suspend fun setAllowed(peerPublicKeyHex: String, allowed: Boolean, pairing: Long?): Boolean =
        setAllowedOutcome(peerPublicKeyHex, allowed, pairing) == Outcome.STOOD

    /** How a peer tap ended; the sheet shows it through `setAllowedOrRedraw` alone. */
    enum class Outcome {
        /** The grant or withdrawal is stored, durably. */
        STOOD,

        /** The grant was refused or does not stand. */
        REFUSED,

        /**
         * The withdrawal's delete and the denial it then owes both failed to
         * write: the peer is denied in this process and the delete is
         * retried, but a restart would lose that, so it is not saved (#193 r7).
         */
        UNSAVED,

        /**
         * Refused, nothing written: the key row this list was opened for is
         * gone or was replaced under its id (#193 r9). The sheet is stale.
         */
        STALE
    }

    /** [setAllowed], telling a refused grant from a withdrawal that is not saved. */
    suspend fun setAllowedOutcome(peerPublicKeyHex: String, allowed: Boolean, pairing: Long?): Outcome {
        val entry = Owed(keyId, instance, peerPublicKeyHex)
        if (allowed) {
            if (pairing == null) return Outcome.REFUSED
            return accepted {
                val granted = withContext(ioDispatcher) {
                    try {
                        if (repository.writeGrant(peerPublicKeyHex, pairing) { store.grant(keyId, instance, peerPublicKeyHex) }) {
                            Outcome.STOOD
                        } else {
                            Outcome.REFUSED
                        }
                    } catch (e: KeyPolicyStore.GrantRefusedException) {
                        Outcome.REFUSED
                    } catch (e: KeyPolicyStore.KeyChangedException) {
                        // The key this sheet was opened for is gone or replaced.
                        Outcome.STALE
                    }
                }
                // The later choice stands: an earlier failed withdrawal is not retried over it.
                if (granted == Outcome.STOOD) settle { it == entry }
                granted
            }
        }
        return accepted { withdraw(entry) }
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
     * Withdraws [entry]'s grant under the edits lock already held, through
     * the store's choke point ([KeyPolicyStore.withdraw]). Its caller may be
     * gone (the sheet was dismissed), so a failure is handled here, not left
     * in an abandoned Deferred: the store has already recorded the grant
     * clear it owes, which denies every peer of the key until its next policy
     * write; then [entry] is recorded as a pending withdrawal, which denies
     * the peer ([isWithdrawalPending]) from that moment, and the withdrawal
     * is retried in [editScope] until its delete lands, or until the key row
     * it was made for is gone or replaced (#193).
     *
     * Returns [Outcome.STOOD] only once the withdrawal is durable, its delete
     * or its owed clear stored: one whose denial is held in the process
     * alone, which a restart loses, is [Outcome.UNSAVED] (#193 r6, r7, ruling 554).
     */
    private suspend fun withdraw(entry: Owed): Outcome {
        val peer = checkNotNull(entry.peer)
        val result = store.withdraw(keyId, instance, peer)
        if (result == KeyPolicyStore.Withdrawal.REMOVED || result == KeyPolicyStore.Withdrawal.STALE) {
            settle { it == entry }
            return if (result == KeyPolicyStore.Withdrawal.STALE) Outcome.STALE else Outcome.STOOD
        }
        Log.e(TAG, "Withdrawing key access failed ($result); every peer is denied until the key's next policy write")
        // Whether it is saved is app state, not the tapping sheet's: a sheet
        // opened later, or the key list, shows it unsaved (#193 r8).
        owe(entry, saved = result == KeyPolicyStore.Withdrawal.OWED, editScope) {
            when (store.withdraw(keyId, instance, peer)) {
                KeyPolicyStore.Withdrawal.REMOVED, KeyPolicyStore.Withdrawal.STALE -> Attempt.DONE
                KeyPolicyStore.Withdrawal.OWED -> Attempt.SAVED
                KeyPolicyStore.Withdrawal.HELD -> Attempt.HELD
            }
        }
        return if (result == KeyPolicyStore.Withdrawal.OWED) Outcome.STOOD else Outcome.UNSAVED
    }

    /**
     * A pending obligation (#193 r8, r9): [peer]'s withdrawn grant of
     * [keyId]'s key row [instance], or, with a null [peer], a policy denial
     * of that key row held only in the process.
     */
    private data class Owed(val keyId: String, val instance: Long, val peer: String?)

    /** A pending obligation's retry token (by identity), and whether its denial is durable. */
    private class Pending(val saved: Boolean)

    /** One retry's result: its write landed, only its denial is durable, or it is still held in the process. */
    private enum class Attempt { DONE, SAVED, HELD }

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
         * The one pending-obligation tracker (#193 r9, ruling 554):
         * withdrawals (key, key row instance, peer) whose write failed, and
         * policy denials (peer null) held only in the process, each retried
         * with its retry's token, which says whether its denial is durable.
         * Held for the life of the process, as the retries are.
         */
        private val pendingObligations = MutableStateFlow<Map<Owed, Pending>>(emptyMap())

        /**
         * Records [entry] as pending ([saved]: its denial is durable) and
         * retries [attempt] in [scope] until it is [Attempt.DONE] or a later
         * edit settles it. The one place an obligation is tracked.
         */
        private fun owe(entry: Owed, saved: Boolean, scope: CoroutineScope, attempt: suspend () -> Attempt) {
            var token = Pending(saved)
            pendingObligations.update { it + (entry to token) }
            scope.launch {
                retry({ pendingObligations.value[entry] === token }) {
                    val again = attempt()
                    if (again == Attempt.DONE) {
                        pendingObligations.update { if (it[entry] === token) it - entry else it }
                        return@retry
                    }
                    if (again == Attempt.SAVED && !token.saved) {
                        val durable = Pending(saved = true)
                        val held = token
                        pendingObligations.update { if (it[entry] === held) it + (entry to durable) else it }
                        token = durable
                    }
                    throw java.io.IOException("A sharing obligation failed to store again")
                }
            }
        }

        /**
         * True while a withdrawal of [peerPublicKeyHex]'s access to [keyId]'s
         * key row [instance] has failed to persist and is being retried: the
         * stored rows still say otherwise, and must not authorize the peer
         * (#174). A withdrawal of another key row under the id, deleted or
         * replaced since, denies nothing (#193 r8).
         */
        fun isWithdrawalPending(keyId: String, instance: Long, peerPublicKeyHex: String?): Boolean =
            peerPublicKeyHex != null && Owed(keyId, instance, peerPublicKeyHex) in pendingObligations.value

        /**
         * The key ids with a withdrawal or a policy denial held only in the
         * process ([Outcome.UNSAVED]), which a restart would lose: the key
         * list shows them, whether or not the sheet that made one is still
         * open (#193 r8, r9).
         */
        val unsavedKeys: Flow<Set<String>> =
            pendingObligations.map { pending -> pending.filterValues { !it.saved }.keys.map { it.keyId }.toSet() }
                .distinctUntilChanged()

        /**
         * Stores [keyId]'s sharing [policy] for its key row [instance]
         * ([KeyPolicyStore.setPolicy]), in the same order as every grant and
         * withdrawal. Every writer of a key's policy goes through here, the
         * sheet and local.setKeyPolicy alike. Leaving
         * [SharingPolicyType.SELECTED_PEERS] clears every grant row of the
         * key in the same transaction, under that order, so a grant the user
         * made earlier lands first and is cleared, never after the clear.
         *
         * The policy is not retried: a failure is logged and returned as
         * false, and the caller reports it. A failed narrowing leaves its
         * denial in the key's policy row, enforced until a later change
         * lands; if that write fails too, the denial is held in the process
         * and tracked here ([pendingObligations], [unsavedKeys]), retried
         * until durable whether or not the sheet is still open (#193 r9). An
         * edit of a key row deleted or replaced since [instance] was read is
         * refused.
         *
         * A remote change (local.setKeyPolicy) passes its [decision], which
         * the store checks inside the write's transaction and audits once
         * committed ([KeyPolicyStore.setPolicy]); its refusal, or its key row
         * being replaced, is thrown to the caller to answer.
         *
         * @return true once the change is stored, false if it was refused.
         */
        suspend fun setKeyPolicy(
            keyId: String,
            store: KeyPolicyStore,
            policy: SharingPolicyType,
            instance: Long,
            editScope: CoroutineScope = acceptedEdits,
            decision: KeyPolicyStore.RemoteDecision? = null
        ): Boolean =
            accepted(editScope) {
                try {
                    // The grant rows are gone: no per-peer withdrawal of the key is outstanding.
                    if (store.setPolicy(keyId, instance, StoredPolicy.valueOf(policy.name), decision)) settle { it.keyId == keyId }
                    // The policy row dropped any denial: no held one is owed.
                    settle { it.keyId == keyId && it.instance == instance && it.peer == null }
                    true
                } catch (e: CancellationException) {
                    throw e
                } catch (e: KeyPolicyStore.DecisionRefusedException) {
                    throw e
                } catch (e: Exception) {
                    if (decision != null && e is KeyPolicyStore.KeyChangedException) throw e
                    Log.e(TAG, "Storing the key's sharing policy failed; it was refused", e)
                    if (store.isHeld(keyId, instance)) {
                        owe(Owed(keyId, instance, null), saved = false, editScope) {
                            if (store.recordHeld(keyId, instance)) Attempt.DONE else Attempt.HELD
                        }
                    }
                    false
                }
            }

        /**
         * Deletes [keyId] with its policy row and grant rows
         * ([KeyPolicyStore.deleteKey]) under the edits lock, and drops its
         * pending withdrawals: no retry of an edit of the deleted key lands
         * on one generated again under its id (#193). Only the key row
         * [instance] the delete was approved for is deleted: false, with
         * nothing deleted, if the key is gone or was generated again under
         * its id meanwhile. Throws if the delete failed.
         * [material], the delete of the key's material, runs in the same
         * queued edit once the rows are deleted ([KeyPolicyStore.deleteKey]):
         * a caller cancelled while the delete waits never leaves it behind.
         */
        suspend fun forgetKey(
            keyId: String,
            instance: Long,
            store: KeyPolicyStore,
            material: com.automatethethings.xkey.storage.MaterialDelete = { true }
        ): Boolean =
            accepted(acceptedEdits) {
                store.deleteKey(keyId, instance, material).also { if (it) settle { it.keyId == keyId } }
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
        private fun settle(which: (Owed) -> Boolean) {
            pendingObligations.update { pending -> pending.filterKeys { !which(it) } }
        }
    }
}
