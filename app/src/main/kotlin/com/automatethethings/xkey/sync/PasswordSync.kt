// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under AGPL-3.0 (see LICENSE) or a commercial license.
// Contact licensing@automatethethings.com for commercial licensing options.

package com.automatethethings.xkey.sync

import android.util.Log
import com.automatethethings.xkey.crypto.SyncCodec
import com.automatethethings.xkey.password.PasswordEntryTooLargeException
import com.automatethethings.xkey.password.PasswordNotNewerException
import com.automatethethings.xkey.password.PasswordNotSyncableException
import com.automatethethings.xkey.password.PasswordPatch
import com.automatethethings.xkey.password.PasswordRecord
import com.automatethethings.xkey.password.PasswordRepository
import com.automatethethings.xkey.password.PasswordUpdateConflictException
import com.automatethethings.xkey.password.PasswordVaultFactorStore
import com.automatethethings.xkey.password.hasSyncablePolicy
import com.automatethethings.xkey.password.requirePasswordStoreUnlocked
import org.json.JSONArray
import org.json.JSONObject

/**
 * Password gather and merge for [SyncEngine], behind the password vault's lock.
 *
 * Both directions of password sync (inbound `local.syncPasswords`, outbound
 * `remote.syncPasswords`) read and write the store through here, so both are
 * refused by the one check, [requirePasswordStoreUnlocked], while the store is
 * locked. The check runs before anything is read or written.
 */
class PasswordSync(
    private val repository: PasswordRepository,
    private val factors: PasswordVaultFactorStore,
    private val clock: () -> Long = System::currentTimeMillis
) {

    /**
     * What [mergeWithDetail] did: the [counts] [merge] answers with, and how
     * many of the skipped entries were held back because the phone deleted
     * them ([keptDeleted]), and how many incoming copies were dated beyond
     * [MAX_CLOCK_SKEW_MS] ahead of the phone's clock ([clamped]), and how
     * many skipped entries have a policy sync does not carry ([notSyncable]).
     */
    data class MergeResult(
        val counts: SyncEngine.ItemCounts,
        val keptDeleted: Int = 0,
        val clamped: Int = 0,
        val notSyncable: Int = 0
    )

    /**
     * Exports the phone's password entries as [SyncPassword] JSON.
     *
     * `SyncPassword` carries no tenant, sharing or expiry, and [merge] adds a
     * new entry as a personal one, with no expiry, in the default tenant. An
     * entry with any other policy is therefore left out, so replicating it
     * into a fresh store cannot silently drop its policy; only how many were
     * left out is logged.
     *
     * @throws com.automatethethings.xkey.password.PasswordStoreLockedException
     *   if the store is locked.
     */
    suspend fun gather(): JSONArray {
        requirePasswordStoreUnlocked(factors)
        val out = JSONArray()
        var withheld = 0
        for (rec in repository.list()) {
            if (!rec.hasDefaultPolicy()) {
                withheld++
                continue
            }
            out.put(JSONObject().apply {
                put("id", rec.passwordId)
                put("name", rec.name)
                put("title", rec.title ?: JSONObject.NULL)
                put("username", rec.username ?: JSONObject.NULL)
                put("password", rec.password)
                put("url", rec.url ?: JSONObject.NULL)
                put("notes", rec.notes ?: JSONObject.NULL)
                put("folder_path", rec.folderPath ?: JSONObject.NULL)
                put("updated_at", SyncCodec.toRfc3339(rec.updatedAt))
            })
        }
        if (withheld > 0) {
            Log.w(TAG, "Withheld $withheld password entries from sync: SyncPassword cannot carry their tenant, sharing or expiry")
        }
        return out
    }

    /**
     * Imports/updates incoming password entries. An entry without an id or
     * password, or too large for go-xkms to read back
     * ([com.automatethethings.xkey.password.PasswordEntryTooLargeException]),
     * is counted as skipped and nothing is written for it, as is one that
     * keeps changing locally while it is merged
     * ([com.automatethethings.xkey.password.PasswordUpdateConflictException]).
     *
     * `SyncPassword` carries no tenant, sharing or expiry, so a sync writes
     * only the entries [gather] would send: an existing entry in the default
     * tenant, personal and with no expiry is patched in place; an entry of
     * another tenant, a shared one or an expiring one is left unchanged and
     * counted as skipped ([MergeResult.notSyncable]). A new one is added as a
     * personal entry, with no expiry, in the default tenant.
     *
     * A sync never writes an entry's tenant, sharing or expiry over the ones
     * it holds: an entry is added only while no entry has its id
     * ([PasswordRepository.insertIfAbsent]), and one added by another writer
     * between the check and the add is patched in place instead, or, if it
     * has been given a policy sync does not carry since, left unchanged.
     *
     * An existing entry is overwritten last-writer-wins: only by an incoming
     * copy whose `updated_at` is strictly newer than the stored one. An older
     * or equal copy, or one without a parseable `updated_at`, keeps the local
     * entry and is counted as skipped.
     *
     * An entry the phone deleted ([PasswordRepository.deletedAt]) is not added
     * back by a copy whose `updated_at` is the deletion time or earlier: the
     * peer has not seen the delete yet. It is counted as skipped. A copy
     * changed after the delete is added again. Deletion records older than
     * [PasswordRepository.DELETION_RETENTION_MS] are dropped first.
     *
     * The phone does not trust a peer clock running ahead of its own: a copy
     * whose `updated_at` is more than [MAX_CLOCK_SKEW_MS] ahead of the
     * phone's clock is clamped to the phone's time. It cannot tell when such a
     * copy was really changed, so it overwrites no existing entry and adds
     * back no deleted one (both counted as skipped); a new one is added with
     * the phone's time as its `updated_at`. Every clamped copy is counted in
     * [MergeResult.clamped].
     *
     * @throws com.automatethethings.xkey.password.PasswordStoreLockedException
     *   if the store is locked; nothing is written.
     */
    suspend fun merge(incoming: JSONArray): SyncEngine.ItemCounts = mergeWithDetail(incoming).counts

    /** [merge], answering with what it held back as well as its counts. */
    suspend fun mergeWithDetail(incoming: JSONArray): MergeResult {
        requirePasswordStoreUnlocked(factors)
        val now = clock()
        repository.pruneDeletions(now)
        var keptDeleted = 0
        var clamped = 0
        var notSyncable = 0
        var added = 0
        var updated = 0
        var skipped = 0
        for (i in 0 until incoming.length()) {
            val obj = incoming.optJSONObject(i) ?: continue
            val id = obj.optString("id", "")
            val password = obj.optString("password", "")
            if (id.isEmpty() || password.isEmpty()) {
                skipped++
                continue
            }
            val sentUpdatedAt = SyncCodec.parseRfc3339(obj.optString("updated_at", ""))
            // A peer clock this far ahead cannot be trusted: the copy is stored at the phone's time.
            val isClamped = sentUpdatedAt > now + MAX_CLOCK_SKEW_MS
            if (isClamped) clamped++
            val record = PasswordRecord(
                passwordId = id,
                name = obj.optString("name", "").ifBlank { id },
                title = obj.optString("title", "").ifBlank { null },
                username = obj.optString("username", "").ifBlank { null },
                password = password,
                url = obj.optString("url", "").ifBlank { null },
                notes = obj.optString("notes", "").ifBlank { null },
                folderPath = obj.optString("folder_path", "").ifBlank { null },
                source = "remote",
                updatedAt = if (isClamped) now else sentUpdatedAt
            )
            val patch = record.asPatch()
            // A clamped copy's real age is unknown, so it overwrites no existing entry (0 refuses every one).
            val olderThan = if (isClamped) 0L else record.updatedAt
            val existed = try {
                // In any tenant: an id names one entry, wherever it lives, but only one gather() would send is written.
                // Last writer wins: an existing entry is patched only while it is older than the incoming copy.
                when {
                    repository.updateFields(id, patch, onlyIfOlderThan = olderThan, onlyIfSyncable = true) -> true
                    // Deleted on the phone, and this copy is no newer than the delete: it stays deleted.
                    isDeletedSince(id, record.updatedAt, isClamped) -> {
                        keptDeleted++
                        skipped++
                        continue
                    }
                    // Added only while still absent: never replaces an entry another writer added since.
                    repository.insertIfAbsent(record) -> false
                    // Added meanwhile: patched in place like any existing entry, keeping the policy it was given.
                    repository.updateFields(id, patch, onlyIfOlderThan = olderThan, onlyIfSyncable = true) -> true
                    // Added and deleted again between the two: it keeps moving, so the next sync retries.
                    else -> throw PasswordUpdateConflictException()
                }
            } catch (e: PasswordEntryTooLargeException) {
                // Too large for go-xkms to read back over USB: nothing is written for it.
                skipped++
                continue
            } catch (e: PasswordNotNewerException) {
                // The local entry is the same age or newer (or the incoming one has no updated_at): it is kept.
                skipped++
                continue
            } catch (e: PasswordNotSyncableException) {
                // Another tenant's, shared or expiring: sync carries none of these, so it is left as it is.
                notSyncable++
                skipped++
                continue
            } catch (e: PasswordUpdateConflictException) {
                // Changed locally on every attempt: the local edit is kept, and the next sync retries.
                skipped++
                continue
            }
            if (existed) updated++ else added++
        }
        return MergeResult(SyncEngine.ItemCounts(added, updated, skipped), keptDeleted = keptDeleted, clamped = clamped, notSyncable = notSyncable)
    }

    /**
     * Whether the phone deleted [id] at or after [updatedAt], the incoming
     * copy's time: the peer's copy predates the delete, so it must not add
     * the entry back. A [clamped] copy's real time is unknown, so any
     * deletion record holds it back.
     */
    private suspend fun isDeletedSince(id: String, updatedAt: Long, clamped: Boolean): Boolean {
        val deletedAt = repository.deletedAt(id) ?: return false
        return clamped || updatedAt <= deletedAt
    }

    /**
     * The patch that sets every field this incoming [PasswordRecord] carries,
     * clearing the ones it leaves blank, as [PasswordRepository.upsert] would
     * write them. The expiry is left out, so the stored one is kept.
     */
    private fun PasswordRecord.asPatch() = PasswordPatch(
        name = name,
        title = title.orEmpty(),
        username = username.orEmpty(),
        password = password,
        url = url.orEmpty(),
        notes = notes.orEmpty(),
        folderPath = folderPath.orEmpty(),
        source = source,
        updatedAt = updatedAt
    )

    /** Whether [merge] would add this entry, from `SyncPassword`, with the policy it has. */
    private fun PasswordRecord.hasDefaultPolicy() = hasSyncablePolicy(tenantId, shared, expiresAt)

    companion object {
        private const val TAG = "PasswordSync"

        /** How far ahead of the phone's clock a peer's `updated_at` may be before it is clamped: 5 minutes. */
        const val MAX_CLOCK_SKEW_MS = 5L * 60 * 1000
    }
}
