// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under AGPL-3.0 (see LICENSE) or a commercial license.
// Contact licensing@automatethethings.com for commercial licensing options.

package com.automatethethings.xkey.sync

import android.util.Log
import com.automatethethings.xkey.crypto.SyncCodec
import com.automatethethings.xkey.password.PasswordEntity
import com.automatethethings.xkey.password.PasswordEntryTooLargeException
import com.automatethethings.xkey.password.PasswordPatch
import com.automatethethings.xkey.password.PasswordRecord
import com.automatethethings.xkey.password.PasswordRepository
import com.automatethethings.xkey.password.PasswordUpdateConflictException
import com.automatethethings.xkey.password.PasswordVaultFactorStore
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
    private val factors: PasswordVaultFactorStore
) {

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
     * `SyncPassword` carries no tenant, sharing or expiry, so an existing
     * entry is patched in place and keeps its own; a new one is added as a
     * personal entry, with no expiry, in the default tenant.
     *
     * A sync never writes an entry's tenant, sharing or expiry over the ones
     * it holds: an entry is added only while no entry has its id
     * ([PasswordRepository.insertIfAbsent]), and one added by another writer
     * between the check and the add, perhaps with its expiry set since, is
     * patched in place instead.
     *
     * @throws com.automatethethings.xkey.password.PasswordStoreLockedException
     *   if the store is locked; nothing is written.
     */
    suspend fun merge(incoming: JSONArray): SyncEngine.ItemCounts {
        requirePasswordStoreUnlocked(factors)
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
                updatedAt = SyncCodec.parseRfc3339(obj.optString("updated_at", ""))
            )
            val patch = record.asPatch()
            val existed = try {
                // In any tenant: an id names one entry, wherever it lives.
                when {
                    repository.updateFields(id, patch) -> true
                    // Added only while still absent: never replaces an entry another writer added since.
                    repository.insertIfAbsent(record) -> false
                    // Added meanwhile: patched in place like any existing entry, keeping the policy it was given.
                    repository.updateFields(id, patch) -> true
                    // Added and deleted again between the two: it keeps moving, so the next sync retries.
                    else -> throw PasswordUpdateConflictException()
                }
            } catch (e: PasswordEntryTooLargeException) {
                // Too large for go-xkms to read back over USB: nothing is written for it.
                skipped++
                continue
            } catch (e: PasswordUpdateConflictException) {
                // Changed locally on every attempt: the local edit is kept, and the next sync retries.
                skipped++
                continue
            }
            if (existed) updated++ else added++
        }
        return SyncEngine.ItemCounts(added, updated, skipped)
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
    private fun PasswordRecord.hasDefaultPolicy() =
        tenantId == PasswordEntity.DEFAULT_TENANT && !shared && expiresAt.isNullOrEmpty()

    private companion object {
        const val TAG = "PasswordSync"
    }
}
