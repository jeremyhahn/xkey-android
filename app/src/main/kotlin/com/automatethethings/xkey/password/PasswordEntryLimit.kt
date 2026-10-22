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
package com.automatethethings.xkey.password

import com.automatethethings.xkey.usb.FrameBudget
import org.json.JSONObject
import java.time.Instant

/**
 * A write refused, before anything is stored, because the entry's
 * `PasswordGetResponse` would serialize to [size] bytes, over the [max] every
 * entry is held to ([PasswordEntryLimit.MAX_ENTRY_SIZE]). The message names
 * only sizes, never content.
 */
class PasswordEntryTooLargeException(val size: Int, val max: Int) :
    Exception("entry is $size bytes as JSON; a PasswordGet response can carry at most $max")

/**
 * The size every password entry is held to, whoever writes it, and the JSON
 * go-xkms reads entries as: `PasswordGetResponse` of
 * `pkg/api/transport/types.go`, names verbatim.
 *
 * go-xkms reads entries over USB, one frame per response, so an entry is
 * refused if its `PasswordGetResponse` would not fit [MAX_ENTRY_SIZE].
 * [PasswordRepository] applies [requireFits] on every write, which covers
 * USB, sync and the phone UI alike.
 */
internal object PasswordEntryLimit {

    /**
     * The largest serialized `PasswordGetResponse` an entry may have. It
     * leaves room for the widest `PasswordListResponse` around it, so every
     * entry can be read with `PasswordGet` and listed on a page of its own
     * within one frame.
     *
     * Derived from the USB frame budget, so the two cannot drift: the
     * 65535-byte frame, less the 16-byte Noise tag, the 37-byte JSON-RPC
     * envelope at the longest id, the 34-byte generation reserve
     * (go-xkms#128 / #10), and the 93-byte empty `passwords` page at the widest
     * numbers, 65,355 bytes. A `PasswordGet` of such an entry fits with room to
     * spare; a list item omits the password, so it is never larger than the
     * entry. The USB tests pin the value and check the one-entry page.
     */
    val MAX_ENTRY_SIZE: Int = FrameBudget.RESULT_BUDGET - FrameBudget.pageOverhead("passwords")

    /**
     * Longest name, in UTF-16 chars, a minimal list item carries when the
     * whole name would not fit. JSON writes a char as at most six bytes, so a
     * capped name stays a few KiB; [listItem] cuts it further if the `id`
     * leaves less room.
     */
    const val MINIMAL_NAME_CHARS = 1024

    /** `PasswordGetResponse` for [record], omitting every empty `omitempty` field. */
    fun getResponse(record: PasswordRecord): JSONObject = JSONObject().apply {
        put("id", record.passwordId)
        put("name", record.name)
        putIfNotEmpty("title", record.title)
        putIfNotEmpty("username", record.username)
        putIfNotEmpty("password", record.password)
        putIfNotEmpty("url", record.url)
        putIfNotEmpty("notes", record.notes)
        putIfNotEmpty("folder_path", record.folderPath)
        put("created_at", iso(record.createdAt))
        put("updated_at", iso(record.updatedAt))
        putIfNotEmpty("expires_at", record.expiresAt)
        if (record.shared) put("shared", true)
        // Every entry is encrypted at rest under the Keystore key.
        put("encrypted", true)
        // tenant_id is a request filter only: go-xkms has no response field for it.
    }

    /**
     * The `PasswordListResponse` item for [record], which carries no password,
     * or null if [record] cannot be listed at all. An item is never larger
     * than [MAX_ENTRY_SIZE].
     *
     * An entry stored before every writer was held to [MAX_ENTRY_SIZE] may be
     * too large for a page of its own. It is then listed in minimal form,
     * `id`, `name`, `created_at`, `updated_at` and `encrypted`, so it still
     * appears and can be deleted by `id`. Every other field is `omitempty` in
     * `PasswordGetResponse`, so leaving them out is wire-valid. The listed
     * name is cut to at most [MINIMAL_NAME_CHARS] chars and to the room the
     * full `id` leaves, down to empty.
     *
     * An entry whose `id` alone is too large for a minimal item gives null:
     * cutting the `id` would list an entry `PasswordDelete` cannot find. No
     * writer stores such an `id` now, since [requireFits] measures a
     * `PasswordGetResponse`, which holds every member of the minimal item;
     * only a legacy sync import could have, and the phone UI deletes it.
     */
    fun listItem(record: PasswordRecord): JSONObject? {
        val full = getResponse(record.copy(password = ""))
        if (serializedSize(full) <= MAX_ENTRY_SIZE) return full
        val minimal = minimalItem(record, record.name)
        if (serializedSize(minimal) <= MAX_ENTRY_SIZE) return minimal
        if (serializedSize(minimalItem(record, "")) > MAX_ENTRY_SIZE) return null
        // The name is too large to list beside the id. Only this listing's copy
        // is cut, to the longest prefix that fits; the stored name is untouched
        // and PasswordDelete still finds the entry by id.
        val name = prefix(record.name, MINIMAL_NAME_CHARS)
        var fits = 0
        var tooLong = name.length + 1
        while (tooLong - fits > 1) {
            val mid = (fits + tooLong) / 2
            if (serializedSize(minimalItem(record, prefix(name, mid))) <= MAX_ENTRY_SIZE) fits = mid else tooLong = mid
        }
        return minimalItem(record, prefix(name, fits))
    }

    /** Refuses [record] with [PasswordEntryTooLargeException] if its `PasswordGetResponse` exceeds [MAX_ENTRY_SIZE]. */
    fun requireFits(record: PasswordRecord) {
        val size = serializedSize(getResponse(record))
        if (size > MAX_ENTRY_SIZE) throw PasswordEntryTooLargeException(size, MAX_ENTRY_SIZE)
    }

    /**
     * Whether [record], with its password left out, surely fits once a stored
     * password whose ciphertext is [storedSize] bytes is added. AES-GCM output
     * is never shorter than the plaintext, and JSON writes one UTF-8 byte as
     * at most six, so this holds without decrypting.
     */
    fun fitsWithStoredPassword(record: PasswordRecord, storedSize: Int): Boolean {
        val withoutPassword = serializedSize(getResponse(record.copy(password = "")))
        // `,"password":"<value>"` with every stored byte at its longest escape.
        val bound = withoutPassword + 1 + JSONObject.quote("password").length + 1 + 2 + 6L * storedSize
        return bound <= MAX_ENTRY_SIZE
    }

    /** The UTF-8 size of [json] as org.json writes it. */
    fun serializedSize(json: JSONObject): Int = json.toString().toByteArray(Charsets.UTF_8).size

    private fun minimalItem(record: PasswordRecord, name: String): JSONObject = JSONObject().apply {
        put("id", record.passwordId)
        put("name", name)
        put("created_at", iso(record.createdAt))
        put("updated_at", iso(record.updatedAt))
        put("encrypted", true)
    }

    /** The first [chars] chars of [name], never splitting a surrogate pair. */
    private fun prefix(name: String, chars: Int): String {
        if (name.length <= chars) return name
        val end = if (chars > 0 && Character.isHighSurrogate(name[chars - 1])) chars - 1 else chars
        return name.substring(0, end)
    }

    private fun JSONObject.putIfNotEmpty(key: String, value: String?) {
        if (!value.isNullOrEmpty()) put(key, value)
    }

    private fun iso(epochMillis: Long): String = Instant.ofEpochMilli(epochMillis).toString()
}
