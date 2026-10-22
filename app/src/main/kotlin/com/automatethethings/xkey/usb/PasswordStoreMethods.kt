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
package com.automatethethings.xkey.usb

import android.util.Log
import com.automatethethings.xkey.password.PasswordEntity
import com.automatethethings.xkey.password.PasswordEntryLimit
import com.automatethethings.xkey.password.PasswordEntryTooLargeException
import com.automatethethings.xkey.password.PasswordPatch
import com.automatethethings.xkey.password.PasswordRecord
import com.automatethethings.xkey.password.PasswordRepository
import com.automatethethings.xkey.password.PasswordScope
import com.automatethethings.xkey.password.PasswordStoreLockedException
import com.automatethethings.xkey.password.PasswordVault
import com.automatethethings.xkey.password.PasswordVaultCredential
import com.automatethethings.xkey.password.SessionPasswordVault
import com.automatethethings.xkey.password.VaultCredentialInvalidException
import com.automatethethings.xkey.password.VaultCredentialRejectedException
import com.automatethethings.xkey.password.VaultNotInitializedException
import com.automatethethings.xkey.password.VaultUnlockLockedOutException
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.Request
import com.automatethethings.xkey.protocol.Response
import com.automatethethings.xkey.protocol.TransportMethods
import org.json.JSONObject
import java.math.BigDecimal
import java.math.BigInteger
import java.security.SecureRandom
import java.time.DateTimeException
import java.time.Instant
import java.time.OffsetDateTime
import java.time.ZoneOffset
import java.util.UUID
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.cancellation.CancellationException

/**
 * The password-store methods go-xkms proxies over USB, with the request and
 * response shapes of go-xkms `pkg/api/transport/types.go` verbatim.
 *
 * Passwords are encrypted at rest by [PasswordRepository] with a Keystore key;
 * a plaintext password is decrypted only for a `PasswordGet` response, and a
 * listing never decrypts. Once [vault] has an enrolled factor, every method
 * that touches an entry answers [ErrorCodes.PASSWORD_STORE_LOCKED] until
 * `PasswordStoreUnlock` succeeds.
 *
 * Every entry belongs to the tenant `PasswordAdd` names in `tenant_id`, the
 * default tenant `""` when it names none. `PasswordGet`, `PasswordList`,
 * `PasswordUpdate` and `PasswordDelete` see only the entries of the tenant
 * their request names: another tenant's entry answers
 * [ErrorCodes.KEY_NOT_FOUND], exactly as an unknown id does, so a request
 * cannot learn that an id exists elsewhere. `tenant_id` is never in a
 * response. `PasswordList`'s `scope` lists the `personal` (not `shared`)
 * entries, the `shared` ones, or `all`, which an absent or empty scope means.
 *
 * `expires_at` must be an RFC 3339 date-time and is stored normalized to UTC
 * (`2027-01-02T05:04:05+02:00` is stored and answered as
 * `2027-01-02T03:04:05Z`); one that does not parse answers
 * [ErrorCodes.INVALID_PARAMS] and nothing is written. The phone stores the
 * expiry and does not enforce it.
 */
class PasswordStoreMethods(
    private val repository: PasswordRepository,
    private val vault: PasswordVault,
    private val random: SecureRandom = SecureRandom(),
    private val clock: () -> Long = System::currentTimeMillis
) : TransportMethods {

    companion object {
        private const val TAG = "PasswordStoreMethods"

        const val PASSWORD_ADD = "PasswordAdd"
        const val PASSWORD_GET = "PasswordGet"
        const val PASSWORD_LIST = "PasswordList"
        const val PASSWORD_UPDATE = "PasswordUpdate"
        const val PASSWORD_DELETE = "PasswordDelete"
        const val PASSWORD_STORE_UNLOCK = "PasswordStoreUnlock"
        const val PASSWORD_STORE_LOCK = "PasswordStoreLock"
        const val PASSWORD_STORE_STATUS = "PasswordStoreStatus"
        const val PASSWORD_GENERATE = "PasswordGenerate"

        private val METHODS = setOf(
            PASSWORD_ADD, PASSWORD_GET, PASSWORD_LIST, PASSWORD_UPDATE, PASSWORD_DELETE,
            PASSWORD_STORE_UNLOCK, PASSWORD_STORE_LOCK, PASSWORD_STORE_STATUS, PASSWORD_GENERATE
        )

        /** Values a `PasswordListRequest.scope` may name, besides absent or empty for all. */
        private val SCOPES = PasswordScope.entries.joinToString(", ") { it.wireName }

        /** Years an expiry may fall in, in UTC: the four-digit years RFC 3339 can write. */
        private val EXPIRY_YEARS = 0..9999

        /** The phone's store is its own Keystore-backed one, not a desktop backend. */
        const val ACCESS_MODE_LOCAL = "local"

        /** `PageRequest.page_size` default when a page is asked for without one. */
        const val DEFAULT_PAGE_SIZE = 25

        /** The largest serialized `PasswordGetResponse` an entry may have; see [PasswordEntryLimit]. */
        val MAX_ENTRY_SIZE: Int = PasswordEntryLimit.MAX_ENTRY_SIZE

        const val DEFAULT_GENERATE_LENGTH = 24
        const val MAX_GENERATE_LENGTH = 256

        private const val UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        private const val LOWER = "abcdefghijklmnopqrstuvwxyz"
        private const val DIGITS = "0123456789"
        private const val SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/~"
    }

    /** A request the store refuses as malformed. */
    private class InvalidParamsException(message: String) : Exception(message)

    /** A request naming an entry that does not exist. */
    private class NotFoundException(message: String) : Exception(message)

    /** An entry stored, before every writer was held to [MAX_ENTRY_SIZE], too large for a `PasswordGet` frame. */
    private class EntryTooLargeException : Exception("password entry does not fit the frame")

    override fun handles(method: String): Boolean = method in METHODS

    /**
     * Names [vault] to the shared handler's password sync, so `local.syncPasswords`
     * on this session is gated by the same lock as these methods.
     */
    override fun routingContext(): CoroutineContext = SessionPasswordVault(vault)

    override suspend fun handle(request: Request): Response {
        return try {
            val params = request.params ?: JSONObject()
            val result = when (request.method) {
                PASSWORD_ADD -> add(params)
                PASSWORD_GET -> get(params)
                PASSWORD_LIST -> list(params)
                PASSWORD_UPDATE -> update(params)
                PASSWORD_DELETE -> delete(params)
                PASSWORD_STORE_UNLOCK -> unlock(request.params)
                PASSWORD_STORE_LOCK -> lock()
                PASSWORD_STORE_STATUS -> status()
                PASSWORD_GENERATE -> generate(params)
                else -> return Response.error(
                    request.id, ErrorCodes.METHOD_NOT_FOUND, "Unknown method: ${request.method}"
                )
            }
            Response.success(request.id, result)
        } catch (e: CancellationException) {
            throw e
        } catch (e: InvalidParamsException) {
            Response.error(request.id, ErrorCodes.INVALID_PARAMS, e.message ?: "invalid params")
        } catch (e: PasswordEntryTooLargeException) {
            Response.error(request.id, ErrorCodes.INVALID_PARAMS, e.message ?: "entry does not fit the frame")
        } catch (e: PageOverflowException) {
            Response.error(request.id, ErrorCodes.INVALID_PARAMS, e.message ?: "page does not fit the frame")
        } catch (e: EntryTooLargeException) {
            Response.error(request.id, ErrorCodes.INTERNAL_ERROR, e.message ?: "entry does not fit the frame")
        } catch (e: VaultCredentialInvalidException) {
            Response.error(request.id, ErrorCodes.INVALID_PARAMS, e.message ?: "invalid credential")
        } catch (e: NotFoundException) {
            Response.error(request.id, ErrorCodes.KEY_NOT_FOUND, e.message ?: "not found")
        } catch (e: VaultNotInitializedException) {
            Response.error(request.id, ErrorCodes.VAULT_NOT_INITIALIZED, e.message ?: "not initialized")
        } catch (e: VaultUnlockLockedOutException) {
            // The PIN path's lockout code, and nothing else: no lockout end, no count.
            Response.error(request.id, ErrorCodes.PIN_LOCKED, "password vault is locked out")
        } catch (e: VaultCredentialRejectedException) {
            Response.error(request.id, ErrorCodes.VAULT_CREDENTIAL_REJECTED, e.message ?: "rejected")
        } catch (e: PasswordStoreLockedException) {
            Response.error(request.id, ErrorCodes.PASSWORD_STORE_LOCKED, e.message ?: "locked")
        } catch (e: Exception) {
            // Never echo the cause: it may carry an entry's content.
            Response.error(request.id, ErrorCodes.INTERNAL_ERROR, "password store operation failed")
        }
    }

    // -------------------------------------------------------------------------
    // Entries
    // -------------------------------------------------------------------------

    private suspend fun add(params: JSONObject): JSONObject {
        requireUnlocked()
        val name = params.string("name")
        if (name.isNullOrEmpty()) throw InvalidParamsException("name is required")
        val password = params.string("password")
        if (password.isNullOrEmpty()) throw InvalidParamsException("password is required")
        val now = clock()
        val record = PasswordRecord(
            passwordId = UUID.randomUUID().toString(),
            name = name,
            title = params.string("title").orNullIfEmpty(),
            username = params.string("username").orNullIfEmpty(),
            password = password,
            url = params.string("url").orNullIfEmpty(),
            notes = params.string("notes").orNullIfEmpty(),
            folderPath = params.string("folder_path").orNullIfEmpty(),
            createdAt = now,
            updatedAt = now,
            expiresAt = params.string("expires_at").orNullIfEmpty()?.let { normalizeExpiry(it) },
            shared = params.bool("shared"),
            tenantId = params.tenant()
        )
        // Refused with PasswordEntryTooLargeException, before the write, if it could not be read back.
        val id = repository.upsert(record)
        return JSONObject().apply {
            put("id", id)
            put("name", name)
            put("created_at", iso(now))
        }
    }

    private suspend fun get(params: JSONObject): JSONObject {
        requireUnlocked()
        val id = params.requireId()
        val record = repository.get(id, params.tenant()) ?: throw NotFoundException("password not found")
        val result = PasswordEntryLimit.getResponse(record)
        // Every writer now refuses such an entry; only one stored before that gets here.
        if (FrameBudget.serializedSize(result) > FrameBudget.RESULT_BUDGET) throw EntryTooLargeException()
        return result
    }

    /** `PasswordListResponse` for `PasswordListRequest` [params], paged within the frame by [FrameBudget.page]. */
    private suspend fun list(params: JSONObject): JSONObject {
        requireUnlocked()
        val folder = params.string("folder_path").orNullIfEmpty()
        val scope = params.scope()
        val tenant = params.tenant()
        val page = params.int("page") ?: 0
        if (page < 0) throw InvalidParamsException("page must not be negative")
        val requestedSize = params.int("page_size") ?: 0
        if (requestedSize < 0) throw InvalidParamsException("page_size must not be negative")
        val descending = (params.int("sort_order") ?: 0) == 1

        val selector: (PasswordRecord) -> Comparable<*>? = when (params.string("sort_field")) {
            "title" -> PasswordRecord::title
            "username" -> PasswordRecord::username
            "url" -> PasswordRecord::url
            "folder_path" -> PasswordRecord::folderPath
            "created_at" -> PasswordRecord::createdAt
            "updated_at" -> PasswordRecord::updatedAt
            else -> PasswordRecord::name
        }
        // Tenant, scope and folder are filtered in the query, so every page is cut from matches only.
        val ascending = repository.listInTenant(tenant, scope, folder)
            .sortedWith(compareBy<PasswordRecord>(selector))
        val records = if (descending) ascending.reversed() else ascending

        // An entry whose id alone overflows a list item is left out, so it
        // cannot stall the pages after it; total counts only listed entries.
        val items = records.mapNotNull { PasswordEntryLimit.listItem(it) }
        val unlisted = records.size - items.size
        if (unlisted > 0) {
            Log.w(TAG, "PasswordList left out $unlisted entries whose id is too large to list; delete them on the phone")
        }
        return FrameBudget.page("passwords", items, page, requestedSize, DEFAULT_PAGE_SIZE)
    }

    private suspend fun update(params: JSONObject): JSONObject {
        requireUnlocked()
        val id = params.requireId()

        // `*string` on the wire: absent (or null) leaves a field unchanged, and
        // the repository applies the patch to the entry as it stands at the write.
        val name = params.string("name")
        if (name != null && name.isEmpty()) throw InvalidParamsException("name must not be empty")
        val password = params.string("password")
        if (password != null && password.isEmpty()) throw InvalidParamsException("password must not be empty")

        val patch = PasswordPatch(
            name = name,
            title = params.string("title"),
            username = params.string("username"),
            password = password,
            url = params.string("url"),
            notes = params.string("notes"),
            folderPath = params.string("folder_path"),
            // `*string` too: "" clears the expiry, any other value must parse.
            expiresAt = params.string("expires_at")?.let { if (it.isEmpty()) it else normalizeExpiry(it) },
            updatedAt = clock()
        )
        val updated = repository.updateFields(id, patch, params.tenant())
        if (!updated) throw NotFoundException("password not found")
        return JSONObject()
    }

    private suspend fun delete(params: JSONObject): JSONObject {
        requireUnlocked()
        val id = params.requireId()
        if (!repository.delete(id, params.tenant())) throw NotFoundException("password not found")
        return JSONObject()
    }

    // -------------------------------------------------------------------------
    // Store
    // -------------------------------------------------------------------------

    private suspend fun unlock(params: JSONObject?): JSONObject {
        vault.unlock(PasswordVaultCredential.fromJson(params))
        return JSONObject()
    }

    private suspend fun lock(): JSONObject {
        vault.lock()
        return JSONObject()
    }

    private suspend fun status(): JSONObject {
        val locked = vault.isLocked()
        return JSONObject().apply {
            put("access_mode", ACCESS_MODE_LOCAL)
            put("is_locked", locked)
            put("barrier_sealed", false)
            put("auto_unsealed", false)
            // A locked store does not disclose how much it holds.
            put("password_count", if (locked) 0 else repository.count())
        }
    }

    /**
     * `PasswordGenerate`: a random password of `length` Unicode code points
     * (characters, not UTF-16 units), [DEFAULT_GENERATE_LENGTH] when absent or
     * 0. Every character comes from `charset` when it is given, or else from
     * the selected built-in classes, with at least one from each. A `charset`
     * holding an unpaired surrogate is refused: it is not a character.
     */
    private fun generate(params: JSONObject): JSONObject {
        val requested = params.int("length") ?: 0
        if (requested < 0 || requested > MAX_GENERATE_LENGTH) {
            throw InvalidParamsException("length must be between 0 and $MAX_GENERATE_LENGTH")
        }
        val length = if (requested == 0) DEFAULT_GENERATE_LENGTH else requested

        // Code points, not UTF-16 units, so a character outside the BMP is picked and shuffled whole.
        val charset = params.string("charset").orNullIfEmpty()
        val classes: List<IntArray> = if (charset != null) {
            val codePoints = charset.codePoints().toArray()
            if (codePoints.any { it in Character.MIN_SURROGATE.code..Character.MAX_SURROGATE.code }) {
                throw InvalidParamsException("charset holds an unpaired surrogate, which is not a character")
            }
            listOf(codePoints)
        } else {
            val selected = listOfNotNull(
                UPPER.takeIf { params.bool("upper") },
                LOWER.takeIf { params.bool("lower") },
                DIGITS.takeIf { params.bool("digits") },
                SYMBOLS.takeIf { params.bool("symbols") }
            )
            selected.ifEmpty { listOf(UPPER, LOWER, DIGITS, SYMBOLS) }.map { it.codePoints().toArray() }
        }
        if (length < classes.size) {
            throw InvalidParamsException("length is shorter than the selected character classes")
        }

        // One character from each selected class, the rest from all of them,
        // then a Fisher-Yates shuffle so the guaranteed ones are not in front.
        val alphabet = classes.reduce { all, cls -> all + cls }
        val picked = IntArray(length)
        classes.forEachIndexed { i, cls -> picked[i] = cls[random.nextInt(cls.size)] }
        for (i in classes.size until length) picked[i] = alphabet[random.nextInt(alphabet.size)]
        for (i in length - 1 downTo 1) {
            val j = random.nextInt(i + 1)
            val t = picked[i]
            picked[i] = picked[j]
            picked[j] = t
        }
        val password = StringBuilder(length).apply { picked.forEach { appendCodePoint(it) } }.toString()
        return JSONObject().apply { put("password", password) }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private suspend fun requireUnlocked() {
        if (vault.isLocked()) throw PasswordStoreLockedException()
    }

    private fun iso(epochMillis: Long): String = Instant.ofEpochMilli(epochMillis).toString()

    private fun String?.orNullIfEmpty(): String? = if (isNullOrEmpty()) null else this

    private fun JSONObject.requireId(): String {
        val id = string("id")
        if (id.isNullOrEmpty()) throw InvalidParamsException("id is required")
        return id
    }

    /** The request's `tenant_id`: absent, null and `""` all name the default tenant. */
    private fun JSONObject.tenant(): String = string("tenant_id") ?: PasswordEntity.DEFAULT_TENANT

    /** The request's `scope`: absent, null or `""` is [PasswordScope.ALL]; an unknown name is refused. */
    private fun JSONObject.scope(): PasswordScope {
        val name = string("scope").orNullIfEmpty() ?: return PasswordScope.ALL
        return PasswordScope.fromWire(name) ?: throw InvalidParamsException("scope must be one of $SCOPES")
    }

    /**
     * [value], an RFC 3339 date-time, as the UTC instant it names in
     * `Instant.toString` form, which is RFC 3339 too: at most 30 chars, with
     * the fraction of a second kept. Refuses one that does not parse or falls
     * outside the years [EXPIRY_YEARS].
     */
    private fun normalizeExpiry(value: String): String {
        val utc = try {
            OffsetDateTime.parse(value).withOffsetSameInstant(ZoneOffset.UTC)
        } catch (e: DateTimeException) {
            throw InvalidParamsException("expires_at must be an RFC 3339 date-time")
        }
        if (utc.year !in EXPIRY_YEARS) throw InvalidParamsException("expires_at must be an RFC 3339 date-time")
        return utc.toInstant().toString()
    }

    private fun JSONObject.string(key: String): String? {
        if (!has(key) || isNull(key)) return null
        return get(key) as? String ?: throw InvalidParamsException("$key must be a string")
    }

    /**
     * An optional `int` field, or null when absent. Only an integral number
     * inside the `Int` range is taken, so an oversized or fractional value is
     * refused rather than wrapped or truncated past the field's own bounds.
     * org.json yields a `Long` for an integer literal past `Int`, a `Double`
     * (Android) or `BigDecimal` (org.json on the JVM) for a fraction, and a
     * `Double` or `BigInteger` for a literal past `Long`.
     */
    private fun JSONObject.int(key: String): Int? {
        if (!has(key) || isNull(key)) return null
        val value = get(key)
        return when (value) {
            is Int -> value
            is Short -> value.toInt()
            is Byte -> value.toInt()
            is Long -> if (value in Int.MIN_VALUE.toLong()..Int.MAX_VALUE.toLong()) value.toInt() else null
            is Double -> value.exactInt()
            is Float -> value.toDouble().exactInt()
            is BigInteger -> if (value.bitLength() <= 31) value.toInt() else null
            is BigDecimal -> try {
                value.intValueExact()
            } catch (e: ArithmeticException) {
                null
            }
            else -> null
        } ?: throw InvalidParamsException("$key must be an integer")
    }

    /** This double as an `Int` when it is finite, integral and inside the `Int` range, else null. */
    private fun Double.exactInt(): Int? =
        if (isFinite() && this % 1.0 == 0.0 && this >= Int.MIN_VALUE && this <= Int.MAX_VALUE) toInt() else null

    private fun JSONObject.bool(key: String): Boolean {
        if (!has(key) || isNull(key)) return false
        return get(key) as? Boolean ?: throw InvalidParamsException("$key must be a boolean")
    }
}
