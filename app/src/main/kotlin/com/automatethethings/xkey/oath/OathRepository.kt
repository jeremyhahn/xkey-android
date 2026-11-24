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
package com.automatethethings.xkey.oath

import android.net.Uri
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.audit.auditedWrite
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import java.net.URLEncoder
import java.security.MessageDigest
import java.util.UUID

/**
 * Presentation wrapper combining an [OathCredentialEntity] with its current OTP code.
 *
 * Used by UI layers to display credential details alongside the live code and
 * the number of seconds remaining until the code expires (TOTP only; for HOTP
 * this value is always 0).
 *
 * @property credential The underlying OATH credential entity.
 * @property code The current one-time password code string.
 * @property secondsRemaining Seconds until the current TOTP code expires (0 for HOTP).
 * @property codeError True when no code could be computed for this row (its
 *           secret cannot be decrypted, or a stored field the engine refuses);
 *           [code] is then [OathRepository.NO_CODE].
 */
data class OathCredentialWithCode(
    val credential: OathCredentialEntity,
    val code: String,
    val secondsRemaining: Int,
    val codeError: Boolean = false
)

/** What [OathRepository.upsertStructured] did with one synced item. */
enum class SyncMergeOutcome {
    /** No row had the id: one was added. */
    ADDED,

    /** A row had the id: it was updated in place. */
    UPDATED,

    /** The id was deleted on the phone: nothing was written. */
    DELETED,

    /**
     * A row had the id with other key material (secret, type, algorithm,
     * digits or period): nothing was written and an audit entry names the id.
     */
    CONFLICT
}

/**
 * The `otpauth://` URI ([Key Uri Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format))
 * that [OathRepository.importStructured] builds from separate fields. Every
 * value is percent-encoded (RFC 3986, a space as `%20`); the issuer and the
 * account are joined by a literal `:`. [counter] is written when non-null.
 *
 * Read it back only through [OathRepository.importStructured]: the
 * external-import parser behind [OathRepository.importFromUri] also splits
 * an issuerless label on an encoded `%3A`.
 */
internal fun otpauthUri(
    type: String,
    issuer: String?,
    accountName: String,
    secret: String,
    algorithm: String,
    digits: Int,
    period: Int,
    counter: Long?
): String = buildString {
    val encodedIssuer = issuer?.let(::percentEncode)
    append("otpauth://$type/")
    if (encodedIssuer != null) append("$encodedIssuer:")
    append(percentEncode(accountName))
    append("?secret=${percentEncode(secret)}")
    if (encodedIssuer != null) append("&issuer=$encodedIssuer")
    append("&algorithm=${percentEncode(algorithm)}")
    append("&digits=$digits")
    append("&period=$period")
    if (counter != null) append("&counter=$counter")
}

/**
 * Uses the charset-name overload: `URLEncoder.encode(String, Charset)` is
 * API 33, above minSdk 28, and throws NoSuchMethodError below it.
 */
private fun percentEncode(value: String): String =
    URLEncoder.encode(value, Charsets.UTF_8.name()).replace("+", "%20")

/**
 * High-level API for managing OATH (TOTP/HOTP) credentials.
 *
 * Combines the persistence layer ([OathCredentialDao]), secret encryption
 * ([OathSecretManager]), and code generation ([OathEngine]) into a single
 * cohesive facade. All credential secrets are encrypted at rest using
 * Android Keystore-backed keys through [OathSecretManager], and are only
 * decrypted transiently during code generation.
 *
 * Features:
 * - Add credentials manually by providing raw secret bytes
 * - Import credentials from `otpauth://` URIs (TOTP and HOTP)
 * - Generate current OTP codes with automatic counter management for HOTP
 * - Observe all credentials as a reactive [Flow] with live codes
 * - Delete credentials
 * - Export local credentials for remote synchronization
 *
 * Usage:
 * ```kotlin
 * val repo = OathRepository(dao, secretManager)
 *
 * // Add a credential manually
 * val oathId = repo.addCredential(
 *     issuer = "GitHub",
 *     accountName = "user@example.com",
 *     secret = decodedSecret
 * )
 *
 * // Import from a QR code URI
 * val oathId2 = repo.importFromUri("otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub")
 *
 * // Generate the current code
 * val code = repo.generateCode(oathId)
 *
 * // Observe all credentials with live codes
 * repo.observeAll().collect { credentialsWithCodes ->
 *     // Update UI
 * }
 * ```
 *
 * @param dao Data access object for credential persistence.
 * @param secretManager Handles encryption and decryption of OATH shared secrets.
 */
class OathRepository(
    private val dao: OathCredentialDao,
    private val secretManager: OathSecretManager
) {

    /**
     * Add a new OATH credential with the given parameters.
     *
     * Generates a unique identifier, encrypts the shared secret using
     * [OathSecretManager], and persists the credential in the local database.
     *
     * @param issuer Optional issuer name (e.g., "GitHub", "Google").
     * @param accountName User account name or email address.
     * @param secret Raw shared secret bytes (unencrypted).
     * @param type OTP type: "TOTP" or "HOTP". Defaults to "TOTP".
     * @param algorithm HMAC algorithm: "SHA1", "SHA256", or "SHA512". Defaults to "SHA1".
     * @param digits Number of digits in the generated code. Defaults to 6.
     * @param periodSeconds Time step in seconds for TOTP. Defaults to 30.
     * @param counter Initial HOTP counter. Persisted with the credential in the
     *        same insert, so an interrupted import can never leave a credential
     *        sitting at counter 0 and desynchronised from the server.
     * @return The generated unique oath identifier.
     */
    suspend fun addCredential(
        issuer: String?,
        accountName: String,
        secret: ByteArray,
        type: String = "TOTP",
        algorithm: String = "SHA1",
        digits: Int = 6,
        periodSeconds: Int = 30,
        counter: Long = 0L,
        caller: OathAuditCaller = OathAuditCaller.LOCAL
    ): String {
        val oathId = UUID.randomUUID().toString()
        val encryptedSecret = secretManager.encryptSecret(secret)
        val now = System.currentTimeMillis()

        val entity = OathCredentialEntity(
            oathId = oathId,
            oathType = type.uppercase(),
            algorithm = algorithm.uppercase(),
            digits = digits,
            periodSeconds = periodSeconds,
            counter = counter,
            issuer = issuer,
            accountName = accountName,
            secretEncrypted = encryptedSecret,
            source = "local",
            createdAt = now
        )

        // Every add (QR scan, manual entry, local.oathAdd) passes here: the
        // one place it is audited, even when the caller is cancelled after
        // the insert commits. The row names the credential, never its secret.
        auditedWrite(
            write = { dao.insert(entity) },
            audit = { AuditLogger.logOathCredentialCreated(
                oathId, issuer, accountName, entity.oathType, caller.deviceId, caller.deviceName
            ) }
        )
        return oathId
    }

    /**
     * Import an OATH credential from an `otpauth://` URI.
     *
     * Parses the URI according to the
     * [Key Uri Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format):
     * ```
     * otpauth://totp/Issuer:account@example.com?secret=BASE32SECRET&issuer=Issuer&algorithm=SHA1&digits=6&period=30
     * otpauth://hotp/Issuer:account@example.com?secret=BASE32SECRET&issuer=Issuer&counter=0
     * ```
     *
     * The label path segment may be either `issuer:account` or just `account`.
     * The `secret` query parameter is required and must be Base32-encoded (RFC 4648).
     * All other query parameters are optional with sensible defaults.
     *
     * This is the path for a URI that comes from outside the app (a scanned
     * QR code): its label also splits on an encoded `%3A` ([parseOathLabel]).
     * A credential the app holds as separate issuer and account fields goes
     * through [importStructured] instead, never through a URI built here.
     *
     * @param uri The `otpauth://` URI string to parse.
     * @return The generated unique oath identifier for the imported credential.
     * @throws IllegalArgumentException if the URI scheme is not `otpauth`,
     *         the type is not `totp` or `hotp`, the `secret` parameter is missing,
     *         not Base32 or under 80 bits, the algorithm is not SHA1, SHA256 or
     *         SHA512, digits is not 6 to 8, or a TOTP period is not a positive
     *         number of seconds (an HOTP period is ignored).
     *         The message never carries the secret.
     */
    suspend fun importFromUri(uri: String): String = importParsed(uri, structuredLabel = false)

    /**
     * Import an OATH credential the app holds as separate fields (local.oathAdd,
     * sync, manual entry): the one path for an app-built URI. It builds the
     * percent-encoded URI with [otpauthUri] and reads its label back with
     * [parseStructuredOathLabel], where only a literal `:` separates the
     * issuer from the account, so an issuerless account `host:user` stays
     * whole (#152, #156).
     *
     * @param type `totp` or `hotp`, in any case.
     * @param secret The Base32-encoded secret.
     * @param counter The HOTP counter; ignored for TOTP.
     * @return The generated unique oath identifier for the imported credential.
     * @throws IllegalArgumentException as [importFromUri] does.
     */
    suspend fun importStructured(
        type: String,
        issuer: String?,
        accountName: String,
        secret: String,
        algorithm: String = "SHA1",
        digits: Int = 6,
        period: Int = 30,
        counter: Long? = null,
        caller: OathAuditCaller = OathAuditCaller.LOCAL
    ): String {
        val otpType = type.lowercase()
        val uri = otpauthUri(
            type = otpType,
            issuer = issuer,
            accountName = accountName,
            secret = secret,
            algorithm = algorithm,
            digits = digits,
            period = period,
            counter = if (otpType == "hotp") counter ?: 0L else null
        )
        return importParsed(uri, structuredLabel = true, caller = caller)
    }

    /**
     * Merge a credential a paired peer synced, under the peer's [oathId]: the
     * one entry point that turns a synced item into an OATH row. The fields
     * are decoded and validated as [importStructured] does them. While no
     * row has [oathId] one is added under it. A row with other key material
     * (secret, type, algorithm, digits or period) is a conflict: the wire
     * item carries no timestamp, so nothing is written and an audit entry
     * names the id. Otherwise the row's label is updated in place
     * ([OathCredentialDao.updateSynced]), keeping its primary key,
     * creation time and usage statistics, with the HOTP counter the larger
     * of the stored one and [counter]. Merging the same item again therefore
     * never adds a second row. An id deleted on the phone
     * ([deleteCredential]) is never added back: the deletion check and each
     * insert run in one DAO transaction
     * ([OathCredentialDao.insertIfAbsentUnlessDeleted]), and a row still
     * stored under a deleted id is removed.
     *
     * @return what the merge did with the item ([SyncMergeOutcome]).
     * @throws IllegalArgumentException if [oathId] is blank or the fields are
     *         invalid (for example a secret that is not Base32); nothing is written.
     */
    suspend fun upsertStructured(
        oathId: String,
        type: String,
        issuer: String?,
        accountName: String,
        secret: String,
        algorithm: String = "SHA1",
        digits: Int = 6,
        period: Int = 30,
        counter: Long? = null
    ): SyncMergeOutcome {
        require(oathId.isNotBlank()) { "Missing OATH credential id" }
        // A row an interrupted merge left beside the deletion record goes too, in the same transaction.
        if (dao.removeIfDeleted(oathId)) return SyncMergeOutcome.DELETED
        val otpType = type.lowercase()
        val parsed = parseOathUri(
            otpauthUri(
                type = otpType,
                issuer = issuer,
                accountName = accountName,
                secret = secret,
                algorithm = algorithm,
                digits = digits,
                period = period,
                counter = if (otpType == "hotp") counter ?: 0L else null
            ),
            structuredLabel = true
        )
        val encryptedSecret = secretManager.encryptSecret(parsed.secret)
        val entity = OathCredentialEntity(
            oathId = oathId,
            oathType = parsed.type,
            algorithm = parsed.algorithm,
            digits = parsed.digits,
            periodSeconds = parsed.periodSeconds,
            counter = parsed.counter,
            issuer = parsed.issuer,
            accountName = parsed.accountName,
            secretEncrypted = encryptedSecret,
            source = "local",
            createdAt = System.currentTimeMillis()
        )
        // Never REPLACE: that deletes the row and inserts a new one, losing its usage statistics.
        // The deletion check and the insert are one transaction: a delete cannot land between them.
        insertedUnlessDeleted(entity)?.let { return it }
        val stored = dao.getByOathId(oathId)
        if (stored != null && !sameKeyMaterial(stored, entity, parsed.secret)) {
            // The wire item has no timestamp to say which copy is newer: the phone's key material is kept.
            AuditLogger.logOathSyncConflict(oathId)
            return SyncMergeOutcome.CONFLICT
        }
        val updated = dao.updateSynced(
            oathId = oathId,
            counter = entity.counter,
            issuer = entity.issuer,
            accountName = entity.accountName
        )
        if (updated > 0) return SyncMergeOutcome.UPDATED
        // Gone between the insert and the update: added again only if the phone did not delete it.
        return insertedUnlessDeleted(entity) ?: SyncMergeOutcome.UPDATED
    }

    /**
     * Add [entity] through [OathCredentialDao.insertIfAbsentUnlessDeleted]:
     * [SyncMergeOutcome.ADDED] or [SyncMergeOutcome.DELETED], or null when a
     * row already has its oath id and nothing was written. A synced add is
     * audited as any other add ([addCredential]), through the same write
     * helper, and only when the row was inserted.
     */
    private suspend fun insertedUnlessDeleted(entity: OathCredentialEntity): SyncMergeOutcome? {
        val outcome = auditedWrite(
            write = {
                when (dao.insertIfAbsentUnlessDeleted(entity)) {
                    OATH_KEPT_DELETED -> SyncMergeOutcome.DELETED
                    -1L -> null
                    else -> SyncMergeOutcome.ADDED
                }
            },
            audit = { result ->
                if (result == SyncMergeOutcome.ADDED) {
                    AuditLogger.logOathCredentialCreated(
                        entity.oathId,
                        entity.issuer,
                        entity.accountName,
                        entity.oathType,
                        null,
                        null
                    )
                }
            }
        )
        return outcome
    }

    /**
     * True if [stored] has the same secret, type, algorithm, digits and
     * period as [incoming] (whose plain secret is [incomingSecret]). A
     * stored secret that cannot be decrypted counts as different, so the
     * merge never replaces it.
     */
    private fun sameKeyMaterial(
        stored: OathCredentialEntity,
        incoming: OathCredentialEntity,
        incomingSecret: ByteArray
    ): Boolean {
        if (!stored.oathType.equals(incoming.oathType, ignoreCase = true) ||
            !stored.algorithm.equals(incoming.algorithm, ignoreCase = true) ||
            stored.digits != incoming.digits ||
            stored.periodSeconds != incoming.periodSeconds
        ) {
            return false
        }
        val storedSecret = try {
            secretManager.decryptSecret(stored.secretEncrypted)
        } catch (e: Exception) {
            return false
        }
        return try {
            MessageDigest.isEqual(storedSecret, incomingSecret)
        } finally {
            storedSecret.fill(0)
        }
    }

    private suspend fun importParsed(
        uri: String,
        structuredLabel: Boolean,
        caller: OathAuditCaller = OathAuditCaller.LOCAL
    ): String {
        val parsed = parseOathUri(uri, structuredLabel)
        return addCredential(
            issuer = parsed.issuer,
            accountName = parsed.accountName,
            secret = parsed.secret,
            type = parsed.type,
            algorithm = parsed.algorithm,
            digits = parsed.digits,
            periodSeconds = parsed.periodSeconds,
            counter = parsed.counter,
            caller = caller
        )
    }

    /** The decoded fields of an `otpauth://` URI, as [parseOathUri] reads them. */
    private class ParsedOath(
        val issuer: String?,
        val accountName: String,
        val secret: ByteArray,
        val type: String,
        val algorithm: String,
        val digits: Int,
        val periodSeconds: Int,
        val counter: Long
    )

    private fun parseOathUri(uri: String, structuredLabel: Boolean): ParsedOath {
        val parsed = Uri.parse(uri)

        require(parsed.scheme == "otpauth") {
            "Invalid URI scheme: expected 'otpauth', got '${parsed.scheme}'"
        }

        val type = parsed.host?.uppercase()
        require(type == "TOTP" || type == "HOTP") {
            "Invalid OTP type: expected 'totp' or 'hotp', got '${parsed.host}'"
        }

        // Parse the label: /Issuer:account or /account
        // Split before decoding, so an encoded ':' (%3A) stays in its part.
        val label = parsed.encodedPath?.removePrefix("/") ?: ""
        val (labelIssuer, accountName) = if (structuredLabel) {
            parseStructuredOathLabel(label)
        } else {
            parseOathLabel(label, parsed.getQueryParameter("issuer"))
        }

        // Secret is required
        val secretBase32 = parsed.getQueryParameter("secret")
        require(!secretBase32.isNullOrBlank()) {
            "Missing required 'secret' query parameter"
        }
        val secret = base32Decode(secretBase32)
        // Never name the secret here: the message reaches the UI and logs.
        require(secret.size >= MIN_SECRET_BYTES) {
            "Secret is too short: ${secret.size} bytes decoded, at least $MIN_SECRET_BYTES required"
        }

        // Optional parameters with defaults
        val issuer = parsed.getQueryParameter("issuer") ?: labelIssuer
        val algorithm = parsed.getQueryParameter("algorithm")?.uppercase() ?: "SHA1"
        val digits = parsed.getQueryParameter("digits")?.toIntOrNull() ?: 6
        val periodSeconds = parsed.getQueryParameter("period")?.toIntOrNull() ?: 30
        // A value OathEngine cannot compute a code from would be stored and
        // then fail on every tick of the list, so it is refused here.
        require(algorithm in SUPPORTED_ALGORITHMS) {
            "Unsupported algorithm: expected SHA1, SHA256 or SHA512"
        }
        require(digits in SUPPORTED_DIGITS) { "Unsupported digits: $digits, expected 6 to 8" }
        // HOTP ignores the period; TOTP needs a positive one, as
        // OathEngine.generateTotpCode requires.
        require(type != "TOTP" || periodSeconds > 0) {
            "Unsupported period: $periodSeconds seconds, expected a positive number of seconds"
        }

        // The HOTP counter is part of the credential, not an update applied
        // after it: a credential inserted at counter 0 and only afterwards
        // advanced is permanently out of step with the server if anything goes
        // wrong in between.
        // An unparseable or negative counter is ignored, as with the other
        // optional numeric parameters above.
        val counter = if (type == "HOTP") {
            parsed.getQueryParameter("counter")?.toLongOrNull()?.takeIf { it >= 0L } ?: 0L
        } else {
            0L
        }

        return ParsedOath(
            issuer = issuer,
            accountName = accountName,
            secret = secret,
            type = type,
            algorithm = algorithm,
            digits = digits,
            periodSeconds = periodSeconds,
            counter = counter
        )
    }

    /**
     * Generate the current OTP code for a credential.
     *
     * For TOTP credentials, computes the code based on the current system time.
     * For HOTP credentials, computes the code from the stored counter and
     * advances the counter with a compare-and-set ([OathCredentialDao.claimCounter]).
     * When the counter moved since it was read (a sync raised it, or another
     * generation took it first), that code is discarded, the credential is
     * read again and the code is generated from the current counter, so two
     * overlapping generations never return the same HOTP code, no code is
     * returned for a counter the store did not move past, and a counter a
     * sync raised is never rewound.
     *
     * Records the usage timestamp and increments the use count in the database,
     * once, for the code that is returned.
     *
     * @param oathId The unique identifier of the OATH credential.
     * @return The generated OTP code string, zero-padded to the configured digit length.
     * @throws NoSuchElementException if no credential exists with the given [oathId].
     * @throws OathCounterExhaustedException if the HOTP counter is at
     *         [HOTP_COUNTER_MAX]: no further code exists for it.
     * @throws IllegalStateException if an HOTP claim fails while the stored
     *         counter has not moved past the value tried, or no claim succeeds
     *         within [MAX_COUNTER_ATTEMPTS] attempts.
     */
    suspend fun generateCode(oathId: String, caller: OathAuditCaller = OathAuditCaller.LOCAL): String {
        var credential = dao.getByOathId(oathId)
            ?: throw NoSuchElementException("No OATH credential found with oathId: $oathId")
        var attempt = 0
        while (true) {
            // A code is handed out only once its counter value is claimed
            // (compare-and-set, one statement): two callers that read the
            // same counter (a desktop generate and a phone tap) cannot both
            // claim it, and a sync that raised the counter makes the claim
            // fail, so the loser re-reads and takes the current value. The
            // code is computed before the claim, so a decrypt or engine
            // failure never burns a counter value.
            val code = when (credential.oathType) {
                "TOTP" -> {
                    val secret = secretManager.decryptSecret(credential.secretEncrypted)
                    try {
                        OathEngine.generateTotpCode(
                            secret = secret,
                            algorithm = credential.algorithm,
                            digits = credential.digits,
                            periodSeconds = credential.periodSeconds
                        )
                    } finally {
                        secret.fill(0)
                    }
                }
                "HOTP" -> {
                    if (credential.counter == HOTP_COUNTER_MAX) {
                        throw OathCounterExhaustedException(oathId)
                    }
                    val secret = secretManager.decryptSecret(credential.secretEncrypted)
                    try {
                        OathEngine.generateHotpCode(
                            secret = secret,
                            counter = credential.counter,
                            algorithm = credential.algorithm,
                            digits = credential.digits
                        )
                    } finally {
                        secret.fill(0)
                    }
                }
                else -> throw IllegalStateException(
                    "Unknown OATH type: ${credential.oathType}"
                )
            }

            // The HOTP counter claim, the usage and the audit row are one
            // audited write: a caller cancelled after the counter commits
            // still leaves its row. A generation the user or desktop asked for
            // (an HOTP copy advances the counter) is audited; list refreshes
            // go through observeAll and are not.
            val tried = credential.counter
            val won = auditedWrite(
                write = {
                    val claimed = credential.oathType != "HOTP" || dao.claimCounter(oathId, tried) > 0
                    if (claimed) dao.recordUsage(oathId, System.currentTimeMillis())
                    claimed
                },
                audit = { claimed ->
                    if (claimed) {
                        AuditLogger.logOathCodeGenerated(
                            oathId, credential.issuer, credential.accountName, caller.deviceId, caller.deviceName
                        )
                    }
                }
            )
            if (won) return code

            // A retry happens only when the counter moved on; otherwise the
            // claim could fail forever on the same value.
            credential = dao.getByOathId(oathId)
                ?: throw NoSuchElementException("No OATH credential found with oathId: $oathId")
            if (credential.counter == HOTP_COUNTER_MAX) {
                throw OathCounterExhaustedException(oathId)
            }
            if (credential.counter <= tried) {
                throw IllegalStateException(
                    "HOTP counter claim failed without progress for OATH credential $oathId"
                )
            }
            attempt++
            if (attempt >= MAX_COUNTER_ATTEMPTS) {
                throw IllegalStateException(
                    "HOTP counter for $oathId could not be advanced after $MAX_COUNTER_ATTEMPTS attempts"
                )
            }
        }
    }

    /**
     * Observe all OATH credentials with their current OTP codes.
     *
     * Returns a reactive [Flow] that emits an updated list whenever the
     * underlying credential data changes. Each emission includes the current
     * code and seconds remaining until expiry for TOTP credentials.
     *
     * For TOTP, the code is computed using the current system time at the
     * moment of emission. For HOTP, the code is computed using the stored
     * counter value without incrementing it.
     *
     * @return A [Flow] emitting [OathCredentialWithCode] instances for all credentials.
     */
    fun observeAll(): Flow<List<OathCredentialWithCode>> {
        return dao.observeAll().map { credentials ->
            credentials.map(::withCode)
        }
    }

    /**
     * The row with its current code ([OathCurrentCode]). One row whose code
     * cannot be computed (an invalidated Keystore key, a stored value the
     * engine refuses) must not take the whole list down: it is shown without
     * a code and can still be deleted.
     */
    private fun withCode(credential: OathCredentialEntity): OathCredentialWithCode =
        when (val current = OathCurrentCode.currentCode(
            credential,
            { secretManager.decryptSecret(it.secretEncrypted) },
            System.currentTimeMillis()
        )) {
            is OathCurrentCode.Available -> OathCredentialWithCode(
                credential = credential,
                code = current.code,
                secondsRemaining = current.secondsLeft ?: 0
            )
            OathCurrentCode.Unavailable -> {
                Log.w(TAG, "No code for OATH row ${credential.oathId}")
                OathCredentialWithCode(
                    credential = credential,
                    code = NO_CODE,
                    secondsRemaining = 0,
                    codeError = true
                )
            }
        }

    /**
     * Delete an OATH credential by its unique identifier.
     *
     * Removes the credential and its encrypted secret from the database.
     * This operation is irreversible. The id is recorded and the row deleted
     * in one transaction ([OathCredentialDao.deleteAndRecordDeletion]), so
     * a sync merge running at the same time, or any later one, never adds
     * the credential back, and no interruption leaves one without the other.
     *
     * Audited here, so a delete on the phone and local.oathRemove write the
     * same single row; nothing is deleted or audited when no credential has
     * [oathId]. Two calls can both read the credential before either
     * deletes it (a phone delete racing local.oathRemove): only the delete
     * that removed the row is audited and returns true.
     *
     * @param oathId The unique identifier of the credential to delete.
     * @return true if this call deleted the credential, false if none had
     *         [oathId] or a concurrent delete removed it first.
     */
    suspend fun deleteCredential(oathId: String, caller: OathAuditCaller = OathAuditCaller.LOCAL): Boolean {
        val credential = dao.getByOathId(oathId) ?: return false
        val deleted = auditedWrite(
            write = { dao.deleteAndRecordDeletion(oathId, System.currentTimeMillis()) },
            audit = { rows ->
                if (rows > 0) {
                    AuditLogger.logOathCredentialDeleted(
                        oathId, credential.issuer, credential.accountName, caller.deviceId, caller.deviceName
                    )
                }
            }
        )
        return deleted > 0
    }

    /**
     * Get all locally-created credentials for synchronization to remote devices.
     *
     * Returns credentials whose [OathCredentialEntity.source] is "local".
     * The encrypted secrets are included in the entities; callers are responsible
     * for secure transport.
     *
     * @return List of local [OathCredentialEntity] instances.
     */
    suspend fun getCredentialsForSync(): List<OathCredentialEntity> {
        return dao.getBySource("local")
    }

    // -------------------------------------------------------------------------
    // Private Helpers
    // -------------------------------------------------------------------------

    companion object {

        private const val TAG = "OathRepository"

        /** What a row shows in place of a code it cannot compute. */
        const val NO_CODE = "------"

        /**
         * The last HOTP counter value: no code is computed at it, and
         * [OathCredentialDao.claimCounter] never advances past it.
         */
        const val HOTP_COUNTER_MAX = Long.MAX_VALUE

        /**
         * How many times [generateCode] reads an HOTP credential again after
         * another generation advanced its counter first.
         */
        const val MAX_COUNTER_ATTEMPTS = 8

        /**
         * RFC 4648 Base32 alphabet (A-Z, 2-7).
         */
        private const val BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

        /** RFC 4226 section 4 R6: a shared secret of at least 128 bits is recommended, 80 required. */
        private const val MIN_SECRET_BYTES = 10

        /** The HMAC algorithms [OathEngine] computes. */
        private val SUPPORTED_ALGORITHMS = setOf("SHA1", "SHA256", "SHA512")

        /** The code lengths [OathEngine] computes. */
        private val SUPPORTED_DIGITS = 6..8

        /**
         * Decode a Base32-encoded string to raw bytes.
         *
         * Implements RFC 4648 Base32 decoding with the standard alphabet (A-Z, 2-7).
         * Padding ('='), spaces, and hyphens are formatting and are stripped;
         * decoding is case-insensitive.
         *
         * Anything else is rejected. In particular the digits `0`, `1`, and `8`
         * are **not** silently folded onto `O`, `L`, and `B`: a shared secret is
         * key material, and rewriting it turns a typo into a credential that
         * looks valid, imports cleanly, and then generates wrong codes forever —
         * a failure that only ever surfaces at the verifier. The caller is told
         * exactly which characters were rejected instead.
         *
         * @param encoded The Base32-encoded string.
         * @return Decoded byte array.
         * @throws IllegalArgumentException if the input contains invalid Base32 characters.
         */
        private fun base32Decode(encoded: String): ByteArray {
            val cleaned = encoded.uppercase()
                .replace("=", "")
                .replace(" ", "")
                .replace("-", "")
            if (cleaned.isEmpty()) {
                return ByteArray(0)
            }

            val invalid = cleaned.filterNot { it in BASE32_ALPHABET }.toSet().sorted()
            require(invalid.isEmpty()) { invalidCharacterMessage(invalid) }

            val output = ByteArray(cleaned.length * 5 / 8)
            var buffer = 0
            var bitsLeft = 0
            var outputIndex = 0

            for (char in cleaned) {
                buffer = (buffer shl 5) or BASE32_ALPHABET.indexOf(char)
                bitsLeft += 5

                if (bitsLeft >= 8) {
                    bitsLeft -= 8
                    output[outputIndex++] = (buffer shr bitsLeft).toByte()
                    buffer = buffer and ((1 shl bitsLeft) - 1)
                }
            }

            return output.copyOf(outputIndex)
        }

        /**
         * Build the rejection message for [invalid], naming every offending
         * character and, when the input carries digits that are commonly
         * mistyped for letters, saying what they were probably meant to be.
         */
        private fun invalidCharacterMessage(invalid: List<Char>): String {
            val named = invalid.joinToString(", ") { "'$it'" }
            val confusable = CONFUSABLE_DIGITS.filterKeys { it in invalid }
            val hint = if (confusable.isEmpty()) {
                ""
            } else {
                confusable.entries.joinToString(
                    prefix = " Did you mean ",
                    separator = ", ",
                    postfix = "?"
                ) { (digit, letter) -> "'$letter' for '$digit'" }
            }
            return "Invalid Base32 character(s) in secret: $named. " +
                "Base32 secrets use A-Z and 2-7 only (RFC 4648).$hint"
        }

        /**
         * Digits that are routinely typed in place of a Base32 letter. They are
         * only ever used to explain a rejection — never to rewrite a secret.
         */
        private val CONFUSABLE_DIGITS = mapOf('0' to 'O', '1' to 'L', '8' to 'B')
    }
}

/**
 * The HOTP counter of [oathId] is at [OathRepository.HOTP_COUNTER_MAX]: the
 * credential is kept, but no further code can be generated for it. The text
 * names only the id, never a secret or a code.
 */
class OathCounterExhaustedException(oathId: String) :
    IllegalStateException("HOTP counter exhausted for OATH credential $oathId")

/**
 * The device an OATH audit row names: the requesting desktop for a protocol
 * request, none for an action on the phone itself.
 *
 * @property deviceId the peer's static key hex, or null when unknown or local
 * @property deviceName its paired-device name, when it is paired
 */
data class OathAuditCaller(val deviceId: String?, val deviceName: String?) {
    companion object {
        /** An action taken on the phone: no requesting device. */
        val LOCAL = OathAuditCaller(null, null)
    }
}
