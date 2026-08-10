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
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
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
 */
data class OathCredentialWithCode(
    val credential: OathCredentialEntity,
    val code: String,
    val secondsRemaining: Int
)

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
        counter: Long = 0L
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

        dao.insert(entity)
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
     * @param uri The `otpauth://` URI string to parse.
     * @return The generated unique oath identifier for the imported credential.
     * @throws IllegalArgumentException if the URI scheme is not `otpauth`,
     *         the type is not `totp` or `hotp`, or the `secret` parameter is missing.
     */
    suspend fun importFromUri(uri: String): String {
        val parsed = Uri.parse(uri)

        require(parsed.scheme == "otpauth") {
            "Invalid URI scheme: expected 'otpauth', got '${parsed.scheme}'"
        }

        val type = parsed.host?.uppercase()
        require(type == "TOTP" || type == "HOTP") {
            "Invalid OTP type: expected 'totp' or 'hotp', got '${parsed.host}'"
        }

        // Parse the label: /Issuer:account or /account
        val label = parsed.path?.removePrefix("/") ?: ""
        val (labelIssuer, accountName) = parseLabel(label)

        // Secret is required
        val secretBase32 = parsed.getQueryParameter("secret")
        require(!secretBase32.isNullOrBlank()) {
            "Missing required 'secret' query parameter"
        }
        val secret = base32Decode(secretBase32)

        // Optional parameters with defaults
        val issuer = parsed.getQueryParameter("issuer") ?: labelIssuer
        val algorithm = parsed.getQueryParameter("algorithm")?.uppercase() ?: "SHA1"
        val digits = parsed.getQueryParameter("digits")?.toIntOrNull() ?: 6
        val periodSeconds = parsed.getQueryParameter("period")?.toIntOrNull() ?: 30

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

        return addCredential(
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
     * For HOTP credentials, computes the code using the stored counter value
     * and automatically increments the counter after generation.
     *
     * Records the usage timestamp and increments the use count in the database.
     *
     * @param oathId The unique identifier of the OATH credential.
     * @return The generated OTP code string, zero-padded to the configured digit length.
     * @throws NoSuchElementException if no credential exists with the given [oathId].
     */
    suspend fun generateCode(oathId: String): String {
        val credential = dao.getByOathId(oathId)
            ?: throw NoSuchElementException("No OATH credential found with oathId: $oathId")

        val secret = secretManager.decryptSecret(credential.secretEncrypted)

        val code = when (credential.oathType) {
            "TOTP" -> OathEngine.generateTotpCode(
                secret = secret,
                algorithm = credential.algorithm,
                digits = credential.digits,
                periodSeconds = credential.periodSeconds
            )
            "HOTP" -> {
                val hotpCode = OathEngine.generateHotpCode(
                    secret = secret,
                    counter = credential.counter,
                    algorithm = credential.algorithm,
                    digits = credential.digits
                )
                // Increment the HOTP counter after successful generation
                dao.updateCounter(oathId, credential.counter + 1)
                hotpCode
            }
            else -> throw IllegalStateException(
                "Unknown OATH type: ${credential.oathType}"
            )
        }

        dao.recordUsage(oathId, System.currentTimeMillis())

        return code
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
            credentials.map { credential ->
                val secret = secretManager.decryptSecret(credential.secretEncrypted)
                val now = System.currentTimeMillis()

                val code = when (credential.oathType) {
                    "TOTP" -> OathEngine.generateTotpCode(
                        secret = secret,
                        algorithm = credential.algorithm,
                        digits = credential.digits,
                        periodSeconds = credential.periodSeconds,
                        timeMs = now
                    )
                    "HOTP" -> OathEngine.generateHotpCode(
                        secret = secret,
                        counter = credential.counter,
                        algorithm = credential.algorithm,
                        digits = credential.digits
                    )
                    else -> "------"
                }

                val secondsRemaining = if (credential.oathType == "TOTP") {
                    val elapsed = (now / 1000L) % credential.periodSeconds.toLong()
                    credential.periodSeconds - elapsed.toInt()
                } else {
                    0
                }

                OathCredentialWithCode(
                    credential = credential,
                    code = code,
                    secondsRemaining = secondsRemaining
                )
            }
        }
    }

    /**
     * Delete an OATH credential by its unique identifier.
     *
     * Removes the credential and its encrypted secret from the database.
     * This operation is irreversible.
     *
     * @param oathId The unique identifier of the credential to delete.
     */
    suspend fun deleteCredential(oathId: String) {
        dao.deleteByOathId(oathId)
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

    /**
     * Parse an otpauth label into issuer and account name components.
     *
     * The label format is either "issuer:account" or just "account".
     * Both components are URL-decoded by the [Uri] parser prior to this call.
     *
     * @param label The decoded label string from the URI path.
     * @return A [Pair] of (issuer, accountName). Issuer is null if not present.
     */
    private fun parseLabel(label: String): Pair<String?, String> {
        val colonIndex = label.indexOf(':')
        return if (colonIndex >= 0) {
            val issuer = label.substring(0, colonIndex).trim()
            val account = label.substring(colonIndex + 1).trim()
            Pair(issuer.ifEmpty { null }, account)
        } else {
            Pair(null, label.trim())
        }
    }

    companion object {

        /**
         * RFC 4648 Base32 alphabet (A-Z, 2-7).
         */
        private const val BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

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
