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

import org.json.JSONObject
import java.security.MessageDigest
import java.util.Base64

/**
 * One factor's credential for the per-user password vault: the body of
 * `PasswordStoreUnlock`, mirroring go-xkms `transport.PasswordVaultCredential`.
 *
 * Wire forms (Go `[]byte` fields are standard base64):
 * - `{"factor":"passphrase","passphrase":"…"}`
 * - `{"factor":"passkey","credential_id":"<b64>","secret":"<b64>"}`, where
 *   `secret` is the 32-byte hmac-secret output (see [WebAuthnPrf])
 * - `{"factor":"piv"|"certificate"|"tpm","key_fingerprint":"…","secret":"<b64>"}`
 *
 * The deployment-wide `{"user_pin":…}` body this replaced is refused: the
 * device PIN no longer unlocks the password store.
 *
 * Not a data class, so a secret never reaches a log through `toString`.
 */
sealed class PasswordVaultCredential {

    /** The factor name exactly as it travels on the wire. */
    abstract val factor: String

    /** A passphrase factor. */
    class Passphrase(val passphrase: String) : PasswordVaultCredential() {
        override val factor: String get() = FACTOR_PASSPHRASE
    }

    /**
     * A passkey factor: the authenticator's hmac-secret output for the
     * enrolled credential, evaluated over [WebAuthnPrf.hmacSecretSalt] of the
     * factor's PRF salt.
     */
    class Passkey(
        val credentialId: ByteArray,
        val secret: ByteArray,
        val prfSalt: ByteArray?
    ) : PasswordVaultCredential() {
        override val factor: String get() = FACTOR_PASSKEY
    }

    /** A key factor ([FACTOR_PIV], [FACTOR_CERTIFICATE] or [FACTOR_TPM]). */
    class Key(
        override val factor: String,
        val keyFingerprint: String,
        val secret: ByteArray
    ) : PasswordVaultCredential()

    companion object {
        const val FACTOR_PASSPHRASE = "passphrase"
        const val FACTOR_PASSKEY = "passkey"
        const val FACTOR_PIV = "piv"
        const val FACTOR_CERTIFICATE = "certificate"
        const val FACTOR_TPM = "tpm"

        /** Size of a CTAP2 hmac-secret output for one salt. */
        const val HMAC_SECRET_OUTPUT_SIZE = 32

        private val KEY_FACTORS = setOf(FACTOR_PIV, FACTOR_CERTIFICATE, FACTOR_TPM)

        /**
         * Parses a credential from request params.
         *
         * @throws VaultCredentialInvalidException if the body is malformed. The
         *   message names the field at fault, never a secret's value.
         */
        fun fromJson(params: JSONObject?): PasswordVaultCredential {
            if (params == null) throw VaultCredentialInvalidException("missing credential")
            val factor = params.stringField("factor")
            if (factor.isNullOrEmpty()) {
                if (params.has("user_pin")) {
                    throw VaultCredentialInvalidException(
                        "user_pin no longer unlocks the password store: send a vault credential"
                    )
                }
                throw VaultCredentialInvalidException("factor is required")
            }
            return when (factor) {
                FACTOR_PASSPHRASE -> {
                    val passphrase = params.stringField("passphrase")
                    if (passphrase.isNullOrEmpty()) {
                        throw VaultCredentialInvalidException("passphrase is required")
                    }
                    Passphrase(passphrase)
                }
                FACTOR_PASSKEY -> {
                    val credentialId = params.bytesField("credential_id")
                    if (credentialId == null || credentialId.isEmpty()) {
                        throw VaultCredentialInvalidException("credential_id is required")
                    }
                    val secret = params.bytesField("secret")
                    if (secret == null || secret.size != HMAC_SECRET_OUTPUT_SIZE) {
                        throw VaultCredentialInvalidException(
                            "secret must be the $HMAC_SECRET_OUTPUT_SIZE-byte hmac-secret output"
                        )
                    }
                    Passkey(credentialId, secret, params.bytesField("prf_salt"))
                }
                in KEY_FACTORS -> {
                    val fingerprint = params.stringField("key_fingerprint")
                    if (fingerprint.isNullOrEmpty()) {
                        throw VaultCredentialInvalidException("key_fingerprint is required")
                    }
                    val secret = params.bytesField("secret")
                    if (secret == null || secret.isEmpty()) {
                        throw VaultCredentialInvalidException("secret is required")
                    }
                    Key(factor, fingerprint, secret)
                }
                else -> throw VaultCredentialInvalidException("unknown factor: $factor")
            }
        }

        private fun JSONObject.stringField(key: String): String? {
            if (!has(key) || isNull(key)) return null
            return get(key) as? String ?: throw VaultCredentialInvalidException("$key must be a string")
        }

        private fun JSONObject.bytesField(key: String): ByteArray? {
            val encoded = stringField(key) ?: return null
            return try {
                Base64.getDecoder().decode(encoded)
            } catch (e: IllegalArgumentException) {
                throw VaultCredentialInvalidException("$key must be base64")
            }
        }
    }
}

/**
 * WebAuthn's PRF extension expressed as CTAP2 hmac-secret.
 *
 * A WebAuthn client never hands the relying party's PRF input to the
 * authenticator as is: it sends `SHA-256("WebAuthn PRF" || 0x00 || salt)` as
 * the hmac-secret salt (WebAuthn Level 3, §10.1.4). Using the same transform
 * here means a passkey enrolled through a browser on any surface yields the
 * same 32-byte secret when the phone evaluates it, and so unlocks from the phone.
 */
object WebAuthnPrf {

    private val CONTEXT = "WebAuthn PRF".toByteArray(Charsets.US_ASCII)

    /** The hmac-secret salt for the PRF input [prfSalt]. */
    fun hmacSecretSalt(prfSalt: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(CONTEXT)
        digest.update(0.toByte())
        digest.update(prfSalt)
        return digest.digest()
    }
}
