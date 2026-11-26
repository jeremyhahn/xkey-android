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

/**
 * The code a credential shows right now, or why it shows none.
 *
 * [currentCode] is the one place a code is computed for display: the list
 * ([OathRepository.observeAll]) and the details screen both use it. It never
 * advances an HOTP counter; only [OathRepository.generateCode] does, on a copy.
 */
sealed interface OathCurrentCode {

    /** [code] is current; [secondsLeft] is the TOTP time left, null for HOTP. */
    data class Available(val code: String, val secondsLeft: Int?) : OathCurrentCode

    /**
     * No code can be computed: the secret cannot be decrypted, the engine
     * refuses a stored value, the type is unknown, or the HOTP counter is
     * exhausted ([OathRepository.HOTP_COUNTER_MAX]). No cause is kept: an
     * exception text can quote key material.
     */
    data object Unavailable : OathCurrentCode

    companion object {
        private const val TOTP = "TOTP"
        private const val HOTP = "HOTP"

        /**
         * The code of [credential] at [nowMs]: TOTP at that time, HOTP at the
         * stored counter (not advanced). The decrypted secret is zeroed before
         * this returns. Never throws for a code failure.
         *
         * @param secretOf Decrypts the credential's secret; may throw.
         */
        fun currentCode(
            credential: OathCredentialEntity,
            secretOf: (OathCredentialEntity) -> ByteArray,
            nowMs: Long
        ): OathCurrentCode = try {
            when (credential.oathType) {
                TOTP -> {
                    val secret = secretOf(credential)
                    try {
                        val code = OathEngine.generateTotpCode(
                            secret = secret,
                            algorithm = credential.algorithm,
                            digits = credential.digits,
                            periodSeconds = credential.periodSeconds,
                            timeMs = nowMs
                        )
                        val elapsed = (nowMs / 1000L) % credential.periodSeconds.toLong()
                        Available(code, credential.periodSeconds - elapsed.toInt())
                    } finally {
                        secret.fill(0)
                    }
                }
                HOTP -> if (credential.counter == OathRepository.HOTP_COUNTER_MAX) {
                    Unavailable
                } else {
                    val secret = secretOf(credential)
                    try {
                        Available(
                            OathEngine.generateHotpCode(
                                secret = secret,
                                counter = credential.counter,
                                algorithm = credential.algorithm,
                                digits = credential.digits
                            ),
                            secondsLeft = null
                        )
                    } finally {
                        secret.fill(0)
                    }
                }
                else -> Unavailable
            }
        } catch (e: Exception) {
            Unavailable
        }
    }
}
