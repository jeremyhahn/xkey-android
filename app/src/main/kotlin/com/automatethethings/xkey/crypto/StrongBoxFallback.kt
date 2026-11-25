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

package com.automatethethings.xkey.crypto

import android.security.keystore.StrongBoxUnavailableException
import java.security.ProviderException

/**
 * Key generation that prefers StrongBox and falls back to the TEE only when
 * StrongBox is unavailable on this device.
 *
 * Requesting StrongBox succeeds at build time and fails only when the key is
 * generated, so the fallback wraps the generation itself. Any failure other
 * than "StrongBox unavailable" propagates: a Keystore fault or a missing
 * attestation chain must not be hidden behind a quietly minted TEE key.
 */
internal object StrongBoxFallback {

    /** Keymaster/KeyMint `ERROR_HARDWARE_TYPE_UNAVAILABLE`. */
    private const val HARDWARE_TYPE_UNAVAILABLE = "-68"

    /**
     * Runs [strongBox]; when it fails because StrongBox is unavailable, runs
     * [onUnavailable] (to remove any half-made entry) and then [tee].
     */
    fun <T> generate(strongBox: () -> T, onUnavailable: (Throwable) -> Unit, tee: () -> T): T {
        try {
            return strongBox()
        } catch (e: Exception) {
            if (!isStrongBoxUnavailable(e)) throw e
            onUnavailable(e)
        }
        return tee()
    }

    /**
     * True for the shapes StrongBox-less devices throw from key generation:
     * a [StrongBoxUnavailableException] (directly or as a cause), or a
     * [ProviderException] whose cause is a Keystore error carrying
     * `HARDWARE_TYPE_UNAVAILABLE`.
     */
    fun isStrongBoxUnavailable(error: Throwable): Boolean {
        if (causes(error).any { it is StrongBoxUnavailableException }) return true
        if (error !is ProviderException) return false
        return causes(error).drop(1).any { cause ->
            isKeystoreError(cause) && cause.message.orEmpty().let {
                it.contains(HARDWARE_TYPE_UNAVAILABLE) || it.contains("HARDWARE_TYPE_UNAVAILABLE", ignoreCase = true)
            }
        }
    }

    private fun isKeystoreError(t: Throwable): Boolean =
        t is java.security.KeyStoreException || t.javaClass.name == "android.security.KeyStoreException"

    private fun causes(error: Throwable): Sequence<Throwable> {
        val seen = HashSet<Throwable>()
        return generateSequence(error) { it.cause }.takeWhile { seen.add(it) }
    }
}
