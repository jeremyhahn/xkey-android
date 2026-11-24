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

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext

/**
 * Makes the ML-DSA [set] key [keyId] on the IO dispatcher and runs [commit]
 * with its SubjectPublicKeyInfo DER as one unit cancellation cannot
 * interrupt: a caller cancelled at any point leaves both the key and what
 * [commit] stored, or neither. A key whose [commit] throws is removed.
 *
 * Every ML-DSA key the app makes goes through here.
 *
 * @return the result of [commit]
 * @throws UnsupportedAlgorithmException for [PqcBacking.HARDWARE] when the
 *   device does not make [set] in hardware.
 */
suspend fun <T> KeystoreManager.generateMlDsaKeyAndCommit(
    keyId: String,
    set: MlDsaParameterSet,
    backing: PqcBacking,
    authDurationSeconds: Int,
    preferStrongBox: Boolean = true,
    commit: suspend (publicKeyDer: ByteArray) -> T
): T {
    currentCoroutineContext().ensureActive()
    return withContext(NonCancellable) {
        try {
            val publicKeyDer = withContext(Dispatchers.IO) {
                generateMlDsaKey(keyId, set, backing, authDurationSeconds, preferStrongBox)
            }
            commit(publicKeyDer)
        } catch (e: Throwable) {
            // Best effort: the failure the caller sees is the one that stopped the commit.
            runCatching { deleteGeneralKey(keyId) }
                .onFailure { Log.w("MlDsaKeyCommit", "Could not remove uncommitted ML-DSA key $keyId: ${it.message}") }
            throw e
        }
    }
}
