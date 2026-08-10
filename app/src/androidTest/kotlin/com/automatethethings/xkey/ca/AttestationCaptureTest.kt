/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
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
package com.automatethethings.xkey.ca

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.Base64

/**
 * Captures a genuine Keystore attestation chain to a file the desktop
 * verifier's tests can be built from.
 *
 * The Go parser had no real fixture: its unit tests constructed the
 * attestation extension by hand and, in doing so, encoded RootOfTrust under
 * context tag 0 with a comment saying it was "simulating tag 704". A parser
 * lenient enough to accept that would also accept a neighbouring SEQUENCE that
 * merely happened to decode, so the fixtures could not tell a correct parser
 * from an over-permissive one. Only bytes from a real device can.
 */
@RunWith(AndroidJUnit4::class)
class AttestationCaptureTest {

    private val context: Context = ApplicationProvider.getApplicationContext()
    private val identity = DeviceIdentity(context)

    @After
    fun tearDown() {
        identity.reset()
    }

    @Test
    fun captureRealAttestationChain() {
        val challenge = "xkey-fixture-challenge".toByteArray()
        val request = identity.createEnrollmentRequest(challenge)

        assertTrue(
            "A real device must return a chain, not a lone self-signed certificate",
            request.attestationChain.size >= 2
        )

        // Emitted to logcat rather than written to a file: the instrumentation
        // runner uninstalls the app when the run ends, taking its storage with
        // it, so anything written under getExternalFilesDir is unreachable by
        // the time the capture is wanted. Chunked because logcat truncates
        // long lines.
        android.util.Log.i(TAG, "CHAIN_BEGIN securityLevel=${request.securityLevel}")
        request.attestationChain.forEachIndexed { index, der ->
            val encoded = Base64.getEncoder().encodeToString(der)
            encoded.chunked(CHUNK).forEach { part ->
                android.util.Log.i(TAG, "CHAIN[$index] $part")
            }
        }
        android.util.Log.i(TAG, "CHAIN_END")
    }

    private companion object {
        const val TAG = "AttestationCapture"
        const val CHUNK = 2000
    }
}
