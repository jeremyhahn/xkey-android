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
package com.automatethethings.xkey.ui

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/**
 * How the phone-initiated re-attest in [DeviceDetailActivity] ends (#137).
 *
 * The step waits on the user's SAS confirmation. Leaving the screen cancels
 * the activity's scope, and that cancellation is not a connection failure: it
 * must not put the advertise-and-wait fallback on a screen that is gone.
 */
class PhoneInitiatedReattestTest {

    @Test
    fun cancellingAPendingSasShowsNoFallback() = runTest {
        val sas = CompletableDeferred<Boolean>()
        val failures = mutableListOf<Exception>()

        val job = launch {
            runPhoneInitiatedReattest(
                activityGone = { false },
                onFailure = { failures += it },
                step = { sas.await() }
            )
        }
        runCurrent()
        job.cancel()
        job.join()

        assertEquals("A cancelled SAS prompt is not a connection failure", emptyList<Exception>(), failures)
        assertTrue("The cancellation must reach the caller", job.isCancelled)
    }

    @Test
    fun aFailureAfterTheActivityIsGoneShowsNoFallback() = runTest {
        val failures = mutableListOf<Exception>()

        runPhoneInitiatedReattest(
            activityGone = { true },
            onFailure = { failures += it },
            step = { throw IOException("link lost") }
        )

        assertEquals("A destroyed screen gets no fallback dialog", emptyList<Exception>(), failures)
    }

    @Test
    fun aFailureWhileTheActivityIsUpShowsTheFallback() = runTest {
        val failures = mutableListOf<Exception>()

        runPhoneInitiatedReattest(
            activityGone = { false },
            onFailure = { failures += it },
            step = { throw IOException("link lost") }
        )

        assertEquals(1, failures.size)
        assertTrue(failures.single() is IOException)
    }
}
