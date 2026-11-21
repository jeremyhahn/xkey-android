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

package com.automatethethings.xkey.auth

import com.automatethethings.xkey.auth.BiometricActivityLauncher.CryptoSigningResult
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [PendingCryptoSignatures.await] with a preparation step (a passkey's
 * counter, made only once the request's turn has come), through the real
 * queue: the preparation runs after admission, and whether it succeeds,
 * fails or is cancelled, before or during it, the next request is admitted.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class PendingCryptoSignaturesPrepareTest {

    /** Its own line of prompts, so no other test's request can hold the screen. */
    private val prompts = PromptOwnership()
    private val pending = PendingCryptoSignatures(prompts = prompts)

    /** Request ids launched, in order. */
    private val launched = mutableListOf<String>()

    private fun launch(requestId: String) {
        launched += requestId
    }

    private fun answer(requestId: String) =
        assertTrue(pending.complete(requestId.toLong(), CryptoSigningResult.Success(SIGNATURE)))

    /** A request holding the screen, so the next ones queue behind it. */
    private fun TestScope.holdScreen(): String {
        val first = async { pending.await(::launch) }
        runCurrent()
        assertFalse(first.isCompleted)
        return launched.single()
    }

    /** The line is not stalled: a new request comes up and is answered. */
    private fun TestScope.assertNextAdmitted() {
        val before = launched.size
        val next = async { pending.await(::launch) }
        runCurrent()
        assertEquals("the next request comes up", before + 1, launched.size)
        answer(launched.last())
        runCurrent()
        assertEquals(CryptoSigningResult.Success(SIGNATURE), next.getCompleted())
    }

    @Test
    fun preparationRunsOnlyOnceTheRequestIsAdmitted() = runTest {
        val first = holdScreen()
        var prepared = false
        val second = async { pending.await({ prepared = true }, ::launch) }
        runCurrent()
        assertFalse("not prepared while it waits for its turn", prepared)

        answer(first)
        runCurrent()

        assertTrue(prepared)
        assertEquals(2, launched.size)
        answer(launched.last())
        runCurrent()
        assertEquals(CryptoSigningResult.Success(SIGNATURE), second.getCompleted())
        assertNextAdmitted()
    }

    @Test
    fun aFailedPreparationFailsTheRequestShowsNothingAndAdmitsTheNext() = runTest {
        val first = holdScreen()
        val second = async {
            runCatching { pending.await({ throw IllegalStateException("counter not advanced") }, ::launch) }
        }
        runCurrent()

        answer(first)
        runCurrent()

        assertTrue(second.getCompleted().exceptionOrNull() is IllegalStateException)
        assertEquals("the failed request is never shown", 1, launched.size)
        assertNextAdmitted()
    }

    @Test
    fun aRequestCancelledBeforeItsPreparationIsNeverPreparedAndAdmitsTheNext() = runTest {
        val first = holdScreen()
        var prepared = false
        val second = async { pending.await({ prepared = true }, ::launch) }
        runCurrent()

        second.cancel()
        runCurrent()
        answer(first)
        runCurrent()

        assertTrue(second.isCancelled)
        assertFalse("a withdrawn request is never prepared", prepared)
        assertEquals(1, launched.size)
        assertNextAdmitted()
    }

    @Test
    fun aRequestCancelledDuringItsPreparationIsNeverShownAndAdmitsTheNext() = runTest {
        val preparing = CompletableDeferred<Unit>()
        var preparationStarted = false
        val request = async {
            pending.await({
                preparationStarted = true
                preparing.await()
            }, ::launch)
        }
        runCurrent()
        assertTrue(preparationStarted)

        request.cancel()
        runCurrent()
        preparing.complete(Unit)
        runCurrent()

        assertTrue(request.isCancelled)
        assertTrue("never shown", launched.isEmpty())
        assertNextAdmitted()
    }

    /**
     * A preparation that ends in a CancellationException of its own (a
     * timeout inside it, say) while its caller is still waiting: the request
     * fails, nothing is shown, and the screen is handed on, not held.
     */
    @Test
    fun aPreparationCancelledFromWithinFailsTheRequestAndAdmitsTheNext() = runTest {
        val request = async {
            runCatching { pending.await({ throw CancellationException("preparation timed out") }, ::launch) }
        }
        runCurrent()

        assertTrue("the caller is answered", request.isCompleted)
        val failure = request.getCompleted().exceptionOrNull()
        assertTrue("it fails, it is not cancelled: $failure", failure != null && failure !is CancellationException)
        assertTrue("never shown", launched.isEmpty())
        assertNextAdmitted()
    }

    private companion object {
        const val SIGNATURE = "c2lnbmF0dXJl"
    }
}
