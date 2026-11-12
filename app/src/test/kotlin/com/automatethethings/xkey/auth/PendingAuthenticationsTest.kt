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
package com.automatethethings.xkey.auth

import androidx.biometric.BiometricPrompt
import com.automatethethings.xkey.auth.BiometricActivityLauncher.BiometricResult
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Every approval prompt is one request the launcher owns, and the id it hands
 * to whatever shows the prompt (its own activity launch, or the lock-screen
 * notification's full-screen intent) is the id the result broadcast must
 * carry to reach the waiting caller.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class PendingAuthenticationsTest {

    private val pending = PendingAuthentications()

    /** The ids handed to the prompts, in launch order. */
    private val launched = mutableListOf<String>()

    @Test
    fun anApprovalCarryingTheLaunchedIdCompletesTheRequest() = runTest {
        val waiting = async { pending.await { launched += it } }
        runCurrent()

        assertTrue(pending.complete(launched.single(), BiometricResult.Success))
        runCurrent()

        assertEquals(BiometricResult.Success, waiting.await())
    }

    @Test
    fun aCancelCarryingTheLaunchedIdCompletesTheRequestWithTheCancel() = runTest {
        val waiting = async { pending.await { launched += it } }
        runCurrent()

        val cancel = BiometricResult.Error(BiometricPrompt.ERROR_USER_CANCELED, "cancelled")
        assertTrue(pending.complete(launched.single(), cancel))

        assertEquals(cancel, waiting.await())
    }

    @Test
    fun aResultForAnIdTheLauncherNeverIssuedCompletesNothing() = runTest {
        val waiting = async { pending.await { launched += it } }
        runCurrent()

        assertFalse(pending.complete("set-key-policy-178", BiometricResult.Success))
        assertFalse(pending.complete("", BiometricResult.Success))
        assertFalse(waiting.isCompleted)

        assertTrue(pending.complete(launched.single(), BiometricResult.Success))
        waiting.await()
    }

    @Test
    fun twoLaunchersNeverIssueTheSameId() = runTest {
        val other = PendingAuthentications()
        val first = async { pending.await { launched += it } }
        val second = async { other.await { launched += it } }
        runCurrent()

        assertNotEquals(launched[0], launched[1])
        // Each launcher answers only the request it issued.
        assertFalse(other.complete(launched[0], BiometricResult.Success))
        assertTrue(pending.complete(launched[0], BiometricResult.Success))
        assertTrue(other.complete(launched[1], BiometricResult.Success))
        first.await()
        second.await()
    }

    @Test
    fun aCancelledCallerWithdrawsItsRequest() = runTest {
        val waiting = async { pending.await { launched += it } }
        runCurrent()

        waiting.cancel()
        runCurrent()

        assertTrue(waiting.isCancelled)
        assertFalse(pending.complete(launched.single(), BiometricResult.Success))
    }

    @Test
    fun aPromptThatCannotLaunchFailsTheRequestAndLeavesNothingPending() = runTest {
        val failure = IllegalStateException("no activity")
        val waiting = async {
            runCatching { pending.await { launched += it; throw failure } }
        }
        runCurrent()

        assertEquals(failure, waiting.await().exceptionOrNull())
        assertFalse(pending.complete(launched.single(), BiometricResult.Success))
    }

    @Test
    fun cancelAllCancelsEveryWaitingCaller() = runTest {
        val first = async { pending.await { launched += it } }
        val second = async { pending.await { launched += it } }
        runCurrent()

        pending.cancelAll()
        runCurrent()

        assertTrue(first.isCancelled)
        assertTrue(second.isCancelled)
    }
}
