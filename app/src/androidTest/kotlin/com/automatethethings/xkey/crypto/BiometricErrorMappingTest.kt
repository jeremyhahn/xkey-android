/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */
package com.automatethethings.xkey.crypto

import androidx.biometric.BiometricPrompt
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.ui.MainActivity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.atomic.AtomicReference

/**
 * The framework-error-code to typed-exception map inside [BiometricHelper].
 *
 * [BiometricPromptFailureTest] proves the suspend functions resume instead of
 * hanging, but a stock emulator can only ever produce one framework error
 * code, so exactly one arm of the map has ever run. The arms decide what the
 * protocol layer reports to the desktop -- a cancellation must not look like a
 * lockout, and a lockout must not look like a generic failure -- and the only
 * way to exercise the rest without a fingerprint sensor is to feed the mapper
 * each code directly.
 *
 * The mapper is private because nothing outside the helper needs it; it is
 * reached here by reflection rather than by widening its visibility for a
 * test. The helper itself needs a real [androidx.fragment.app.FragmentActivity]
 * to construct, so this suite is instrumented even though the mapping it
 * checks is pure.
 */
@RunWith(AndroidJUnit4::class)
class BiometricErrorMappingTest {

    /**
     * Built once per test: launching an activity per mapped code would make a
     * table-driven test dominated by activity lifecycle.
     */
    private lateinit var helper: BiometricHelper

    @Before
    fun setUp() {
        val captured = AtomicReference<BiometricHelper?>(null)
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity -> captured.set(BiometricHelper(activity)) }
        }
        helper = captured.get()
            ?: throw AssertionError("no activity was available to build the helper")
    }

    // ------------------------------------------------------------------
    // Cancellation: the user said no, in one of its three spellings
    // ------------------------------------------------------------------

    @Test
    fun everySpellingOfCancellationBecomesUserCancelled() {
        val codes = intArrayOf(
            BiometricPrompt.ERROR_USER_CANCELED,
            BiometricPrompt.ERROR_NEGATIVE_BUTTON,
            BiometricPrompt.ERROR_CANCELED
        )
        for (code in codes) {
            val mapped = map(code, "cancelled")
            assertTrue(
                "code $code must map to UserCancelledException, got $mapped",
                mapped is UserCancelledException
            )
        }
    }

    // ------------------------------------------------------------------
    // Lockout: temporary and permanent are different outcomes
    // ------------------------------------------------------------------

    @Test
    fun aTemporaryLockoutIsReportedAsRecoverable() {
        val mapped = map(BiometricPrompt.ERROR_LOCKOUT, "too many attempts")
        assertTrue("expected a lockout, got $mapped", mapped is BiometricLockoutException)
        assertFalse(
            "a plain ERROR_LOCKOUT clears itself after a cooldown",
            (mapped as BiometricLockoutException).isPermanent
        )
    }

    @Test
    fun aPermanentLockoutIsReportedAsPermanent() {
        val mapped = map(BiometricPrompt.ERROR_LOCKOUT_PERMANENT, "locked out")
        assertTrue("expected a lockout, got $mapped", mapped is BiometricLockoutException)
        assertTrue(
            "ERROR_LOCKOUT_PERMANENT needs a device-credential unlock",
            (mapped as BiometricLockoutException).isPermanent
        )
    }

    // ------------------------------------------------------------------
    // Unavailable: nothing the caller can do, and not the user's doing
    // ------------------------------------------------------------------

    @Test
    fun everyUnavailableConditionBecomesBiometricUnavailable() {
        val codes = intArrayOf(
            BiometricPrompt.ERROR_NO_BIOMETRICS,
            BiometricPrompt.ERROR_HW_NOT_PRESENT,
            BiometricPrompt.ERROR_HW_UNAVAILABLE,
            BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL,
            BiometricPrompt.ERROR_SECURITY_UPDATE_REQUIRED
        )
        for (code in codes) {
            val mapped = map(code, "unavailable")
            assertTrue(
                "code $code must map to BiometricUnavailableException, got $mapped",
                mapped is BiometricUnavailableException
            )
        }
    }

    /**
     * Each unavailable condition carries its own reason: an operator reading
     * an audit record has to be able to tell "no sensor" from "nothing
     * enrolled" from "the platform needs updating".
     */
    @Test
    fun eachUnavailableConditionExplainsItself() {
        val reasons = intArrayOf(
            BiometricPrompt.ERROR_NO_BIOMETRICS,
            BiometricPrompt.ERROR_HW_NOT_PRESENT,
            BiometricPrompt.ERROR_HW_UNAVAILABLE,
            BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL,
            BiometricPrompt.ERROR_SECURITY_UPDATE_REQUIRED
        ).map { map(it, "ignored").message }

        assertEquals(
            "every unavailable reason must be distinct",
            reasons.size,
            reasons.toSet().size
        )
    }

    // ------------------------------------------------------------------
    // Everything else: a generic BiometricException that keeps the code
    // ------------------------------------------------------------------

    @Test
    fun transientFailuresKeepTheirFrameworkErrorCode() {
        val codes = intArrayOf(
            BiometricPrompt.ERROR_UNABLE_TO_PROCESS,
            BiometricPrompt.ERROR_TIMEOUT,
            BiometricPrompt.ERROR_NO_SPACE,
            BiometricPrompt.ERROR_VENDOR
        )
        for (code in codes) {
            val mapped = map(code, "detail")
            assertTrue(
                "code $code must map to BiometricException, got $mapped",
                mapped is BiometricException
            )
            assertEquals(
                "the framework code must survive the mapping",
                code,
                (mapped as BiometricException).errorCode
            )
        }
    }

    /**
     * The two codes whose text the framework supplies must forward it; the two
     * whose text the helper writes must not be silently emptied.
     */
    @Test
    fun theFrameworkMessageIsForwardedWhereItCarriesDetail() {
        assertTrue(
            map(BiometricPrompt.ERROR_UNABLE_TO_PROCESS, "sensor dirty")
                .message!!.contains("sensor dirty")
        )
        assertTrue(
            map(BiometricPrompt.ERROR_VENDOR, "vendor 0x42")
                .message!!.contains("vendor 0x42")
        )
        assertTrue(
            map(BiometricPrompt.ERROR_TIMEOUT, "ignored")
                .message!!.contains("timed out")
        )
    }

    @Test
    fun anUnrecognisedCodeStillProducesATypedException() {
        val mapped = map(UNKNOWN_ERROR_CODE, "something new")
        assertTrue("expected a BiometricException, got $mapped", mapped is BiometricException)
        assertEquals(UNKNOWN_ERROR_CODE, (mapped as BiometricException).errorCode)
        assertTrue(
            "an unrecognised code must forward the framework text verbatim",
            mapped.message!!.contains("something new")
        )
    }

    /**
     * No arm may fall through to an exception with nothing in it: the message
     * is what reaches the audit log and, via the protocol layer, the desktop.
     */
    @Test
    fun everyCodeInTheFrameworkRangeExplainsItself() {
        for (code in 0..20) {
            val mapped = map(code, "code $code")
            assertNotNull("code $code produced a message-less exception", mapped.message)
            assertTrue(
                "code $code produced a blank message",
                mapped.message!!.isNotBlank()
            )
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /** Invokes the private mapper on a helper bound to a real activity. */
    private fun map(errorCode: Int, message: String): XKeyCryptoException {
        val method = BiometricHelper::class.java
            .getDeclaredMethod("mapErrorToException", Int::class.javaPrimitiveType, String::class.java)
            .apply { isAccessible = true }
        return method.invoke(helper, errorCode, message) as XKeyCryptoException
    }

    private companion object {
        /** Outside every code androidx.biometric currently defines. */
        const val UNKNOWN_ERROR_CODE = 9999
    }
}
