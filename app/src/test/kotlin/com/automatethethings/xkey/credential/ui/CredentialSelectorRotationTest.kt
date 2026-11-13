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

package com.automatethethings.xkey.credential.ui

import android.app.Application
import android.content.Intent
import android.content.res.Configuration
import android.hardware.biometrics.BiometricManager
import android.os.Looper
import com.automatethethings.xkey.auth.NotificationKeys
import com.automatethethings.xkey.auth.PendingAuthentications
import com.automatethethings.xkey.auth.PromptOwnership
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import java.time.Duration
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.shadow.api.Shadow
import org.robolectric.shadows.ShadowBiometricManager

/**
 * The AndroidX biometric ceremony outlives a configuration change, so the
 * activity that started it keeps its queue entry across the recreation: a
 * rotation must not hand the screen to the next queued approval while the
 * first prompt is still up.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class CredentialSelectorRotationTest {

    private val held = mutableListOf<String>()

    @After
    fun tearDown() {
        held.forEach { PromptOwnership.process.end(it) }
    }

    @Test
    fun `a rotation with a second approval queued keeps the first prompt's ownership`() {
        val app = RuntimeEnvironment.getApplication()
        val biometrics = app.getSystemService(BiometricManager::class.java)
        val shadow = Shadow.extract<ShadowBiometricManager>(biometrics)
        shadow.setCanAuthenticate(true)
        shadow.setAuthenticatorType(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
        )

        val intent = PromptOwnership.queued(
            Intent(app, CredentialSelectorActivity::class.java)
                .setAction(CredentialSelectorActivity.ACTION_CREATE_CREDENTIAL)
                .putExtra(CredentialSelectorActivity.EXTRA_REQUEST_JSON, """{"rp":{"id":"example.com"}}"""),
            "credentialSelector",
        )
        val first = intent.getStringExtra(PromptOwnership.EXTRA_PROMPT_KEY)!!
        held += first
        val controller = Robolectric.buildActivity(CredentialSelectorActivity::class.java, intent).setup()
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals("the first prompt holds the screen", PromptOwnership.State.ACTIVE, PromptOwnership.process.state(first))

        val second = NotificationKeys.wakeOnly("rotationTest").also { held += it }
        var secondShown = false
        PromptOwnership.process.enqueue(
            second,
            clock = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Job()),
            onQueueExpired = {},
        ) { secondShown = true }
        val entriesBefore = PromptOwnership.process.entries

        controller.configurationChange(Configuration(app.resources.configuration).apply {
            orientation = if (orientation == Configuration.ORIENTATION_PORTRAIT) {
                Configuration.ORIENTATION_LANDSCAPE
            } else {
                Configuration.ORIENTATION_PORTRAIT
            }
        })
        shadowOf(Looper.getMainLooper()).idle()

        assertEquals(
            "the recreated activity still owns the prompt its ceremony shows",
            PromptOwnership.State.ACTIVE,
            PromptOwnership.process.state(first),
        )
        assertFalse("the queued approval waits behind the live prompt", secondShown)
        assertEquals("the recreated activity takes no second entry", entriesBefore, PromptOwnership.process.entries)

        controller.pause().stop().destroy()
        assertEquals(
            "gone for good, the activity hands the screen on",
            PromptOwnership.State.ACTIVE,
            PromptOwnership.process.state(second),
        )
    }

    @Test
    fun `a registration queued past the deadline times out and never shows`() {
        val app = RuntimeEnvironment.getApplication()
        val biometrics = app.getSystemService(BiometricManager::class.java)
        val shadow = Shadow.extract<ShadowBiometricManager>(biometrics)
        shadow.setCanAuthenticate(true)
        shadow.setAuthenticatorType(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
        )

        // Earlier approvals hold the screen past the registration's deadline.
        val holder = NotificationKeys.wakeOnly("deadlineTest").also { held += it }
        PromptOwnership.process.enqueue(
            holder,
            clock = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Job()),
            onQueueExpired = {},
        ) {}

        val intent = PromptOwnership.queued(
            Intent(app, CredentialSelectorActivity::class.java)
                .setAction(CredentialSelectorActivity.ACTION_CREATE_CREDENTIAL)
                .putExtra(CredentialSelectorActivity.EXTRA_REQUEST_JSON, """{"rp":{"id":"example.com"}}"""),
            "credentialSelector",
        )
        val registration = intent.getStringExtra(PromptOwnership.EXTRA_PROMPT_KEY)!!
        held += registration
        val controller = Robolectric.buildActivity(CredentialSelectorActivity::class.java, intent).setup()
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals("the registration waits its turn", PromptOwnership.State.QUEUED, PromptOwnership.process.state(registration))

        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(PendingAuthentications.QUEUE_DEADLINE_MILLIS + 1))

        assertEquals(
            "past the queue deadline the registration settles expired",
            PromptOwnership.Outcome.EXPIRED,
            PromptOwnership.process.outcome(registration),
        )
        assertTrue("the activity cancels the registration", controller.get().isFinishing)

        PromptOwnership.process.end(holder)
        shadowOf(Looper.getMainLooper()).idle()
        assertNotEquals(
            "the freed screen never goes to the timed-out registration",
            registration,
            PromptOwnership.process.activeKey,
        )
        controller.pause().stop().destroy()
    }
}
