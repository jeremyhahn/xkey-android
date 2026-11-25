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

import android.app.Application
import android.app.Notification
import android.app.NotificationManager
import com.automatethethings.xkey.XKeyApplication
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/**
 * The approval notification shows on a locked phone, so what it shows there
 * must not name the site the owner signs in to: the notification and its
 * channel are private, and the public version a locked screen shows names no
 * relying party.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class BiometricNotificationPrivacyTest {

    private val rpName = "Example Corp"
    private val key = NotificationKeys.wakeOnly("privacyTest")

    @After
    fun tearDown() {
        PromptOwnership.process.end(key)
    }

    private fun texts(notification: Notification): String =
        listOf(Notification.EXTRA_TITLE, Notification.EXTRA_TEXT, Notification.EXTRA_SUB_TEXT, Notification.EXTRA_BIG_TEXT)
            .mapNotNull { notification.extras.getCharSequence(it)?.toString() }
            .plus(listOfNotNull(notification.tickerText?.toString()))
            .joinToString("\n")

    @Test
    fun `the approval notification is private and its public version names no relying party`() {
        val app = RuntimeEnvironment.getApplication()
        PromptOwnership.process.enqueue(key, clock = CoroutineScope(Job()), onQueueExpired = {}) {}
        assertEquals(PromptOwnership.State.ACTIVE, PromptOwnership.process.state(key))

        BiometricNotificationHelper(app).showBiometricRequiredNotification("sign", rpName, key)

        val posted = app.getSystemService(NotificationManager::class.java).activeNotifications
            .single { it.tag == key }.notification
        assertEquals(Notification.VISIBILITY_PRIVATE, posted.visibility)
        assertNotNull("a locked screen shows the public version", posted.publicVersion)
        val public = posted.publicVersion
        assertFalse("the public version names no relying party: ${texts(public)}", texts(public).contains(rpName))
    }

    @Test
    fun `the approval channel keeps notification contents off the lock screen`() {
        val app = RuntimeEnvironment.getApplication()
        val channel = XKeyApplication.biometricChannel(app)
        assertEquals(XKeyApplication.BIOMETRIC_CHANNEL_ID, channel.id)
        assertEquals(Notification.VISIBILITY_PRIVATE, channel.lockscreenVisibility)
    }
}
