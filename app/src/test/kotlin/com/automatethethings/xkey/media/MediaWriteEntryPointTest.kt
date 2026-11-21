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
package com.automatethethings.xkey.media

import android.Manifest
import android.app.Application
import android.app.NotificationManager
import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/**
 * Captures waiting for write access must be reachable without the
 * notification: on Android 13+ a fresh install may not post it, and the
 * user can turn its channel off. Settings opens the same write request.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class MediaWriteEntryPointTest {

    private lateinit var context: Context
    private lateinit var notifications: NotificationManager

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        notifications = context.getSystemService(NotificationManager::class.java)
        MediaWriteAuthorizations.clear(context)
    }

    @After
    fun tearDown() {
        MediaWriteAuthorizations.clear(context)
    }

    private fun write(uri: String) = PendingMediaWrite(
        uri = uri,
        filePath = null,
        keyId = "key-1",
        keyLabel = "Key",
        data = ContentAuthenticityData(
            contentHash = "a".repeat(64),
            signatures = listOf(
                SignatureEntry(
                    keyFingerprint = "b".repeat(64),
                    signerName = "Test Signer",
                    algorithm = "ES256",
                    value = "c2lnbmF0dXJl",
                    timestamp = "2026-01-01T00:00:00Z",
                    role = SignerRole.CREATOR
                )
            )
        )
    )

    @Test
    fun `with notifications unavailable, pending captures are reachable from the settings entry point`() {
        shadowOf(context as Application).denyPermissions(Manifest.permission.POST_NOTIFICATIONS)
        shadowOf(notifications).setNotificationsEnabled(false)
        MediaWriteAuthorizations.add(context, write("content://media/external/images/media/1"))
        MediaWriteAuthorizations.add(context, write("content://media/external/images/media/2"))

        MediaWriteAuthorizations.notifyPending(context)

        val entry = MediaWriteAuthorizations.settingsEntry(context)
        assertNotNull("settings offers the waiting captures without the notification", entry)
        assertEquals(2, entry!!.count)
        assertEquals(MediaWriteRequestActivity::class.java.name, entry.intent.component?.className)
    }

    @Test
    fun `settings shows no entry when nothing waits`() {
        assertNull(MediaWriteAuthorizations.settingsEntry(context))
    }

    @Test
    fun `enabling auto-signing asks for the notification permission on Android 13 and later until it is granted`() {
        shadowOf(context as Application).denyPermissions(Manifest.permission.POST_NOTIFICATIONS)
        assertEquals(Manifest.permission.POST_NOTIFICATIONS, MediaWriteAuthorizations.notificationPermissionToRequest(context))

        shadowOf(context as Application).grantPermissions(Manifest.permission.POST_NOTIFICATIONS)
        assertNull(MediaWriteAuthorizations.notificationPermissionToRequest(context))
    }

    @Test
    fun `before Android 13 no notification permission is asked for`() {
        // The unit tests run offline on the SDK 34 runtime alone, so the pre-13 branch is
        // reached by reporting SDK 32 (Android 12L) for this test, with the permission denied.
        shadowOf(context as Application).denyPermissions(Manifest.permission.POST_NOTIFICATIONS)
        val sdk = android.os.Build.VERSION.SDK_INT
        org.robolectric.util.ReflectionHelpers.setStaticField(android.os.Build.VERSION::class.java, "SDK_INT", 32)
        try {
            assertNull(MediaWriteAuthorizations.notificationPermissionToRequest(context))
        } finally {
            org.robolectric.util.ReflectionHelpers.setStaticField(android.os.Build.VERSION::class.java, "SDK_INT", sdk)
        }
    }
}
