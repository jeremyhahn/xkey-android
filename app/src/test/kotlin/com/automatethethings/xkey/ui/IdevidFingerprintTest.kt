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
package com.automatethethings.xkey.ui

import android.app.Application
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.MessageDigest

/**
 * The IDevID fingerprint the device screen shows, and the one its copy button
 * puts on the clipboard, is the certificate's whole SHA-256: a truncated
 * fingerprint cannot be compared against the full one a peer reports.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class IdevidFingerprintTest {

    private val der = ByteArray(300) { it.toByte() }

    private val expected = MessageDigest.getInstance("SHA-256").digest(der)
        .joinToString(":") { "%02X".format(it) }

    @Test
    fun `the fingerprint is the whole SHA-256 as 32 colon-separated bytes`() {
        val fingerprint = DeviceDetailActivity.computeFingerprint(der)
        assertEquals(expected, fingerprint)
        val bytes = fingerprint.split(":")
        assertEquals(32, bytes.size)
        bytes.forEach { assertEquals("two hex digits: $it", true, it.matches(Regex("[0-9A-F]{2}"))) }
    }

    @Test
    fun `the copy button copies the fingerprint the screen shows`() {
        val clip = DeviceDetailActivity.fingerprintClip(der)
        assertEquals(1, clip.itemCount)
        assertEquals(DeviceDetailActivity.computeFingerprint(der), clip.getItemAt(0).text.toString())
        assertEquals(expected, clip.getItemAt(0).text.toString())
    }
}
