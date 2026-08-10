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
package com.automatethethings.xkey.settings

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for [MediaSigningSettingsData] data class.
 *
 * Tests verify default values, copy behavior, and data class equality
 * semantics. The [MediaSigningSettingsRepository] requires Android
 * DataStore and is covered by instrumented tests.
 */
class MediaSigningSettingsTest {

    @Test
    fun `default values are correct`() {
        val settings = MediaSigningSettingsData()

        assertFalse(settings.autoSignEnabled)
        assertNull(settings.signingKeyId)
        assertTrue(settings.signPhotos)
        assertTrue(settings.signVideos)
    }

    @Test
    fun `copy with modified autoSignEnabled`() {
        val original = MediaSigningSettingsData()
        val modified = original.copy(autoSignEnabled = true)

        assertTrue(modified.autoSignEnabled)
        assertNull(modified.signingKeyId)
        assertTrue(modified.signPhotos)
        assertTrue(modified.signVideos)
    }

    @Test
    fun `copy with modified signingKeyId`() {
        val original = MediaSigningSettingsData()
        val modified = original.copy(signingKeyId = "my-signing-key-123")

        assertFalse(modified.autoSignEnabled)
        assertEquals("my-signing-key-123", modified.signingKeyId)
        assertTrue(modified.signPhotos)
        assertTrue(modified.signVideos)
    }

    @Test
    fun `copy with all fields modified`() {
        val modified = MediaSigningSettingsData(
            autoSignEnabled = true,
            signingKeyId = "key-456",
            signPhotos = false,
            signVideos = false
        )

        assertTrue(modified.autoSignEnabled)
        assertEquals("key-456", modified.signingKeyId)
        assertFalse(modified.signPhotos)
        assertFalse(modified.signVideos)
    }

    @Test
    fun `equality for identical default instances`() {
        val settings1 = MediaSigningSettingsData()
        val settings2 = MediaSigningSettingsData()

        assertEquals(settings1, settings2)
        assertEquals(settings1.hashCode(), settings2.hashCode())
    }

    @Test
    fun `equality for identical non-default instances`() {
        val settings1 = MediaSigningSettingsData(
            autoSignEnabled = true,
            signingKeyId = "key-1",
            signPhotos = false,
            signVideos = true
        )
        val settings2 = MediaSigningSettingsData(
            autoSignEnabled = true,
            signingKeyId = "key-1",
            signPhotos = false,
            signVideos = true
        )

        assertEquals(settings1, settings2)
        assertEquals(settings1.hashCode(), settings2.hashCode())
    }

    @Test
    fun `inequality when fields differ`() {
        val base = MediaSigningSettingsData()

        assertNotEquals(base, base.copy(autoSignEnabled = true))
        assertNotEquals(base, base.copy(signingKeyId = "some-key"))
        assertNotEquals(base, base.copy(signPhotos = false))
        assertNotEquals(base, base.copy(signVideos = false))
    }

    @Test
    fun `toString contains all field names`() {
        val settings = MediaSigningSettingsData(
            autoSignEnabled = true,
            signingKeyId = "key-test",
            signPhotos = false,
            signVideos = true
        )
        val str = settings.toString()

        assertTrue(str.contains("autoSignEnabled"))
        assertTrue(str.contains("signingKeyId"))
        assertTrue(str.contains("signPhotos"))
        assertTrue(str.contains("signVideos"))
    }
}
