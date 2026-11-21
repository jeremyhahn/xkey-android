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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The URIs the media signing service has handled stay bounded whatever the
 * outcome: a capture queued for the user's write access (the usual path for
 * a camera's capture on Android 11 and later) is remembered through the same
 * bounded insertion as a signed one, so a long-running service never grows
 * the set without limit, and the most recent captures are still deduplicated.
 */
class ProcessedUrisBoundTest {

    private fun capture(n: Int) = "content://media/external/images/media/$n"

    @Test
    fun `more than the bound of queued captures leave the set at or under it`() {
        val processed = RecentUris(RecentUris.DEFAULT_BOUND)
        val total = RecentUris.DEFAULT_BOUND + 500

        // Every capture is queued for authorization: none is ever signed here.
        repeat(total) { processed.add(capture(it)) }

        assertTrue("size ${processed.size} is over the bound", processed.size <= RecentUris.DEFAULT_BOUND)
        assertEquals(1000, RecentUris.DEFAULT_BOUND)
    }

    @Test
    fun `recent captures are still deduplicated and the oldest go first`() {
        val processed = RecentUris(RecentUris.DEFAULT_BOUND)
        val total = RecentUris.DEFAULT_BOUND + 500
        repeat(total) { processed.add(capture(it)) }

        val recent = (total - RecentUris.DEFAULT_BOUND until total).map(::capture)
        recent.forEach { assertTrue("$it was forgotten", processed.contains(it)) }
        assertFalse("a repeated event for a recent capture is new again", processed.add(capture(total - 1)))
        assertFalse("the oldest capture is kept past the bound", processed.contains(capture(0)))
    }

    @Test
    fun `a capture seen again moves to the recent end`() {
        val processed = RecentUris(3)
        listOf(1, 2, 3).forEach { processed.add(capture(it)) }
        processed.add(capture(1))
        processed.add(capture(4))

        assertTrue(processed.contains(capture(1)))
        assertFalse(processed.contains(capture(2)))
        assertEquals(3, processed.size)
    }

    /** The service remembers a handled URI only through [RecentUris]: no other set it could grow. */
    @Test
    fun `the service remembers handled captures only through the bounded set`() {
        val root = listOf(
            File("src/main/kotlin/com/automatethethings/xkey"),
            File("app/src/main/kotlin/com/automatethethings/xkey")
        ).first { it.isDirectory }
        val service = File(root, "media/MediaSigningService.kt").readText()

        assertTrue(
            "processedUris is a RecentUris",
            Regex("""val processedUris\s*=\s*RecentUris\(""").containsMatchIn(service)
        )
        assertFalse(
            "the service evicts from processedUris by hand",
            Regex("""processedUris\.(iterator|remove|size)""").containsMatchIn(service)
        )
    }
}
