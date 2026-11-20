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

package com.automatethethings.xkey.media

import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException
import java.io.InputStream

/**
 * A sidecar is whatever file sits beside the media: its signature data is
 * read through one bounded reader, never whole.
 */
class SidecarReadBoundTest {

    @Test
    fun `a sidecar larger than the bound is refused after reading at most the bound`() {
        var read = 0L
        val endless = object : InputStream() {
            override fun read(): Int { read++; return ' '.code }
            override fun read(b: ByteArray, off: Int, len: Int): Int {
                java.util.Arrays.fill(b, off, off + len, ' '.code.toByte())
                read += len
                return len
            }
        }

        try {
            ContentAuthenticityData.fromJsonStream(endless, limit = 64 * 1024)
            fail("an endless sidecar was accepted")
        } catch (expected: IOException) {
            // refused
        }
        assertTrue("read $read bytes", read <= 64 * 1024 + 8192)
    }
}
