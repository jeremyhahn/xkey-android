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

import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.ByteArrayInputStream

/**
 * Fixed SHA-256 vectors (FIPS 180-2) for [MediaHasher]: the algorithm and the
 * lowercase hex form must match existing SHA-256 manifests.
 */
class MediaHasherTest {

    @Test
    fun `hashBytes gives the lowercase hex SHA-256 of abc`() {
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            MediaHasher.hashBytes("abc".toByteArray(Charsets.US_ASCII))
        )
    }

    @Test
    fun `hashStream gives the lowercase hex SHA-256 of an empty stream`() {
        assertEquals(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            MediaHasher.hashStream(ByteArrayInputStream(ByteArray(0)))
        )
    }
}
