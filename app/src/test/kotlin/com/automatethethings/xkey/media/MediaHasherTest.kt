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
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

/**
 * Unit tests for [MediaHasher] SHA-256 hashing functionality.
 *
 * Tests verify correctness against known SHA-256 test vectors and
 * ensure consistency between the byte array and stream hashing paths.
 */
class MediaHasherTest {

    @Test
    fun `hashBytes produces correct SHA-256 for known input`() {
        // SHA-256("hello world") = b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
        val result = MediaHasher.hashBytes("hello world".toByteArray())

        assertEquals(
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
            result
        )
    }

    @Test
    fun `hashBytes produces correct SHA-256 for empty input`() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        val result = MediaHasher.hashBytes(ByteArray(0))

        assertEquals(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            result
        )
    }

    @Test
    fun `hashStream produces same result as hashBytes`() {
        val data = "hello world".toByteArray()

        val bytesHash = MediaHasher.hashBytes(data)
        val streamHash = MediaHasher.hashStream(ByteArrayInputStream(data))

        assertEquals(bytesHash, streamHash)
    }

    @Test
    fun `hashStream produces correct SHA-256 for empty stream`() {
        val result = MediaHasher.hashStream(ByteArrayInputStream(ByteArray(0)))

        assertEquals(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            result
        )
    }

    @Test
    fun `hashBytes produces 64 character hex string`() {
        val result = MediaHasher.hashBytes("test data".toByteArray())

        assertEquals(64, result.length)
        assertTrue(result.matches(Regex("[0-9a-f]{64}")))
    }

    @Test
    fun `hashBytes handles large input`() {
        // 1 MB + 1 byte of zeros to exceed typical buffer sizes
        val largeData = ByteArray(1_048_577) { 0 }
        val result = MediaHasher.hashBytes(largeData)

        // Verify it produces a valid 64-char hex hash
        assertEquals(64, result.length)
        assertTrue(result.matches(Regex("[0-9a-f]{64}")))

        // Verify consistency - hashing the same large data again gives the same result
        val result2 = MediaHasher.hashBytes(largeData)
        assertEquals(result, result2)
    }

    @Test
    fun `hashStream handles large input consistently with hashBytes`() {
        val largeData = ByteArray(1_048_577) { 0 }

        val bytesHash = MediaHasher.hashBytes(largeData)
        val streamHash = MediaHasher.hashStream(ByteArrayInputStream(largeData))

        assertEquals(bytesHash, streamHash)
    }

    @Test
    fun `hashBytes produces different hashes for different input`() {
        val hash1 = MediaHasher.hashBytes("hello".toByteArray())
        val hash2 = MediaHasher.hashBytes("world".toByteArray())

        assertTrue(hash1 != hash2)
    }
}
