// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under AGPL-3.0 (see LICENSE) or a commercial license.

package com.automatethethings.xkey.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for [SyncCodec], the stateless codec shared by the sync engine,
 * key-sharing, and backup handlers.
 */
class SyncCodecTest {

    @Test
    fun `sha256Hex matches known empty vector`() {
        assertEquals(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            SyncCodec.sha256Hex(ByteArray(0))
        )
    }

    @Test
    fun `storeChecksum is order-independent`() {
        assertEquals(
            SyncCodec.storeChecksum(listOf("a", "b", "c")),
            SyncCodec.storeChecksum(listOf("c", "a", "b"))
        )
    }

    @Test
    fun `storeChecksum changes with content`() {
        assertNotEquals(
            SyncCodec.storeChecksum(listOf("a")),
            SyncCodec.storeChecksum(listOf("b"))
        )
    }

    @Test
    fun `pem der round trips`() {
        val der = byteArrayOf(0x30, 0x03, 0x01, 0x02, 0x03, 0x7f, 0x00, 0x55.toByte())
        val pem = SyncCodec.derToPem(der)
        assertTrue(pem.startsWith("-----BEGIN CERTIFICATE-----"))
        assertTrue(pem.trimEnd().endsWith("-----END CERTIFICATE-----"))
        assertArrayEquals(der, SyncCodec.pemToDer(pem))
    }

    @Test
    fun `pemToDer returns null on empty body`() {
        assertNull(SyncCodec.pemToDer("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"))
    }

    @Test
    fun `rfc3339 round trips`() {
        val millis = 1_700_000_000_000L
        assertEquals(millis, SyncCodec.parseRfc3339(SyncCodec.toRfc3339(millis)))
    }

    @Test
    fun `toRfc3339 empty for non-positive`() {
        assertEquals("", SyncCodec.toRfc3339(0))
        assertEquals("", SyncCodec.toRfc3339(-1))
    }

    @Test
    fun `parseRfc3339 zero on blank or garbage`() {
        assertEquals(0L, SyncCodec.parseRfc3339(""))
        assertEquals(0L, SyncCodec.parseRfc3339("not-a-date"))
    }

    // -----------------------------------------------------------------------
    // Digests
    // -----------------------------------------------------------------------

    @Test
    fun `sha256Hex matches the FIPS 180-2 abc vector`() {
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            SyncCodec.sha256Hex("abc".toByteArray(Charsets.UTF_8))
        )
    }

    @Test
    fun `sha256Hex is lowercase hex of exactly 64 characters`() {
        val hex = SyncCodec.sha256Hex(ByteArray(64) { 0xFF.toByte() })
        assertEquals(64, hex.length)
        assertEquals(hex.lowercase(), hex)
        assertTrue(hex.all { it in "0123456789abcdef" })
    }

    @Test
    fun `storeChecksum hashes the sorted newline-joined keys`() {
        // Independently derived: sha256 over "a\nb\nc".
        assertEquals(
            SyncCodec.sha256Hex("a\nb\nc".toByteArray(Charsets.UTF_8)),
            SyncCodec.storeChecksum(listOf("b", "c", "a"))
        )
    }

    @Test
    fun `storeChecksum of an empty store is the empty-string digest`() {
        assertEquals(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            SyncCodec.storeChecksum(emptyList())
        )
    }

    @Test
    fun `storeChecksum keeps duplicate keys distinct from a single key`() {
        assertNotEquals(
            SyncCodec.storeChecksum(listOf("a")),
            SyncCodec.storeChecksum(listOf("a", "a"))
        )
    }

    // -----------------------------------------------------------------------
    // PEM / DER
    // -----------------------------------------------------------------------

    @Test
    fun `derToPem wraps the body at 64 characters`() {
        val der = ByteArray(200) { it.toByte() }
        val lines = SyncCodec.derToPem(der).trimEnd().lines()
        assertEquals("-----BEGIN CERTIFICATE-----", lines.first())
        assertEquals("-----END CERTIFICATE-----", lines.last())
        val body = lines.subList(1, lines.size - 1)
        assertTrue("every full line must be 64 chars", body.dropLast(1).all { it.length == 64 })
        assertTrue("last body line must not be empty", body.last().isNotEmpty())
        assertTrue("last body line must not exceed 64 chars", body.last().length <= 64)
        assertEquals(
            java.util.Base64.getEncoder().encodeToString(der),
            body.joinToString("")
        )
    }

    @Test
    fun `derToPem ends with a trailing newline`() {
        assertTrue(SyncCodec.derToPem(byteArrayOf(1, 2, 3)).endsWith("-----END CERTIFICATE-----\n"))
    }

    @Test
    fun `pemToDer accepts a headerless base64 body`() {
        val der = byteArrayOf(0x30, 0x01, 0x02)
        val b64 = java.util.Base64.getEncoder().encodeToString(der)
        assertArrayEquals(der, SyncCodec.pemToDer(b64))
    }

    @Test
    fun `pemToDer ignores interior whitespace and CRLF line endings`() {
        val der = ByteArray(96) { (it * 3).toByte() }
        val pem = SyncCodec.derToPem(der).replace("\n", "\r\n")
        assertArrayEquals(der, SyncCodec.pemToDer(pem))
    }

    @Test
    fun `pemToDer returns null on non-base64 content`() {
        assertNull(SyncCodec.pemToDer("-----BEGIN CERTIFICATE-----\n!!!not base64!!!\n-----END CERTIFICATE-----"))
    }

    @Test
    fun `pemToDer returns null on empty input`() {
        assertNull(SyncCodec.pemToDer(""))
        assertNull(SyncCodec.pemToDer("   \n  \n"))
    }

    @Test
    fun `pemToDer tolerates a key-labelled block`() {
        // The header line is dropped by prefix, not by label, so any PEM type works.
        val der = byteArrayOf(0x02, 0x01, 0x00)
        val pem = "-----BEGIN PRIVATE KEY-----\n" +
            java.util.Base64.getEncoder().encodeToString(der) + "\n" +
            "-----END PRIVATE KEY-----\n"
        assertArrayEquals(der, SyncCodec.pemToDer(pem))
    }

    @Test
    fun `pem round trip survives a 1 KiB payload`() {
        val der = ByteArray(1024) { (it xor 0x5A).toByte() }
        assertArrayEquals(der, SyncCodec.pemToDer(SyncCodec.derToPem(der)))
    }

    // -----------------------------------------------------------------------
    // RFC 3339
    // -----------------------------------------------------------------------

    @Test
    fun `toRfc3339 renders UTC with a Z suffix`() {
        assertEquals("2023-11-14T22:13:20Z", SyncCodec.toRfc3339(1_700_000_000_000L))
        assertEquals("1970-01-01T00:00:00.001Z", SyncCodec.toRfc3339(1L))
    }

    @Test
    fun `parseRfc3339 accepts fractional seconds`() {
        assertEquals(1_700_000_000_123L, SyncCodec.parseRfc3339("2023-11-14T22:13:20.123Z"))
    }

    @Test
    fun `parseRfc3339 accepts a numeric UTC offset`() {
        assertEquals(1_699_992_800_000L, SyncCodec.parseRfc3339("2023-11-14T22:13:20+02:00"))
    }

    @Test
    fun `parseRfc3339 returns zero for a date without a time zone`() {
        assertEquals(0L, SyncCodec.parseRfc3339("2023-11-14T22:13:20"))
        assertEquals(0L, SyncCodec.parseRfc3339("2023-11-14"))
    }

    @Test
    fun `parseRfc3339 returns zero for whitespace-only input`() {
        assertEquals(0L, SyncCodec.parseRfc3339("   "))
    }
}
