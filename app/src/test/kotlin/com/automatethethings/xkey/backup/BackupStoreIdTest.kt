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
package com.automatethethings.xkey.backup

import android.content.Context
import com.automatethethings.xkey.crypto.SyncCodec
import io.mockk.every
import io.mockk.mockk
import java.io.File
import java.nio.ByteBuffer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * JVM tests for the ids [BackupStore] generates and the order [BackupStore.latestId]
 * uses. The device-side cases live in androidTest BackupStoreTest.
 */
class BackupStoreIdTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private lateinit var context: Context

    @Before
    fun setUp() {
        context = mockk(relaxed = true)
        every { context.filesDir } returns tmp.root
    }

    private fun store() = BackupStore(context)

    private fun backupDir() = File(tmp.root, "backups")

    @Test
    fun `two generated ids in a row are distinct and both load`() {
        val s = store()
        val a = s.store("", byteArrayOf(1))
        val b = s.store("", byteArrayOf(2))

        assertNotEquals(a, b)
        assertTrue(a.startsWith("backup-"))
        assertTrue(b.startsWith("backup-"))
        assertArrayEquals(byteArrayOf(1), s.load(a))
        assertArrayEquals(byteArrayOf(2), s.load(b))
    }

    @Test
    fun `many generated ids in a tight loop are distinct and all load`() {
        val s = store()
        val ids = (0 until 200).map { i -> s.store("", byteArrayOf(i.toByte(), (i shr 8).toByte())) }

        assertEquals(ids.size, ids.toSet().size)
        ids.forEachIndexed { i, id ->
            assertArrayEquals(byteArrayOf(i.toByte(), (i shr 8).toByte()), s.load(id))
        }
    }

    @Test
    fun `generated ids from two store instances do not collide`() {
        val a = store().store("", byteArrayOf(1))
        val b = store().store("", byteArrayOf(2))

        assertNotEquals(a, b)
        assertArrayEquals(byteArrayOf(1), store().load(a))
        assertArrayEquals(byteArrayOf(2), store().load(b))
    }

    @Test
    fun `latestId is the last stored even when mtimes are equal`() {
        val s = store()
        val ids = (0 until 5).map { s.store("", byteArrayOf(it.toByte())) }
        val stamp = 1_700_000_000_000L
        backupDir().listFiles()!!.forEach { it.setLastModified(stamp) }

        assertEquals(ids.last(), store().latestId())
    }

    @Test
    fun `latestId is the last stored even when it has the oldest mtime`() {
        val s = store()
        val first = s.store("first", byteArrayOf(1))
        val second = s.store("second", byteArrayOf(2))
        val files = backupDir().listFiles()!!
        files.forEach { it.setLastModified(1_700_000_000_000L) }
        recordFile(second).setLastModified(1_600_000_000_000L)

        assertNotEquals(first, store().latestId())
        assertEquals(second, store().latestId())
    }

    @Test
    fun `storing an explicit id again makes it the latest`() {
        val s = store()
        s.store("a", byteArrayOf(1))
        s.store("b", byteArrayOf(2))
        s.store("a", byteArrayOf(3))
        backupDir().listFiles()!!.forEach { it.setLastModified(1_700_000_000_000L) }

        assertEquals("a", store().latestId())
        assertArrayEquals(byteArrayOf(3), store().load("a"))
    }

    @Test
    fun `createdAtMillis is the creation time, not a later mtime`() {
        val before = System.currentTimeMillis()
        val id = store().store("", byteArrayOf(1))
        val after = System.currentTimeMillis()
        recordFile(id).setLastModified(1_600_000_000_000L)

        val created = store().createdAtMillis(id)
        assertTrue("created $created not in [$before, $after]", created in before..after)
    }

    @Test
    fun `createdAtMillis of an unknown id is 0`() {
        assertEquals(0L, store().createdAtMillis("nope"))
    }

    @Test
    fun `an XKB1 record from an older build loads and keeps its mtime as creation time`() {
        val dir = backupDir().apply { mkdirs() }
        val id = "backup-1690000000000"
        val f = File(dir, "${SyncCodec.sha256Hex(id.toByteArray())}.backup")
        f.writeBytes(xkb1(id, byteArrayOf(9, 8, 7)))
        f.setLastModified(1_690_000_000_000L)

        val s = store()
        assertArrayEquals(byteArrayOf(9, 8, 7), s.load(id))
        assertEquals(id, s.latestId())
        assertEquals(1_690_000_000_000L, s.createdAtMillis(id))
    }

    @Test
    fun `a backup stored after an XKB1 record is the latest even with an older mtime`() {
        val dir = backupDir().apply { mkdirs() }
        val old = "backup-1690000000000"
        val f = File(dir, "${SyncCodec.sha256Hex(old.toByteArray())}.backup")
        f.writeBytes(xkb1(old, byteArrayOf(1)))
        f.setLastModified(1_790_000_000_000L)

        val fresh = store().store("", byteArrayOf(2))
        recordFile(fresh).setLastModified(1_600_000_000_000L)

        assertEquals(fresh, store().latestId())
        assertArrayEquals(byteArrayOf(1), store().load(old))
    }

    @Test
    fun `a bare legacy blob migrates and loads under its filename`() {
        val dir = backupDir().apply { mkdirs() }
        val legacy = File(dir, "backup-1680000000000")
        legacy.writeBytes(byteArrayOf(4, 5, 6))
        legacy.setLastModified(1_680_000_000_000L)

        val s = store()
        assertArrayEquals(byteArrayOf(4, 5, 6), s.load("backup-1680000000000"))
        assertEquals("backup-1680000000000", s.latestId())
        assertEquals(1_680_000_000_000L, s.createdAtMillis("backup-1680000000000"))
        assertTrue(!legacy.exists())
    }

    private fun recordFile(id: String) =
        File(backupDir(), "${SyncCodec.sha256Hex(id.toByteArray(Charsets.UTF_8))}.backup")

    private fun xkb1(id: String, blob: ByteArray): ByteArray {
        val idBytes = id.toByteArray(Charsets.UTF_8)
        return ByteBuffer.allocate(4 + 4 + idBytes.size + blob.size)
            .put("XKB1".toByteArray(Charsets.US_ASCII))
            .putInt(idBytes.size)
            .put(idBytes)
            .put(blob)
            .array()
    }
}
