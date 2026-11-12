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
import java.io.IOException
import java.nio.ByteBuffer
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
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

    // -----------------------------------------------------------------
    // A fixed clock: every store lands in the same millisecond
    // -----------------------------------------------------------------

    private val fixedMillis = 1_700_000_000_000L

    private fun fixedClockStore() = BackupStore(context) { fixedMillis }

    @Test
    fun `generated ids in one millisecond are distinct across two instances and keep every payload`() {
        val first = fixedClockStore()
        val second = fixedClockStore()
        val stored = mutableListOf<Pair<String, ByteArray>>()
        repeat(3) { i -> stored += first.store("", byteArrayOf(1, i.toByte())) to byteArrayOf(1, i.toByte()) }
        repeat(3) { i -> stored += second.store("", byteArrayOf(2, i.toByte())) to byteArrayOf(2, i.toByte()) }
        stored += first.store("", byteArrayOf(3)) to byteArrayOf(3)

        val ids = stored.map { it.first }
        assertEquals(ids.toString(), ids.size, ids.toSet().size)
        ids.forEach { assertTrue(it, it.startsWith("backup-$fixedMillis")) }
        val reader = fixedClockStore()
        stored.forEach { (id, payload) -> assertArrayEquals(id, payload, reader.load(id)) }
        assertEquals(ids.size, backupDir().listFiles()!!.size)
    }

    @Test
    fun `in one millisecond the latest is the last stored and createdAt is that millisecond`() {
        val ids = (0 until 4).map { fixedClockStore().store("", byteArrayOf(it.toByte())) }
        backupDir().listFiles()!!.forEach { it.setLastModified(fixedMillis) }

        assertEquals(ids.last(), fixedClockStore().latestId())
        ids.forEach { assertEquals(fixedMillis, fixedClockStore().createdAtMillis(it)) }
    }

    @Test
    fun `overlapping writes from separate instances in one millisecond get distinct ids and keep every payload`() {
        val threads = 8
        val rounds = 25
        // One barrier trip per round, so every thread enters store() at the same moment.
        val barrier = CyclicBarrier(threads)
        val stored = ConcurrentHashMap<String, ByteArray>()
        val ids = Collections.synchronizedList(mutableListOf<String>())
        val pool = Executors.newFixedThreadPool(threads)
        try {
            val futures = (0 until threads).map { t ->
                pool.submit {
                    val own = fixedClockStore()
                    repeat(rounds) { r ->
                        val payload = byteArrayOf(t.toByte(), r.toByte())
                        barrier.await(30, TimeUnit.SECONDS)
                        val id = own.store("", payload)
                        ids += id
                        stored[id] = payload
                    }
                }
            }
            futures.forEach { it.get(60, TimeUnit.SECONDS) }
        } finally {
            pool.shutdownNow()
        }

        assertEquals(threads * rounds, ids.size)
        val duplicates = ids.groupingBy { it }.eachCount().filterValues { it > 1 }
        assertTrue("duplicate ids: $duplicates", duplicates.isEmpty())
        val reader = fixedClockStore()
        stored.forEach { (id, payload) -> assertArrayEquals(id, payload, reader.load(id)) }
        assertEquals(threads * rounds, backupDir().listFiles()!!.size)
    }

    // -----------------------------------------------------------------
    // Storage failures surface; only malformed headers are skipped
    // -----------------------------------------------------------------

    /** Replaces the record of [id] with a directory: present, but unreadable. */
    private fun makeUnreadable(id: String) {
        val file = recordFile(id)
        assertTrue(file.delete())
        assertTrue(file.mkdir())
    }

    @Test
    fun `an unreadable newest record makes latestId fail instead of picking an older backup`() {
        val s = store()
        s.store("older", byteArrayOf(1))
        s.store("newest", byteArrayOf(2))
        makeUnreadable("newest")

        assertThrows(IOException::class.java) { store().latestId() }
    }

    @Test
    fun `an unreadable record makes store fail instead of reusing its sequence`() {
        val s = store()
        s.store("older", byteArrayOf(1))
        s.store("newest", byteArrayOf(2))
        makeUnreadable("newest")

        assertThrows(IOException::class.java) { store().store("", byteArrayOf(3)) }
    }

    @Test
    fun `a truncated or malformed record header is skipped`() {
        val s = store()
        val good = s.store("good", byteArrayOf(1))
        val dir = backupDir()
        // XKB2 magic, then only 3 of the 16 header bytes.
        File(dir, "${"a".repeat(64)}.backup").writeBytes("XKB2".toByteArray() + byteArrayOf(0, 0, 0))
        // Shorter than a magic.
        File(dir, "${"b".repeat(64)}.backup").writeBytes(byteArrayOf(1, 2))
        // An unknown magic.
        File(dir, "${"c".repeat(64)}.backup").writeBytes("ZZZZ".toByteArray() + ByteArray(32))

        assertEquals(good, store().latestId())
        val next = store().store("", byteArrayOf(2))
        assertEquals(next, store().latestId())
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
