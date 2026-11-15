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

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * A run whose screen is gone for good ([MediaSaveRuns.abandon]) is
 * forgotten once it ends, and what it left is released; a run whose screen
 * is only recreated stays for the next instance. Staging files an earlier
 * process left are swept ([MediaSaveRuns.sweep]); this process's stay.
 */
class MediaSaveRunsAbandonTest {

    @get:Rule
    val temp = TemporaryFolder()

    private fun id() = UUID.randomUUID().toString()

    private fun awaitGone(id: String) {
        val deadline = System.currentTimeMillis() + 10_000
        while (MediaSaveRuns.isLive(id)) {
            assertTrue("timed out", System.currentTimeMillis() < deadline)
            Thread.sleep(10)
        }
    }

    @Test
    fun `a run abandoned while it runs is forgotten and released when it ends`() {
        val id = id()
        val gate = CountDownLatch(1)
        val staged = temp.newFile("cosign-staged.png")
        MediaSaveRuns.attach(id) { gate.await(10, TimeUnit.SECONDS); staged }
        val released = CountDownLatch(1)
        MediaSaveRuns.abandon<File>(id) { result -> result.getOrNull()?.delete(); released.countDown() }
        assertTrue("still running", MediaSaveRuns.isLive(id))

        gate.countDown()
        assertTrue(released.await(10, TimeUnit.SECONDS))
        awaitGone(id)
        assertFalse("its staged file is released", staged.exists())
    }

    @Test
    fun `a run abandoned after it ended is released at once`() {
        val id = id()
        val staged = temp.newFile("cosign-ended.png")
        val run = MediaSaveRuns.attach(id) { staged }
        runBlocking { run.join() }
        var released: Result<File>? = null
        MediaSaveRuns.abandon<File>(id) { released = it }
        assertSame(staged, released!!.getOrThrow())
        assertFalse(MediaSaveRuns.isLive(id))
    }

    @Test
    fun `a failed run abandoned hands its failure to the release`() {
        val id = id()
        val run = MediaSaveRuns.attach<File>(id) { throw java.io.IOException("storage full") }
        runBlocking { run.join() }
        var released: Result<File>? = null
        MediaSaveRuns.abandon<File>(id) { released = it }
        assertEquals("storage full", released!!.exceptionOrNull()!!.message)
        assertFalse(MediaSaveRuns.isLive(id))
    }

    @Test
    fun `a run not abandoned stays for a recreated screen`() {
        val id = id()
        val run = MediaSaveRuns.attach(id) { "done" }
        runBlocking { run.join() }
        assertTrue(MediaSaveRuns.isLive(id))
        assertSame("the next instance reattaches the same run", run, MediaSaveRuns.attach(id) { "again" })
        MediaSaveRuns.finished(id)
        assertNotSame(run, MediaSaveRuns.attach(id) { "again" })
        MediaSaveRuns.finished(id)
    }

    @Test
    fun `abandoning an unknown run does nothing`() {
        var called = false
        MediaSaveRuns.abandon<Any>(id()) { called = true }
        assertFalse(called)
    }

    @Test
    fun `the sweep removes staging files an earlier process left and keeps this process's`() {
        val dir = temp.newFolder("media-recovery")
        val earlier = File(dir, "cosign-0123456789abcdef.png").apply { writeBytes(byteArrayOf(1)); age() }
        val mine = MediaSaveRuns.stage(dir, ".png")
        val kept = File(dir, ".clip.png.123.xkeytmp").apply { writeBytes(byteArrayOf(2)) }

        MediaSaveRuns.sweep(dir)

        assertFalse("an earlier process's staged copy is gone", earlier.exists())
        assertTrue("this process's staged copy stays", mine.exists())
        assertTrue("other recovery files are not the sweep's", kept.exists())
        assertTrue(mine.name.startsWith("cosign-"))
    }

    @Test
    fun `the sweep keeps an earlier process's staging file a restored screen still names`() {
        val dir = temp.newFolder("media-recovery-kept")
        val named = File(dir, "cosign-0123456789abcdef-named.png").apply { writeBytes(byteArrayOf(1)) }
        val orphan = File(dir, "cosign-fedcba9876543210-orphan.png").apply { writeBytes(byteArrayOf(2)); age() }

        MediaSaveRuns.sweep(dir, keep = listOf(named))

        assertTrue("a staged copy a restored exchange names stays", named.exists())
        assertFalse("one nothing names is gone", orphan.exists())

        // Another screen of this process starts before the exchange ends.
        MediaSaveRuns.sweep(dir)
        assertTrue("a later sweep in this process keeps it too", named.exists())
    }

    @Test
    fun `a staged copy a not yet restored screen names survives another screen's start sweep`() {
        val dir = temp.newFolder("media-recovery-unrestored")
        // Saved by a co-sign screen of an earlier process; that screen is
        // not restored yet, so no sweep has been told to keep it.
        val unrestored = File(dir, "cosign-0123456789abcdef-saved.png").apply { writeBytes(byteArrayOf(1)) }
        val stale = File(dir, "cosign-fedcba9876543210-stale.png").apply { writeBytes(byteArrayOf(2)); age() }

        // Another screen (or another co-sign instance) starts first.
        MediaSaveRuns.sweep(dir)

        assertTrue("a copy saved state could still name stays", unrestored.exists())
        assertFalse("a copy past every saved state's reach is gone", stale.exists())
    }

    @Test
    fun `holding a staged copy restarts its window`() {
        val dir = temp.newFolder("media-recovery-held")
        val held = File(dir, "cosign-0123456789abcdef-held.png").apply { writeBytes(byteArrayOf(1)); age() }

        // Its screen saved its state again: the copy is named anew.
        MediaSaveRuns.hold(listOf(held))
        MediaSaveRuns.sweep(dir)

        assertTrue("a copy saved state names again stays", held.exists())
    }

    /** Dates this file past the window in which saved screen state could name it. */
    private fun File.age() {
        assertTrue(setLastModified(System.currentTimeMillis() - MediaSaveRuns.STAGED_RETENTION_MS - 60_000))
    }
}
