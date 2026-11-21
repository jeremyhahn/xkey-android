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

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicInteger

/**
 * The automatic signer's memory stays bounded however many captures arrive:
 * each capture is hashed with constant-size buffers, and the jobs that sign
 * them pass one gate that starts a single job per URI and holds no more
 * memory across jobs than its bound.
 */
class MediaJobBoundTest {

    @get:Rule
    val folder = TemporaryFolder()

    /** Bytes the calling thread has allocated so far. */
    private fun allocated(): Long {
        // The unit tests compile against android.jar, which has no java.lang.management: reflect.
        val bean = Class.forName("java.lang.management.ManagementFactory").getMethod("getThreadMXBean").invoke(null)
        val method = Class.forName("com.sun.management.ThreadMXBean")
            .getMethod("getThreadAllocatedBytes", Long::class.javaPrimitiveType)
        return method.invoke(bean, Thread.currentThread().id) as Long
    }

    /** An MP4 whose media data is [payload] bytes. */
    private fun mp4(payload: Int): java.io.File = with(XmpFixtures) {
        val file = folder.newFile("VID_${payload}.mp4")
        file.outputStream().use { out ->
            out.write(box("ftyp", ascii("isom") + be32(0x200) + ascii("isommp42")))
            out.write(box("moov", box("mvhd", ByteArray(12) { 1 })))
            out.write(be32(payload + 8L) + ascii("mdat"))
            val chunk = ByteArray(1024 * 1024) { 0x11 }
            var left = payload
            while (left > 0) {
                val n = minOf(left, chunk.size)
                out.write(chunk, 0, n)
                left -= n
            }
        }
        file
    }

    @Test
    fun `a video under the embed bound is hashed with constant-size buffers, never held whole`() {
        val size = 24 * 1024 * 1024
        val video = mp4(size)
        val embedLimit = 64 * 1024 * 1024
        // Warm up class loading so only the hash itself is measured.
        AutoSignHash.contentHashFile(mp4(16), "video/mp4", embedLimit = embedLimit)

        val before = allocated()
        val hash = AutoSignHash.contentHashFile(video, "video/mp4", embedLimit = embedLimit)
        val used = allocated() - before

        assertEquals(MediaHasher.hashStreamedFile(video, "video/mp4").canonical, hash)
        assertTrue("hashing allocated $used bytes for a $size-byte video", used < 4L * 1024 * 1024)
    }

    @Test
    fun `concurrent notifications start one job per URI and stay within the memory bound`() = runBlocking<Unit> {
        val perJob = 10L * 1024 * 1024
        val gate = MediaJobGate(memoryBound = 3 * perJob, perJobBytes = perJob)
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val uris = (1..10).map { "content://media/external/video/media/$it" }
        val started = ConcurrentHashMap<String, AtomicInteger>()
        val running = AtomicInteger()
        var peak = 0
        val jobs = java.util.Collections.synchronizedList(mutableListOf<Job>())
        val ready = CountDownLatch(1)

        // Five notifications for each URI, from several threads at once.
        val threads = (1..5).map {
            Thread {
                ready.await()
                for (uri in uris) {
                    gate.launch(scope, uri) {
                        started.getOrPut(uri) { AtomicInteger() }.incrementAndGet()
                        val now = running.incrementAndGet()
                        synchronized(this@MediaJobBoundTest) { peak = maxOf(peak, now) }
                        delay(50)
                        running.decrementAndGet()
                    }?.let { jobs += it }
                }
            }.apply { start() }
        }
        ready.countDown()
        threads.forEach { it.join() }
        jobs.toList().joinAll()

        assertEquals("one job per URI", uris.toSet(), started.keys)
        assertTrue("no URI hashed twice: $started", started.values.all { it.get() == 1 })
        assertEquals(uris.size, jobs.size)
        assertTrue("$peak jobs held memory at once", peak * perJob <= 3 * perJob)
        assertTrue("jobs still ran side by side within the bound", peak >= 1)
    }

    @Test
    fun `a URI is accepted again once its job has ended`() = runBlocking<Unit> {
        val gate = MediaJobGate(memoryBound = 1, perJobBytes = 1)
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val uri = "content://media/external/images/media/7"

        gate.launch(scope, uri) { }!!.join()

        assertTrue("a later notification is not refused", gate.launch(scope, uri) { } != null)
    }
}
