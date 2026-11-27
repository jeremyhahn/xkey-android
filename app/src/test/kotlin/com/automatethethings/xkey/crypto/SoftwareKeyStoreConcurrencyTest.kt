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
package com.automatethethings.xkey.crypto

import android.content.Context
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * #255: a record change is two file steps, and the cross-id metadata scan
 * runs from any store instance over the same directory. A scan (or a read
 * of one record) that lands between the two steps of another instance's
 * write must never see the half-written record: it waits for the write.
 * Each case pauses one instance between its two file steps and reads
 * through a second instance; every wait is bounded, so a deadlock fails the
 * test rather than hanging the build.
 */
class SoftwareKeyStoreConcurrencyTest {

    @get:Rule
    val tmp = TemporaryFolder()

    /** Pauses the first matching file step: signals [entered], then waits on [release]. */
    private class Pause {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        @Volatile var armed = true

        fun at(file: File, suffix: String) {
            if (armed && file.name.endsWith(suffix)) {
                armed = false
                entered.countDown()
                release.await(WAIT_S, TimeUnit.SECONDS)
            }
        }
    }

    private fun context(filesDir: File): Context = mockk<Context>().also { every { it.filesDir } returns filesDir }

    private fun cipher(): KeystoreAeadCipher = mockk<KeystoreAeadCipher>().also {
        every { it.encrypt(any()) } answers { firstArg() }
        every { it.decrypt(any()) } answers { firstArg() }
    }

    private fun key(id: String) = SoftwareKey(id, "AES", "symmetric", 256, false, true, ByteArray(32) { id.length.toByte() })

    /**
     * Runs [write] on one thread until [pause] holds it between its file
     * steps, then [read] on another; the read gets [READ_GRACE_MS] to answer
     * while the write is paused before the write is released. Returns what
     * the read answered.
     */
    private fun <T> readDuringWrite(pause: Pause, write: () -> Unit, read: () -> T): T {
        val writeError = AtomicReference<Throwable?>()
        val readResult = AtomicReference<Result<T>?>()
        val writer = Thread { runCatching(write).onFailure { writeError.set(it) } }
        writer.start()
        assertTrue("the write reached its pause", pause.entered.await(WAIT_S, TimeUnit.SECONDS))
        val reader = Thread { readResult.set(runCatching(read)) }
        reader.start()
        reader.join(READ_GRACE_MS)
        pause.release.countDown()
        writer.join(WAIT_S * 1000)
        reader.join(WAIT_S * 1000)
        assertFalse("the write finished", writer.isAlive)
        assertFalse("the read finished", reader.isAlive)
        writeError.get()?.let { throw it }
        return readResult.get()!!.getOrThrow()
    }

    @Test
    fun aScanDuringAnotherInstancesPutWaitsForBothFiles() {
        val filesDir = tmp.newFolder("files")
        val pause = Pause()
        val writer = SoftwareKeyStore(
            context(filesDir),
            cipher(),
            writeFile = { file, bytes ->
                file.writeBytes(bytes)
                pause.at(file, ".key")
            }
        )
        val reader = SoftwareKeyStore(context(filesDir), cipher())
        reader.put(key("b"))
        // "hw" is no software key (a hardware key's id): its presence reads
        // the scan, which material with no metadata beside it would make
        // unreadable for every id.
        val seen = readDuringWrite(pause, { writer.put(key("a")) }) {
            listOf(reader.presence("hw"), reader.presence("b"))
        }
        assertEquals(listOf(KeyPresence.ABSENT, KeyPresence.PRESENT), seen)
        assertFalse(reader.contains("hw"))
        assertArrayEquals(key("a").material, reader.get("a")!!.material)
    }

    @Test
    fun aReadDuringAnotherInstancesDeleteSeesTheRecordWholeOrGone() {
        val filesDir = tmp.newFolder("files")
        val pause = Pause()
        pause.armed = false
        val deleter = SoftwareKeyStore(
            context(filesDir),
            cipher(),
            unlink = { file ->
                file.delete().also { pause.at(file, ".key") }
            }
        )
        val reader = SoftwareKeyStore(context(filesDir), cipher())
        deleter.put(key("a"))
        val before = reader.generation("a")
        pause.armed = true
        // Between the delete's two unlinks the record is metadata only: a
        // read then would take it for a delete that stopped short.
        val seen = readDuringWrite(pause, { deleter.delete("a") }) { reader.generation("a") }
        assertTrue("generation was $seen", seen == null || seen == before)
        assertFalse(seen.orEmpty().startsWith(SoftwareKeyStore.METADATA_ONLY))
        assertNull(reader.generation("a"))
        assertEquals(KeyPresence.ABSENT, reader.presence("a"))
    }

    @Test
    fun aScanDuringAnotherInstancesMigrationWaitsForBothRenames() {
        val filesDir = tmp.newFolder("files")
        val dir = File(filesDir, "software_keys").apply { mkdirs() }
        val reader = SoftwareKeyStore(context(filesDir), cipher())
        // The reader migrates its (empty) directory before the older
        // build's record is there, so only the migrating instance moves it.
        assertEquals(KeyPresence.ABSENT, reader.presence("hw"))
        File(dir, "k.meta").writeText("""{"keyId":"k"}""")
        File(dir, "k.key").writeBytes(ByteArray(4))
        val pause = Pause()
        val migrator = SoftwareKeyStore(
            context(filesDir),
            cipher(),
            rename = { from, to ->
                from.renameTo(to).also { pause.at(to, ".key") }
            }
        )
        val seen = readDuringWrite(pause, { migrator.presence("k") }) {
            listOf(reader.presence("hw"), reader.presence("k"))
        }
        assertEquals(listOf(KeyPresence.ABSENT, KeyPresence.PRESENT), seen)
        assertEquals(KeyPresence.PRESENT, reader.presence("k"))
        assertFalse(File(dir, "k.key").exists())
    }

    private companion object {
        const val WAIT_S = 5L
        const val READ_GRACE_MS = 500L
    }
}
