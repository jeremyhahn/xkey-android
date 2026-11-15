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
package com.automatethethings.xkey.remote

import com.automatethethings.xkey.protocol.SharePermission
import io.mockk.mockk
import io.mockk.unmockkAll
import java.io.File
import java.io.IOException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/**
 * A sharing baseline lives only as long as the share that took it: however
 * the load or the send ends, the ledger keeps nothing for the key afterwards,
 * and no code takes a baseline outside [SharePermissionLedger.withBaseline].
 */
class ShareBaselineScopeTest {

    private val share = DesktopKeyShare(mockk(relaxed = true))
    private val permission = mockk<SharePermission>(relaxed = true)

    @Before
    fun setUp() = stubAndroidLog()

    @After
    fun tearDown() = unmockkAll()

    @Test
    fun `a share whose load fails leaves the ledger holding nothing for the key`() = runBlocking {
        val before = SharePermissionLedger.retainedKeyCount()
        var held = -1
        try {
            share.sendLoaded("load-fails", load = {
                held = SharePermissionLedger.retainedKeyCount()
                throw IOException("the key could not be read")
            }, permission = permission, currentEntity = { null })
            fail("the load failure reaches the caller")
        } catch (e: IOException) {
            // The load failed.
        }
        assertEquals("the baseline was held while loading", before + 1, held)
        assertEquals("the ledger holds nothing for the key", before, SharePermissionLedger.retainedKeyCount())
    }

    @Test
    fun `a share cancelled while loading leaves the ledger holding nothing for the key`() = runBlocking {
        val before = SharePermissionLedger.retainedKeyCount()
        val loading = CompletableDeferred<Int>()
        val pending = async(start = CoroutineStart.UNDISPATCHED) {
            share.sendLoaded("load-cancelled", load = {
                loading.complete(SharePermissionLedger.retainedKeyCount())
                awaitCancellation()
            }, permission = permission, currentEntity = { null })
        }
        assertEquals("the baseline is held while loading", before + 1, loading.await())
        pending.cancel()
        pending.join()
        assertTrue(pending.isCancelled)
        assertEquals("the ledger holds nothing for the key", before, SharePermissionLedger.retainedKeyCount())
    }

    @Test
    fun `a baseline closed twice releases the key once`() = runBlocking {
        val other = SharePermissionLedger.baselineForTest("closed-twice")
        val before = SharePermissionLedger.retainedKeyCount()
        SharePermissionLedger.withBaseline("closed-twice") { it.close() }
        assertEquals("the other holder keeps the key", before, SharePermissionLedger.retainedKeyCount())
        other.close()
        assertEquals(before - 1, SharePermissionLedger.retainedKeyCount())
    }

    /**
     * Production code takes a baseline only through withBaseline: the one
     * Baseline construction is the ledger's own acquire, and nothing outside
     * the tests calls the test seam.
     */
    @Test
    fun `no baseline is taken outside withBaseline`() {
        val root = listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory }
        val sources = root.walkTopDown().filter { it.extension == "kt" }.associate { it.name to it.readText() }
        val constructions = sources.flatMap { (name, text) ->
            CONSTRUCTION.findAll(text).map { name }.toList()
        }
        assertEquals("one Baseline construction, in the ledger", listOf("RemoteShareClient.kt"), constructions)
        val ledger = sources.getValue("RemoteShareClient.kt")
        assertEquals("acquire is called only by withBaseline and the test seam", 2, ACQUIRE_CALL.findAll(ledger).count())
        val seamCallers = sources.filter { (_, text) -> SEAM_CALL in text }.keys
        assertEquals("no production code calls baselineForTest", emptySet<String>(), seamCallers)
    }

    private operator fun Regex.contains(text: String) = containsMatchIn(text)

    private companion object {
        /** A Baseline built, not declared. */
        val CONSTRUCTION = Regex("""(?<!class )\bBaseline\(""")

        /** A call of the ledger's private acquire, not its declaration. */
        val ACQUIRE_CALL = Regex("""(?<!fun )\bacquire\(keyId\)""")

        /** A call of the test seam, not its declaration. */
        val SEAM_CALL = Regex("""(?<!fun )\bbaselineForTest\(""")
    }
}
