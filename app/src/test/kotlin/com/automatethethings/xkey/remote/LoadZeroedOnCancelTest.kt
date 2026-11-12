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

import kotlinx.coroutines.Job
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.Executors

/**
 * The sharing sheet decrypts a software key's material on the IO dispatcher.
 * A cancellation that lands while that load hands its result back drops the
 * result before the caller owns it, so the loader must zero it itself.
 */
class LoadZeroedOnCancelTest {

    private val io = Executors.newSingleThreadExecutor()
    private val ioDispatcher = io.asCoroutineDispatcher()

    @After
    fun tearDown() {
        io.shutdownNow()
    }

    @Test
    fun `cancelling during the share-input load zeroes the decrypted buffer`() = runBlocking {
        val decrypted = ByteArray(32) { 7 }
        var received: ByteArray? = null
        lateinit var caller: Job
        caller = launch {
            received = loadZeroedOnCancel(ioDispatcher, zero = { it.fill(0) }) {
                // The sheet is dismissed while the key is being decrypted:
                // the load finishes, but its caller is already cancelled.
                caller.cancel()
                decrypted
            }
        }
        caller.join()

        assertNull("the cancelled caller never received the material", received)
        assertTrue("the dropped material must be zero", decrypted.all { it == 0.toByte() })
    }

    @Test
    fun `a load that completes hands the material over untouched`() = runBlocking {
        val decrypted = ByteArray(32) { 7 }
        val out = loadZeroedOnCancel(ioDispatcher, zero = { it.fill(0) }) { decrypted }
        assertSame(decrypted, out)
        assertArrayEquals(ByteArray(32) { 7 }, out)
    }
}
