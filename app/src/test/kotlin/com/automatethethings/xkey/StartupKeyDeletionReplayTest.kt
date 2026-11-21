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
package com.automatethethings.xkey

import android.util.Log
import com.automatethethings.xkey.storage.FakeKeyPolicyTables
import com.automatethethings.xkey.storage.KeyPolicyStore
import com.automatethethings.xkey.storage.materialDelete
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Codex round 3 (#270): the start-up replay of owed key deletes opens the
 * database and the Keystore on its own coroutine. An open that throws there
 * must not crash the process, and the owed deletes stay recorded, so the
 * next start replays them.
 */
class StartupKeyDeletionReplayTest {

    private val tables = FakeKeyPolicyTables()

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.e(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.d(any(), any<String>()) } returns 0
    }

    @After
    fun tearDown() = unmockkAll()

    @Test
    fun aStartupReplayWhoseInitializationThrowsKeepsItsPendingDeletes() = runBlocking<Unit> {
        val store = tables.store()
        store.deleteMaterial("k1", materialDelete { false })
        assertTrue(store.isDeletionPending("k1"))

        var replayed = false
        // The open throws: no crash, nothing replayed, nothing dropped.
        val ran = replayOwedKeyDeletionsAtStartup(
            openStore = { throw IllegalStateException("database unavailable") },
            replay = { replayed = true }
        )
        assertFalse(ran)
        assertFalse(replayed)
        assertTrue("an owed delete was dropped", store.isDeletionPending("k1"))

        // The next start opens the store and replays it.
        assertTrue(replayOwedKeyDeletionsAtStartup(openStore = { store }, replay = { s: KeyPolicyStore ->
            s.replayDeletions(materialDelete { true })
        }))
        assertFalse(store.isDeletionPending("k1"))
    }
}
