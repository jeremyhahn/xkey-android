/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
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
package com.automatethethings.xkey.settings

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for [SyncStateRepository], the timestamp behind
 * `local.syncStatus` / `remote.syncStatus`.
 *
 * The repository has no clear method, so the suite empties its DataStore
 * directly and restores whatever the device had once it is done.
 */
@RunWith(AndroidJUnit4::class)
class SyncStateRepositoryTest {

    private lateinit var repository: SyncStateRepository
    private var snapshot: Long = 0L

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        repository = SyncStateRepository(context)
        runBlocking {
            snapshot = repository.getLastSyncMillis()
            PreferenceStoreProbe.clear(repository)
        }
    }

    @After
    fun tearDown() {
        runBlocking {
            PreferenceStoreProbe.clear(repository)
            if (snapshot != 0L) {
                repository.setLastSyncMillis(snapshot)
            }
        }
    }

    @Test
    fun neverSynced_readsAsZero() = runBlocking {
        assertEquals(0L, repository.getLastSyncMillis())
    }

    @Test
    fun setLastSyncMillis_defaultsToNow() = runBlocking {
        val before = System.currentTimeMillis()

        repository.setLastSyncMillis()

        val recorded = repository.getLastSyncMillis()
        assertTrue(
            "expected a timestamp at or after $before, got $recorded",
            recorded >= before
        )
        assertTrue(
            "expected a timestamp at or before now, got $recorded",
            recorded <= System.currentTimeMillis()
        )
    }

    @Test
    fun aSecondInstanceSeesTheSamePersistedValue() = runBlocking {
        repository.setLastSyncMillis(1_700_000_123_000L)

        val other = SyncStateRepository(ApplicationProvider.getApplicationContext<Context>())

        assertEquals(1_700_000_123_000L, other.getLastSyncMillis())
    }
}
