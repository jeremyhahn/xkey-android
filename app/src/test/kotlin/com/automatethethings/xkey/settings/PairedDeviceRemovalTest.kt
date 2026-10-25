/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */

package com.automatethethings.xkey.settings

import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import io.mockk.every
import io.mockk.just
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.runs
import io.mockk.unmockkAll
import java.util.concurrent.CopyOnWriteArrayList
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/**
 * [PairedDeviceRepository] tells its removal listeners about every key that
 * stops being paired, and [PairedDeviceRepository.requirePaired] refuses a key
 * that is not (#59).
 */
class PairedDeviceRemovalTest {

    private companion object {
        val KEY_A = "a".repeat(64)
        val KEY_B = "b".repeat(64)
    }

    private val removed = CopyOnWriteArrayList<String>()
    private val listener = PairedDeviceRemovalListener { removed.add(it) }
    private lateinit var repo: PairedDeviceRepository

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.e(any(), any<String>(), any()) } returns 0
        mockkObject(AuditLogger)
        every { AuditLogger.logDeviceUnpaired(any(), any()) } just runs
        repo = PairedDeviceRepository(InMemorySharedPreferences())
        PairedDeviceRepository.addRemovalListener(listener)
    }

    @After
    fun tearDown() {
        PairedDeviceRepository.removeRemovalListener(listener)
        unmockkAll()
    }

    @Test
    fun removeDeviceNotifiesTheRemovedKey() {
        repo.addDevice(KEY_A, "desktop-a")
        repo.addDevice(KEY_B, "desktop-b")

        repo.removeDevice(KEY_A)

        assertEquals(listOf(KEY_A), removed)
        assertFalse(repo.isDeviceKnown(KEY_A))
        assertTrue(repo.isDeviceKnown(KEY_B))
    }

    /** The record may already be gone while a session with that peer still runs. */
    @Test
    fun removeDeviceNotifiesEvenWhenNoRecordMatched() {
        repo.removeDevice(KEY_A)

        assertEquals(listOf(KEY_A), removed)
    }

    @Test
    fun clearNotifiesEveryStoredKey() {
        repo.addDevice(KEY_A, "desktop-a")
        repo.addDevice(KEY_B, "desktop-b")

        repo.clear()

        assertEquals(setOf(KEY_A, KEY_B), removed.toSet())
        assertTrue(repo.getAllDevices().isEmpty())
    }

    /** A re-pairing under a new key evicts the old entry; the old key is no longer paired. */
    @Test
    fun addDeviceNotifiesAnEvictedEntryUnderAnotherKey() {
        repo.addDevice(KEY_A, "desktop")

        repo.addDevice(KEY_B, "desktop")

        assertEquals(listOf(KEY_A), removed)
    }

    @Test
    fun reAddingTheSameKeyNotifiesNothing() {
        repo.addDevice(KEY_A, "desktop")

        repo.addDevice(KEY_A, "desktop")

        assertTrue("re-pairing the same key is not a removal: $removed", removed.isEmpty())
    }

    /** The Activity that unpairs and the service that holds the session build their own repositories. */
    @Test
    fun listenersHearARemovalThroughAnyInstance() {
        val prefs = InMemorySharedPreferences()
        PairedDeviceRepository(prefs).addDevice(KEY_A, "desktop")

        PairedDeviceRepository(prefs).removeDevice(KEY_A)

        assertEquals(listOf(KEY_A), removed)
    }

    @Test
    fun aFailingListenerDoesNotStopTheOthers() {
        val failing = PairedDeviceRemovalListener { throw IllegalStateException("boom") }
        PairedDeviceRepository.addRemovalListener(failing)
        try {
            repo.addDevice(KEY_A, "desktop")
            repo.removeDevice(KEY_A)
        } finally {
            PairedDeviceRepository.removeRemovalListener(failing)
        }

        assertEquals(listOf(KEY_A), removed)
    }

    @Test
    fun requirePairedAcceptsAPairedKey() {
        repo.addDevice(KEY_A, "desktop")

        repo.requirePaired(KEY_A)
    }

    @Test
    fun requirePairedRefusesAnUnknownOrMissingKey() {
        repo.addDevice(KEY_A, "desktop")
        repo.removeDevice(KEY_A)

        for (key in listOf(KEY_A, KEY_B, null)) {
            try {
                repo.requirePaired(key)
                fail("requirePaired($key) must throw")
            } catch (e: PeerNotPairedException) {
                assertEquals(key, e.publicKeyHex)
            }
        }
    }
}
