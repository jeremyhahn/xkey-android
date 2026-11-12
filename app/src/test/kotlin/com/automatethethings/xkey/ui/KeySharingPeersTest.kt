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

package com.automatethethings.xkey.ui

import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.settings.InMemorySharedPreferences
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.storage.dao.KeySharingPolicyDao
import com.automatethethings.xkey.storage.entity.KeySharingPolicy
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.runs
import io.mockk.unmockkAll
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The key-sharing sheet's peer list while a re-paired peer's grant
 * revocation is still pending (#174): the peer is shown unselected and not
 * selectable, a grant for it is refused, and once the revocation completes
 * the list updates on its own and the peer can be granted again.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class KeySharingPeersTest {

    private companion object {
        const val KEY = "k-1"
        val PEER_A = "a".repeat(64)
        val PEER_B = "b".repeat(64)
    }

    /** The `key_sharing_policies` table; the DAO's Flow query re-emits on every change. */
    private val table = MutableStateFlow<List<KeySharingPolicy>>(emptyList())
    private lateinit var dao: KeySharingPolicyDao
    private lateinit var repo: PairedDeviceRepository

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.e(any(), any<String>(), any()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        mockkObject(AuditLogger)
        every { AuditLogger.logDeviceUnpaired(any(), any()) } just runs

        dao = mockk()
        every { dao.getPoliciesForKey(any()) } answers {
            val keyId = firstArg<String>()
            table.map { rows -> rows.filter { it.keyId == keyId } }
        }
        coEvery { dao.setPolicy(any()) } answers {
            val row = firstArg<KeySharingPolicy>()
            table.value = table.value.filterNot {
                it.keyId == row.keyId && it.peerPublicKeyHex == row.peerPublicKeyHex
            } + row
        }
        coEvery { dao.removePolicy(any(), any()) } answers {
            val before = table.value
            table.value = before.filterNot { it.keyId == firstArg<String>() && it.peerPublicKeyHex == secondArg<String>() }
            before.size - table.value.size
        }
        coEvery { dao.clearPoliciesForPeer(any()) } answers {
            val before = table.value
            table.value = before.filterNot { it.peerPublicKeyHex == firstArg<String>() }
            before.size - table.value.size
        }

        repo = PairedDeviceRepository(InMemorySharedPreferences())
        repo.addDevice(PEER_A, "desktop-a")
        repo.addDevice(PEER_B, "desktop-b")
        table.value = listOf(KeySharingPolicy(KEY, PEER_A), KeySharingPolicy(KEY, PEER_B))
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    private fun List<KeySharingPeers.Peer>.of(peer: String) = single { it.device.publicKeyHex == peer }

    @Test
    fun aRePairedPeerIsPendingAndUngrantableUntilItsRevocationCompletes() = runTest {
        // A is unpaired and re-paired; no cleanup has run, so its old row stays.
        repo.removeDevice(PEER_A)
        repo.addDevice(PEER_A, "desktop-a")
        assertTrue(repo.isRevocationPending(PEER_A))

        val peers = KeySharingPeers(KEY, dao, repo)
        val seen = mutableListOf<List<KeySharingPeers.Peer>>()
        backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) { peers.peers().toList(seen) }

        val pending = seen.last().of(PEER_A)
        assertFalse("the old row must not show as a grant", pending.allowed)
        assertFalse("a pending peer must not be selectable", pending.selectable)
        assertTrue(seen.last().of(PEER_B).allowed)
        assertTrue(seen.last().of(PEER_B).selectable)

        // The user taps it anyway: nothing is written.
        assertFalse(peers.setAllowed(PEER_A, true))
        coVerify(exactly = 0) { dao.setPolicy(any()) }

        // The cleanup deletes A's rows and then acknowledges the revocation.
        dao.clearPoliciesForPeer(PEER_A)
        assertFalse(seen.last().of(PEER_A).selectable)
        repo.completeRevocation(PEER_A, repo.pendingRevocationGeneration(PEER_A)!!)

        val done = seen.last().of(PEER_A)
        assertFalse(done.allowed)
        assertTrue("the list updates once the revocation completes", done.selectable)

        assertTrue(peers.setAllowed(PEER_A, true))
        assertTrue(seen.last().of(PEER_A).allowed)
        assertEquals(listOf(PEER_B, PEER_A), table.value.map { it.peerPublicKeyHex })
    }
}
