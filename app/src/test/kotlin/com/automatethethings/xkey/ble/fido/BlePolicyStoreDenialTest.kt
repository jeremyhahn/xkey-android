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

package com.automatethethings.xkey.ble.fido

import android.util.Log
import com.automatethethings.xkey.credential.PasskeySignCounter
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.protocol.SharePermission
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.storage.FakeKeyPolicyTables
import com.automatethethings.xkey.storage.KeyPolicyStore
import com.automatethethings.xkey.storage.dao.CredentialMetadataDao
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.dao.KeySharingPolicyDao
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import com.automatethethings.xkey.testing.ReleaseMocks
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import java.util.concurrent.ConcurrentHashMap

/**
 * #270 review r3: the BLE authenticator decides a share through the
 * [KeyPolicyStore], so an ALL_PEERS passkey whose narrowing to PRIVATE or
 * SELECTED_PEERS failed to land on its key row stays denied to a BLE client,
 * after a restart too (a new store over the same tables).
 */
class BlePolicyStoreDenialTest {

    /** Drops what MockK recorded here, so it does not outlive the test. */
    @get:Rule
    val releaseMocks = ReleaseMocks()

    private val tables = FakeKeyPolicyTables()
    private val keyId = "passkey"
    private val keystore = mockk<KeystoreManager>(relaxed = true)
    private val keyDao = mockk<KeyDao>(relaxed = true)

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { keystore.publicKeyDERAt(any()) } returns byteArrayOf(1)
        coEvery { keyDao.getByKeyId(any()) } answers { tables.key(firstArg()) }
        coEvery { keyDao.getFido2ByRpId(any()) } answers {
            listOfNotNull(tables.key(keyId)?.takeIf { it.rpId == firstArg<String>() })
        }
    }

    @After
    fun tearDown() = unmockkAll()

    /** An ALL_PEERS ES256 passkey for example.com, with its policy row. */
    private fun addPasskey(): Long {
        val instance = tables.addKey(keyId, SharingPolicyType.ALL_PEERS, keyType = "fido2")
        tables.keys.value = tables.keys.value + (keyId to tables.key(keyId)!!.copy(
            algorithm = "ES256", rpId = "example.com", isDiscoverable = true
        ))
        return instance
    }

    /** The BLE backend as XKeyGattService builds it, over a store [store]. */
    private fun backend(store: KeyPolicyStore) = AndroidFidoCredentialBackend(
        keyDao = keyDao,
        credentialDao = mockk<CredentialMetadataDao>(relaxed = true),
        sharePermission = SharePermission(mockk<KeySharingPolicyDao>(relaxed = true), null, store),
        signCounter = mockk<PasskeySignCounter>(relaxed = true),
        keystoreManager = keystore,
        userPrompt = null,
        settings = { BiometricSettingsData() },
        pendingKeyDeletions = FilePendingKeyDeletions(
            java.io.File.createTempFile("pending-key-deletions", "").also { it.delete(); it.deleteOnExit() }
        )
    )

    private fun restarted() = KeyPolicyStore(tables, tables, ConcurrentHashMap())

    private fun assertFailedNarrowingStaysDenied(to: SharingPolicyType) = runBlocking {
        val instance = addPasskey()
        assertEquals("an ALL_PEERS passkey is offered", 1, backend(restarted()).credentials("example.com").size)

        tables.failing += "setKeyPolicy"
        try {
            tables.store().setPolicy(keyId, instance, to)
            fail("the narrowing's key row write was to fail")
        } catch (expected: Exception) {
        }
        tables.failing.clear()
        assertEquals("the key row still says All Peers", SharingPolicyType.ALL_PEERS, tables.keyPolicy(keyId))
        assertNotEquals(SharingPolicyType.ALL_PEERS, tables.enforced(keyId))

        assertEquals(
            "a failed narrowing to $to was offered to a BLE client after a restart",
            emptyList<Any>(),
            backend(restarted()).credentials("example.com")
        )
    }

    @Test
    fun `a failed narrowing to private stays denied over BLE after a restart`() =
        assertFailedNarrowingStaysDenied(SharingPolicyType.PRIVATE)

    @Test
    fun `a failed narrowing to selected peers stays denied over BLE after a restart`() =
        assertFailedNarrowingStaysDenied(SharingPolicyType.SELECTED_PEERS)
}
