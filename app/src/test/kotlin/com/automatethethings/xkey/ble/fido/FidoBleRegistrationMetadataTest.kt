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

package com.automatethethings.xkey.ble.fido

import android.app.KeyguardManager
import android.app.NotificationManager
import android.content.Context
import android.os.Looper
import android.util.Log
import com.automatethethings.xkey.credential.PasskeySignCounter
import com.automatethethings.xkey.crypto.KeySecurityLevel
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.protocol.MethodNames
import com.automatethethings.xkey.protocol.Request
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.protocol.SharePermission
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.CredentialMetadataDao
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import com.automatethethings.xkey.testing.ReleaseMocks
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.slot
import io.mockk.unmockkAll
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test

/**
 * A passkey a BLE client registers is shared with all peers, and the key
 * metadata a paired desktop reads (local.listKeys, local.getKeyInfo) says so:
 * the legacy shareable flag agrees with the sharing policy, as [KeyEntity]
 * documents (PRIVATE means false, ALL_PEERS or SELECTED_PEERS means true).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class FidoBleRegistrationMetadataTest {

    /** Drops what MockK recorded here, so it does not outlive the test. */
    @get:Rule
    val releaseMocks = ReleaseMocks()

    private val keyDao = mockk<KeyDao>(relaxed = true)
    private val credentialDao = mockk<CredentialMetadataDao>(relaxed = true)
    private val keystore = mockk<KeystoreManager>(relaxed = true)
    private val stored = slot<KeyEntity>()
    private lateinit var handler: RequestHandler

    private val pendingKeyDeletions = FilePendingKeyDeletions(
        java.io.File.createTempFile("pending-key-deletions", "").also { it.delete(); it.deleteOnExit() }
    )

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.v(any(), any<String>()) } returns 0
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0
        mockkStatic(Looper::class)
        every { Looper.getMainLooper() } returns mockk(relaxed = true)

        coEvery { keystore.generateKeyWithAuthDuration(any(), any(), any()) } returns byteArrayOf(0xA5.toByte())
        coEvery { keyDao.completePasskeyRegistration(capture(stored), any(), any()) } returns emptyList()
        coEvery { keyDao.getAll() } answers { listOf(stored.captured) }
        coEvery { keyDao.getByKeyId(any()) } answers {
            stored.captured.takeIf { it.keyId == firstArg<String>() }
        }

        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.keyDao() } returns keyDao
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database
        Dispatchers.setMain(UnconfinedTestDispatcher())

        val context = mockk<Context>(relaxed = true)
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)
        handler = RequestHandler(
            context = context,
            keystoreManager = keystore,
            biometricLauncher = null,
            sessionAuthManager = null
        )
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        unmockkAll()
    }

    private suspend fun registerOverBle(): String {
        val backend = AndroidFidoCredentialBackend(
            keyDao = keyDao,
            credentialDao = credentialDao,
            sharePermission = mockk<SharePermission>(relaxed = true),
            signCounter = mockk<PasskeySignCounter>(relaxed = true),
            keystoreManager = keystore,
            userPrompt = null,
            settings = { BiometricSettingsData() },
            pendingKeyDeletions = pendingKeyDeletions
        )
        backend.create(
            CredentialRequest("example.com", "Example", byteArrayOf(7), "alice", "Alice", discoverable = true)
        )
        return stored.captured.keyId
    }

    private suspend fun call(method: String, params: JSONObject?): JSONObject {
        val response = handler.handleRequest(Request(id = 7L, method = method, params = params))
        assertNull(method, response.error)
        return response.result as JSONObject
    }

    @Test
    fun `local listKeys reports a BLE-registered passkey as shareable with all peers`() = runTest {
        val keyId = registerOverBle()

        assertEquals(SharingPolicyType.ALL_PEERS, stored.captured.sharingPolicy)
        val keys = call(MethodNames.LOCAL_LIST_KEYS, JSONObject()).getJSONArray("keys")
        assertEquals(1, keys.length())
        val listed = keys.getJSONObject(0)
        assertEquals(keyId, listed.getString("keyId"))
        assertTrue("listKeys shareable", listed.getBoolean("shareable"))
    }

    @Test
    fun `local getKeyInfo reports a BLE-registered passkey as shareable with all peers`() = runTest {
        val keyId = registerOverBle()

        val info = call(MethodNames.LOCAL_GET_KEY_INFO, JSONObject().put("keyId", keyId))
        assertEquals(keyId, info.getString("keyId"))
        assertEquals("example.com", info.getString("rpId"))
        assertTrue("getKeyInfo shareable", info.getBoolean("shareable"))
    }

    @Test
    fun `a BLE-registered passkey records the security level its key was generated at`() = runTest {
        // StrongBox is preferred; a phone without it generates in the TEE.
        // The row says where the key really is, read from its KeyInfo.
        every { keystore.credentialSecurityLevel(any()) } returns KeySecurityLevel.STRONGBOX
        registerOverBle()
        assertTrue("a StrongBox key is recorded as StrongBox-backed", stored.captured.strongBoxBacked)

        every { keystore.credentialSecurityLevel(any()) } returns KeySecurityLevel.TEE
        registerOverBle()
        assertFalse("a TEE key is not recorded as StrongBox-backed", stored.captured.strongBoxBacked)
    }
}
