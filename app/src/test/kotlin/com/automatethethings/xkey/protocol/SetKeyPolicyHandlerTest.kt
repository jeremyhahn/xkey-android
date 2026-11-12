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
package com.automatethethings.xkey.protocol

import android.app.KeyguardManager
import android.app.NotificationManager
import android.content.Context
import android.os.Looper
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.auth.BiometricActivityLauncher
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.UserCancelledException
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.runs
import io.mockk.unmockkAll
import io.mockk.verify
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Pins the approval rule for `local.setKeyPolicy` (#178).
 *
 * Widening a key to every peer needs a confirmed peer and the owner's
 * approval on the phone; a refused or impossible prompt leaves the stored
 * policy alone. Narrowing, and a key already open to every peer, need
 * neither. Every stored change is audited. Requests go through the real
 * [RequestHandler.handleRequest], so the wire error codes are the ones a peer
 * sees. The Android edges are mocked as in [UserVerificationWireErrorTest].
 */
@OptIn(ExperimentalCoroutinesApi::class)
class SetKeyPolicyHandlerTest {

    private lateinit var keyDao: KeyDao
    private lateinit var context: Context
    private lateinit var launcher: BiometricActivityLauncher

    private val keyId = "key-178"
    private val peer = "ab".repeat(32)

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

        keyDao = mockk(relaxed = true)
        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.keyDao() } returns keyDao
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database

        mockkObject(AuditLogger)
        every { AuditLogger.logKeySharingChanged(any(), any(), any(), any(), any()) } just runs

        Dispatchers.setMain(UnconfinedTestDispatcher())

        context = mockk(relaxed = true)
        val keyguard = mockk<KeyguardManager>(relaxed = true)
        every { keyguard.isKeyguardLocked } returns false
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns keyguard
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)

        launcher = mockk(relaxed = true)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        unmockkAll()
    }

    private fun handler(
        withLauncher: Boolean = true,
        confirmedPeer: String? = peer
    ): RequestHandler = RequestHandler(
        context = context,
        keystoreManager = mockk<KeystoreManager>(relaxed = true),
        biometricLauncher = if (withLauncher) launcher else null,
        sessionAuthManager = null
    ).also { it.setConnectedDevicePublicKeyHex(confirmedPeer) }

    private fun key(policy: SharingPolicyType, label: String = "Work key") = KeyEntity(
        keyId = keyId,
        keyType = "aes",
        algorithm = "AES-256-GCM",
        label = label,
        keySizeBits = 256,
        shareable = policy != SharingPolicyType.PRIVATE,
        sharingPolicy = policy,
        source = "local"
    )

    private fun request(shareable: Boolean?) = Request(
        id = 178L,
        method = MethodNames.LOCAL_SET_KEY_POLICY,
        params = JSONObject().put("keyId", keyId).also {
            if (shareable != null) it.put("shareable", shareable)
        }
    )

    private fun assertUpdated(response: Response) {
        assertNull(response.error)
        assertEquals(true, response.result?.getBoolean("updated"))
    }

    private fun assertPolicyUntouched() {
        coVerify(exactly = 0) { keyDao.updateSharingPolicy(any(), any()) }
        verify(exactly = 0) { AuditLogger.logKeySharingChanged(any(), any(), any(), any(), any()) }
    }

    @Test
    fun `widening approved on the phone stores ALL_PEERS and audits it`() = runTest {
        coEvery { keyDao.getByKeyId(keyId) } returns key(SharingPolicyType.PRIVATE)

        val response = handler().handleRequest(request(shareable = true))

        assertUpdated(response)
        coVerify(exactly = 1) {
            launcher.requestAuthentication(any(), match { it.contains("Work key") }, any(), any())
        }
        coVerify(exactly = 1) { keyDao.updateSharingPolicy(keyId, SharingPolicyType.ALL_PEERS) }
        verify(exactly = 1) {
            AuditLogger.logKeySharingChanged(keyId, "Work key", "aes", "PRIVATE", "ALL_PEERS")
        }
    }

    @Test
    fun `the prompt names a key with no label by its id`() = runTest {
        coEvery { keyDao.getByKeyId(keyId) } returns key(SharingPolicyType.PRIVATE, label = "")

        assertUpdated(handler().handleRequest(request(shareable = true)))

        coVerify(exactly = 1) {
            launcher.requestAuthentication(any(), match { it.contains(keyId) }, any(), any())
        }
    }

    @Test
    fun `widening the owner cancels answers BIOMETRIC_FAILED and stores nothing`() = runTest {
        coEvery { keyDao.getByKeyId(keyId) } returns key(SharingPolicyType.PRIVATE)
        coEvery { launcher.requestAuthentication(any(), any(), any(), any()) } throws UserCancelledException()

        val response = handler().handleRequest(request(shareable = true))

        assertNull(response.result)
        assertEquals(ErrorCodes.BIOMETRIC_FAILED, response.error?.code)
        assertPolicyUntouched()
    }

    @Test
    fun `widening with no biometric launcher answers BIOMETRIC_FAILED and stores nothing`() = runTest {
        coEvery { keyDao.getByKeyId(keyId) } returns key(SharingPolicyType.PRIVATE)

        val response = handler(withLauncher = false).handleRequest(request(shareable = true))

        assertNull(response.result)
        assertEquals(ErrorCodes.BIOMETRIC_FAILED, response.error?.code)
        assertPolicyUntouched()
    }

    @Test
    fun `widening with no confirmed peer answers OPERATION_DENIED without a prompt`() = runTest {
        coEvery { keyDao.getByKeyId(keyId) } returns key(SharingPolicyType.PRIVATE)

        val response = handler(confirmedPeer = null).handleRequest(request(shareable = true))

        assertNull(response.result)
        assertEquals(ErrorCodes.OPERATION_DENIED, response.error?.code)
        coVerify(exactly = 0) { launcher.requestAuthentication(any(), any(), any(), any()) }
        assertPolicyUntouched()
    }

    @Test
    fun `narrowing stores PRIVATE with no prompt and audits it`() = runTest {
        coEvery { keyDao.getByKeyId(keyId) } returns key(SharingPolicyType.ALL_PEERS)

        val response = handler().handleRequest(request(shareable = false))

        assertUpdated(response)
        coVerify(exactly = 0) { launcher.requestAuthentication(any(), any(), any(), any()) }
        coVerify(exactly = 1) { keyDao.updateSharingPolicy(keyId, SharingPolicyType.PRIVATE) }
        verify(exactly = 1) {
            AuditLogger.logKeySharingChanged(keyId, "Work key", "aes", "ALL_PEERS", "PRIVATE")
        }
    }

    @Test
    fun `a key already open to every peer needs no prompt`() = runTest {
        coEvery { keyDao.getByKeyId(keyId) } returns key(SharingPolicyType.ALL_PEERS)

        val response = handler(withLauncher = false).handleRequest(request(shareable = true))

        assertUpdated(response)
        coVerify(exactly = 0) { launcher.requestAuthentication(any(), any(), any(), any()) }
    }

    @Test
    fun `an absent shareable changes nothing and needs no prompt`() = runTest {
        coEvery { keyDao.getByKeyId(keyId) } returns key(SharingPolicyType.PRIVATE)

        val response = handler(withLauncher = false).handleRequest(request(shareable = null))

        assertUpdated(response)
        assertPolicyUntouched()
    }

    @Test
    fun `an unknown key answers KEY_NOT_FOUND`() = runTest {
        coEvery { keyDao.getByKeyId(keyId) } returns null

        val response = handler().handleRequest(request(shareable = true))

        assertEquals(ErrorCodes.KEY_NOT_FOUND, response.error?.code)
        assertTrue(response.error?.message.orEmpty().contains(keyId))
        assertPolicyUntouched()
    }
}
