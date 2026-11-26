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
import com.automatethethings.xkey.auth.SessionAuthManager
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.ResolvedKey
import com.automatethethings.xkey.crypto.UserKeyKind
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyPolicyDao
import com.automatethethings.xkey.storage.entity.KeyDeletionEntity
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verify
import java.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withContext
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The deleted-key check before a handler runs reaches the key the handler
 * reads (#255).
 *
 * A passkey made through local.generateKey is a general key, and loadKey and
 * sign find it by `credentialId` in whichever one namespace holds the id.
 * When a legacy deleteKey removed a credential of the same id beside that
 * general key and the credential's tombstone could not be dropped, the
 * tombstone owes the credential alone: the surviving general key still loads
 * and signs, while a credential with its own tombstone stays refused.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class RetainedCredentialTombstoneTest {

    private lateinit var keystore: KeystoreManager
    private lateinit var handler: RequestHandler

    /** The namespace holding [KEY_ID], as KeystoreManager.soleKind reports it. */
    private var holding = UserKeyKind.GENERAL

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

        // The credential's delete committed beside the surviving key row,
        // and its tombstone stayed: it owes the credential's material only.
        val credentialEntry = KeystoreManager.KEYSTORE_ENTRY + KeystoreManager.credentialAlias(KEY_ID)
        val tombstone = KeyDeletionEntity(
            keyId = KEY_ID,
            keyInstance = SURVIVING_ROW,
            source = null,
            generation = JSONObject().put(credentialEntry, "1").toString()
        )
        val policies = mockk<KeyPolicyDao>(relaxed = true)
        coEvery { policies.deletion(KEY_ID) } returns tombstone
        coEvery { policies.keyInstance(KEY_ID) } returns SURVIVING_ROW
        coEvery { policies.policyRow(any()) } returns null
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns mockk(relaxed = true) {
            every { keyPolicyDao() } returns policies
        }
        Dispatchers.setMain(UnconfinedTestDispatcher())

        val context = mockk<Context>(relaxed = true)
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns
            mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)

        keystore = mockk(relaxed = true)
        every { keystore.soleKind(KEY_ID) } answers { holding }
        every { keystore.resolveKey(any(), any()) } answers {
            val kind = secondArg<UserKeyKind>()
            if (kind == holding) ResolvedKey(KeystoreManager.userKeyAlias(firstArg(), kind), kind) else null
        }
        every { keystore.getCOSEPublicKey(KEY_ID, any()) } answers {
            if (secondArg<UserKeyKind>() == holding) COSE_KEY else null
        }
        coEvery { keystore.signWithoutBiometric(any(), any(), any()) } returns SIGNATURE

        handler = RequestHandler(
            context = context,
            keystoreManager = keystore,
            biometricLauncher = mockk(relaxed = true),
            sessionAuthManager = SessionAuthManager(clock = { 0L }),
        )
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        unmockkAll()
    }

    @Test
    fun `loadKey loads the general key that survived a retained credential tombstone`() = runTest {
        val response = call(MethodNames.LOAD_KEY, JSONObject().put("credentialId", KEY_ID))

        assertNull(response.error)
        val result = response.result!!
        assertTrue(result.getBoolean("exists"))
        assertEquals(Base64.getEncoder().encodeToString(COSE_KEY), result.getString("publicKey"))
    }

    @Test
    fun `sign signs with the general key that survived a retained credential tombstone`() = runTest {
        val response = call(MethodNames.SIGN, signParams())

        assertNull(response.error)
        coVerify(exactly = 1) { keystore.signWithoutBiometric(KEY_ID, UserKeyKind.GENERAL, any()) }
        coVerify(exactly = 0) { keystore.signWithoutBiometric(any(), UserKeyKind.CREDENTIAL, any()) }
    }

    @Test
    fun `a credential with its own tombstone is still refused by loadKey and sign`() = runTest {
        holding = UserKeyKind.CREDENTIAL

        val load = call(MethodNames.LOAD_KEY, JSONObject().put("credentialId", KEY_ID))
        val sign = call(MethodNames.SIGN, signParams())

        assertEquals(ErrorCodes.KEY_NOT_FOUND, load.error?.code)
        assertEquals(ErrorCodes.KEY_NOT_FOUND, sign.error?.code)
        verify(exactly = 0) { keystore.getCOSEPublicKey(any(), any()) }
        coVerify(exactly = 0) { keystore.signWithoutBiometric(any(), any(), any()) }
    }

    private fun signParams(): JSONObject = JSONObject()
        .put("credentialId", KEY_ID)
        .put("dataHash", Base64.getEncoder().encodeToString(ByteArray(32) { 1 }))
        .put("userVerificationRequired", false)

    private suspend fun call(method: String, params: JSONObject): Response {
        val raw = withContext(
            RequestHandler.servedConnection(SessionBindingProvider { null }, null, "usb:one")
        ) {
            handler.handleRawRequest(Request(id = 1, method = method, params = params).toJson())
        }
        return Response.fromJson(raw)
    }

    private companion object {
        const val KEY_ID = "shared-id"
        const val SURVIVING_ROW = 7L
        val COSE_KEY = byteArrayOf(0xA5.toByte(), 1, 2, 3)
        val SIGNATURE = ByteArray(64) { 7 }
    }
}
