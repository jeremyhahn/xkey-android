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

package com.automatethethings.xkey.protocol

import android.app.KeyguardManager
import android.app.NotificationManager
import android.content.Context
import android.os.Looper
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.oath.OathCredentialDao
import com.automatethethings.xkey.pin.LockoutStatus
import com.automatethethings.xkey.pin.PinLockedException
import com.automatethethings.xkey.pin.PinManager
import com.automatethethings.xkey.storage.XKeyDatabase
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
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
import org.junit.Assert.assertFalse
import org.junit.Before
import org.junit.Test

/**
 * The local.* PIN and OATH handlers return the error code or result the
 * request deserves (#133): a locked SO PIN is PIN_LOCKED, a new PIN of the
 * wrong length is INVALID_PARAMS, and removing an unknown OATH id does not
 * claim a deletion. Only the handler's Android edges and the [PinManager]
 * are mocked, as in [GenerationEchoTest].
 */
@OptIn(ExperimentalCoroutinesApi::class)
class PinOathHandlerErrorsTest {

    private lateinit var pinManager: PinManager
    private lateinit var oathDao: OathCredentialDao
    private lateinit var handler: RequestHandler

    private val locked = PinLockedException(
        LockoutStatus(failedAttempts = 5, maxAttempts = 5, isLocked = true, lockoutUntil = 1L, recoverySeconds = 60)
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

        mockkObject(AuditLogger)
        every { AuditLogger.logOathCredentialDeleted(any(), any(), any()) } returns Unit

        oathDao = mockk(relaxed = true)
        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.oathCredentialDao() } returns oathDao
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database

        Dispatchers.setMain(UnconfinedTestDispatcher())

        val context = mockk<Context>(relaxed = true)
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns
            mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)

        pinManager = mockk(relaxed = true)
        handler = RequestHandler(
            context = context,
            keystoreManager = mockk<KeystoreManager>(relaxed = true),
            biometricLauncher = null,
            sessionAuthManager = null,
            pairedDeviceRepository = null,
            pinManager = pinManager
        )
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        unmockkAll()
    }

    // -----------------------------------------------------------------
    // A locked SO PIN is PIN_LOCKED
    // -----------------------------------------------------------------

    @Test
    fun `pinSet of the SO PIN while it is locked returns PIN_LOCKED`() = runTest {
        coEvery { pinManager.setSOPIN(any(), any()) } throws locked

        val response = call(MethodNames.LOCAL_PIN_SET, """{"pinType":"SO_PIN","currentPin":"123456","newPin":"654321"}""")

        assertEquals(ErrorCodes.PIN_LOCKED, errorCode(response))
    }

    @Test
    fun `pinSet of the User PIN while the SO PIN is locked returns PIN_LOCKED`() = runTest {
        coEvery { pinManager.setUserPIN(any(), any()) } throws locked

        val response = call(MethodNames.LOCAL_PIN_SET, """{"pinType":"USER_PIN","soPin":"123456","newPin":"654321"}""")

        assertEquals(ErrorCodes.PIN_LOCKED, errorCode(response))
    }

    @Test
    fun `pinResetLockout while the SO PIN is locked returns PIN_LOCKED`() = runTest {
        coEvery { pinManager.resetLockout(any()) } throws locked

        val response = call(MethodNames.LOCAL_PIN_RESET_LOCKOUT, """{"soPin":"123456"}""")

        assertEquals(ErrorCodes.PIN_LOCKED, errorCode(response))
    }

    // -----------------------------------------------------------------
    // A new PIN outside 6 to 63 characters is INVALID_PARAMS
    // -----------------------------------------------------------------

    @Test
    fun `pinSet with a new PIN shorter than 6 returns INVALID_PARAMS`() = runTest {
        val response = call(MethodNames.LOCAL_PIN_SET, """{"pinType":"SO_PIN","newPin":"12345"}""")

        assertEquals(ErrorCodes.INVALID_PARAMS, errorCode(response))
        assertPinManagerNotCalled()
    }

    @Test
    fun `pinSet with a new PIN longer than 63 returns INVALID_PARAMS`() = runTest {
        val response = call(
            MethodNames.LOCAL_PIN_SET,
            """{"pinType":"USER_PIN","soPin":"123456","newPin":"${"7".repeat(64)}"}"""
        )

        assertEquals(ErrorCodes.INVALID_PARAMS, errorCode(response))
        assertPinManagerNotCalled()
    }

    @Test
    fun `pinChange with a new PIN of the wrong length returns INVALID_PARAMS`() = runTest {
        val response = call(MethodNames.LOCAL_PIN_CHANGE, """{"pinType":"USER_PIN","currentPin":"654321","newPin":"123"}""")

        assertEquals(ErrorCodes.INVALID_PARAMS, errorCode(response))
        assertPinManagerNotCalled()
    }

    @Test
    fun `pinSet with a 6 and a 63 character new PIN succeeds`() = runTest {
        for (pin in listOf("123456", "8".repeat(63))) {
            val response = call(MethodNames.LOCAL_PIN_SET, """{"pinType":"SO_PIN","newPin":"$pin"}""")

            assertFalse(response.has("error"))
            coVerify { pinManager.setSOPIN(null, pin) }
        }
    }

    // -----------------------------------------------------------------
    // oathRemove of an unknown id deletes nothing
    // -----------------------------------------------------------------

    @Test
    fun `oathRemove of an unknown id does not report deleted true`() = runTest {
        coEvery { oathDao.getByOathId("nope") } returns null

        val response = call(MethodNames.LOCAL_OATH_REMOVE, """{"credential_id":"nope"}""")

        assertFalse(response.has("error"))
        assertFalse(response.getJSONObject("result").getBoolean("deleted"))
        coVerify(exactly = 0) { oathDao.deleteByOathId(any()) }
        verify(exactly = 0) { AuditLogger.logOathCredentialDeleted(any(), any(), any()) }
    }

    @Test
    fun `oathRemove of a known id reports deleted true`() = runTest {
        coEvery { oathDao.getByOathId("known") } returns mockk(relaxed = true)

        val response = call(MethodNames.LOCAL_OATH_REMOVE, """{"credential_id":"known"}""")

        assertEquals(true, response.getJSONObject("result").getBoolean("deleted"))
        coVerify { oathDao.deleteByOathId("known") }
    }

    private suspend fun call(method: String, params: String): JSONObject {
        val request = """{"id":1,"method":"$method","params":$params}"""
        return JSONObject(String(handler.handleRawRequest(request.toByteArray(Charsets.UTF_8)), Charsets.UTF_8))
    }

    /**
     * The length check comes before any [PinManager] call, so a bad new PIN
     * never verifies the current or SO PIN or moves an attempt counter.
     */
    private fun assertPinManagerNotCalled() {
        coVerify(exactly = 0) { pinManager.setSOPIN(any(), any()) }
        coVerify(exactly = 0) { pinManager.changeSOPIN(any(), any()) }
        coVerify(exactly = 0) { pinManager.verifySOPIN(any()) }
        coVerify(exactly = 0) { pinManager.setUserPIN(any(), any()) }
        coVerify(exactly = 0) { pinManager.changeUserPIN(any(), any()) }
        coVerify(exactly = 0) { pinManager.verifyUserPIN(any()) }
    }

    private fun errorCode(response: JSONObject): Int = response.getJSONObject("error").getInt("code")
}
