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
import android.util.Base64
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.oath.OathCredentialDao
import com.automatethethings.xkey.pin.LockoutStatus
import com.automatethethings.xkey.pin.PinHasher
import com.automatethethings.xkey.pin.PinLockedException
import com.automatethethings.xkey.pin.PinManager
import com.automatethethings.xkey.settings.PinSettingsData
import com.automatethethings.xkey.settings.PinSettingsRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.slot
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
import org.junit.Assert.assertTrue
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
    private lateinit var context: Context
    private var pinSettings = PinSettingsData()

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

        this.context = context
        pinManager = mockk(relaxed = true)
        handler = handlerWith(pinManager)
    }

    private fun handlerWith(pins: PinManager) = RequestHandler(
        context = context,
        keystoreManager = mockk<KeystoreManager>(relaxed = true),
        biometricLauncher = null,
        sessionAuthManager = null,
        pairedDeviceRepository = null,
        pinManager = pins
    )

    /**
     * Serves the handler from a real [PinManager] over [settings], so a test
     * sees what the manager throws and what it writes back to [pinSettings].
     * "correct-pin" is the only PIN that verifies.
     */
    private fun useRealPinManager(settings: PinSettingsData) {
        pinSettings = settings
        mockkStatic(Base64::class)
        every { Base64.decode(any<String>(), any()) } answers {
            java.util.Base64.getDecoder().decode(firstArg<String>())
        }
        every { Base64.encodeToString(any(), any()) } answers {
            java.util.Base64.getEncoder().encodeToString(firstArg())
        }
        mockkObject(PinHasher)
        every { PinHasher.verifyPin(any(), any(), any()) } answers { firstArg<String>() == "correct-pin" }
        val repository = mockk<PinSettingsRepository>(relaxed = true)
        coEvery { repository.getSettings() } answers { pinSettings }
        val written = slot<PinSettingsData>()
        coEvery { repository.updateSettings(capture(written)) } answers { pinSettings = written.captured }
        handler = handlerWith(PinManager(repository))
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
    // A PIN that is not set or not supplied is PIN_REQUIRED (#190)
    // -----------------------------------------------------------------

    @Test
    fun `pinVerify of the User PIN before it is set returns PIN_REQUIRED`() = runTest {
        useRealPinManager(PinSettingsData(soPinSet = true, soPinHashBase64 = HASH, soPinSaltBase64 = SALT))

        val response = call(MethodNames.LOCAL_PIN_VERIFY, """{"pin":"123456","pinType":"USER_PIN"}""")

        assertEquals(ErrorCodes.PIN_REQUIRED, errorCode(response))
    }

    @Test
    fun `pinSet of the SO PIN without currentPin while it is set returns PIN_REQUIRED`() = runTest {
        useRealPinManager(PinSettingsData(soPinSet = true, soPinHashBase64 = HASH, soPinSaltBase64 = SALT))

        val response = call(MethodNames.LOCAL_PIN_SET, """{"pinType":"SO_PIN","newPin":"654321"}""")

        assertEquals(ErrorCodes.PIN_REQUIRED, errorCode(response))
        assertEquals(0, pinSettings.failedSoPinAttempts)
    }

    @Test
    fun `pinChange of a PIN that is not set returns PIN_REQUIRED`() = runTest {
        useRealPinManager(PinSettingsData())

        for (pinType in listOf("SO_PIN", "USER_PIN")) {
            val response = call(
                MethodNames.LOCAL_PIN_CHANGE,
                """{"pinType":"$pinType","currentPin":"123456","newPin":"654321"}"""
            )

            assertEquals(pinType, ErrorCodes.PIN_REQUIRED, errorCode(response))
        }
    }

    // -----------------------------------------------------------------
    // pinType on verify: absent is the User PIN, unknown is INVALID_PARAMS
    // -----------------------------------------------------------------

    @Test
    fun `pinVerify with an unknown pinType returns INVALID_PARAMS`() = runTest {
        val response = call(MethodNames.LOCAL_PIN_VERIFY, """{"pin":"123456","pinType":"ADMIN_PIN"}""")

        assertEquals(ErrorCodes.INVALID_PARAMS, errorCode(response))
        assertPinManagerNotCalled()
    }

    @Test
    fun `pinVerify with no pinType verifies the User PIN`() = runTest {
        coEvery { pinManager.verifyUserPIN("123456") } returns true

        val response = call(MethodNames.LOCAL_PIN_VERIFY, """{"pin":"123456"}""")

        assertTrue(response.getJSONObject("result").getBoolean("verified"))
        coVerify(exactly = 0) { pinManager.verifySOPIN(any()) }
    }

    // -----------------------------------------------------------------
    // Every PIN_LOCKED carries lockoutUntil and failedAttempts
    // -----------------------------------------------------------------

    @Test
    fun `pinSet pinChange and pinResetLockout PIN_LOCKED carry lockoutUntil and failedAttempts`() = runTest {
        coEvery { pinManager.setSOPIN(any(), any()) } throws locked
        coEvery { pinManager.changeUserPIN(any(), any()) } throws locked
        coEvery { pinManager.resetLockout(any()) } throws locked

        val responses = listOf(
            call(MethodNames.LOCAL_PIN_SET, """{"pinType":"SO_PIN","currentPin":"123456","newPin":"654321"}"""),
            call(MethodNames.LOCAL_PIN_CHANGE, """{"pinType":"USER_PIN","currentPin":"123456","newPin":"654321"}"""),
            call(MethodNames.LOCAL_PIN_RESET_LOCKOUT, """{"soPin":"123456"}""")
        )

        for (response in responses) {
            val error = response.getJSONObject("error")
            assertEquals(ErrorCodes.PIN_LOCKED, error.getInt("code"))
            val data = error.getJSONObject("data")
            assertEquals(locked.lockoutStatus.lockoutUntil, data.getLong("lockoutUntil"))
            assertEquals(locked.lockoutStatus.failedAttempts, data.getInt("failedAttempts"))
        }
    }

    // -----------------------------------------------------------------
    // A wrong PIN stays PIN_INCORRECT
    // -----------------------------------------------------------------

    @Test
    fun `a wrong PIN still returns PIN_INCORRECT and counts a failed attempt`() = runTest {
        useRealPinManager(
            PinSettingsData(
                soPinSet = true, soPinHashBase64 = HASH, soPinSaltBase64 = SALT,
                userPinSet = true, userPinHashBase64 = HASH, userPinSaltBase64 = SALT
            )
        )

        val response = call(MethodNames.LOCAL_PIN_VERIFY, """{"pin":"wrong-pin","pinType":"USER_PIN"}""")

        assertEquals(ErrorCodes.PIN_INCORRECT, errorCode(response))
        assertEquals(1, pinSettings.failedUserPinAttempts)
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

    private companion object {
        /** Any stored hash and salt: [PinHasher.verifyPin] is mocked. */
        const val HASH = "AAAA"
        const val SALT = "AAAA"
    }
}
