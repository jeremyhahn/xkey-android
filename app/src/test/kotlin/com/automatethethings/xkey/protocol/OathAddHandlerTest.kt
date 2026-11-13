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
import com.automatethethings.xkey.oath.OathRepository
import com.automatethethings.xkey.pin.PinManager
import com.automatethethings.xkey.storage.XKeyDatabase
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.slot
import io.mockk.unmockkAll
import java.security.KeyStore
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
 * local.oathAdd hands `OathRepository.importFromUri` an `otpauth://` URI
 * whose issuer and account are percent-encoded the way SyncEngine.mergeOath
 * encodes them, carries `counter` for HOTP only, and answers with the id
 * importFromUri stored the credential under (#152).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class OathAddHandlerTest {

    private lateinit var handler: RequestHandler
    private val uri = slot<String>()

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
        every { AuditLogger.logOathCredentialCreated(any(), any(), any(), any()) } returns Unit

        val database = mockk<XKeyDatabase>(relaxed = true)
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database

        // OathSecretManager opens the AndroidKeyStore when it is built.
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance(any<String>()) } returns mockk(relaxed = true)
        mockkConstructor(OathRepository::class)
        coEvery { anyConstructed<OathRepository>().importFromUri(capture(uri)) } returns STORED_ID

        Dispatchers.setMain(UnconfinedTestDispatcher())

        val context = mockk<Context>(relaxed = true)
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns
            mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)

        handler = RequestHandler(
            context = context,
            keystoreManager = mockk<KeystoreManager>(relaxed = true),
            biometricLauncher = null,
            sessionAuthManager = null,
            pairedDeviceRepository = null,
            pinManager = mockk<PinManager>(relaxed = true)
        )
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        unmockkAll()
    }

    @Test
    fun `issuer and account with reserved characters are percent-encoded`() = runTest {
        add(credential(issuer = "A&B Co: x/y?#z", account = "a b:c&d?e#f/g@example.com"))

        val issuer = "A%26B%20Co%3A%20x%2Fy%3F%23z"
        assertEquals(
            "otpauth://totp/$issuer:a%20b%3Ac%26d%3Fe%23f%2Fg%40example.com" +
                "?secret=$SECRET&issuer=$issuer&algorithm=SHA1&digits=6&period=30",
            uri.captured
        )
    }

    @Test
    fun `non-ASCII issuer and account are percent-encoded as UTF-8`() = runTest {
        add(credential(issuer = "Café", account = "jürgen"))

        assertEquals(
            "otpauth://totp/Caf%C3%A9:j%C3%BCrgen" +
                "?secret=$SECRET&issuer=Caf%C3%A9&algorithm=SHA1&digits=6&period=30",
            uri.captured
        )
    }

    @Test
    fun `a missing issuer leaves the label prefix and issuer parameter out`() = runTest {
        add(credential(issuer = null, account = "a b"))

        assertEquals(
            "otpauth://totp/a%20b?secret=$SECRET&algorithm=SHA1&digits=6&period=30",
            uri.captured
        )
    }

    @Test
    fun `a TOTP add passes no counter`() = runTest {
        add(credential(account = "alice").put("type", "totp").put("counter", 9))

        assertFalse(uri.captured, uri.captured.contains("counter="))
    }

    @Test
    fun `a HOTP add passes the request counter`() = runTest {
        add(credential(issuer = "Acme", account = "alice").put("type", "HOTP").put("counter", 42))

        assertEquals(
            "otpauth://hotp/Acme:alice" +
                "?secret=$SECRET&issuer=Acme&algorithm=SHA1&digits=6&period=30&counter=42",
            uri.captured
        )
    }

    @Test
    fun `a HOTP add without a counter passes counter 0`() = runTest {
        add(credential(account = "alice").put("type", "hotp"))

        assertTrue(uri.captured, uri.captured.endsWith("&counter=0"))
    }

    @Test
    fun `credential_id is the id importFromUri returned`() = runTest {
        val response = add(credential(account = "alice"))

        assertTrue(response.toString(), response.has("result"))
        val result = response.getJSONObject("result")
        assertTrue(result.getBoolean("success"))
        assertEquals(STORED_ID, result.getString("credential_id"))
    }

    @Test
    fun `missing credential fields still return INVALID_PARAMS`() = runTest {
        val noCredential = call("""{}""")
        val noName = call(JSONObject().put("credential", credential(account = "a").put("name", "")).toString())
        val noAccount = call(JSONObject().put("credential", credential(account = "")).toString())
        val noSecret = call(JSONObject().put("credential", credential(account = "a").put("secret", "")).toString())

        assertEquals("Missing credential", noCredential.getJSONObject("error").getString("message"))
        for (response in listOf(noName, noAccount, noSecret)) {
            assertEquals(ErrorCodes.INVALID_PARAMS, response.getJSONObject("error").getInt("code"))
            assertEquals("Missing required credential fields", response.getJSONObject("error").getString("message"))
        }
        assertEquals(ErrorCodes.INVALID_PARAMS, noCredential.getJSONObject("error").getInt("code"))
        coVerify(exactly = 0) { anyConstructed<OathRepository>().importFromUri(any()) }
    }

    private fun credential(issuer: String? = "Acme", account: String): JSONObject =
        JSONObject().apply {
            put("name", CALLER_NAME)
            put("account_name", account)
            put("secret", SECRET)
            if (issuer != null) put("issuer", issuer)
        }

    private suspend fun add(credential: JSONObject): JSONObject =
        call(JSONObject().put("credential", credential).toString())

    private suspend fun call(params: String): JSONObject {
        val request = """{"id":1,"method":"${MethodNames.LOCAL_OATH_ADD}","params":$params}"""
        return JSONObject(String(handler.handleRawRequest(request.toByteArray(Charsets.UTF_8)), Charsets.UTF_8))
    }

    private companion object {
        const val SECRET = "JBSWY3DPEHPK3PXP"
        const val CALLER_NAME = "caller-chosen-name"
        const val STORED_ID = "3f2b8c1e-stored-oath-id"
    }
}
