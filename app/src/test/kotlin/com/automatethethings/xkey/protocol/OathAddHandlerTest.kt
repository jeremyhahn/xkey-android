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
import android.net.Uri
import android.os.Looper
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.oath.OathCredentialDao
import com.automatethethings.xkey.oath.OathCredentialEntity
import com.automatethethings.xkey.oath.OathSecretManager
import com.automatethethings.xkey.pin.PinManager
import com.automatethethings.xkey.storage.XKeyDatabase
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.net.URLDecoder
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
 * `local.oathAdd` stores the issuer and account exactly as sent, whatever
 * characters they hold, and returns as `credential_id` the id the phone
 * stored: the one `local.oathList`, `local.oathGenerate` and
 * `local.oathRemove` key on (follow-up of #133).
 *
 * The real [com.automatethethings.xkey.oath.OathRepository.importFromUri]
 * runs; only the Android edges are replaced. [Uri.parse] is a JVM stand-in
 * that splits and decodes a URI as Android's `Uri` does, and the DAO keeps
 * what it is given in a list.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class OathAddHandlerTest {

    private lateinit var oathDao: OathCredentialDao
    private lateinit var handler: RequestHandler
    private val stored = mutableListOf<OathCredentialEntity>()
    private val parsedUris = mutableListOf<String>()

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

        mockkStatic(Uri::class)
        every { Uri.parse(any()) } answers {
            val s = firstArg<String>()
            parsedUris.add(s)
            androidLikeUri(s)
        }

        // OathSecretManager opens the Android Keystore when it is built.
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance(any<String>()) } returns mockk(relaxed = true)
        mockkConstructor(OathSecretManager::class)
        every { anyConstructed<OathSecretManager>().encryptSecret(any()) } returns ByteArray(28)

        mockkObject(AuditLogger)
        every { AuditLogger.logOathCredentialCreated(any(), any(), any(), any()) } returns Unit

        oathDao = mockk(relaxed = true)
        coEvery { oathDao.insert(any()) } answers {
            stored.add(firstArg())
            stored.size.toLong()
        }
        coEvery { oathDao.getAll() } answers { stored.toList() }
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
    fun `issuer and account with URI delimiters are stored as sent`() = runTest {
        val issuer = "ACME & Co / Ops?#"
        val account = "alice smith:ops/eu?x=1&y#2@example.com"

        val response = add(credential(issuer = issuer, account = account))

        assertTrue("add failed: $response", response.has("result"))
        assertEquals(1, stored.size)
        assertEquals(issuer, stored[0].issuer)
        assertEquals(account, stored[0].accountName)
        assertEquals("TOTP", stored[0].oathType)
    }

    @Test
    fun `credential_id is the stored id that oathList reports`() = runTest {
        val added = add(credential(issuer = "Example", account = "alice@example.com"))
        val credentialId = added.getJSONObject("result").getString("credential_id")

        assertEquals(stored.single().oathId, credentialId)

        val listed = call(MethodNames.LOCAL_OATH_LIST, "{}")
            .getJSONObject("result").getJSONArray("credentials")
        assertEquals(1, listed.length())
        assertEquals(credentialId, listed.getJSONObject(0).getString("name"))
    }

    @Test
    fun `a HOTP add carries its counter and a TOTP add carries none`() = runTest {
        add(credential(issuer = "Example", account = "hotp user", type = "hotp", counter = 42))
        add(credential(issuer = "Example", account = "totp user", type = "totp", counter = 7))

        assertEquals("HOTP", stored[0].oathType)
        assertEquals(42L, stored[0].counter)
        assertTrue(parsedUris[0].contains("&counter=42"))

        assertEquals("TOTP", stored[1].oathType)
        assertEquals(0L, stored[1].counter)
        assertFalse(parsedUris[1].contains("counter="))
    }

    private fun credential(
        issuer: String,
        account: String,
        type: String = "totp",
        counter: Long? = null
    ): JSONObject = JSONObject().apply {
        put("name", "$issuer:$account")
        put("issuer", issuer)
        put("account_name", account)
        put("secret", "JBSWY3DPEHPK3PXP")
        put("type", type)
        put("algorithm", "SHA1")
        put("digits", 6)
        put("period", 30)
        if (counter != null) put("counter", counter)
    }

    private suspend fun add(credential: JSONObject): JSONObject =
        call(MethodNames.LOCAL_OATH_ADD, JSONObject().put("credential", credential).toString())

    private suspend fun call(method: String, params: String): JSONObject {
        val request = """{"id":1,"method":"$method","params":$params}"""
        return JSONObject(String(handler.handleRawRequest(request.toByteArray(Charsets.UTF_8)), Charsets.UTF_8))
    }

    /**
     * A [Uri] that splits [s] as Android's hierarchical `Uri` does (the
     * fragment at the first `#`, the query at the first `?` before it) and
     * decodes the path as `getPath` does and a query value as
     * `getQueryParameter` does.
     */
    private fun androidLikeUri(s: String): Uri {
        val scheme = s.substringBefore(':')
        val noFragment = s.substringAfter("://").substringBefore('#')
        val beforeQuery = noFragment.substringBefore('?')
        val query = if ('?' in noFragment) noFragment.substringAfter('?') else null
        val host = beforeQuery.substringBefore('/')
        val rawPath = beforeQuery.removePrefix(host)
        val uri = mockk<Uri>()
        every { uri.scheme } returns scheme
        every { uri.host } returns host
        every { uri.path } returns URLDecoder.decode(rawPath.replace("+", "%2B"), Charsets.UTF_8)
        every { uri.getQueryParameter(any()) } answers {
            val key = firstArg<String>()
            query?.split('&')
                ?.firstOrNull { it.substringBefore('=') == key }
                ?.substringAfter('=', "")
                ?.let { URLDecoder.decode(it, Charsets.UTF_8) }
        }
        return uri
    }
}
