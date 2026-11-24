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
import io.mockk.verify
import java.net.URI
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
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The desktop's local.oathAdd, local.oathRemove and local.oathGenerate go
 * through OathRepository, which writes the audit row: each action still
 * writes exactly one row, under the id the credential is stored under, now
 * that the handler no longer writes its own.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class OathDesktopAuditTest {

    private lateinit var handler: RequestHandler
    private val inserted = mutableListOf<OathCredentialEntity>()

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
        every { AuditLogger.logOathCredentialDeleted(any(), any(), any()) } returns Unit
        every { AuditLogger.logOathCodeGenerated(any(), any(), any()) } returns Unit

        val dao = mockk<OathCredentialDao>(relaxed = true)
        coEvery { dao.insert(any()) } answers { inserted += firstArg<OathCredentialEntity>(); 1L }
        coEvery { dao.getByOathId(any()) } returns null
        coEvery { dao.getByOathId(STORED_ID) } returns stored()
        // A relaxed mock returns 0, which reads as a lost counter race.
        coEvery { dao.claimCounter(any(), any()) } returns 1
        // Likewise a delete count of 0 reads as a delete that removed nothing.
        coEvery { dao.deleteByOathId(any()) } returns 1
        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.oathCredentialDao() } returns dao
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database

        // OathSecretManager opens the AndroidKeyStore when it is built.
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance(any<String>()) } returns mockk(relaxed = true)
        mockkConstructor(OathSecretManager::class)
        every { anyConstructed<OathSecretManager>().encryptSecret(any()) } answers { firstArg() }
        every { anyConstructed<OathSecretManager>().decryptSecret(any()) } answers { firstArg() }

        mockkStatic(Uri::class)
        every { Uri.parse(any()) } answers { jvmUri(firstArg()) }

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
    fun `a desktop add writes one created row under the stored id`() = runTest {
        val credential = JSONObject()
            .put("name", "caller-chosen-name")
            .put("issuer", "Acme")
            .put("account_name", "alice")
            .put("secret", SECRET)
        val response = call(MethodNames.LOCAL_OATH_ADD, JSONObject().put("credential", credential))

        assertTrue(response.toString(), response.getJSONObject("result").getBoolean("success"))
        val id = inserted.single().oathId
        verify(exactly = 1) { AuditLogger.logOathCredentialCreated(id, "Acme", "alice", "TOTP") }
        verify(exactly = 1) { AuditLogger.logOathCredentialCreated(any(), any(), any(), any()) }
    }

    @Test
    fun `a desktop remove writes one deleted row`() = runTest {
        val response = call(MethodNames.LOCAL_OATH_REMOVE, JSONObject().put("credential_id", STORED_ID))

        assertEquals(true, response.getJSONObject("result").getBoolean("deleted"))
        verify(exactly = 1) { AuditLogger.logOathCredentialDeleted(STORED_ID, "Acme", "alice") }
        verify(exactly = 1) { AuditLogger.logOathCredentialDeleted(any(), any(), any()) }
    }

    @Test
    fun `a desktop remove of an unknown id writes no row`() = runTest {
        val response = call(MethodNames.LOCAL_OATH_REMOVE, JSONObject().put("credential_id", "nope"))

        assertEquals(false, response.getJSONObject("result").getBoolean("deleted"))
        verify(exactly = 0) { AuditLogger.logOathCredentialDeleted(any(), any(), any()) }
    }

    @Test
    fun `a desktop generate writes one generated row`() = runTest {
        val response = call(MethodNames.LOCAL_OATH_GENERATE, JSONObject().put("credential_id", STORED_ID))

        assertEquals(6, response.getJSONObject("result").getString("code").length)
        verify(exactly = 1) { AuditLogger.logOathCodeGenerated(STORED_ID, "Acme", "alice") }
        verify(exactly = 1) { AuditLogger.logOathCodeGenerated(any(), any(), any()) }
    }

    private fun stored() = OathCredentialEntity(
        oathId = STORED_ID,
        oathType = "HOTP",
        algorithm = "SHA1",
        digits = 6,
        periodSeconds = 30,
        counter = 3L,
        issuer = "Acme",
        accountName = "alice",
        secretEncrypted = ByteArray(10) { it.toByte() },
        source = "local",
        createdAt = 0L
    )

    /** An android [Uri] answering what the importer reads, from [URI]. */
    private fun jvmUri(uriString: String): Uri {
        val uri = URI(uriString)
        val params = uri.rawQuery.orEmpty().split("&").filter { it.isNotEmpty() }
            .map { it.split("=", limit = 2) }
            .associate { it[0] to URLDecoder.decode(it.getOrElse(1) { "" }, Charsets.UTF_8.name()) }
        return mockk {
            every { scheme } returns uri.scheme
            every { host } returns uri.host
            every { encodedPath } returns uri.rawPath
            every { getQueryParameter(any()) } answers { params[firstArg()] }
        }
    }

    private suspend fun call(method: String, params: JSONObject): JSONObject {
        val request = """{"id":1,"method":"$method","params":$params}"""
        return JSONObject(String(handler.handleRawRequest(request.toByteArray(Charsets.UTF_8)), Charsets.UTF_8))
    }

    private companion object {
        const val SECRET = "JBSWY3DPEHPK3PXP"
        const val STORED_ID = "stored-oath-1"
    }
}
