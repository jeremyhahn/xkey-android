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
package com.automatethethings.xkey.sync

import android.content.Context
import android.net.Uri
import com.automatethethings.xkey.oath.OathCredentialDao
import com.automatethethings.xkey.oath.OathCredentialEntity
import com.automatethethings.xkey.oath.OathSecretManager
import com.automatethethings.xkey.storage.XKeyDatabase
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import kotlinx.coroutines.test.runTest
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import java.net.URI
import java.net.URLDecoder
import java.security.KeyStore

/**
 * [SyncEngine.mergeOath] reads a synced credential's label on the structured
 * path: the issuer and account arrive as separate fields, so a `:` inside
 * either stays in it. On the external-import path an issuerless account
 * `host:user` would be stored as issuer `host`, account `user`.
 *
 * The DAO records what is inserted, the secret manager passes the secret
 * through, and `Uri.parse` is backed by [URI] (the JVM has no android.net).
 */
class SyncEngineMergeOathTest {

    private val inserted = mutableListOf<OathCredentialEntity>()
    private lateinit var engine: SyncEngine

    @Before
    fun setUp() {
        val dao = mockk<OathCredentialDao>()
        coEvery { dao.getByOathId(any()) } returns null
        coEvery { dao.insert(any()) } answers { inserted += firstArg<OathCredentialEntity>(); 1L }
        val db = mockk<XKeyDatabase>()
        every { db.oathCredentialDao() } returns dao
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns db

        // The secret manager opens the Android Keystore as it is constructed.
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance("AndroidKeyStore") } returns mockk(relaxed = true)
        mockkConstructor(OathSecretManager::class)
        every { anyConstructed<OathSecretManager>().encryptSecret(any()) } answers { firstArg() }

        mockkStatic(Uri::class)
        every { Uri.parse(any()) } answers { jvmUri(firstArg()) }

        engine = SyncEngine(mockk<Context>())
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    /** An android [Uri] answering what `importFromUri` reads, from [URI]. */
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

    private fun credential(id: String, issuer: String?, account: String) = JSONObject().apply {
        put("id", id)
        put("secret", "JBSWY3DPEHPK3PXP")
        put("account_name", account)
        if (issuer != null) put("issuer", issuer)
        put("type", "totp")
    }

    @Test
    fun `mergeOath keeps an issuerless account with a colon whole`() = runTest {
        val counts = engine.mergeOath(JSONArray().put(credential("c1", null, "host:user")))

        assertEquals(SyncEngine.ItemCounts(added = 1, updated = 0, skipped = 0), counts)
        assertEquals(1, inserted.size)
        assertNull(inserted[0].issuer)
        assertEquals("host:user", inserted[0].accountName)
    }

    @Test
    fun `mergeOath keeps an issuer and account with colons whole`() = runTest {
        engine.mergeOath(JSONArray().put(credential("c2", "Corp:EU", "host:user")))

        assertEquals(1, inserted.size)
        assertEquals("Corp:EU", inserted[0].issuer)
        assertEquals("host:user", inserted[0].accountName)
    }
}
