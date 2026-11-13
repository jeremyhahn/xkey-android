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

package com.automatethethings.xkey.oath

import android.net.Uri
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import java.net.URI
import java.net.URLDecoder

/**
 * The two ways into [OathRepository]: [OathRepository.importStructured] for
 * the credentials the app holds as separate fields, which keeps a `:` inside
 * the issuer or account, and [OathRepository.importFromUri] for an external
 * URI, whose issuerless label also splits on an encoded `%3A` (#152, #156).
 *
 * The DAO records what is inserted, the secret manager passes the secret
 * through, and `Uri.parse` is backed by [URI] (the JVM has no android.net).
 */
class OathRepositoryImportPathTest {

    private val inserted = mutableListOf<OathCredentialEntity>()
    private lateinit var repository: OathRepository

    @Before
    fun setUp() {
        val dao = mockk<OathCredentialDao>()
        coEvery { dao.insert(any()) } answers { inserted += firstArg<OathCredentialEntity>(); 1L }
        val secretManager = mockk<OathSecretManager>()
        every { secretManager.encryptSecret(any()) } answers { firstArg() }
        mockkStatic(Uri::class)
        every { Uri.parse(any()) } answers { jvmUri(firstArg()) }
        repository = OathRepository(dao, secretManager)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `a structured import keeps an issuerless account with a colon whole`() = runTest {
        val id = repository.importStructured(type = "totp", issuer = null, accountName = "host:user", secret = SECRET)

        assertEquals(id, inserted.single().oathId)
        assertNull(inserted.single().issuer)
        assertEquals("host:user", inserted.single().accountName)
    }

    @Test
    fun `a structured import keeps colons in the issuer and the account`() = runTest {
        repository.importStructured(type = "TOTP", issuer = "Corp:EU", accountName = "host:user", secret = SECRET)

        assertEquals("Corp:EU", inserted.single().issuer)
        assertEquals("host:user", inserted.single().accountName)
        assertEquals("TOTP", inserted.single().oathType)
    }

    @Test
    fun `a structured HOTP import stores its counter and a TOTP one ignores it`() = runTest {
        repository.importStructured(type = "hotp", issuer = "Acme", accountName = "a", secret = SECRET, counter = 42)
        repository.importStructured(type = "totp", issuer = "Acme", accountName = "b", secret = SECRET, counter = 42)

        assertEquals(42L, inserted[0].counter)
        assertEquals(0L, inserted[1].counter)
    }

    @Test
    fun `a structured import reads back a secret and fields with uri punctuation`() = runTest {
        repository.importStructured(
            type = "totp",
            issuer = "A&B=C?D#E 50%",
            accountName = "a+b&c@example.com",
            secret = "jbsw y3dp ehpk 3pxp"
        )
        repository.importStructured(type = "totp", issuer = null, accountName = "plain", secret = SECRET)

        assertEquals("A&B=C?D#E 50%", inserted[0].issuer)
        assertEquals("a+b&c@example.com", inserted[0].accountName)
        assertArrayEquals(inserted[1].secretEncrypted, inserted[0].secretEncrypted)
    }

    @Test
    fun `an external uri still splits an issuerless label on an encoded colon`() = runTest {
        repository.importFromUri("otpauth://totp/GitHub%3Aalice?secret=$SECRET")

        assertEquals("GitHub", inserted.single().issuer)
        assertEquals("alice", inserted.single().accountName)
    }

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

    private companion object {
        const val SECRET = "JBSWY3DPEHPK3PXP"
    }
}
