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

import android.app.Application
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.automatethethings.xkey.storage.XKeyDatabase
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Input that [OathEngine] cannot compute a code from never reaches the
 * table, through either import path. The secret manager passes the secret
 * through (the JVM has no Android Keystore).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class OathRepositoryHardeningTest {

    private lateinit var database: XKeyDatabase
    private lateinit var dao: OathCredentialDao
    private lateinit var repository: OathRepository

    @Before
    fun setUp() {
        database = Room.inMemoryDatabaseBuilder(ApplicationProvider.getApplicationContext(), XKeyDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        dao = database.oathCredentialDao()
        val secretManager = mockk<OathSecretManager>()
        every { secretManager.encryptSecret(any()) } answers { firstArg() }
        every { secretManager.decryptSecret(any()) } answers { firstArg() }
        repository = OathRepository(dao, secretManager)
    }

    @After
    fun tearDown() {
        database.close()
    }

    @Test
    fun `an otpauth uri with fields no code can be computed from is rejected and nothing is stored`() {
        val bad = listOf(
            "otpauth://totp/x?secret=$SECRET&digits=10",
            "otpauth://totp/x?secret=$SECRET&digits=4",
            "otpauth://totp/x?secret=$SECRET&period=0",
            "otpauth://totp/x?secret=$SECRET&period=-30",
            "otpauth://totp/x?secret=$SECRET&period=301",
            "otpauth://totp/x?secret=$SECRET&algorithm=MD5",
            "otpauth://hotp/x?secret=$SECRET&digits=9",
            "otpauth://totp/x?secret=A",
            "otpauth://totp/x?secret==",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PX"
        )
        for (uri in bad) {
            val error = runCatching { runBlocking { repository.importFromUri(uri) } }.exceptionOrNull()
            assertTrue("$uri: ${error?.javaClass}", error is IllegalArgumentException)
            assertFalse("$uri: the message must not carry the secret", error!!.message.orEmpty().contains(SECRET))
        }
        assertEquals(0, runBlocking { dao.count() })
    }

    @Test
    fun `a structured import with fields no code can be computed from is rejected and nothing is stored`() {
        val bad: List<suspend () -> String> = listOf(
            { repository.importStructured(type = "totp", issuer = null, accountName = "x", secret = SECRET, digits = 10) },
            { repository.importStructured(type = "totp", issuer = null, accountName = "x", secret = SECRET, digits = 4) },
            { repository.importStructured(type = "totp", issuer = null, accountName = "x", secret = SECRET, period = 0) },
            { repository.importStructured(type = "totp", issuer = null, accountName = "x", secret = SECRET, period = -30) },
            { repository.importStructured(type = "totp", issuer = null, accountName = "x", secret = SECRET, algorithm = "MD5") },
            { repository.importStructured(type = "hotp", issuer = null, accountName = "x", secret = "A") },
            { repository.importStructured(type = "totp", issuer = null, accountName = "x", secret = "=") }
        )
        bad.forEachIndexed { index, import ->
            val error = runCatching { runBlocking { import() } }.exceptionOrNull()
            assertTrue("case $index: ${error?.javaClass}", error is IllegalArgumentException)
            assertFalse("case $index: the message must not carry the secret", error!!.message.orEmpty().contains(SECRET))
        }
        assertEquals(0, runBlocking { dao.count() })
    }

    @Test
    fun `the supported ranges still import, algorithm in any case`() = runBlocking {
        repository.importFromUri("otpauth://totp/a?secret=$SECRET&digits=6&period=1&algorithm=sha1")
        repository.importFromUri("otpauth://totp/b?secret=$SECRET&digits=7&period=300&algorithm=Sha256")
        repository.importFromUri("otpauth://hotp/c?secret=$SECRET&digits=8&algorithm=SHA512")
        repository.importStructured(type = "totp", issuer = null, accountName = "d", secret = SECRET, period = 60)

        assertEquals(4, dao.count())
        assertEquals(setOf("SHA1", "SHA256", "SHA512"), dao.getAll().map { it.algorithm }.toSet())
    }

    private companion object {
        /** 16 Base32 characters: 10 bytes, the 80-bit minimum. */
        const val SECRET = "JBSWY3DPEHPK3PXP"
    }
}
