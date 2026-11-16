/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
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
package com.automatethethings.xkey.ui

import android.app.Application
import androidx.test.core.app.ApplicationProvider
import com.automatethethings.xkey.media.MediaHasher
import com.automatethethings.xkey.storage.entity.ContactEntity
import com.automatethethings.xkey.storage.entity.KeyEntity
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File

/**
 * [knownPublicKey] finds a contact's key by its fingerprint, else a local
 * key whose own hash is the fingerprint, and suspends on the database
 * instead of blocking its thread: no app source blocks on a coroutine.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class CoSignKnownPublicKeyTest {

    private lateinit var db: TestDatabase
    private val app: Application get() = ApplicationProvider.getApplicationContext()

    @Before
    fun setUp() {
        db = TestDatabase()
    }

    @After
    fun tearDown() {
        db.close()
    }

    @Test
    fun `a contact's key, else a local key by its hash, else none`() = runBlocking {
        val contactKey = byteArrayOf(1, 2, 3)
        val localKey = byteArrayOf(4, 5, 6)
        db.database.contactDao().insert(
            ContactEntity(
                name = "Witness",
                publicKeyDer = contactKey,
                publicKeyFingerprint = "SHA256:contact",
                algorithm = "ES256",
                source = "import"
            )
        )
        db.database.keyDao().insert(
            KeyEntity(
                keyId = "key-local",
                keyType = "signing",
                algorithm = "ES256",
                label = "Local",
                keySizeBits = 256,
                source = "generated",
                publicKeyDer = localKey
            )
        )

        assertArrayEquals(contactKey, knownPublicKey(app, "SHA256:contact"))
        assertArrayEquals(localKey, knownPublicKey(app, MediaHasher.hashBytes(localKey)))
        assertNull(knownPublicKey(app, "SHA256:unknown"))
    }

    @Test
    fun `no app source blocks on a coroutine`() {
        val main = listOf(File("src/main"), File("app/src/main")).firstOrNull { it.isDirectory }
            ?: error("src/main not found from ${File(".").absolutePath}")
        val word = Regex("""\brunBlocking\b""")
        val hits = main.walkTopDown().filter { it.isFile && it.extension == "kt" }
            .filter { word.containsMatchIn(it.readText()) }.map { it.name }.toList()
        assertEquals("runBlocking blocks its thread; use a coroutine scope", emptyList<String>(), hits)
    }
}
