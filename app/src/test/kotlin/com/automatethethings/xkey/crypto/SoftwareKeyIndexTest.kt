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

package com.automatethethings.xkey.crypto

import android.content.Context
import android.util.Log
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Before
import org.junit.Test
import java.io.File
import java.security.KeyStore

/**
 * The key resolver reads the software key store's metadata once (#255):
 * [KeystoreManager] keeps one [SoftwareKeyStore], whose scan of the other
 * records is kept until a write or delete of the store, through any
 * instance of it, invalidates it. A metadata file changed outside the
 * store is therefore not re-read by a repeated resolver call, and is read
 * again after the next store write.
 */
class SoftwareKeyIndexTest {

    private lateinit var context: Context
    private lateinit var dir: File
    private val cipher = mockk<KeystoreAeadCipher>().also {
        every { it.encrypt(any()) } answers { firstArg() }
        every { it.decrypt(any()) } answers { firstArg() }
    }

    @Before
    fun setUp() {
        // Main's shared ML-DSA store is per process: each test starts with none.
        com.automatethethings.xkey.crypto.PqcSoftwareKeyStore.clearSharedForTest()
        mockkStatic(Log::class)
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance(any<String>()) } returns mockk(relaxed = true)
        val files = java.nio.file.Files.createTempDirectory("software-index").toFile().apply { deleteOnExit() }
        context = mockk(relaxed = true)
        every { context.filesDir } returns files
        dir = File(files, "software_keys")
    }

    @After
    fun tearDown() {
        com.automatethethings.xkey.crypto.PqcSoftwareKeyStore.clearSharedForTest()
        unmockkAll()
    }

    private fun key(id: String) = SoftwareKey(id, "AES256-GCM", "symmetric", 256, true, true, ByteArray(32) { 7 })

    @Test
    fun theKeystoreManagerKeepsOneSoftwareKeyStore() {
        val keystore = KeystoreManager(context)
        assertSame(keystore.softwareKeys(), keystore.softwareKeys())
    }

    @Test
    fun repeatedResolverCallsReadMetadataOnceAndSeeLaterWritesAndDeletes() {
        val keystore = KeystoreManager(context)
        val other = SoftwareKeyStore(context, cipher)
        other.put(key("a"))
        val aMeta = dir.listFiles()!!.single { it.name.endsWith(".meta") }
        val aText = aMeta.readText()

        assertEquals(KeyPresence.ABSENT, keystore.softwareKeyPresence("x"))
        // a's metadata turns unparseable outside the store: a scan that read
        // it again would answer UNREADABLE for every other id.
        aMeta.writeText("not json")
        repeat(3) {
            assertEquals("a repeated call must not read metadata again", KeyPresence.ABSENT, keystore.softwareKeyPresence("x"))
        }

        // A write through another instance of the store invalidates the scan.
        other.put(key("b"))
        assertEquals("a later write must be seen", KeyPresence.UNREADABLE, keystore.softwareKeyPresence("x"))
        assertEquals(KeyPresence.PRESENT, keystore.softwareKeyPresence("b"))

        aMeta.writeText(aText)
        assertEquals("no store write since: the scan is kept", KeyPresence.UNREADABLE, keystore.softwareKeyPresence("x"))

        // So does a delete, through the resolver's own store.
        keystore.softwareKeys().delete("b")
        assertEquals("a later delete must be seen", KeyPresence.ABSENT, keystore.softwareKeyPresence("x"))
        assertEquals(KeyPresence.ABSENT, keystore.softwareKeyPresence("b"))
        assertEquals(KeyPresence.PRESENT, keystore.softwareKeyPresence("a"))
    }

    @Test
    fun anUnlistableStoreIsStillUnreadableAfterAKeptScan() {
        val keystore = KeystoreManager(context)
        SoftwareKeyStore(context, cipher).put(key("a"))
        assertEquals(KeyPresence.ABSENT, keystore.softwareKeyPresence("x"))
        dir.setExecutable(false)
        dir.setReadable(false)
        try {
            assertEquals(KeyPresence.UNREADABLE, keystore.softwareKeyPresence("x"))
        } finally {
            dir.setReadable(true)
            dir.setExecutable(true)
        }
    }
}
