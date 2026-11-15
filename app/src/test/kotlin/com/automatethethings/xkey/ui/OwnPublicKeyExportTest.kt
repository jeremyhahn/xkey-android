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
package com.automatethethings.xkey.ui

import android.content.Context
import com.automatethethings.xkey.crypto.KeyPresence
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.SoftwareKeyStore
import com.automatethethings.xkey.crypto.UserKeyKind
import com.automatethethings.xkey.storage.OwnPublicKeyRead
import com.automatethethings.xkey.storage.readOwnPublicKey
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.spyk
import io.mockk.unmockkAll
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.security.KeyStore
import java.security.cert.Certificate

/**
 * #255 review r6: the key detail screen's public-key copy and the contacts
 * screen's QR export read a key's public key through one read
 * ([readOwnPublicKey]). With a key store throwing, that read is a refusal the
 * screen shows (a snackbar, or the export dialog's message), never an
 * exception out of the button listener or the screen's coroutine, which
 * would crash the app.
 */
class OwnPublicKeyExportTest {

    private val entries = hashSetOf("xkey_credential_$ID")
    private lateinit var keystore: KeystoreManager
    private lateinit var software: SoftwareKeyStore

    @Before
    fun setUp() {
        mockkStatic(android.util.Log::class)
        every { android.util.Log.d(any(), any<String>()) } returns 0
        every { android.util.Log.w(any(), any<String>()) } returns 0
        every { android.util.Log.w(any(), any<String>(), any()) } returns 0
        val platform = mockk<KeyStore>(relaxed = true)
        every { platform.containsAlias(any()) } answers { firstArg<String>() in entries }
        every { platform.getCertificate(any()) } answers {
            if (firstArg<String>() in entries) mockk<Certificate>(relaxed = true) else null
        }
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance(any<String>()) } returns platform
        keystore = spyk(KeystoreManager(mockk<Context>(relaxed = true)))
        every { keystore.ed25519Prefs() } returns null
        software = mockk()
        every { software.presence(any()) } returns KeyPresence.ABSENT
        every { keystore.softwareKeys() } returns software
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun anUnreadableEd25519StoreIsARefusalNotACrash() {
        every { keystore.ed25519Prefs() } throws java.security.GeneralSecurityException("master key unavailable")
        assertTrue(keystore.readOwnPublicKey(ID) is OwnPublicKeyRead.Unreadable)
    }

    @Test
    fun anUnreadableSoftwareStoreIsARefusalNotACrash() {
        every { software.presence(any()) } returns KeyPresence.UNREADABLE
        assertTrue(keystore.readOwnPublicKey(ID) is OwnPublicKeyRead.Unreadable)
    }

    @Test
    fun aSoftwareKeyBesideACredentialExportsNoPublicKey() {
        every { software.presence(ID) } returns KeyPresence.PRESENT
        assertTrue(keystore.readOwnPublicKey(ID) is OwnPublicKeyRead.Unavailable)
    }

    @Test
    fun aReadableStoreExportsTheCredentialsPublicKey() {
        every { keystore.getPublicKeyPEM(ID, UserKeyKind.CREDENTIAL) } returns "credential pem"
        val read = keystore.readOwnPublicKey(ID)
        assertTrue("$read", read is OwnPublicKeyRead.Pem && read.pem == "credential pem")
    }

    /**
     * Both export callers use the one read, and handle its refusal; no
     * screen resolves a key's namespace itself, outside a read that turns an
     * unreadable store into a refusal.
     */
    @Test
    fun bothExportCallersReadThroughTheRefusingRead() {
        val root = listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory }
        val ui = File(root, "com/automatethethings/xkey/ui")
        val callers = mapOf(
            "KeyDetailActivity.kt" to "private fun exportPublicKey(",
            "ContactManagementActivity.kt" to "private suspend fun loadOwnPublicKeys("
        )
        for ((file, start) in callers) {
            val source = File(ui, file).readText()
            val at = source.indexOf(start)
            assertTrue("$file has $start", at >= 0)
            val body = source.substring(at, source.indexOf("\n    }\n", at))
            assertTrue("$file reads through readOwnPublicKey", "readOwnPublicKey(" in body)
            assertTrue("$file handles the refusal", "OwnPublicKeyRead.Unreadable" in body)
        }
        val resolvers = Regex("""\.(soleKind|exportKind|resolveKey|resolveKeystoreAlias|holdsUserKey|userKeyPresence|userKeyIdInUse)\(""")
        for (file in ui.walk().filter { it.extension == "kt" }) {
            val found = resolvers.findAll(file.readText()).map { it.value }.toList()
            assertFalse("${file.name} resolves a key's namespace outside the refusing read: $found", found.isNotEmpty())
        }
    }

    private companion object {
        const val ID = "credential-only"
    }
}
