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
package com.automatethethings.xkey.storage

import android.content.Context
import com.automatethethings.xkey.ca.AndroidCA
import com.automatethethings.xkey.crypto.KeyPresence
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.SoftwareKeyStore
import com.automatethethings.xkey.crypto.SyncCodec
import com.automatethethings.xkey.crypto.UserKeyKind
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.spyk
import io.mockk.unmockkAll
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.Certificate

/**
 * #255 review r3 (round 3): the key detail screen's Export Public Key and
 * the contacts screen's export read a key through [readOwnPublicKey]. The
 * root and intermediate CA keys are listed by their raw Keystore aliases, so
 * that read exports their public keys, read-only, while neither alias
 * resolves as a user key for any other use.
 */
class CaPublicKeyExportTest {

    private val root = ecPublicKeyDer()
    private val intermediate = ecPublicKeyDer()
    private val certificates = mapOf(
        AndroidCA.ROOT_CA_ALIAS to root,
        AndroidCA.INTERMEDIATE_CA_ALIAS to intermediate
    )
    private lateinit var keystore: KeystoreManager

    @Before
    fun setUp() {
        mockkStatic(android.util.Log::class)
        every { android.util.Log.d(any(), any<String>()) } returns 0
        every { android.util.Log.w(any(), any<String>()) } returns 0
        every { android.util.Log.w(any(), any<String>(), any()) } returns 0
        val platform = mockk<KeyStore>(relaxed = true)
        every { platform.containsAlias(any()) } answers { firstArg<String>() in certificates }
        every { platform.getCertificate(any()) } answers {
            certificates[firstArg<String>()]?.let { der ->
                mockk<Certificate> { every { publicKey } returns mockk { every { encoded } returns der } }
            }
        }
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance(any<String>()) } returns platform
        mockkStatic(android.util.Base64::class)
        every { android.util.Base64.encodeToString(any(), any()) } answers {
            java.util.Base64.getEncoder().encodeToString(firstArg<ByteArray>())
        }
        keystore = spyk(KeystoreManager(mockk<Context>(relaxed = true)))
        every { keystore.ed25519Prefs() } returns null
        val software = mockk<SoftwareKeyStore>()
        every { software.presence(any()) } returns KeyPresence.ABSENT
        every { keystore.softwareKeys() } returns software
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun theRootCaKeyExportsItsPublicKey() {
        assertExports(AndroidCA.ROOT_CA_ALIAS, root)
    }

    @Test
    fun theIntermediateCaKeyExportsItsPublicKey() {
        assertExports(AndroidCA.INTERMEDIATE_CA_ALIAS, intermediate)
    }

    @Test
    fun aCaAliasResolvesAsNoUserKey() {
        for (alias in certificates.keys) {
            assertNull(keystore.soleKind(alias))
            for (kind in UserKeyKind.entries) assertNull(keystore.resolveKey(alias, kind))
        }
    }

    private fun assertExports(alias: String, der: ByteArray) {
        val read = keystore.readOwnPublicKey(alias)
        assertTrue("$alias: $read", read is KeyRead.Value)
        val pem = (read as KeyRead.Value).value
        assertTrue(pem, pem.startsWith("-----BEGIN PUBLIC KEY-----\n") && pem.endsWith("-----END PUBLIC KEY-----"))
        assertArrayEquals(der, SyncCodec.pemToDer(pem))
    }

    private companion object {
        fun ecPublicKeyDer(): ByteArray =
            KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair().public.encoded
    }
}
