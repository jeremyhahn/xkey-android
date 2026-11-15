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

import android.app.Application
import android.content.Context
import com.automatethethings.xkey.storage.FakeKeyPolicyTables
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.spyk
import io.mockk.unmockkAll
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec

/**
 * #255 review r7: a file encryption generates an ephemeral Keystore key and
 * deletes it when it ends, failed or not. That delete went through the
 * cross-backend presence guard, which throws while the Ed25519 or software
 * key store cannot be read, so it threw before the Keystore entry was
 * deleted and every failed attempt left an ephemeral private key behind.
 * The cleanup now deletes the exact alias generated in its own backend.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class FileEncryptorEphemeralKeyLeakTest {

    /** Keystore aliases present. */
    private val entries = HashSet<String>()

    private var ed25519Readable = true
    private var softwareReadable = true

    /** Ephemeral keys generated. */
    private var generated = 0

    private lateinit var keystore: KeystoreManager

    @Before
    fun setUp() {
        entries.clear()
        ed25519Readable = true
        softwareReadable = true
        generated = 0
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

        val platform = mockk<KeyStore>(relaxed = true)
        every { platform.containsAlias(any()) } answers { firstArg<String>() in entries }
        every { platform.deleteEntry(any()) } answers { entries.remove(firstArg<String>()) }
        every { platform.getKey(any(), any()) } returns null
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance(any<String>()) } returns platform

        // The Keystore generator: generating a key adds its alias.
        val generator = mockk<KeyPairGenerator>(relaxed = true)
        var alias: String? = null
        every { generator.initialize(any<java.security.spec.AlgorithmParameterSpec>()) } answers {
            alias = (firstArg<Any>() as android.security.keystore.KeyGenParameterSpec).keystoreAlias
        }
        every { generator.generateKeyPair() } answers { generated++; entries.add(alias!!); pair }
        mockkStatic(KeyPairGenerator::class)
        every { KeyPairGenerator.getInstance(any<String>(), "AndroidKeyStore") } returns generator

        keystore = spyk(KeystoreManager(mockk<Context>(relaxed = true)))
        every { keystore.ed25519Prefs() } answers {
            if (!ed25519Readable) throw java.security.GeneralSecurityException("master key unavailable")
            null
        }
        val software = mockk<SoftwareKeyStore>()
        every { software.presence(any()) } answers {
            if (softwareReadable) KeyPresence.ABSENT else KeyPresence.UNREADABLE
        }
        every { keystore.softwareKeys() } returns software
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun aFailedEncryptionWithTheEd25519StoreUnreadableLeavesNoEphemeralKey() = runTest {
        ed25519Readable = false
        assertFailedEncryptionLeavesNoKey()
    }

    @Test
    fun aFailedEncryptionWithTheSoftwareStoreUnreadableLeavesNoEphemeralKey() = runTest {
        softwareReadable = false
        assertFailedEncryptionLeavesNoKey()
    }

    private suspend fun assertFailedEncryptionLeavesNoKey() {
        // The guard the cleanup used to pass throws here: the setup is the failing one.
        val guard = runCatching { keystore.holdsUserKey("probe", UserKeyKind.GENERAL) }.exceptionOrNull()
        assertTrue("the presence guard refuses: $guard", guard is KeyPresenceUnreadableException)

        val failure = runCatching {
            FileEncryptor(keystore, FakeKeyPolicyTables().store())
                .encryptForRecipient(ByteArray(8), ByteArrayInputStream(ByteArray(4)), ByteArrayOutputStream())
        }.exceptionOrNull()

        assertTrue("the encryption failed", failure != null)
        assertTrue("an ephemeral key was generated", generated > 0)
        assertTrue("ephemeral keys left in the Keystore: $entries", entries.isEmpty())
    }

}
