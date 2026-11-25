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
import org.junit.Assert.assertEquals
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
 *
 * #255 review r8: the delete's result was ignored, so an encryption whose
 * ephemeral private key could not be deleted returned as a success. The
 * delete reports deleted, absent or failed; a failure fails the encryption,
 * and on an encryption already failing it rides along as a suppressed cause.
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
        // Main's shared ML-DSA store is per process: each test starts with none.
        com.automatethethings.xkey.crypto.PqcSoftwareKeyStore.clearSharedForTest()
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
        com.automatethethings.xkey.crypto.PqcSoftwareKeyStore.clearSharedForTest()
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

    /** How the platform's deleteEntry behaves: deletes, throws, or leaves the entry. */
    private var deleteFails: String? = null

    /** An encryption that runs to its end: the ECDH succeeds. */
    private suspend fun encrypt(): Result<ByteArray> {
        io.mockk.coEvery { keystore.performECDH(any(), any()) } returns ByteArray(32) { 7 }
        val platform = KeyStore.getInstance("AndroidKeyStore")
        every { platform.deleteEntry(any()) } answers {
            when (deleteFails) {
                "throws" -> throw java.security.KeyStoreException("entry is busy")
                "leaves" -> Unit
                else -> { entries.remove(firstArg<String>()); Unit }
            }
        }
        val out = ByteArrayOutputStream()
        return runCatching {
            FileEncryptor(keystore, FakeKeyPolicyTables().store())
                .encryptForRecipient(ByteArray(8), ByteArrayInputStream(ByteArray(4)), out)
            out.toByteArray()
        }
    }

    @Test
    fun anEncryptionWhoseEphemeralKeyIsDeletedSucceeds() = runTest {
        val result = encrypt()
        assertTrue("the encryption succeeded: ${result.exceptionOrNull()}", result.isSuccess)
        assertTrue("an ephemeral key was generated", generated > 0)
        assertTrue("ephemeral keys left in the Keystore: $entries", entries.isEmpty())
        assertEquals(GeneratedKeyDiscard.ABSENT, keystore.discardGeneratedKey("xkey_key_gone"))
    }

    @Test
    fun anEncryptionWhoseEphemeralDeleteThrowsFails() = runTest {
        deleteFails = "throws"
        assertEphemeralDeleteFailureFails()
    }

    @Test
    fun anEncryptionWhoseEphemeralKeyOutlivesItsDeleteFails() = runTest {
        deleteFails = "leaves"
        assertEphemeralDeleteFailureFails()
    }

    private suspend fun assertEphemeralDeleteFailureFails() {
        val failure = encrypt().exceptionOrNull()
        assertTrue("an encryption leaving its ephemeral key behind succeeded", failure is EncryptionException)
        assertTrue("the failure names the undeleted ephemeral key: $failure", "not deleted" in failure!!.message.orEmpty())
        val left = entries.single()
        assertEquals("the discard reports the key left", GeneratedKeyDiscard.FAILED, keystore.discardGeneratedKey(left))
    }

    @Test
    fun aFailedEncryptionKeepsItsCauseAndCarriesAFailedDelete() = runTest {
        deleteFails = "throws"
        io.mockk.coEvery { keystore.performECDH(any(), any()) } throws java.security.InvalidKeyException("bad peer key")
        val platform = KeyStore.getInstance("AndroidKeyStore")
        every { platform.deleteEntry(any()) } throws java.security.KeyStoreException("entry is busy")
        val failure = runCatching {
            FileEncryptor(keystore, FakeKeyPolicyTables().store())
                .encryptForRecipient(ByteArray(8), ByteArrayInputStream(ByteArray(4)), ByteArrayOutputStream())
        }.exceptionOrNull()
        assertTrue("the encryption's own failure is kept: $failure", failure is java.security.InvalidKeyException)
        assertTrue(
            "the failed delete rides along: ${failure!!.suppressed.toList()}",
            failure.suppressed.any { it is EncryptionException && "not deleted" in it.message.orEmpty() }
        )
    }

}
