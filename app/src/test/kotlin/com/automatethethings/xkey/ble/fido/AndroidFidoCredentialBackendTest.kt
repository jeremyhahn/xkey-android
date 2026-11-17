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

package com.automatethethings.xkey.ble.fido

import android.util.Log
import com.automatethethings.xkey.credential.PasskeySignCounter
import com.automatethethings.xkey.crypto.BiometricRequiredException
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.UserCancelledException
import com.automatethethings.xkey.protocol.SharePermission
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.storage.dao.CredentialMetadataDao
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.CredentialMetadataEntity
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.slot
import io.mockk.unmockkAll
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.security.MessageDigest
import java.util.Base64

/**
 * The Android backend of the BLE authenticator: the sharing policy decides
 * which passkeys a BLE client sees and may sign with, the counter comes from
 * the one [PasskeySignCounter], and the key never leaves Keystore.
 */
class AndroidFidoCredentialBackendTest {

    private val keyDao = mockk<KeyDao>(relaxed = true)
    private val credentialDao = mockk<CredentialMetadataDao>(relaxed = true)
    private val sharePermission = mockk<SharePermission>()
    private val signCounter = mockk<PasskeySignCounter>()
    private val keystore = mockk<KeystoreManager>(relaxed = true)

    private val shared = passkey(byteArrayOf(1, 2), SharingPolicyType.ALL_PEERS)
    private val private = passkey(byteArrayOf(3, 4), SharingPolicyType.PRIVATE)

    private fun passkey(id: ByteArray, policy: SharingPolicyType) = KeyEntity(
        keyId = b64(id),
        keyType = "fido2",
        algorithm = "ES256",
        label = "Example",
        keySizeBits = 256,
        source = "local",
        rpId = "example.com",
        userId = b64(byteArrayOf(9)),
        isDiscoverable = true,
        sharingPolicy = policy
    )

    private fun backend(prompt: FidoUserPrompt? = null) = AndroidFidoCredentialBackend(
        keyDao = keyDao,
        credentialDao = credentialDao,
        sharePermission = sharePermission,
        signCounter = signCounter,
        keystoreManager = keystore,
        userPrompt = prompt,
        settings = { BiometricSettingsData() }
    )

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.i(any(), any()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        coEvery { keyDao.getFido2ByRpId("example.com") } returns listOf(shared, private)
        coEvery { keyDao.getByKeyId(shared.keyId) } returns shared
        coEvery { keyDao.getByKeyId(private.keyId) } returns private
        coEvery { sharePermission.canShare(any(), null) } answers {
            firstArg<KeyEntity>().sharingPolicy == SharingPolicyType.ALL_PEERS
        }
        coEvery { signCounter.next(any()) } returns 5
        coEvery { keystore.signWithoutBiometric(any(), any()) } returns byteArrayOf(0x30)
    }

    @After
    fun tearDown() = unmockkAll()

    @Test
    fun `credentials lists only the passkeys the sharing policy shows a BLE client`() = runTest {
        val listed = backend().credentials("example.com")

        assertEquals(1, listed.size)
        assertArrayEquals(byteArrayOf(1, 2), listed[0].id)
        assertArrayEquals(byteArrayOf(9), listed[0].userHandle)
        assertTrue(listed[0].discoverable)
    }

    @Test
    fun `sign hashes authenticatorData and clientDataHash once inside the signature`() = runTest {
        val cred = backend().credentials("example.com").single()
        val input = slot<ByteArray>()
        coEvery { keystore.signWithoutBiometric(shared.keyId, capture(input)) } returns byteArrayOf(0x31)
        val cdh = ByteArray(32) { 1 }

        val signed = backend().sign(cred, { count -> byteArrayOf(count.toByte()) }, cdh)

        assertArrayEquals(byteArrayOf(5), signed.authenticatorData)
        assertArrayEquals(byteArrayOf(0x31), signed.signature)
        // SHA256withECDSA hashes its input, so the input is the raw
        // concatenation; a pre-hashed input would sign SHA-256(SHA-256(...)).
        assertArrayEquals(byteArrayOf(5) + cdh, input.captured)
        coVerify(exactly = 1) { signCounter.next(shared.keyId) }
    }

    @Test
    fun `sign refuses a passkey whose sharing policy changed after it was listed`() = runTest {
        val cred = backend().credentials("example.com").single()
        coEvery { keyDao.getByKeyId(shared.keyId) } returns shared.copy(sharingPolicy = SharingPolicyType.PRIVATE)

        val e = assertThrows(FidoRefusedException::class.java) {
            kotlinx.coroutines.runBlocking { backend().sign(cred, { ByteArray(0) }, ByteArray(32)) }
        }

        assertEquals(Ctap2.ERR_NO_CREDENTIALS, e.status)
        coVerify(exactly = 0) { signCounter.next(any()) }
        coVerify(exactly = 0) { keystore.signWithoutBiometric(any(), any()) }
    }

    @Test
    fun `create stores a passkey a BLE client can use again`() = runTest {
        coEvery { keystore.generateKeyWithAuthDuration(any(), any(), any()) } returns byteArrayOf(0xA5.toByte())
        val stored = slot<KeyEntity>()
        coEvery { keyDao.insert(capture(stored)) } returns 1L

        val made = backend().create(
            CredentialRequest("example.com", "Example", byteArrayOf(7), "alice", "Alice", discoverable = true)
        )

        assertArrayEquals(byteArrayOf(0xA5.toByte()), made.cosePublicKey)
        assertEquals(b64(made.id), stored.captured.keyId)
        assertEquals("fido2", stored.captured.keyType)
        assertEquals("example.com", stored.captured.rpId)
        assertEquals(b64(byteArrayOf(7)), stored.captured.userId)
        assertEquals(SharingPolicyType.ALL_PEERS, stored.captured.sharingPolicy)
        coVerify { credentialDao.insert(any()) }
    }

    /** Rows the DAOs hold, so a test sees what a failed create leaves behind. */
    private fun trackStoredRows(): Pair<MutableSet<String>, MutableSet<String>> {
        val keyRows = mutableSetOf<String>()
        val metadataRows = mutableSetOf<String>()
        coEvery { keystore.generateKeyWithAuthDuration(any(), any(), any()) } returns byteArrayOf(0xA5.toByte())
        coEvery { keyDao.insert(any()) } answers { keyRows += firstArg<KeyEntity>().keyId; 1L }
        coEvery { keyDao.deleteByKeyId(any()) } answers { if (keyRows.remove(firstArg())) 1 else 0 }
        coEvery { credentialDao.insert(any()) } answers {
            metadataRows += firstArg<CredentialMetadataEntity>().credentialId; 1L
        }
        coEvery { credentialDao.deleteByCredentialId(any()) } answers { if (metadataRows.remove(firstArg())) 1 else 0 }
        return keyRows to metadataRows
    }

    private fun assertCreateLeavesNothing(failure: Throwable, failKeyRow: Boolean) {
        val (keyRows, metadataRows) = trackStoredRows()
        if (failKeyRow) {
            coEvery { keyDao.insert(any()) } throws failure
        } else {
            coEvery { credentialDao.insert(any()) } throws failure
        }

        val thrown = runCatching {
            kotlinx.coroutines.runBlocking {
                backend().create(CredentialRequest("example.com", "Example", byteArrayOf(7), "alice", "Alice", true))
            }
        }.exceptionOrNull()

        assertTrue("create must fail", thrown != null)
        assertEquals("no key row may outlive a failed create", emptySet<String>(), keyRows)
        assertEquals("no metadata row may point at a deleted key", emptySet<String>(), metadataRows)
        io.mockk.verify(exactly = 1) { keystore.deleteKey(any()) }
    }

    @Test
    fun `a failed key row write leaves no metadata and no Keystore key`() =
        assertCreateLeavesNothing(IllegalStateException("disk full"), failKeyRow = true)

    @Test
    fun `a cancelled key row write leaves no metadata and no Keystore key`() =
        assertCreateLeavesNothing(kotlinx.coroutines.CancellationException("disconnected"), failKeyRow = true)

    @Test
    fun `a failed metadata write leaves no key row and no Keystore key`() =
        assertCreateLeavesNothing(IllegalStateException("disk full"), failKeyRow = false)

    @Test
    fun `without a prompt the user check is unavailable`() = runTest {
        assertEquals(UserCheck.UNAVAILABLE, backend().checkUser("example.com", registering = false))
        assertEquals(false, backend().userVerificationAvailable)
    }

    @Test
    fun `the prompt's answer is the user check`() = runTest {
        val prompt = object : FidoUserPrompt {
            override val available = true
            override suspend fun verify(rpId: String, registering: Boolean) = UserCheck.DECLINED
            override suspend fun chooseAccount(rpId: String, accounts: List<String>): Int? = null
            override suspend fun signWithKey(keyId: String, signedData: ByteArray, rpId: String) = ByteArray(0)
        }

        assertEquals(UserCheck.DECLINED, backend(prompt).checkUser("example.com", registering = true))
        assertEquals(true, backend(prompt).userVerificationAvailable)
    }

    @Test
    fun `the account chooser names each passkey by display name and user name and returns the pick`() = runTest {
        fun named(id: Byte, name: String?, display: String?) =
            FidoCredential(byteArrayOf(id), "example.com", byteArrayOf(id), name, display, discoverable = true)
        val candidates = listOf(named(1, "alice", "Alice"), named(2, "bob", "bob"), named(3, null, null))
        val asked = mutableListOf<List<String>>()
        val prompt = object : FidoUserPrompt {
            override val available = true
            override suspend fun verify(rpId: String, registering: Boolean) = UserCheck.VERIFIED
            override suspend fun chooseAccount(rpId: String, accounts: List<String>): Int {
                asked += accounts
                return 1
            }
            override suspend fun signWithKey(keyId: String, signedData: ByteArray, rpId: String) = ByteArray(0)
        }

        val chosen = backend(prompt).chooseCredential("example.com", candidates)

        assertEquals(listOf(listOf("Alice (alice)", "bob", "Account 3")), asked)
        assertArrayEquals(byteArrayOf(2), chosen!!.userHandle)
        assertEquals(null, backend().chooseCredential("example.com", candidates))
    }

    /** A prompt whose key-bound signature records what it was asked to sign. */
    private class BoundPrompt(private val outcome: () -> ByteArray) : FidoUserPrompt {
        val signed = mutableListOf<Pair<String, ByteArray>>()
        override val available = true
        override suspend fun verify(rpId: String, registering: Boolean) = UserCheck.VERIFIED
        override suspend fun chooseAccount(rpId: String, accounts: List<String>): Int? = null
        override suspend fun signWithKey(keyId: String, signedData: ByteArray, rpId: String): ByteArray {
            signed += keyId to signedData
            return outcome()
        }
    }

    @Test
    fun `a per-operation passkey signs through a prompt bound to its signature`() = runTest {
        val perOperation = shared.copy(authDurationSeconds = 0)
        coEvery { keyDao.getFido2ByRpId("example.com") } returns listOf(perOperation)
        coEvery { keyDao.getByKeyId(shared.keyId) } returns perOperation
        val prompt = BoundPrompt { byteArrayOf(0x32) }
        val cdh = ByteArray(32) { 2 }
        val cred = backend(prompt).credentials("example.com").single()

        val signed = backend(prompt).sign(cred, { count -> byteArrayOf(count.toByte()) }, cdh)

        assertArrayEquals(byteArrayOf(0x32), signed.signature)
        assertEquals(shared.keyId, prompt.signed.single().first)
        assertArrayEquals(byteArrayOf(5) + cdh, prompt.signed.single().second)
        coVerify(exactly = 0) { keystore.signWithoutBiometric(any(), any()) }
    }

    @Test
    fun `a passkey Keystore will not sign silently signs through the bound prompt`() = runTest {
        coEvery { keystore.signWithoutBiometric(any(), any()) } throws BiometricRequiredException()
        val prompt = BoundPrompt { byteArrayOf(0x33) }
        val cred = backend(prompt).credentials("example.com").single()

        val signed = backend(prompt).sign(cred, { byteArrayOf(1) }, ByteArray(32))

        assertArrayEquals(byteArrayOf(0x33), signed.signature)
        assertEquals(1, prompt.signed.size)
    }

    @Test
    fun `a declined key-bound prompt answers OPERATION_DENIED and signs nothing`() = runTest {
        val perOperation = shared.copy(authDurationSeconds = 0)
        coEvery { keyDao.getFido2ByRpId("example.com") } returns listOf(perOperation)
        coEvery { keyDao.getByKeyId(shared.keyId) } returns perOperation
        val prompt = BoundPrompt { throw UserCancelledException() }
        val cred = backend(prompt).credentials("example.com").single()

        val e = assertThrows(FidoRefusedException::class.java) {
            kotlinx.coroutines.runBlocking { backend(prompt).sign(cred, { byteArrayOf(1) }, ByteArray(32)) }
        }

        assertEquals(Ctap2.ERR_OPERATION_DENIED, e.status)
    }

    @Test
    fun `a per-operation passkey without a prompt answers OPERATION_DENIED`() = runTest {
        val perOperation = shared.copy(authDurationSeconds = 0)
        coEvery { keyDao.getFido2ByRpId("example.com") } returns listOf(perOperation)
        coEvery { keyDao.getByKeyId(shared.keyId) } returns perOperation
        val cred = backend().credentials("example.com").single()

        val e = assertThrows(FidoRefusedException::class.java) {
            kotlinx.coroutines.runBlocking { backend().sign(cred, { byteArrayOf(1) }, ByteArray(32)) }
        }

        assertEquals(Ctap2.ERR_OPERATION_DENIED, e.status)
        coVerify(exactly = 0) { keystore.signWithoutBiometric(any(), any()) }
    }

    @Test
    fun `a passkey made private while its key-bound prompt was open releases no signature`() = runTest {
        val perOperation = shared.copy(authDurationSeconds = 0)
        coEvery { keyDao.getFido2ByRpId("example.com") } returns listOf(perOperation)
        coEvery { keyDao.getByKeyId(shared.keyId) } returns perOperation
        val prompt = BoundPrompt {
            // The owner makes the passkey private while the prompt is up.
            coEvery { keyDao.getByKeyId(shared.keyId) } returns perOperation.copy(
                sharingPolicy = SharingPolicyType.PRIVATE
            )
            byteArrayOf(0x34)
        }
        val cred = backend(prompt).credentials("example.com").single()

        val e = assertThrows(FidoRefusedException::class.java) {
            kotlinx.coroutines.runBlocking { backend(prompt).sign(cred, { byteArrayOf(1) }, ByteArray(32)) }
        }

        assertEquals(Ctap2.ERR_OPERATION_DENIED, e.status)
    }

    @Test
    fun `a passkey deleted while it signed releases no signature`() = runTest {
        coEvery { keystore.signWithoutBiometric(any(), any()) } answers {
            coEvery { keyDao.getByKeyId(shared.keyId) } returns null
            byteArrayOf(0x35)
        }
        val cred = backend().credentials("example.com").single()

        val e = assertThrows(FidoRefusedException::class.java) {
            kotlinx.coroutines.runBlocking { backend().sign(cred, { byteArrayOf(1) }, ByteArray(32)) }
        }

        assertEquals(Ctap2.ERR_OPERATION_DENIED, e.status)
    }

    private companion object {
        fun b64(b: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(b)
    }
}
