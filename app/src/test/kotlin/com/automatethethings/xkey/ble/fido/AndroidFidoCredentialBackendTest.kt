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
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.protocol.SharePermission
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.storage.dao.CredentialMetadataDao
import com.automatethethings.xkey.storage.dao.KeyDao
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
    fun `sign takes the shared counter and signs the hash in Keystore`() = runTest {
        val cred = backend().credentials("example.com").single()
        val hash = slot<ByteArray>()
        coEvery { keystore.signWithoutBiometric(shared.keyId, capture(hash)) } returns byteArrayOf(0x31)
        val cdh = ByteArray(32) { 1 }

        val signed = backend().sign(cred, { count -> byteArrayOf(count.toByte()) }, cdh)

        assertArrayEquals(byteArrayOf(5), signed.authenticatorData)
        assertArrayEquals(byteArrayOf(0x31), signed.signature)
        assertArrayEquals(MessageDigest.getInstance("SHA-256").digest(byteArrayOf(5) + cdh), hash.captured)
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
        }

        assertEquals(UserCheck.DECLINED, backend(prompt).checkUser("example.com", registering = true))
        assertEquals(true, backend(prompt).userVerificationAvailable)
    }

    private companion object {
        fun b64(b: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(b)
    }
}
