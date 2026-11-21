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
import com.automatethethings.xkey.crypto.ApprovedKeyChangedException
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.protocol.SharePermission
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.storage.dao.CredentialMetadataDao
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import com.automatethethings.xkey.testing.ReleaseMocks
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import java.util.Base64

/**
 * A BLE assertion signs with the passkey the client chose, or not at all.
 * While its prompt or signing turn waits, another transport may delete the
 * passkey and create a new one under the same credential ID (a new row, a new
 * Keystore key under the same alias). The assertion must then be refused: a
 * signature by the new key would not verify against the public key the client
 * registered.
 */
class PasskeyReplacedWhileSigningTest {

    @get:Rule
    val releaseMocks = ReleaseMocks()

    private val keyDao = mockk<KeyDao>(relaxed = true)
    private val sharePermission = mockk<SharePermission>()
    private val signCounter = mockk<PasskeySignCounter>()
    private val keystore = mockk<KeystoreManager>(relaxed = true)

    private val keyId = Base64.getUrlEncoder().withoutPadding().encodeToString(byteArrayOf(1, 2))
    private val alias = "xkey_credential_$keyId"

    /** The Keystore as the backend sees it: the public key under each alias. */
    private val keys = mutableMapOf(alias to OLD_DER)

    private fun row(rowId: Long, cose: ByteArray, authDuration: Int) = KeyEntity(
        id = rowId,
        keyId = keyId,
        keyType = "fido2",
        algorithm = "ES256",
        label = "Example",
        keySizeBits = 256,
        source = "local",
        rpId = "example.com",
        userId = "CQ",
        isDiscoverable = true,
        publicKeyCose = cose,
        authDurationSeconds = authDuration,
        sharingPolicy = SharingPolicyType.ALL_PEERS
    )

    /** Another transport deletes the passkey and registers a new one under the same ID. */
    private fun recreate(authDuration: Int) {
        val replacement = row(2, byteArrayOf(0x0B), authDuration)
        coEvery { keyDao.getByKeyId(keyId) } returns replacement
        coEvery { keyDao.getFido2ByRpId("example.com") } returns listOf(replacement)
        keys[alias] = NEW_DER
    }

    private fun backend(prompt: FidoUserPrompt? = null) = AndroidFidoCredentialBackend(
        keyDao = keyDao,
        credentialDao = mockk<CredentialMetadataDao>(relaxed = true),
        sharePermission = sharePermission,
        signCounter = signCounter,
        keystoreManager = keystore,
        userPrompt = prompt,
        settings = { BiometricSettingsData() },
        pendingKeyDeletions = FilePendingKeyDeletions(
            java.io.File.createTempFile("pending-key-deletions", "").also { it.delete(); it.deleteOnExit() }
        )
    )

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.i(any(), any()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        coEvery { sharePermission.canShare(any(), null) } returns true
        coEvery { signCounter.next(any()) } returns 5
        every { keystore.keyRowAlias(keyId, any(), any()) } returns alias
        every { keystore.resolveKeystoreAlias(keyId) } returns alias
        every { keystore.publicKeyDERAt(any()) } answers { keys[firstArg()] }
        // Signs with whatever key the alias holds now.
        coEvery { keystore.signWithoutBiometric(keyId, any()) } answers { signatureBy(keys.getValue(alias)) }
        // Signs only while the alias holds the approved key, as Keystore's
        // signApproved does.
        coEvery { keystore.signApproved(any(), any(), any(), any()) } answers {
            val current = keys[firstArg()]
            if (current == null || !current.contentEquals(secondArg())) {
                throw ApprovedKeyChangedException(firstArg())
            }
            signatureBy(current)
        }
    }

    @After
    fun tearDown() = unmockkAll()

    private fun stored(authDuration: Int) {
        val original = row(1, byteArrayOf(0x0A), authDuration)
        coEvery { keyDao.getByKeyId(keyId) } returns original
        coEvery { keyDao.getFido2ByRpId("example.com") } returns listOf(original)
    }

    /** Signs with the key under the alias it is handed, when the prompt is approved. */
    private inner class KeyBoundPrompt(
        private val beforeTurn: () -> Unit = {},
        private val beforeSignature: () -> Unit = {}
    ) : FidoUserPrompt {
        override val available = true
        override suspend fun verify(rpId: String, registering: Boolean) = UserCheck.VERIFIED
        override suspend fun chooseAccount(rpId: String, accounts: List<String>): Int? = null
        override suspend fun signWithKey(
            keyId: String,
            keyAlias: String,
            rpId: String,
            signedData: suspend () -> ByteArray
        ): ByteArray {
            beforeTurn()
            signedData()
            beforeSignature()
            return signatureBy(keys.getValue(keyAlias))
        }
    }

    private suspend fun assertNoAssertion(backend: AndroidFidoCredentialBackend) {
        val cred = backend.credentials("example.com").single()
        val outcome = runCatching { backend.sign(cred, { byteArrayOf(5) }, ByteArray(32)) }
        outcome.getOrNull()?.let {
            assertFalse("signed with the new key", it.signature.contentEquals(signatureBy(NEW_DER)))
            fail("an assertion was released for a passkey replaced while it signed")
        }
        val refused = outcome.exceptionOrNull()
        if (refused !is FidoRefusedException) throw AssertionError("expected a refusal, got $refused", refused)
        assertEquals(Ctap2.ERR_OPERATION_DENIED, refused.status)
    }

    @Test
    fun `a passkey recreated while its key-bound prompt waits yields no assertion`() = runTest {
        stored(authDuration = 0)
        assertNoAssertion(backend(KeyBoundPrompt(beforeTurn = { recreate(authDuration = 0) })))
    }

    @Test
    fun `a passkey recreated while its key-bound signature is made yields no assertion`() = runTest {
        stored(authDuration = 0)
        assertNoAssertion(backend(KeyBoundPrompt(beforeSignature = { recreate(authDuration = 0) })))
    }

    @Test
    fun `a passkey recreated during its silent signing turn yields no assertion`() = runTest {
        stored(authDuration = -1)
        coEvery { signCounter.next(keyId) } answers {
            recreate(authDuration = -1)
            5
        }
        assertNoAssertion(backend())
    }

    /** A prompt whose user check and account chooser run [during] while they wait. */
    private inner class CeremonyPrompt(private val during: () -> Unit) : FidoUserPrompt {
        override val available = true
        override suspend fun verify(rpId: String, registering: Boolean): UserCheck {
            during()
            return UserCheck.VERIFIED
        }
        override suspend fun chooseAccount(rpId: String, accounts: List<String>): Int? {
            during()
            return 0
        }
        override suspend fun signWithKey(
            keyId: String,
            keyAlias: String,
            rpId: String,
            signedData: suspend () -> ByteArray
        ): ByteArray = signatureBy(keys.getValue(keyAlias)).also { signedData() }
    }

    /**
     * The order Ctap2Authenticator.getAssertion runs a ceremony in: list,
     * choose the account, check the user, sign. [ask] is the step the
     * passkey is recreated during.
     */
    private suspend fun assertNoAssertionAfter(
        backend: AndroidFidoCredentialBackend,
        ask: suspend (FidoCredential) -> Unit
    ) {
        val cred = backend.credentials("example.com").single()
        ask(cred)
        val outcome = runCatching { backend.sign(cred, { byteArrayOf(5) }, ByteArray(32)) }
        outcome.getOrNull()?.let {
            assertFalse("signed with the new key", it.signature.contentEquals(signatureBy(NEW_DER)))
            fail("an assertion was released for a passkey replaced before it signed")
        }
        val refused = outcome.exceptionOrNull()
        if (refused !is FidoRefusedException) throw AssertionError("expected a refusal, got $refused", refused)
    }

    @Test
    fun `a passkey recreated during the user check yields no assertion`() = runTest {
        stored(authDuration = -1)
        val backend = backend(CeremonyPrompt { recreate(authDuration = -1) })
        assertNoAssertionAfter(backend) { backend.checkUser("example.com", registering = false) }
    }

    @Test
    fun `a passkey recreated while the account is chosen yields no assertion`() = runTest {
        stored(authDuration = -1)
        val backend = backend(CeremonyPrompt { recreate(authDuration = -1) })
        assertNoAssertionAfter(backend) { cred ->
            assertEquals(cred.id.toList(), backend.chooseCredential("example.com", listOf(cred))?.id?.toList())
        }
    }

    @Test
    fun `a key-bound passkey recreated during the user check yields no assertion`() = runTest {
        stored(authDuration = 0)
        val backend = backend(CeremonyPrompt { recreate(authDuration = 0) })
        assertNoAssertionAfter(backend) { backend.checkUser("example.com", registering = false) }
    }

    private companion object {
        val OLD_DER = byteArrayOf(0x30, 0x01)
        val NEW_DER = byteArrayOf(0x30, 0x02)

        fun signatureBy(der: ByteArray): ByteArray = byteArrayOf(0x53) + der
    }
}
