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

import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.biometric.BiometricManager
import com.automatethethings.xkey.auth.BiometricActivityLauncher
import com.automatethethings.xkey.auth.NotificationKeys
import com.automatethethings.xkey.auth.PromptOwnership
import com.automatethethings.xkey.crypto.BiometricHelper
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.yield
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
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
        every { Log.w(any(), any<String>(), any()) } returns 0
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
    fun `passkeys stored with padded, standard or raw ids are listed and sign under their stored id`() = runTest {
        // Stored ids as other writers left them: padded base64, standard
        // base64 with '+' and '/', and an id that is not base64 at all.
        val padded = shared.copy(keyId = "AQI=")
        val standard = shared.copy(keyId = "+/8A")
        val raw = shared.copy(keyId = "passkey#1")
        val stored = listOf(padded, standard, raw)
        coEvery { keyDao.getFido2ByRpId("example.com") } returns stored
        stored.forEach { coEvery { keyDao.getByKeyId(it.keyId) } returns it }

        val listed = backend().credentials("example.com")

        assertEquals(3, listed.size)
        assertArrayEquals(byteArrayOf(1, 2), listed[0].id)
        assertArrayEquals(byteArrayOf(0xFB.toByte(), 0xFF.toByte(), 0), listed[1].id)
        assertArrayEquals("passkey#1".toByteArray(Charsets.UTF_8), listed[2].id)
        listed.zip(stored).forEach { (credential, entity) ->
            val signed = backend().sign(credential, { byteArrayOf(5) }, ByteArray(32))
            assertArrayEquals(byteArrayOf(0x30), signed.signature)
            coVerify(exactly = 1) { signCounter.next(entity.keyId) }
            coVerify(exactly = 1) { keystore.signWithoutBiometric(entity.keyId, any()) }
        }
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
        // One transaction over both row stores: a delete that throws (stubbed
        // per row on the two deletes above) rolls every row back.
        coEvery { keyDao.deletePasskeyRows(any()) } coAnswers {
            val keysBefore = keyRows.toSet()
            val metadataBefore = metadataRows.toSet()
            try {
                firstArg<List<String>>().forEach {
                    credentialDao.deleteByCredentialId(it)
                    keyDao.deleteByKeyId(it)
                }
            } catch (e: Throwable) {
                keyRows.clear(); keyRows += keysBefore
                metadataRows.clear(); metadataRows += metadataBefore
                throw e
            }
        }
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

    /** [shared] and [private] stored as rows, both discoverable for user 9 on example.com. */
    private fun storedResidents(): Pair<MutableSet<String>, MutableSet<String>> {
        val (keyRows, metadataRows) = trackStoredRows()
        keyRows += listOf(shared.keyId, private.keyId)
        metadataRows += listOf(shared.keyId, private.keyId)
        return keyRows to metadataRows
    }

    @Test
    fun `a repeated resident registration replaces the client's discoverable passkey for that user`() = runTest {
        val (keyRows, metadataRows) = storedResidents()

        val made = backend().create(
            CredentialRequest("example.com", "Example", byteArrayOf(9), "alice", "Alice", discoverable = true)
        )

        // The new passkey replaces the shared one in both stores and in
        // Keystore. The private one, which a BLE client never sees, stays.
        assertEquals(setOf(private.keyId, b64(made.id)), keyRows)
        assertEquals(setOf(private.keyId, b64(made.id)), metadataRows)
        io.mockk.verify(exactly = 1) { keystore.deleteKey(shared.keyId) }
        io.mockk.verify(exactly = 0) { keystore.deleteKey(private.keyId) }
    }

    @Test
    fun `a failed resident registration leaves the old passkey usable`() = runTest {
        val (keyRows, metadataRows) = storedResidents()
        coEvery { credentialDao.insert(any()) } throws IllegalStateException("disk full")

        val thrown = runCatching {
            backend().create(CredentialRequest("example.com", "Example", byteArrayOf(9), "alice", "Alice", true))
        }.exceptionOrNull()

        assertTrue("create must fail", thrown != null)
        assertEquals(setOf(shared.keyId, private.keyId), keyRows)
        assertEquals(setOf(shared.keyId, private.keyId), metadataRows)
        io.mockk.verify(exactly = 0) { keystore.deleteKey(shared.keyId) }
        val signed = backend().sign(backend().credentials("example.com").single(), { byteArrayOf(5) }, ByteArray(32))
        assertArrayEquals(byteArrayOf(0x30), signed.signature)
    }

    /** Key rows as one live store: what a registration inserts, the next one's lookup sees. */
    private fun liveKeyRows(): MutableMap<String, KeyEntity> {
        val rows = linkedMapOf<String, KeyEntity>()
        coEvery { keystore.generateKeyWithAuthDuration(any(), any(), any()) } returns byteArrayOf(0xA5.toByte())
        coEvery { keyDao.insert(any()) } answers { val e = firstArg<KeyEntity>(); rows[e.keyId] = e; 1L }
        coEvery { keyDao.deleteByKeyId(any()) } answers { if (rows.remove(firstArg<String>()) != null) 1 else 0 }
        coEvery { keyDao.deletePasskeyRows(any()) } coAnswers {
            firstArg<List<String>>().forEach { rows.remove(it) }
        }
        coEvery { keyDao.getFido2ByRpId("example.com") } coAnswers { yield(); rows.values.toList() }
        return rows
    }

    @Test
    fun `two concurrent resident registrations for one account leave exactly one discoverable passkey`() = runTest {
        val rows = liveKeyRows()
        val request = CredentialRequest("example.com", "Example", byteArrayOf(9), "alice", "Alice", discoverable = true)

        val first = async { backend().create(request) }
        val second = async { backend().create(request) }
        val made = listOf(first.await(), second.await())

        assertEquals(1, rows.size)
        assertTrue(made.any { b64(it.id) in rows })
    }

    @Test
    fun `a registration whose replacement lookup fails rolls back and leaves the old passkey usable`() = runTest {
        val (keyRows, metadataRows) = storedResidents()
        var lookups = 0
        coEvery { keyDao.getFido2ByRpId("example.com") } answers {
            if (lookups++ == 0) throw IllegalStateException("database closed") else listOf(shared, private)
        }

        val thrown = runCatching {
            backend().create(CredentialRequest("example.com", "Example", byteArrayOf(9), "alice", "Alice", true))
        }.exceptionOrNull()

        assertTrue("create must fail, got $thrown", thrown is IllegalStateException)
        assertEquals(setOf(shared.keyId, private.keyId), keyRows)
        assertEquals(setOf(shared.keyId, private.keyId), metadataRows)
        io.mockk.verify(exactly = 0) { keystore.deleteKey(shared.keyId) }
        val signed = backend().sign(backend().credentials("example.com").single(), { byteArrayOf(5) }, ByteArray(32))
        assertArrayEquals(byteArrayOf(0x30), signed.signature)
    }

    @Test
    fun `a replacement whose key row will not delete fails the registration and leaves the old passkey whole`() = runTest {
        val (keyRows, metadataRows) = storedResidents()
        coEvery { keyDao.deleteByKeyId(shared.keyId) } throws IllegalStateException("disk I/O error")

        val thrown = runCatching {
            backend().create(CredentialRequest("example.com", "Example", byteArrayOf(9), "alice", "Alice", true))
        }.exceptionOrNull()

        // The registration fails, the new passkey is gone, and the old one
        // keeps both its rows (the credential provider still lists it) and
        // its Keystore key.
        assertTrue("create must fail, got $thrown", thrown is IllegalStateException)
        assertEquals(setOf(shared.keyId, private.keyId), keyRows)
        assertEquals(setOf(shared.keyId, private.keyId), metadataRows)
        io.mockk.verify(exactly = 0) { keystore.deleteKey(shared.keyId) }
        io.mockk.verify(exactly = 1) { keystore.deleteKey(any()) }
    }

    @Test
    fun `user handles match by their bytes, whatever base64 stored them`() = runTest {
        val handle = byteArrayOf(0xFB.toByte(), 0xFF.toByte())
        // "+/8=": the same bytes as the request's "-_8", in standard padded base64.
        val sameUser = shared.copy(userId = Base64.getEncoder().encodeToString(handle))
        val otherUser = passkey(byteArrayOf(5, 6), SharingPolicyType.ALL_PEERS)
            .copy(userId = b64(byteArrayOf(0xFB.toByte())))
        val (keyRows, metadataRows) = trackStoredRows()
        keyRows += listOf(sameUser.keyId, otherUser.keyId)
        metadataRows += listOf(sameUser.keyId, otherUser.keyId)
        coEvery { keyDao.getFido2ByRpId("example.com") } returns listOf(sameUser, otherUser)

        val made = backend().create(CredentialRequest("example.com", "Example", handle, "alice", "Alice", true))

        assertEquals(setOf(otherUser.keyId, b64(made.id)), keyRows)
        io.mockk.verify(exactly = 1) { keystore.deleteKey(sameUser.keyId) }
        io.mockk.verify(exactly = 0) { keystore.deleteKey(otherUser.keyId) }
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
            override suspend fun chooseAccount(rpId: String, accounts: List<String>): Int? = null
            override suspend fun signWithKey(keyId: String, keyAlias: String, rpId: String, signedData: suspend () -> ByteArray) = ByteArray(0)
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
            override suspend fun signWithKey(keyId: String, keyAlias: String, rpId: String, signedData: suspend () -> ByteArray) = ByteArray(0)
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
        override suspend fun signWithKey(
            keyId: String,
            keyAlias: String,
            rpId: String,
            signedData: suspend () -> ByteArray
        ): ByteArray {
            signed += keyId to signedData()
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
    fun `per-operation passkeys in the general and the credential namespace sign under their own Keystore alias`() = runTest {
        // local.generateKey stores a desktop-made passkey as xkey_key_<id>; the
        // credential provider as xkey_credential_<id>. The key-bound prompt
        // must be handed the alias the key really has.
        val general = shared.copy(keyId = "gen1", authDurationSeconds = 0)
        val credential = shared.copy(keyId = "cred1", authDurationSeconds = 0)
        coEvery { keyDao.getFido2ByRpId("example.com") } returns listOf(general, credential)
        coEvery { keyDao.getByKeyId("gen1") } returns general
        coEvery { keyDao.getByKeyId("cred1") } returns credential
        every { keystore.resolveKeystoreAlias("gen1") } returns "xkey_key_gen1"
        every { keystore.resolveKeystoreAlias("cred1") } returns "xkey_credential_cred1"
        val manager = mockk<BiometricManager>()
        every { manager.canAuthenticate(any()) } returns BiometricManager.BIOMETRIC_SUCCESS
        mockkStatic(BiometricManager::class)
        every { BiometricManager.from(any()) } returns manager
        val launcher = mockk<BiometricActivityLauncher>(relaxed = true)
        val aliases = mutableListOf<String?>()
        coEvery {
            launcher.requestCryptoSignatureOnTurn(any(), any(), any(), any(), any(), captureNullable(aliases), any())
        } returns byteArrayOf(0x36)
        val unlocked = object : FidoLockScreen {
            override val locked = false
            override fun post(operationType: String, rpId: String, key: String, prompt: Intent, onTimeout: () -> Unit) = Unit
            override fun cancel(key: String) = Unit
        }
        val prompt = BiometricFidoUserPrompt(mockk<Context>(relaxed = true), unlocked) { launcher }

        val signatures = backend(prompt).credentials("example.com").map { cred ->
            backend(prompt).sign(cred, { byteArrayOf(1) }, ByteArray(32)).signature
        }

        assertEquals(listOf("xkey_key_gen1", "xkey_credential_cred1"), aliases)
        signatures.forEach { assertArrayEquals(byteArrayOf(0x36), it) }
    }

    @Test
    fun `concurrent provider and BLE assertions sign strictly increasing counters in signing order`() = runTest {
        val perOperation = shared.copy(authDurationSeconds = 0)
        coEvery { keyDao.getFido2ByRpId("example.com") } returns listOf(perOperation)
        coEvery { keyDao.getByKeyId(shared.keyId) } returns perOperation
        var counter = 0L
        coEvery { signCounter.next(shared.keyId) } answers { ++counter }
        val signedCounts = mutableListOf<Long>()
        // The key-bound prompt as the launcher runs it: its own entry on the
        // one prompt queue, signing only once that entry's turn comes.
        val prompt = object : FidoUserPrompt {
            override val available = true
            override suspend fun verify(rpId: String, registering: Boolean) = UserCheck.VERIFIED
            override suspend fun chooseAccount(rpId: String, accounts: List<String>): Int? = null
            override suspend fun signWithKey(
                keyId: String,
                keyAlias: String,
                rpId: String,
                signedData: suspend () -> ByteArray
            ): ByteArray = PromptOwnership.process.turn(
                NotificationKeys.wakeOnly("bleSignature"),
                PromptOwnership.Kind.CRYPTO_SIGNING
            ) {
                signedCounts += signedData()[0].toLong()
                byteArrayOf(0x37)
            }!!
        }
        // A credential provider assertion holds the screen first: it reads
        // its counter and signs inside its one queue turn, as
        // GetCredentialHandler does.
        val providerMayFinish = CompletableDeferred<Unit>()
        val provider = launch {
            BiometricHelper.inOneTurn("passkeyAssertion") {
                providerMayFinish.await()
                signedCounts += signCounter.next(shared.keyId)
            }
        }
        runCurrent()
        val cred = backend(prompt).credentials("example.com").single()

        val ble = async { backend(prompt).sign(cred, { count -> byteArrayOf(count.toByte()) }, ByteArray(32)) }
        runCurrent()
        providerMayFinish.complete(Unit)
        provider.join()
        ble.await()

        assertEquals("counters in the order they were signed", listOf(1L, 2L), signedCounts)
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
    fun `a cancelled key-bound sign propagates the cancellation, not a CTAP error`() = runTest {
        val perOperation = shared.copy(authDurationSeconds = 0)
        coEvery { keyDao.getFido2ByRpId("example.com") } returns listOf(perOperation)
        coEvery { keyDao.getByKeyId(shared.keyId) } returns perOperation
        val prompt = BoundPrompt { throw CancellationException("the client went away") }
        val cred = backend(prompt).credentials("example.com").single()

        val thrown = runCatching { backend(prompt).sign(cred, { byteArrayOf(1) }, ByteArray(32)) }.exceptionOrNull()

        assertTrue("got $thrown", thrown is CancellationException)
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
