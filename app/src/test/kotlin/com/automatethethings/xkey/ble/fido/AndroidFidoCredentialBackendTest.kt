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
import com.automatethethings.xkey.testing.ReleaseMocks
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
import org.junit.Rule
import org.junit.Test
import java.security.MessageDigest
import java.util.Base64

/**
 * The Android backend of the BLE authenticator: the sharing policy decides
 * which passkeys a BLE client sees and may sign with, the counter comes from
 * the one [PasskeySignCounter], and the key never leaves Keystore.
 */
class AndroidFidoCredentialBackendTest {

    /** Drops what MockK recorded here, so it does not outlive the test. */
    @get:Rule
    val releaseMocks = ReleaseMocks()

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

    private fun backend(
        prompt: FidoUserPrompt? = null,
        pending: PendingKeyDeletions = pendingKeyDeletions
    ) = AndroidFidoCredentialBackend(
        keyDao = keyDao,
        credentialDao = credentialDao,
        sharePermission = sharePermission,
        signCounter = signCounter,
        keystoreManager = keystore,
        userPrompt = prompt,
        settings = { BiometricSettingsData() },
        pendingKeyDeletions = pending
    )

    /** One record file per test, shared by every backend it makes, as across a restart. */
    private val pendingKeyDeletions = FilePendingKeyDeletions(
        java.io.File.createTempFile("pending-key-deletions", "").also { it.delete(); it.deleteOnExit() }
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
    fun `passkeys whose algorithm the BLE signer cannot use are never offered or signed with`() = runTest {
        // local.generateKey can store shared fido2 rows of other algorithms;
        // every BLE signature is ES256 (SHA256withECDSA on a P-256 key).
        val others = listOf("ES384", "ES512", "RS256").mapIndexed { i, alg ->
            shared.copy(keyId = b64(byteArrayOf(0x40, i.toByte())), algorithm = alg)
        }
        coEvery { keyDao.getFido2ByRpId("example.com") } returns others
        others.forEach { coEvery { keyDao.getByKeyId(it.keyId) } returns it }

        assertTrue("no unsupported passkey is listed", backend().credentials("example.com").isEmpty())
        others.forEach { entity ->
            val wire = Base64.getUrlDecoder().decode(entity.keyId)
            val e = assertThrows(FidoRefusedException::class.java) {
                kotlinx.coroutines.runBlocking {
                    backend().sign(
                        FidoCredential(wire, "example.com", byteArrayOf(9), null, null, true),
                        { byteArrayOf(5) },
                        ByteArray(32)
                    )
                }
            }
            assertEquals(Ctap2.ERR_NO_CREDENTIALS, e.status)
        }
        coVerify(exactly = 0) { keystore.signWithoutBiometric(any(), any()) }
        coVerify(exactly = 0) { signCounter.next(any()) }
    }

    @Test
    fun `an unsupported passkey ahead of an ES256 one in the allowList never shadows it`() = runTest {
        val es384 = shared.copy(keyId = b64(byteArrayOf(0x41)), algorithm = "ES384")
        coEvery { keyDao.getFido2ByRpId("example.com") } returns listOf(es384, shared)
        coEvery { keyDao.getByKeyId(es384.keyId) } returns es384
        // The allowList as Ctap2Authenticator.getAssertion applies it: the
        // credentials offered, filtered to the IDs the client allows.
        val allowList = listOf(byteArrayOf(0x41), byteArrayOf(1, 2))
        val listed = backend().credentials("example.com")
        val candidates = listed.filter { c -> allowList.any { it.contentEquals(c.id) } }

        assertEquals(listOf(byteArrayOf(1, 2).toList()), candidates.map { it.id.toList() })
        val signed = backend().sign(candidates.first(), { byteArrayOf(5) }, ByteArray(32))
        assertArrayEquals(byteArrayOf(0x30), signed.signature)
        coVerify(exactly = 1) { keystore.signWithoutBiometric(shared.keyId, any()) }
        coVerify(exactly = 0) { keystore.signWithoutBiometric(es384.keyId, any()) }
    }

    @Test
    fun `create stores a passkey a BLE client can use again`() = runTest {
        coEvery { keystore.generateKeyWithAuthDuration(any(), any(), any()) } returns byteArrayOf(0xA5.toByte())
        val stored = slot<KeyEntity>()
        coEvery { keyDao.completePasskeyRegistration(capture(stored), any(), any()) } returns emptyList()

        val made = backend().create(
            CredentialRequest("example.com", "Example", byteArrayOf(7), "alice", "Alice", discoverable = true)
        )

        assertArrayEquals(byteArrayOf(0xA5.toByte()), made.cosePublicKey)
        assertEquals(b64(made.id), stored.captured.keyId)
        assertEquals("fido2", stored.captured.keyType)
        assertEquals("example.com", stored.captured.rpId)
        assertEquals(b64(byteArrayOf(7)), stored.captured.userId)
        assertEquals(SharingPolicyType.ALL_PEERS, stored.captured.sharingPolicy)
        coVerify { keyDao.completePasskeyRegistration(any(), match { it.credentialId == b64(made.id) }, emptyList()) }
        assertTrue("a whole passkey is offered", pendingKeyDeletions.registrations().isEmpty())
    }

    /** What [KeyDao.deletePasskeyRows] matches: the row as read is the row now, its policy unchanged. */
    private fun unchanged(read: KeyEntity, now: KeyEntity?): Boolean =
        now != null && now.id == read.id && now.policyRevision == read.policyRevision &&
            now.sharingPolicy == read.sharingPolicy

    /** Rows the DAOs hold, so a test sees what a failed create leaves behind. */
    private fun trackStoredRows(): Pair<MutableSet<String>, MutableSet<String>> {
        val keyRows = mutableSetOf<String>()
        val metadataRows = mutableSetOf<String>()
        val entities = mutableMapOf(shared.keyId to shared, private.keyId to private)
        coEvery { keystore.generateKeyWithAuthDuration(any(), any(), any()) } returns byteArrayOf(0xA5.toByte())
        coEvery { keyDao.insert(any()) } answers {
            val e = firstArg<KeyEntity>(); keyRows += e.keyId; entities[e.keyId] = e; 1L
        }
        coEvery { keyDao.getByKeyId(any()) } answers { firstArg<String>().let { if (it in keyRows) entities[it] else null } }
        coEvery { keyDao.deleteByKeyId(any()) } answers { if (keyRows.remove(firstArg())) 1 else 0 }
        coEvery { credentialDao.insert(any()) } answers {
            metadataRows += firstArg<CredentialMetadataEntity>().credentialId; 1L
        }
        coEvery { credentialDao.deleteByCredentialId(any()) } answers { if (metadataRows.remove(firstArg())) 1 else 0 }
        // A new passkey's two rows in one transaction (stubbed per row on the
        // two inserts above): when the metadata insert throws, the key row
        // is rolled back with it.
        coEvery { keyDao.insertPasskeyRows(any(), any()) } coAnswers {
            val key = firstArg<KeyEntity>()
            keyDao.insert(key)
            try {
                credentialDao.insert(secondArg())
            } catch (e: Throwable) {
                keyRows.remove(key.keyId)
                throw e
            }
        }
        // One transaction over both row stores: a delete that throws (stubbed
        // per row on the two deletes above) rolls every row back. A row goes
        // only while its policy is still the one the caller read.
        coEvery { keyDao.deletePasskeyRows(any()) } coAnswers {
            val keysBefore = keyRows.toSet()
            val metadataBefore = metadataRows.toSet()
            try {
                firstArg<List<KeyEntity>>().filter { unchanged(it, keyDao.getByKeyId(it.keyId)) }.map {
                    keyDao.deleteByKeyId(it.keyId)
                    credentialDao.deleteByCredentialId(it.keyId)
                    it.keyId
                }
            } catch (e: Throwable) {
                keyRows.clear(); keyRows += keysBefore
                metadataRows.clear(); metadataRows += metadataBefore
                throw e
            }
        }
        stubCompletion(keyRows, metadataRows)
        return keyRows to metadataRows
    }

    /**
     * A registration's commit as one transaction over both row stores: the
     * new passkey's rows (stubbed by [KeyDao.insertPasskeyRows]) and the
     * replaced passkeys' deletes (stubbed by [KeyDao.deletePasskeyRows]),
     * all rolled back when any of them throws.
     */
    private fun stubCompletion(keyRows: MutableSet<String>, metadataRows: MutableSet<String>) {
        coEvery { keyDao.completePasskeyRegistration(any(), any(), any()) } coAnswers {
            val keysBefore = keyRows.toSet()
            val metadataBefore = metadataRows.toSet()
            try {
                keyDao.insertPasskeyRows(firstArg(), secondArg())
                keyDao.deletePasskeyRows(thirdArg())
            } catch (e: Throwable) {
                keyRows.clear(); keyRows += keysBefore
                metadataRows.clear(); metadataRows += metadataBefore
                throw e
            }
        }
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
    fun `a failed metadata write whose deletion record cannot be written still leaves nothing`() = runTest {
        val (keyRows, metadataRows) = trackStoredRows()
        coEvery { credentialDao.insert(any()) } throws IllegalStateException("disk full")
        coEvery { keyDao.getFido2ByRpId("example.com") } answers {
            keyRows.mapNotNull { id -> kotlinx.coroutines.runBlocking { keyDao.getByKeyId(id) } }
        }
        // Storage is full: the deletion record cannot be written either.
        val unwritable = object : PendingKeyDeletions {
            override fun add(keyIds: Collection<String>) = throw java.io.IOException("disk full")
            override fun addRegistration(keyId: String) = Unit
            override fun remove(keyId: String) = Unit
            override fun all(): Set<String> = emptySet()
            override fun registrations(): Set<String> = emptySet()
        }

        val thrown = runCatching {
            backend(pending = unwritable)
                .create(CredentialRequest("example.com", "Example", byteArrayOf(7), "alice", "Alice", true))
        }.exceptionOrNull()

        assertTrue("create must fail", thrown != null)
        assertEquals("no key row may outlive a failed create", emptySet<String>(), keyRows)
        assertEquals("no metadata row may outlive a failed create", emptySet<String>(), metadataRows)
        io.mockk.verify(exactly = 1) { keystore.deleteKey(any()) }
        assertTrue(
            "the failed passkey is never offered",
            backend(pending = unwritable).credentials("example.com").isEmpty()
        )
    }

    /** Lists the key rows [keyRows] holds for example.com, as the DAO would. */
    private fun listStoredRows(keyRows: Set<String>) {
        coEvery { keyDao.getFido2ByRpId("example.com") } answers {
            keyRows.toList().mapNotNull { id -> kotlinx.coroutines.runBlocking { keyDao.getByKeyId(id) } }
        }
    }

    /** Storage that fails every row delete while [broken] says so, then recovers. */
    private fun rowDeletesFailWhile(keyRows: MutableSet<String>, broken: () -> Boolean) {
        coEvery { keyDao.deleteByKeyId(any()) } answers {
            if (broken()) throw IllegalStateException("disk I/O error")
            if (keyRows.remove(firstArg())) 1 else 0
        }
    }

    @Test
    fun `a failed metadata write whose rollback delete also fails is never offered and is cleaned up on retry`() = runTest {
        val (keyRows, metadataRows) = trackStoredRows()
        listStoredRows(keyRows)
        var broken = true
        rowDeletesFailWhile(keyRows) { broken }
        coEvery { credentialDao.insert(any()) } answers {
            if (broken) throw IllegalStateException("disk full")
            metadataRows += firstArg<CredentialMetadataEntity>().credentialId; 1L
        }

        val thrown = runCatching {
            backend().create(CredentialRequest("example.com", "Example", byteArrayOf(7), "alice", "Alice", true))
        }.exceptionOrNull()
        assertTrue("create must fail", thrown != null)
        assertTrue("the failed registration is never offered", backend().credentials("example.com").isEmpty())

        // Storage recovers; the next registration, on a fresh backend as
        // after a restart, cleans up whatever the failed one left.
        broken = false
        val made = backend().create(CredentialRequest("example.com", "Example", byteArrayOf(8), "bob", "Bob", true))

        assertEquals(setOf(b64(made.id)), keyRows)
        assertEquals(setOf(b64(made.id)), metadataRows)
        assertEquals(listOf(made.id.toList()), backend().credentials("example.com").map { it.id.toList() })
        io.mockk.verify(exactly = 1) { keystore.deleteKey(any()) }
    }

    @Test
    fun `a failed replacement whose rollback delete also fails is never offered and is cleaned up on retry`() = runTest {
        val (keyRows, metadataRows) = storedResidents()
        listStoredRows(keyRows)
        var broken = true
        rowDeletesFailWhile(keyRows) { broken }
        val generated = mutableListOf<String>()
        coEvery { keystore.generateKeyWithAuthDuration(any(), any(), any()) } answers {
            generated += firstArg<String>(); byteArrayOf(0xA5.toByte())
        }

        // The new passkey's rows are written, the old passkey's rows will not
        // go, and neither will the new passkey's in the rollback.
        val thrown = runCatching {
            backend().create(CredentialRequest("example.com", "Example", byteArrayOf(9), "alice", "Alice", true))
        }.exceptionOrNull()
        assertTrue("create must fail", thrown != null)
        val failed = generated.single()
        assertEquals(
            "only the old shared passkey is offered",
            listOf(byteArrayOf(1, 2).toList()),
            backend().credentials("example.com").map { it.id.toList() }
        )
        val signed = backend().sign(backend().credentials("example.com").single(), { byteArrayOf(5) }, ByteArray(32))
        assertArrayEquals(byteArrayOf(0x30), signed.signature)

        broken = false
        val made = backend().create(CredentialRequest("example.com", "Example", byteArrayOf(8), "bob", "Bob", false))

        assertEquals(setOf(shared.keyId, private.keyId, b64(made.id)), keyRows)
        assertEquals(setOf(shared.keyId, private.keyId, b64(made.id)), metadataRows)
        io.mockk.verify(exactly = 1) { keystore.deleteKey(failed) }
        io.mockk.verify(exactly = 0) { keystore.deleteKey(shared.keyId) }
        assertEquals(
            listOf(byteArrayOf(1, 2).toList(), made.id.toList()).toSet(),
            backend().credentials("example.com").map { it.id.toList() }.toSet()
        )
    }

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

    /**
     * Keystore as a set of key ids: [shared] and [private] to start, each new
     * passkey's key once generated. Deleting a key in [failingOnce] throws the
     * first time and succeeds after, as a Keystore that is briefly busy.
     */
    private fun keystoreKeys(failsOnce: (String) -> Boolean): MutableSet<String> {
        val keys = mutableSetOf(shared.keyId, private.keyId)
        val failed = mutableSetOf<String>()
        coEvery { keystore.generateKeyWithAuthDuration(any(), any(), any()) } answers {
            keys += firstArg<String>(); byteArrayOf(0xA5.toByte())
        }
        every { keystore.deleteKey(any()) } answers {
            val id = firstArg<String>()
            if (failsOnce(id) && failed.add(id)) throw IllegalStateException("Keystore busy")
            keys.remove(id)
        }
        return keys
    }

    @Test
    fun `a failed registration whose Keystore delete fails deletes the key on a later retry`() = runTest {
        val (keyRows, metadataRows) = storedResidents()
        // The first new passkey's rollback delete fails once.
        var firstNewKey: String? = null
        val keys = keystoreKeys { id -> id != shared.keyId && id != private.keyId && (firstNewKey ?: id) == id }
        val generate = slot<String>()
        coEvery { keystore.generateKeyWithAuthDuration(capture(generate), any(), any()) } answers {
            if (firstNewKey == null) firstNewKey = generate.captured
            keys += generate.captured; byteArrayOf(0xA5.toByte())
        }
        coEvery { credentialDao.insert(any()) } throws IllegalStateException("disk full") andThenAnswer {
            metadataRows += firstArg<CredentialMetadataEntity>().credentialId; 1L
        }

        val thrown = runCatching {
            backend().create(CredentialRequest("example.com", "Example", byteArrayOf(7), "alice", "Alice", true))
        }.exceptionOrNull()
        assertTrue("create must fail", thrown != null)
        assertTrue("its key row is gone", firstNewKey !in keyRows)

        // A later registration, on a fresh backend as after a restart, retries
        // the delete that failed.
        val made = backend().create(CredentialRequest("example.com", "Example", byteArrayOf(8), "bob", "Bob", true))

        assertEquals(setOf(shared.keyId, private.keyId, b64(made.id)), keys)
        io.mockk.verify(exactly = 2) { keystore.deleteKey(firstNewKey!!) }
    }

    @Test
    fun `a resident replacement whose Keystore delete fails deletes the old key on a later retry`() = runTest {
        val (keyRows, _) = storedResidents()
        val keys = keystoreKeys { it == shared.keyId }

        val made = backend().create(
            CredentialRequest("example.com", "Example", byteArrayOf(9), "alice", "Alice", discoverable = true)
        )
        assertEquals(setOf(private.keyId, b64(made.id)), keyRows)

        // A later registration, on a fresh backend as after a restart, retries
        // the delete that failed; the private passkey's key is never touched.
        val next = backend().create(CredentialRequest("example.com", "Example", byteArrayOf(8), "bob", "Bob", true))

        assertEquals(setOf(private.keyId, b64(made.id), b64(next.id)), keys)
        io.mockk.verify(exactly = 2) { keystore.deleteKey(shared.keyId) }
        io.mockk.verify(exactly = 0) { keystore.deleteKey(private.keyId) }
    }

    /** Key rows as one live store: what a registration inserts, the next one's lookup sees. */
    private fun liveKeyRows(): MutableMap<String, KeyEntity> {
        val rows = linkedMapOf<String, KeyEntity>()
        coEvery { keystore.generateKeyWithAuthDuration(any(), any(), any()) } returns byteArrayOf(0xA5.toByte())
        coEvery { keyDao.insert(any()) } answers { val e = firstArg<KeyEntity>(); rows[e.keyId] = e; 1L }
        coEvery { keyDao.insertPasskeyRows(any(), any()) } coAnswers { keyDao.insert(firstArg()) }
        coEvery { keyDao.deleteByKeyId(any()) } answers { if (rows.remove(firstArg<String>()) != null) 1 else 0 }
        coEvery { keyDao.deletePasskeyRows(any()) } coAnswers {
            firstArg<List<KeyEntity>>().filter { unchanged(it, rows[it.keyId]) }.map { rows.remove(it.keyId); it.keyId }
        }
        coEvery { keyDao.getFido2ByRpId("example.com") } coAnswers { yield(); rows.values.toList() }
        coEvery { keyDao.getByKeyId(any()) } answers { rows[firstArg()] }
        coEvery { keyDao.completePasskeyRegistration(any(), any(), any()) } coAnswers {
            keyDao.insertPasskeyRows(firstArg(), secondArg())
            keyDao.deletePasskeyRows(thirdArg())
        }
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
    fun `a cancel during the registration's commit never undoes the committed passkey`() = runTest {
        val (keyRows, metadataRows) = storedResidents()
        lateinit var registering: kotlinx.coroutines.Job
        // The client sends CANCEL while the new passkey's last row is written:
        // the commit runs to its end, so the passkey is whole.
        coEvery { credentialDao.insert(any()) } answers {
            metadataRows += firstArg<CredentialMetadataEntity>().credentialId
            registering.cancel()
            1L
        }

        registering = launch {
            backend().create(CredentialRequest("example.com", "Example", byteArrayOf(9), "alice", "Alice", true))
        }
        registering.join()

        val made = (keyRows - private.keyId).single()
        assertTrue("the old passkey was replaced", made != shared.keyId)
        assertEquals(setOf(private.keyId, made), metadataRows)
        io.mockk.verify(exactly = 1) { keystore.deleteKey(shared.keyId) }
        io.mockk.verify(exactly = 0) { keystore.deleteKey(made) }
        assertTrue("a whole passkey has no record", pendingKeyDeletions.all().isEmpty())
        assertTrue("a whole passkey has no record", pendingKeyDeletions.registrations().isEmpty())
    }

    @Test
    fun `a passkey made private after the replacement lookup is not replaced`() = runTest {
        val (keyRows, metadataRows) = storedResidents()
        // Listed as shared, then made private before its rows are deleted.
        coEvery { keyDao.getByKeyId(shared.keyId) } returns shared.copy(sharingPolicy = SharingPolicyType.PRIVATE)

        val made = backend().create(CredentialRequest("example.com", "Example", byteArrayOf(9), "alice", "Alice", true))

        assertEquals(setOf(shared.keyId, private.keyId, b64(made.id)), keyRows)
        assertEquals(setOf(shared.keyId, private.keyId, b64(made.id)), metadataRows)
        io.mockk.verify(exactly = 0) { keystore.deleteKey(shared.keyId) }
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
        coEvery { keyDao.getByKeyId(sameUser.keyId) } returns sameUser
        coEvery { keyDao.getByKeyId(otherUser.keyId) } returns otherUser

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
