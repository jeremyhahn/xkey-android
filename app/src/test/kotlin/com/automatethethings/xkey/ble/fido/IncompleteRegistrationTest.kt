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

import android.app.Application
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.automatethethings.xkey.credential.PasskeySignCounter
import com.automatethethings.xkey.crypto.KeySecurityLevel
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.protocol.SharePermission
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.entity.CredentialMetadataEntity
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.Base64

/**
 * A BLE registration that does not complete leaves no passkey row any reader
 * sees: not the credential provider (`credential_metadata`), not the paired
 * desktop's local list (`keys`), not a BLE client, and none of them can sign
 * with it. Run on a real Room database, as the readers query it.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class IncompleteRegistrationTest {

    private lateinit var database: XKeyDatabase
    private val keystore = mockk<KeystoreManager>(relaxed = true)
    private val sharePermission = mockk<SharePermission>()
    private val signCounter = mockk<PasskeySignCounter>()
    private val generated = mutableListOf<String>()
    private val pending = FilePendingKeyDeletions(
        java.io.File.createTempFile("pending-key-deletions", "").also { it.delete(); it.deleteOnExit() }
    )

    private val oldId = b64(byteArrayOf(1, 2))

    @Before
    fun setUp() {
        database = Room.inMemoryDatabaseBuilder(ApplicationProvider.getApplicationContext(), XKeyDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        coEvery { keystore.generateKeyWithAuthDuration(any(), any(), any()) } answers {
            generated += firstArg<String>(); byteArrayOf(0xA5.toByte())
        }
        coEvery { keystore.signApproved(any(), any(), any(), any()) } returns byteArrayOf(0x30)
        every { keystore.keyRowAlias(any(), any(), any()) } answers { "xkey_credential_" + firstArg<String>() }
        every { keystore.publicKeyDERAt(any()) } returns byteArrayOf(0x30, 0x01)
        every { keystore.deleteKey(any(), any()) } returns com.automatethethings.xkey.crypto.GeneratedKeyDiscard.DELETED
        coEvery { sharePermission.canShare(any(), null) } answers {
            firstArg<KeyEntity>().sharingPolicy == SharingPolicyType.ALL_PEERS
        }
        coEvery { signCounter.next(any()) } returns 1
        runBlocking {
            database.keyDao().insertPasskeyRows(
                FidoKeyRows.passkey(
                    keyId = oldId, label = "Example", publicKeyCose = byteArrayOf(1), rpId = RP,
                    rpName = "Example", userId = b64(USER), userName = "alice", userDisplayName = "Alice",
                    discoverable = true, createdAt = 1, policy = SharingPolicyType.ALL_PEERS,
                    securityLevel = KeySecurityLevel.TEE
                ),
                metadata(oldId)
            )
        }
    }

    @After
    fun tearDown() = database.close()

    private fun metadata(id: String) = CredentialMetadataEntity(
        credentialId = id, rpId = RP, rpName = "Example", userId = b64(USER), userName = "alice",
        userDisplayName = "Alice", publicKeyCose = byteArrayOf(1), signCount = 0, isDiscoverable = true
    )

    private fun backend() = AndroidFidoCredentialBackend(
        keyDao = database.keyDao(),
        credentialDao = database.credentialMetadataDao(),
        sharePermission = sharePermission,
        signCounter = signCounter,
        keystoreManager = keystore,
        userPrompt = null,
        settings = { BiometricSettingsData() },
        pendingKeyDeletions = pending
    )

    private fun request() = CredentialRequest(RP, "Example", USER, "alice", "Alice", discoverable = true)

    /** Storage refuses every key row delete: neither a replacement nor a rollback can remove a row. */
    private fun refuseRowDeletes() = database.openHelper.writableDatabase.execSQL(
        "CREATE TRIGGER refuse_deletes BEFORE DELETE ON keys BEGIN SELECT RAISE(ABORT, 'disk I/O error'); END"
    )

    /**
     * The failed passkey [failed] is in no reader's view: the credential
     * provider's queries, the local list's query and the BLE backend's list
     * show only the old passkey, and neither the provider nor BLE can sign.
     */
    private fun assertInvisible(failed: String) = runBlocking {
        val metadata = database.credentialMetadataDao()
        assertEquals("credential provider list", listOf(oldId), metadata.getByRpId(RP).map { it.credentialId })
        assertEquals(
            "credential provider discoverable list",
            listOf(oldId),
            metadata.getDiscoverableByRpId(RP).map { it.credentialId }
        )
        assertNull("credential provider lookup before signing", metadata.getByCredentialId(failed))
        assertEquals("local list", listOf(oldId), database.keyDao().getFido2ByRpId(RP).map { it.keyId })
        assertNull("key row lookup before signing", database.keyDao().getByKeyId(failed))
        assertEquals("BLE list", listOf(oldId), backend().credentials(RP).map { b64(it.id) })
        val e = assertThrows(FidoRefusedException::class.java) {
            runBlocking {
                backend().sign(
                    FidoCredential(Base64.getUrlDecoder().decode(failed), RP, USER, "alice", "Alice", true),
                    { ByteArray(37) },
                    ByteArray(32)
                )
            }
        }
        assertEquals(Ctap2.ERR_NO_CREDENTIALS, e.status)
        coVerify(exactly = 0) { keystore.signApproved(match { it.endsWith(failed) }, any(), any(), any()) }
    }

    @Test
    fun `a registration whose replacement and rollback deletes fail leaves no row any reader sees`() = runBlocking {
        refuseRowDeletes()

        val thrown = runCatching { backend().create(request()) }.exceptionOrNull()

        assertTrue("create must fail", thrown != null)
        assertInvisible(generated.single())
    }

    @Test
    fun `a registration that stops after its key is made, with nothing undone, leaves no row any reader sees`() =
        runBlocking {
            // As at a process death: nothing the registration set up can be
            // undone, neither its rows nor its Keystore key.
            refuseRowDeletes()
            every { keystore.deleteKey(any(), com.automatethethings.xkey.crypto.UserKeyKind.CREDENTIAL) } returns
                com.automatethethings.xkey.crypto.GeneratedKeyDiscard.FAILED
            // The registration stops at its last step before it is whole: its
            // second look at the passkey it replaces.
            lateinit var job: Job
            var looks = 0
            coEvery { sharePermission.canShare(match { it.keyId == oldId }, null) } answers {
                if (++looks == 2) job.cancel()
                true
            }
            job = launch(Dispatchers.Default) { backend().create(request()) }
            job.join()

            looks = Int.MIN_VALUE
            assertTrue("the registration must not complete", job.isCancelled)
            assertInvisible(generated.single())
        }

    @Test
    fun `a whole passkey whose completion record cannot be cleared is kept by a later registration`() = runBlocking {
        val stuck = object : PendingKeyDeletions by pending {
            override fun remove(keyId: String) {
                if (keyId == generated.firstOrNull()) throw java.io.IOException("disk full")
                pending.remove(keyId)
            }
        }
        val first = AndroidFidoCredentialBackend(
            database.keyDao(), database.credentialMetadataDao(), sharePermission, signCounter, keystore,
            null, { BiometricSettingsData() }, stuck
        ).create(request())

        // A later registration, as after a restart, retries what is recorded.
        backend().create(CredentialRequest(RP, "Example", byteArrayOf(8), "bob", "Bob", discoverable = true))

        val firstId = b64(first.id)
        assertEquals(firstId, database.keyDao().getByKeyId(firstId)?.keyId)
        assertEquals(firstId, database.credentialMetadataDao().getByCredentialId(firstId)?.credentialId)
        verify(exactly = 0) { keystore.deleteKey(firstId, any()) }
        assertTrue(backend().credentials(RP).any { b64(it.id) == firstId })
    }

    private companion object {
        const val RP = "example.com"
        val USER = byteArrayOf(9)
        fun b64(raw: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(raw)
    }
}
