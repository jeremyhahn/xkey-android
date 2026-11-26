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
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.protocol.SharePermission
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.CredentialMetadataEntity
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import com.automatethethings.xkey.testing.ReleaseMocks
import io.mockk.coEvery
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.Base64

/**
 * A passkey the owner makes private, or shares with selected peers only,
 * after a BLE registration last read it and before its rows are deleted is
 * not the client's to replace any more: its rows and its Keystore key stay.
 * Runs over a real Room database, so the policy check and the delete are the
 * ones the phone runs.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class ReplacementPolicyRaceTest {

    /** Drops what MockK recorded here, so it does not outlive the test. */
    @get:Rule
    val releaseMocks = ReleaseMocks()

    private lateinit var database: XKeyDatabase
    private val keystore = mockk<KeystoreManager>(relaxed = true)
    private val userHandle = byteArrayOf(9)
    private val oldKeyId = Base64.getUrlEncoder().withoutPadding().encodeToString(byteArrayOf(1, 2))

    @Before
    fun setUp() {
        coEvery { keystore.generateKeyWithAuthDuration(any(), any(), any()) } returns byteArrayOf(0xA5.toByte())
        database = Room.inMemoryDatabaseBuilder(ApplicationProvider.getApplicationContext(), XKeyDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        runBlocking {
            database.keyDao().insert(
                KeyEntity(
                    keyId = oldKeyId,
                    keyType = "fido2",
                    algorithm = "ES256",
                    label = "Example",
                    keySizeBits = 256,
                    source = "local",
                    rpId = "example.com",
                    userId = Base64.getUrlEncoder().withoutPadding().encodeToString(userHandle),
                    isDiscoverable = true,
                    sharingPolicy = SharingPolicyType.ALL_PEERS
                )
            )
            database.credentialMetadataDao().insert(
                CredentialMetadataEntity(
                    credentialId = oldKeyId,
                    rpId = "example.com",
                    rpName = "Example",
                    userId = Base64.getUrlEncoder().withoutPadding().encodeToString(userHandle),
                    userName = "alice",
                    userDisplayName = "Alice",
                    publicKeyCose = byteArrayOf(1),
                    signCount = 0,
                    isDiscoverable = true
                )
            )
        }
    }

    @After
    fun tearDown() = database.close()

    /**
     * The real key DAO, except that every read of the old passkey's row is
     * followed by the owner's policy change: whatever the registration read
     * last, the change lands after it.
     */
    private fun changingAfterEachRead(policy: SharingPolicyType): KeyDao {
        val real = database.keyDao()
        return object : KeyDao by real {
            override suspend fun getByKeyId(keyId: String): KeyEntity? =
                real.getByKeyId(keyId).also { if (keyId == oldKeyId) real.updateSharingPolicy(keyId, policy) }
        }
    }

    private fun assertOldPasskeyStaysAfterChangeTo(policy: SharingPolicyType) = runBlocking {
        val backend = AndroidFidoCredentialBackend(
            keyDao = changingAfterEachRead(policy),
            credentialDao = database.credentialMetadataDao(),
            sharePermission = SharePermission(
                database.keySharingPolicyDao(),
                null,
                com.automatethethings.xkey.storage.KeyPolicyStore.of(database, keystore)
            ),
            signCounter = mockk<PasskeySignCounter>(relaxed = true),
            keystoreManager = keystore,
            userPrompt = null,
            settings = { BiometricSettingsData() },
            pendingKeyDeletions = FilePendingKeyDeletions(
                java.io.File.createTempFile("pending-key-deletions", "").also { it.delete(); it.deleteOnExit() }
            )
        )

        backend.create(CredentialRequest("example.com", "Example", userHandle, "alice", "Alice", discoverable = true))

        val old = database.keyDao().getByKeyId(oldKeyId)
        assertNotNull("the old passkey's key row must stay", old)
        assertEquals(policy, old!!.sharingPolicy)
        assertNotNull(
            "the old passkey's metadata row must stay",
            database.credentialMetadataDao().getByCredentialId(oldKeyId)
        )
        verify(exactly = 0) { keystore.deleteKey(oldKeyId, com.automatethethings.xkey.crypto.UserKeyKind.CREDENTIAL) }
    }

    @Test
    fun `a passkey made private after the last check keeps its rows and its key`() =
        assertOldPasskeyStaysAfterChangeTo(SharingPolicyType.PRIVATE)

    @Test
    fun `a passkey shared with selected peers after the last check keeps its rows and its key`() =
        assertOldPasskeyStaysAfterChangeTo(SharingPolicyType.SELECTED_PEERS)
}
