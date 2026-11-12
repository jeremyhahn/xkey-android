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
package com.automatethethings.xkey.credential

import com.automatethethings.xkey.storage.dao.CredentialMetadataDao
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.CredentialMetadataEntity
import com.automatethethings.xkey.storage.entity.KeyEntity
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests for the one signature counter both assertion paths share.
 *
 * A passkey is served by the credential provider and by the phone backend.
 * The relying party must see a counter that rises on every assertion,
 * whichever path served it, and two assertions must never sign one value.
 */
class PasskeySignCounterTest {

    /**
     * The two stores a passkey's counter lives in, faked over in-memory
     * values. A null value means the store has no row for the passkey.
     * [readDelayMs] widens the gap between a read and the writes that follow
     * it, so an unguarded read-modify-write races.
     */
    private class Stores(
        @Volatile var metadata: Long?,
        @Volatile var key: Long?,
        private val readDelayMs: Long = 0
    ) {
        private val metadataEntity = mockk<CredentialMetadataEntity> {
            every { signCount } answers { metadata ?: 0 }
        }
        private val keyEntity = mockk<KeyEntity> {
            every { signCount } answers { key ?: 0 }
        }

        val credentialDao = mockk<CredentialMetadataDao> {
            coEvery { getByCredentialId(ID) } coAnswers {
                delay(readDelayMs)
                if (metadata == null) null else metadataEntity
            }
            coEvery { updateSignCount(ID, any(), any()) } answers {
                if (metadata != null) metadata = secondArg()
            }
        }

        val keyDao = mockk<KeyDao> {
            coEvery { getByKeyId(ID) } coAnswers {
                delay(readDelayMs)
                if (key == null) null else keyEntity
            }
            coEvery { updateSignCount(ID, any(), any()) } answers {
                if (key != null) key = secondArg()
            }
        }

        fun counter() = PasskeySignCounter(credentialDao, keyDao)
    }

    @Test
    fun phoneBackendThenProviderRises() = runBlocking {
        val stores = Stores(metadata = 3, key = 3)
        // Main's phone backend advanced only the key store, so the provider,
        // which read the metadata store, signed 4 again.
        val phoneBackend = stores.counter().next(ID)
        val provider = stores.counter().next(ID)

        assertEquals(4L, phoneBackend)
        assertTrue("provider signed $provider after $phoneBackend", provider > phoneBackend)
    }

    @Test
    fun providerThenPhoneBackendRises() = runBlocking {
        val stores = Stores(metadata = 7, key = 7)
        val provider = stores.counter().next(ID)
        val phoneBackend = stores.counter().next(ID)

        assertEquals(8L, provider)
        assertTrue("phone backend signed $phoneBackend after $provider", phoneBackend > provider)
    }

    @Test
    fun concurrentAdvancesNeverShareAValue() = runBlocking {
        val stores = Stores(metadata = 10, key = 10, readDelayMs = 20)
        val values = listOf(stores.counter(), stores.counter())
            .map { counter -> async(Dispatchers.Default) { counter.next(ID) } }
            .awaitAll()

        assertEquals("two assertions signed one value: $values", 2, values.toSet().size)
        assertEquals(values.max(), stores.metadata)
        assertEquals(values.max(), stores.key)
    }

    @Test
    fun anAdvanceWritesBothStores() = runBlocking {
        val stores = Stores(metadata = 0, key = 0)
        val value = stores.counter().next(ID)

        assertEquals(1L, value)
        assertEquals(value, stores.metadata)
        assertEquals(value, stores.key)
    }

    @Test
    fun storesThatDisagreeContinueFromTheLarger() = runBlocking {
        val keyAhead = Stores(metadata = 3, key = 9)
        assertEquals(10L, keyAhead.counter().next(ID))
        assertEquals(10L, keyAhead.metadata)
        assertEquals(10L, keyAhead.key)

        val metadataAhead = Stores(metadata = 12, key = 5)
        assertEquals(13L, metadataAhead.counter().next(ID))
        assertEquals(13L, metadataAhead.metadata)
        assertEquals(13L, metadataAhead.key)
    }

    @Test
    fun aPasskeyInOneStoreOnlyStillAdvances() = runBlocking {
        // Keys the phone backend created have no provider metadata row.
        val stores = Stores(metadata = null, key = 2)
        assertEquals(3L, stores.counter().next(ID))
        assertEquals(4L, stores.counter().next(ID))
        assertEquals(4L, stores.key)
    }

    private companion object {
        const val ID = "credential-216"
    }
}
