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
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
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
     * A read returns the value the store held when it was read.
     *
     * With [overlapReads] the key store read, the last read before the
     * writes, holds every caller until a second caller has read too, so two
     * unguarded read-modify-writes always overlap. A caller the lock keeps
     * out never arrives; the first then goes on after [OVERLAP_WAIT_MS] of
     * virtual time.
     */
    private class Stores(
        @Volatile var metadata: Long?,
        @Volatile var key: Long?,
        private val overlapReads: Boolean = false
    ) {
        private val keyReaders = AtomicInteger()
        private val bothRead = CompletableDeferred<Unit>()

        private suspend fun overlap() {
            if (!overlapReads) return
            if (keyReaders.incrementAndGet() >= 2) bothRead.complete(Unit)
            withTimeoutOrNull(OVERLAP_WAIT_MS) { bothRead.await() }
        }

        val credentialDao = mockk<CredentialMetadataDao> {
            coEvery { getByCredentialId(ID) } coAnswers {
                metadata?.let { seen -> mockk<CredentialMetadataEntity> { every { signCount } returns seen } }
            }
            coEvery { updateSignCount(ID, any(), any()) } answers {
                if (failMetadataWrite) throw IllegalStateException("metadata store unavailable")
                if (metadata != null) metadata = secondArg()
            }
        }

        val keyDao = mockk<KeyDao> {
            coEvery { getByKeyId(ID) } coAnswers {
                val read = key?.let { seen -> mockk<KeyEntity> { every { signCount } returns seen } }
                overlap()
                read
            }
            coEvery { updateSignCount(ID, any(), any()) } answers {
                if (failKeyWrite) throw IllegalStateException("key store unavailable")
                if (key != null) key = secondArg()
            }
        }

        /** Makes the next sign_count write to that store throw. */
        @Volatile var failMetadataWrite = false
        @Volatile var failKeyWrite = false

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
    fun concurrentAdvancesNeverShareAValue() = runTest {
        // Without the shared lock both callers read 10 before either writes.
        val stores = Stores(metadata = 10, key = 10, overlapReads = true)
        val values = listOf(stores.counter(), stores.counter())
            .map { counter -> async { counter.next(ID) } }
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

    @Test
    fun aCounterThatCannotBePersistedRefusesBeforeAnySignature() = runBlocking {
        for (failing in listOf("metadata", "key")) {
            val stores = Stores(metadata = 5, key = 5)
            stores.failMetadataWrite = failing == "metadata"
            stores.failKeyWrite = failing == "key"
            val signed = mutableListOf<Long>()

            val result = runCatching { assertWith(stores.counter(), signed) }

            assertTrue("a failed $failing write must refuse the assertion", result.isFailure)
            assertTrue("a failed $failing write signed $signed", signed.isEmpty())
        }
    }

    @Test
    fun theAssertionAfterAPersistenceFailureStillRises() = runBlocking {
        for (failing in listOf("metadata", "key")) {
            val stores = Stores(metadata = 5, key = 5)
            val signed = mutableListOf(stores.counter().next(ID))
            stores.failMetadataWrite = failing == "metadata"
            stores.failKeyWrite = failing == "key"
            runCatching { assertWith(stores.counter(), signed) }
            // A write that landed before the failure counts as handed out.
            val persisted = maxOf(stores.metadata!!, stores.key!!)
            stores.failMetadataWrite = false
            stores.failKeyWrite = false

            val next = assertWith(stores.counter(), signed)

            assertTrue(
                "after a failed $failing write the next assertion signed $next, " +
                    "not above ${signed.dropLast(1)} and $persisted",
                signed.dropLast(1).all { next > it } && next > persisted
            )
            assertEquals(next, stores.metadata)
            assertEquals(next, stores.key)
        }
    }

    /**
     * One assertion the way both handlers run it: take the counter, then
     * sign. A value reaches [signed] only once the counter has returned it.
     */
    private suspend fun assertWith(counter: PasskeySignCounter, signed: MutableList<Long>): Long {
        val value = counter.next(ID)
        signed += value
        return value
    }

    private companion object {
        const val ID = "credential-216"
        const val OVERLAP_WAIT_MS = 1_000L
    }
}
