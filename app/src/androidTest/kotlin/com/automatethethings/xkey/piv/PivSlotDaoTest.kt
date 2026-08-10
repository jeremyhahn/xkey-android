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
package com.automatethethings.xkey.piv

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for [PivSlotDao].
 *
 * A PIV slot is addressed by its hex id, and the unique index on `slot_id`
 * combined with `OnConflictStrategy.REPLACE` is what makes re-generating a key
 * overwrite the slot rather than leave two rows claiming slot 9A. The
 * `has_key = 1` predicate behind the populated-slot queries is what the PIV
 * screen counts, so an empty placeholder row must not be counted as a key.
 *
 * The database is always **in-memory**, so nothing touches the shared on-device
 * `piv_slots` table — which matters here in particular, because other suites
 * assert on the live populated-slot count.
 */
@RunWith(AndroidJUnit4::class)
class PivSlotDaoTest {

    private lateinit var database: XKeyDatabase
    private lateinit var dao: PivSlotDao

    private val now = System.currentTimeMillis()

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        database = Room.inMemoryDatabaseBuilder(context, XKeyDatabase::class.java).build()
        dao = database.pivSlotDao()
    }

    @After
    fun tearDown() {
        database.close()
    }

    private fun slot(
        slotId: String,
        algorithm: String? = "ES256",
        hasKey: Boolean = true,
        publicKeyDer: ByteArray? = byteArrayOf(0x30, 0x59),
        certificateDer: ByteArray? = null,
        useCount: Int = 0,
        lastUsedAt: Long? = null
    ) = PivSlotEntity(
        slotId = slotId,
        algorithm = algorithm,
        publicKeyDer = publicKeyDer,
        certificateDer = certificateDer,
        hasKey = hasKey,
        createdAt = now,
        lastUsedAt = lastUsedAt,
        useCount = useCount
    )

    // -------------------------------------------------------------------------
    // Upsert and read back
    // -------------------------------------------------------------------------

    @Test
    fun upsert_returnsTheAssignedRowId() = runBlocking {
        assertTrue(dao.upsert(slot("9A")) > 0)
    }

    @Test
    fun upsert_roundTripsEveryColumnIncludingTheBlobs() = runBlocking {
        val publicKey = byteArrayOf(0x30, 0x59, 0x30, 0x13)
        val certificate = byteArrayOf(0x30, 0x82.toByte(), 0x01, 0x22)
        dao.upsert(
            slot("9C", algorithm = "RS2048", publicKeyDer = publicKey, certificateDer = certificate)
        )

        val stored = dao.getBySlotId("9C")!!
        assertEquals("9C", stored.slotId)
        assertEquals("RS2048", stored.algorithm)
        assertTrue(stored.hasKey)
        assertEquals(now, stored.createdAt)
        assertNull(stored.lastUsedAt)
        assertEquals(0, stored.useCount)
        assertTrue(stored.publicKeyDer!!.contentEquals(publicKey))
        assertTrue(stored.certificateDer!!.contentEquals(certificate))
    }

    @Test
    fun upsert_acceptsAnEmptySlotPlaceholderWithNoKeyMaterial() = runBlocking {
        dao.upsert(slot("9E", algorithm = null, hasKey = false, publicKeyDer = null))

        val stored = dao.getBySlotId("9E")!!
        assertNull(stored.algorithm)
        assertNull(stored.publicKeyDer)
        assertNull(stored.certificateDer)
        assertTrue(!stored.hasKey)
    }

    @Test
    fun upsert_replacesAnExistingSlotRatherThanDuplicatingIt() = runBlocking {
        dao.upsert(slot("9A", algorithm = "ES256"))
        dao.upsert(slot("9A", algorithm = "ES384"))

        assertEquals(1, dao.getAll().size)
        assertEquals("ES384", dao.getBySlotId("9A")!!.algorithm)
    }

    @Test
    fun getBySlotId_returnsNullForAnUnpopulatedSlot() = runBlocking {
        dao.upsert(slot("9A"))

        assertNull(dao.getBySlotId("9D"))
    }

    @Test
    fun getBySlotId_matchesTheHexIdExactly() = runBlocking {
        dao.upsert(slot("9A"))

        // The manager always writes PivSlot.hexId, which is upper case; a
        // lower-case lookup is a caller bug and must not silently match.
        assertNull(dao.getBySlotId("9a"))
    }

    // -------------------------------------------------------------------------
    // Listing and ordering
    // -------------------------------------------------------------------------

    @Test
    fun getAll_isEmptyForAFreshDatabase() = runBlocking {
        assertTrue(dao.getAll().isEmpty())
    }

    @Test
    fun getAll_ordersBySlotId() = runBlocking {
        dao.upsert(slot("9E"))
        dao.upsert(slot("82"))
        dao.upsert(slot("9A"))
        dao.upsert(slot("F9"))

        assertEquals(listOf("82", "9A", "9E", "F9"), dao.getAll().map { it.slotId })
    }

    @Test
    fun observeAll_emitsEverySlotIncludingEmptyPlaceholders() = runBlocking {
        dao.upsert(slot("9A", hasKey = true))
        dao.upsert(slot("9C", hasKey = false, algorithm = null, publicKeyDer = null))

        assertEquals(listOf("9A", "9C"), dao.observeAll().first().map { it.slotId })
    }

    @Test
    fun observeAll_emitsAnEmptyListForAFreshDatabase() = runBlocking {
        assertTrue(dao.observeAll().first().isEmpty())
    }

    // -------------------------------------------------------------------------
    // Populated-slot predicate
    // -------------------------------------------------------------------------

    @Test
    fun observePopulatedSlots_excludesSlotsWithNoKey() = runBlocking {
        dao.upsert(slot("9A", hasKey = true))
        dao.upsert(slot("9C", hasKey = false, algorithm = null, publicKeyDer = null))
        dao.upsert(slot("9D", hasKey = true))

        assertEquals(
            listOf("9A", "9D"),
            dao.observePopulatedSlots().first().map { it.slotId }
        )
    }

    @Test
    fun observePopulatedSlots_isEmptyWhenEverySlotIsAPlaceholder() = runBlocking {
        dao.upsert(slot("9A", hasKey = false, algorithm = null, publicKeyDer = null))

        assertTrue(dao.observePopulatedSlots().first().isEmpty())
    }

    @Test
    fun countPopulated_countsOnlySlotsHoldingAKey() = runBlocking {
        dao.upsert(slot("9A", hasKey = true))
        dao.upsert(slot("9C", hasKey = true))
        dao.upsert(slot("9D", hasKey = false, algorithm = null, publicKeyDer = null))

        assertEquals(2, dao.countPopulated())
    }

    @Test
    fun countPopulated_isZeroForAFreshDatabase() = runBlocking {
        assertEquals(0, dao.countPopulated())
    }

    @Test
    fun observePopulatedCount_tracksTheSamePredicate() = runBlocking {
        assertEquals(0, dao.observePopulatedCount().first())

        dao.upsert(slot("9A", hasKey = true))
        assertEquals(1, dao.observePopulatedCount().first())

        dao.upsert(slot("9A", hasKey = false, algorithm = null, publicKeyDer = null))
        assertEquals(0, dao.observePopulatedCount().first())
    }

    // -------------------------------------------------------------------------
    // Delete
    // -------------------------------------------------------------------------

    @Test
    fun deleteBySlotId_removesTheRowAndReportsOne() = runBlocking {
        dao.upsert(slot("9A"))

        assertEquals(1, dao.deleteBySlotId("9A"))
        assertNull(dao.getBySlotId("9A"))
    }

    @Test
    fun deleteBySlotId_reportsZeroForAnUnpopulatedSlot() = runBlocking {
        assertEquals(0, dao.deleteBySlotId("9A"))
    }

    @Test
    fun deleteBySlotId_leavesOtherSlotsAlone() = runBlocking {
        dao.upsert(slot("9A"))
        dao.upsert(slot("9C"))

        dao.deleteBySlotId("9A")

        assertEquals(listOf("9C"), dao.getAll().map { it.slotId })
    }

    // -------------------------------------------------------------------------
    // Usage tracking
    // -------------------------------------------------------------------------

    @Test
    fun recordUsage_incrementsTheCountAndStampsTheTime() = runBlocking {
        dao.upsert(slot("9A"))

        dao.recordUsage("9A", 1_700_000_000_000L)

        val stored = dao.getBySlotId("9A")!!
        assertEquals(1, stored.useCount)
        assertEquals(1_700_000_000_000L, stored.lastUsedAt)
    }

    @Test
    fun recordUsage_accumulatesAcrossCalls() = runBlocking {
        dao.upsert(slot("9A", useCount = 4))

        dao.recordUsage("9A", 1L)
        dao.recordUsage("9A", 2L)

        val stored = dao.getBySlotId("9A")!!
        assertEquals(6, stored.useCount)
        assertEquals(2L, stored.lastUsedAt)
    }

    @Test
    fun recordUsage_defaultsTheTimestampToNow() = runBlocking {
        dao.upsert(slot("9A"))

        val before = System.currentTimeMillis()
        dao.recordUsage("9A")
        val after = System.currentTimeMillis()

        assertTrue(dao.getBySlotId("9A")!!.lastUsedAt!! in before..after)
    }

    @Test
    fun recordUsage_isSilentForAnUnpopulatedSlot() = runBlocking {
        dao.recordUsage("9A", 1L)

        assertNull(dao.getBySlotId("9A"))
    }

    @Test
    fun recordUsage_touchesOnlyTheNamedSlot() = runBlocking {
        dao.upsert(slot("9A"))
        dao.upsert(slot("9C"))

        dao.recordUsage("9A", 1L)

        assertEquals(0, dao.getBySlotId("9C")!!.useCount)
        assertNull(dao.getBySlotId("9C")!!.lastUsedAt)
    }
}
