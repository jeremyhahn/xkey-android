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
package com.automatethethings.xkey.ca

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for [CertificateDao].
 *
 * The DAO is where the CA's lifecycle questions are actually answered — what is
 * revoked, what has expired, what expires soon — and those are SQL predicates
 * over the `certificates` table, not Kotlin. Room generates the implementation
 * against a real SQLite instance, so the queries can only be proved on a device.
 *
 * The database here is always **in-memory**, so nothing touches the shared
 * on-device `certificates` table and there is no state to clean up beyond
 * closing it. Rows are built with explicit timestamps so the expiry windows are
 * exact rather than dependent on how long the test takes to run.
 */
@RunWith(AndroidJUnit4::class)
class CertificateDaoTest {

    private lateinit var database: XKeyDatabase
    private lateinit var dao: CertificateDao

    private val now = System.currentTimeMillis()
    private val oneDay = 86_400_000L

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        database = Room.inMemoryDatabaseBuilder(context, XKeyDatabase::class.java).build()
        dao = database.certificateDao()
    }

    @After
    fun tearDown() {
        database.close()
    }

    private fun certificate(
        serial: String,
        subject: String = "CN=device-$serial",
        profile: String = "tls-client",
        notAfter: Long = now + 365 * oneDay,
        isCA: Boolean = false,
        keyId: String? = null,
        createdAt: Long = now
    ) = CertificateEntity(
        serialNumber = serial,
        subjectDN = subject,
        issuerDN = "CN=xKey Intermediate CA",
        notBefore = now - oneDay,
        notAfter = notAfter,
        profile = profile,
        fingerprint = serial.repeat(4),
        certificatePEM = "-----BEGIN CERTIFICATE-----\n$serial\n-----END CERTIFICATE-----",
        chainPEM = null,
        keyId = keyId,
        isCA = isCA,
        createdAt = createdAt
    )

    // -------------------------------------------------------------------------
    // Insert and lookup
    // -------------------------------------------------------------------------

    @Test
    fun insertedCertificatesAreFoundBySerial() {
        runBlocking {
            val id = dao.insert(certificate("0a"))

            assertTrue(id > 0)
            val row = dao.getBySerial("0a")
            assertNotNull(row)
            assertEquals("CN=device-0a", row!!.subjectDN)
            assertEquals("tls-client", row.profile)
            assertFalse(row.revoked)
            assertNull(row.revokedAt)
            assertNull(dao.getBySerial("no-such-serial"))
        }
    }

    @Test
    fun getAllIsOrderedByCreationDescending() {
        runBlocking {
            dao.insert(certificate("0a", createdAt = now - 3 * oneDay))
            dao.insert(certificate("0b", createdAt = now - oneDay))
            dao.insert(certificate("0c", createdAt = now - 2 * oneDay))

            assertEquals(
                listOf("0b", "0c", "0a"),
                dao.getAll().map { it.serialNumber }
            )
            assertEquals(3, dao.countAll())
        }
    }

    @Test
    fun reissuingTheSameSerialReplacesTheRow() {
        runBlocking {
            dao.insert(certificate("0a", subject = "CN=first"))

            dao.insert(certificate("0a", subject = "CN=second"))

            assertEquals(1, dao.countAll())
            assertEquals("CN=second", dao.getBySerial("0a")!!.subjectDN)
        }
    }

    @Test
    fun certificatesAreFilteredByProfile() {
        runBlocking {
            dao.insert(certificate("0a", profile = "tls-server"))
            dao.insert(certificate("0b", profile = "tls-client"))
            dao.insert(certificate("0c", profile = "tls-server"))

            assertEquals(
                setOf("0a", "0c"),
                dao.getByProfile("tls-server").map { it.serialNumber }.toSet()
            )
            assertTrue(dao.getByProfile("code-signing").isEmpty())
            assertEquals(2, dao.observeByProfile("tls-server").first().size)
        }
    }

    @Test
    fun caCertificatesAreQueriedSeparately() {
        runBlocking {
            dao.insert(certificate("0a", profile = "ca-root", isCA = true))
            dao.insert(certificate("0b"))

            assertEquals(listOf("0a"), dao.getCACertificates().map { it.serialNumber })
            assertEquals(1, dao.observeCA().first().size)
        }
    }

    @Test
    fun certificatesAreQueriedByKeyId() {
        runBlocking {
            dao.insert(certificate("0a", keyId = "key-1"))
            dao.insert(certificate("0b", keyId = "key-2"))
            dao.insert(certificate("0c"))

            assertEquals(listOf("0a"), dao.getByKeyId("key-1").map { it.serialNumber })
            assertTrue(dao.getByKeyId("key-3").isEmpty())
        }
    }

    @Test
    fun subjectsAreSearchedBySubstring() {
        runBlocking {
            dao.insert(certificate("0a", subject = "CN=api.example.com"))
            dao.insert(certificate("0b", subject = "CN=db.test"))

            assertEquals(listOf("0a"), dao.searchBySubject("example").map { it.serialNumber })
            assertEquals(2, dao.searchBySubject("CN=").size)
            assertTrue(dao.searchBySubject("nothing").isEmpty())
        }
    }

    @Test
    fun observeAllEmitsTheCurrentTable() {
        runBlocking {
            dao.insert(certificate("0a"))
            dao.insert(certificate("0b"))

            assertEquals(2, dao.observeAll().first().size)
        }
    }

    // -------------------------------------------------------------------------
    // Revocation
    // -------------------------------------------------------------------------

    @Test
    fun revokeMarksOnlyTheTargetedSerial() {
        runBlocking {
            dao.insert(certificate("0a"))
            dao.insert(certificate("0b"))
            assertEquals(false, dao.isRevoked("0a"))

            dao.revoke("0a", now, AndroidCA.CRLReason.KEY_COMPROMISE)

            val revoked = dao.getBySerial("0a")!!
            assertTrue(revoked.revoked)
            assertEquals(now, revoked.revokedAt)
            assertEquals(AndroidCA.CRLReason.KEY_COMPROMISE, revoked.revokedReason)
            assertEquals(false, dao.isRevoked("0b"))
            assertEquals(1, dao.countRevoked())
            assertEquals(listOf("0a"), dao.getRevoked().map { it.serialNumber })
            assertEquals(1, dao.observeRevoked().first().size)
        }
    }

    @Test
    fun revokeDefaultsToTheUnspecifiedReasonAndNow() {
        runBlocking {
            dao.insert(certificate("0a"))
            val before = System.currentTimeMillis()

            dao.revoke("0a")

            val revoked = dao.getBySerial("0a")!!
            assertTrue(revoked.revoked)
            assertEquals(AndroidCA.CRLReason.UNSPECIFIED, revoked.revokedReason)
            assertTrue("${revoked.revokedAt} < $before", revoked.revokedAt!! >= before)
        }
    }

    @Test
    fun revokingAnUnknownSerialChangesNothing() {
        runBlocking {
            dao.insert(certificate("0a"))

            dao.revoke("no-such-serial", now, AndroidCA.CRLReason.SUPERSEDED)

            assertEquals(0, dao.countRevoked())
            assertFalse(dao.getBySerial("0a")!!.revoked)
        }
    }

    // -------------------------------------------------------------------------
    // Expiry windows
    // -------------------------------------------------------------------------

    @Test
    fun expiredCertificatesExcludeRevokedOnes() {
        runBlocking {
            dao.insert(certificate("0a", notAfter = now - oneDay))       // expired
            dao.insert(certificate("0b", notAfter = now + 400 * oneDay)) // live
            dao.insert(certificate("0c", notAfter = now - 2 * oneDay))   // expired, revoked
            dao.revoke("0c", now, AndroidCA.CRLReason.CESSATION_OF_OPERATION)

            val expired = dao.getExpired(now)

            assertEquals(listOf("0a"), expired.map { it.serialNumber })
            assertEquals(1, dao.countExpired(now))
        }
    }

    @Test
    fun expiredIsOrderedByTheOldestFirst() {
        runBlocking {
            dao.insert(certificate("0a", notAfter = now - oneDay))
            dao.insert(certificate("0b", notAfter = now - 5 * oneDay))
            dao.insert(certificate("0c", notAfter = now - 3 * oneDay))

            assertEquals(
                listOf("0b", "0c", "0a"),
                dao.getExpired(now).map { it.serialNumber }
            )
        }
    }

    @Test
    fun expiringSoonIsBoundedAtBothEnds() {
        runBlocking {
            dao.insert(certificate("0a", notAfter = now - oneDay))        // already expired
            dao.insert(certificate("0b", notAfter = now + 5 * oneDay))    // inside the window
            dao.insert(certificate("0c", notAfter = now + 60 * oneDay))   // beyond the window
            dao.insert(certificate("0d", notAfter = now + 10 * oneDay))   // inside, revoked
            dao.revoke("0d", now, AndroidCA.CRLReason.SUPERSEDED)

            val soon = dao.getExpiringSoon(now, now + 30 * oneDay)

            assertEquals(listOf("0b"), soon.map { it.serialNumber })
            assertEquals(1, dao.countExpiringSoon(now, now + 30 * oneDay))
        }
    }

    @Test
    fun aCertificateExpiringExactlyAtTheThresholdIsIncluded() {
        runBlocking {
            val threshold = now + 30 * oneDay
            dao.insert(certificate("0a", notAfter = threshold))
            dao.insert(certificate("0b", notAfter = threshold + 1))

            assertEquals(
                listOf("0a"),
                dao.getExpiringSoon(now, threshold).map { it.serialNumber }
            )
        }
    }

    @Test
    fun theDefaultExpiryWindowIsThirtyDays() {
        runBlocking {
            dao.insert(certificate("0a", notAfter = now + 29 * oneDay))
            dao.insert(certificate("0b", notAfter = now + 31 * oneDay))
            dao.insert(certificate("0c", notAfter = now - oneDay))

            // Called without arguments, so the DAO's default `now` / `threshold`
            // are the ones under test.
            assertEquals(listOf("0a"), dao.getExpiringSoon().map { it.serialNumber })
            assertEquals(1, dao.countExpiringSoon())
            assertEquals(listOf("0c"), dao.getExpired().map { it.serialNumber })
            assertEquals(1, dao.countExpired())
        }
    }

    // -------------------------------------------------------------------------
    // Deletion
    // -------------------------------------------------------------------------

    @Test
    fun deleteBySerialRemovesOnlyThatRow() {
        runBlocking {
            dao.insert(certificate("0a"))
            dao.insert(certificate("0b"))

            dao.deleteBySerial("0a")

            assertNull(dao.getBySerial("0a"))
            assertNotNull(dao.getBySerial("0b"))
            assertEquals(1, dao.countAll())
        }
    }

    @Test
    fun deleteByFingerprintRemovesOnlyThatRow() {
        runBlocking {
            dao.insert(certificate("0a"))
            dao.insert(certificate("0b"))

            dao.deleteByFingerprint("0a".repeat(4))

            assertNull(dao.getBySerial("0a"))
            assertEquals(1, dao.countAll())
        }
    }

    @Test
    fun deleteByIdRemovesOnlyThatRow() {
        runBlocking {
            val id = dao.insert(certificate("0a"))
            dao.insert(certificate("0b"))

            dao.deleteById(id)

            assertNull(dao.getBySerial("0a"))
            assertEquals(1, dao.countAll())
        }
    }

    @Test
    fun deletingSomethingThatIsNotThereIsHarmless() {
        runBlocking {
            dao.insert(certificate("0a"))

            dao.deleteBySerial("no-such-serial")
            dao.deleteByFingerprint("no-such-fingerprint")
            dao.deleteById(9_999L)

            assertEquals(1, dao.countAll())
        }
    }

    @Test
    fun anEmptyTableAnswersEveryQuery() {
        runBlocking {
            assertEquals(0, dao.countAll())
            assertEquals(0, dao.countRevoked())
            assertTrue(dao.getAll().isEmpty())
            assertTrue(dao.getRevoked().isEmpty())
            assertTrue(dao.getCACertificates().isEmpty())
            assertTrue(dao.getExpired(now).isEmpty())
            assertTrue(dao.getExpiringSoon(now, now + 30 * oneDay).isEmpty())
            assertTrue(dao.observeAll().first().isEmpty())
        }
    }
}
