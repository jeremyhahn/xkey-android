/*
 * Copyright (c) 2025 Jeremy Hahn
 * Copyright (c) 2025 Automate The Things, LLC
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

package com.automatethethings.xkey.ui

import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.storage.dao.ContactDao
import com.automatethethings.xkey.storage.entity.ContactEntity
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.unmockkAll
import io.mockk.verify
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * [deleteContactAudited] writes a contact-deleted audit entry only when the
 * delete removed a row: a contact already gone (another screen, a second
 * tap) writes none.
 */
class ContactDeleteAuditTest {

    private val contact = ContactEntity(
        name = "Bob",
        publicKeyDer = byteArrayOf(0x01),
        publicKeyFingerprint = "SHA256:def456",
        algorithm = "ES256",
        source = "qr"
    )
    private val contactDao = mockk<ContactDao>()

    @Before
    fun setUp() {
        mockkObject(AuditLogger)
        every { AuditLogger.logContactDeleted(any(), any()) } returns Unit
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `a delete that removed no row is not audited`() = runTest {
        coEvery { contactDao.deleteByFingerprint("SHA256:def456") } returns 0

        assertFalse(deleteContactAudited(contactDao, contact))

        verify(exactly = 0) { AuditLogger.logContactDeleted(any(), any()) }
    }

    @Test
    fun `a delete that removed the row is audited once`() = runTest {
        coEvery { contactDao.deleteByFingerprint("SHA256:def456") } returns 1

        assertTrue(deleteContactAudited(contactDao, contact))

        verify(exactly = 1) { AuditLogger.logContactDeleted("Bob", "SHA256:def456") }
    }
}
