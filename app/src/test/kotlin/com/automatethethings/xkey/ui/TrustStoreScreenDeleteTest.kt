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

import android.content.Context
import com.automatethethings.xkey.truststore.TestCertificates
import com.automatethethings.xkey.truststore.TrustStoreRepository
import io.mockk.every
import io.mockk.mockk
import io.mockk.unmockkAll
import java.io.File
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Unit tests for TrustStoreActivity.confirmDelete's deletion step: the
 * screen reports a failed delete and refreshes the list either way.
 */
class TrustStoreScreenDeleteTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private lateinit var context: Context
    private lateinit var repository: TrustStoreRepository

    private val fingerprint = TestCertificates.fingerprint(TestCertificates.LEAF_A_PEM)

    @Before
    fun setUp() {
        val storeDir = tempFolder.newFolder("trust_store")
        context = mockk()
        every { context.getDir("trust_store", Context.MODE_PRIVATE) } returns storeDir
        repository = TrustStoreRepository(context, mockk())
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    private class Screen {
        val deletedRows = mutableListOf<String>()
        val results = mutableListOf<Boolean>()
        var refreshes = 0
    }

    private suspend fun confirmDelete(repo: TrustStoreRepository): Screen {
        val screen = Screen()
        deleteFromTrustStoreScreen(
            repo,
            fingerprint,
            deleteRow = { screen.deletedRows += fingerprint },
            showResult = { screen.results += it },
            refresh = { screen.refreshes++ }
        )
        return screen
    }

    @Test
    fun `a failed delete shows a failure message, keeps the row and refreshes the list`() = runTest {
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM))
        val refusing = TrustStoreRepository(context, mockk(), fileDeleter = { file: File ->
            if (file.name == "$fingerprint.der") false else file.delete()
        })

        val screen = confirmDelete(refusing)

        assertEquals(listOf(false), screen.results)
        assertTrue(screen.deletedRows.isEmpty())
        assertEquals(1, screen.refreshes)
        assertTrue(repository.hasCertificate(fingerprint))
    }

    @Test
    fun `a successful delete shows success, deletes the row and refreshes the list`() = runTest {
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM))

        val screen = confirmDelete(repository)

        assertEquals(listOf(true), screen.results)
        assertEquals(listOf(fingerprint), screen.deletedRows)
        assertEquals(1, screen.refreshes)
    }
}
