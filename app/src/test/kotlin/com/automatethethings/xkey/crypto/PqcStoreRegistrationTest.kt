/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */

package com.automatethethings.xkey.crypto

import android.content.Context
import com.automatethethings.xkey.XKeyApplication
import io.mockk.every
import io.mockk.mockk
import org.junit.After
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The software ML-DSA store is registered when the process starts, so a PIV
 * key manager built without a store (a PIV slot screen reopened alone after
 * Android killed the app) finds it before any other screen has run.
 */
class PqcStoreRegistrationTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private lateinit var context: Context

    @Before
    fun setUp() {
        PqcSoftwareKeyStore.clearSharedForTest()
        context = mockk(relaxed = true)
        every { context.applicationContext } returns context
        every { context.filesDir } returns tmp.root
    }

    @After
    fun tearDown() {
        PqcSoftwareKeyStore.clearSharedForTest()
    }

    @Test
    fun `a fresh process has no shared store`() {
        assertNull(PqcSoftwareKeyStore.shared)
    }

    @Test
    fun `the startup path registers the shared store before any screen`() {
        XKeyApplication.registerPqcSoftwareStore(context)

        val store = PqcSoftwareKeyStore.shared
        assertNotNull(store)
        assertSame(store, PqcSoftwareKeyStore.registerShared(context))
    }

    @Test
    fun `registering again keeps the store already registered`() {
        val first = PqcSoftwareKeyStore.registerShared(context)
        XKeyApplication.registerPqcSoftwareStore(context)

        assertSame(first, PqcSoftwareKeyStore.shared)
    }

    @Test
    fun `a store built with a test cipher never replaces the shared one`() {
        XKeyApplication.registerPqcSoftwareStore(context)
        val registered = PqcSoftwareKeyStore.shared

        PqcSoftwareKeyStore(context, mockk(relaxed = true))

        assertSame(registered, PqcSoftwareKeyStore.shared)
    }
}
