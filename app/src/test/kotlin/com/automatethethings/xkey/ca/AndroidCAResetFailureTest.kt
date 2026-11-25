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

package com.automatethethings.xkey.ca

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verify
import java.security.KeyStore
import java.security.KeyStoreException
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * [AndroidCA.reset] that cannot delete a CA key fails: the CA's private key
 * may still be on the device, so the reset is never reported complete and
 * the stored certificates stay with it.
 */
class AndroidCAResetFailureTest {

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.i(any(), any()) } returns 0
        every { Log.e(any(), any(), any()) } returns 0
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun aCaKeyThatCannotBeDeletedFailsTheReset() = runBlocking<Unit> {
        val prefs = mockk<SharedPreferences>(relaxed = true)
        val context = mockk<Context>(relaxed = true)
        every { context.getSharedPreferences(any(), any()) } returns prefs
        val keyStore = mockk<KeyStore>(relaxed = true)
        every { keyStore.containsAlias(any()) } returns true
        every { keyStore.deleteEntry(any()) } throws KeyStoreException("entry is busy")
        val ca = AndroidCA(context) { keyStore }

        val outcome = runCatching { ca.reset() }

        assertTrue("a failed CA key delete must fail the reset, got $outcome", outcome.isFailure)
        verify(exactly = 0) { prefs.edit() }
    }
}
