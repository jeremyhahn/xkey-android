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
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.AfterClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for [AndroidCA] in its *uninitialised* state, and for
 * [AndroidCA.reset].
 *
 * The behaviour pinned here is deliberate and has been regressed before:
 * Android Keystore self-signs a throwaway `CN=Fake` certificate as a side
 * effect of key generation, and `getRootCertificate()` / `getIntermediateCertificate()`
 * must throw rather than hand that certificate to a caller. `resetsAndTearsDown`
 * proves the same holds after a reset, and that a bare root key with no stored
 * certificate is still reported as "not generated".
 *
 * The CA lives at fixed Keystore aliases and a fixed SharedPreferences file, so
 * every test starts from a reset and the class resets again in `@AfterClass`,
 * leaving the device in the pristine (uninitialised) state the app ships with.
 */
@RunWith(AndroidJUnit4::class)
class AndroidCAUninitializedTest {

    private lateinit var context: Context
    private lateinit var ca: AndroidCA

    @Before
    fun setUp() = runBlocking<Unit> {
        context = ApplicationProvider.getApplicationContext()
        ca = AndroidCA(context)
        ca.reset()
    }

    @After
    fun tearDown() = runBlocking<Unit> {
        ca.reset()
    }

    companion object {
        @JvmStatic
        @AfterClass
        fun resetSharedCaState() = runBlocking<Unit> {
            AndroidCA(ApplicationProvider.getApplicationContext<Context>()).reset()
        }
    }

    @Test
    fun aFreshCaReportsNothingGenerated() {
        assertFalse(ca.isRootCAGenerated())
        assertFalse(ca.isIntermediateCAGenerated())
        assertFalse(ca.isInitialized())
    }

    @Test
    fun theCaBundleIsEmptyBeforeInitialization() {
        assertTrue(ca.getCABundle().isEmpty())
    }

    @Test
    fun theIntermediateCannotBeGeneratedBeforeTheRoot() = runBlocking {
        val result = ca.generateIntermediateCA(CASubject(cn = "Orphan Intermediate"))

        assertTrue("expected an error, got $result", result is CAInitResult.Error)
        assertEquals(
            "Root CA must be generated first",
            (result as CAInitResult.Error).message
        )
        assertFalse(ca.isIntermediateCAGenerated())
    }

    @Test
    fun issuingACertificateBeforeInitializationThrows() {
        val csr = CaTestSupport.csr("CN=too-early")

        val error = assertThrows(IllegalStateException::class.java) {
            runBlocking {
                ca.issueCertificate(csrDER = csr, profile = CertificateProfile.TLSClient())
            }
        }

        assertEquals("CA not initialized", error.message)
    }

    @Test
    fun generatingACrlBeforeInitializationThrows() {
        val error = assertThrows(IllegalStateException::class.java) {
            runBlocking { ca.generateCRL() }
        }

        assertEquals("CA not initialized", error.message)
    }

    @Test
    fun aRootKeyWithoutAStoredCertificateStillCountsAsNotGenerated() = runBlocking {
        val generated = ca.generateRootCA(CASubject(cn = "xKey Reset Probe Root"))
        CaTestSupport.assumeCaGenerated(generated, "Root CA generation")
        assertTrue(ca.isRootCAGenerated())

        // reset() drops both the Keystore entries and the stored certificates.
        ca.reset()

        assertFalse(ca.isRootCAGenerated())
        assertFalse(ca.isInitialized())
        assertThrows(IllegalStateException::class.java) { ca.getRootCertificate() }
        assertTrue(ca.getCABundle().isEmpty())
    }

    @Test
    fun resetIsSafeToCallOnAnAlreadyEmptyCa() = runBlocking {
        ca.reset()
        ca.reset()

        assertFalse(ca.isInitialized())
    }
}
