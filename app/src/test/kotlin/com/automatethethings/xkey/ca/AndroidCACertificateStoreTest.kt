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
import android.content.SharedPreferences
import android.util.Base64
import android.util.Log
import com.automatethethings.xkey.truststore.TestCertificates
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.util.Date
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for the certificate-reading half of [AndroidCA].
 *
 * Issuance needs StrongBox/TEE keys and lives in the instrumented `AndroidCATest`,
 * but the accessors read their certificates back out of SharedPreferences and
 * never touch the Keystore (the `keyStore` property is lazy), so they are
 * reachable on the JVM with a mocked [Context]. That makes it possible to pin
 * two things the instrumented suite cannot reach: what happens when the stored
 * blob is corrupt, and what `CACertificateInfo.isExpired` reports for a CA
 * certificate that has actually expired.
 *
 * The "absent certificate" behaviour is deliberate and has been regressed
 * before: Android Keystore self-signs a throwaway `CN=Fake`
 * certificate as a side effect of key generation, so the accessors must throw
 * (or return null) rather than fall back to whatever the Keystore holds.
 */
class AndroidCACertificateStoreTest {

    /**
     * Mirrors the private SharedPreferences keys in [AndroidCA]; the file name
     * and key names are part of the on-device storage format.
     */
    private companion object {
        const val PREFS_NAME = "xkey_ca"
        const val PREF_ROOT_CERT_DER = "root_ca_cert_der"
        const val PREF_INTERMEDIATE_CERT_DER = "intermediate_ca_cert_der"
    }

    private val stored = mutableMapOf<String, String>()
    private lateinit var context: Context
    private lateinit var ca: AndroidCA

    @Before
    fun setUp() {
        stored.clear()

        mockkStatic(Log::class)
        every { Log.i(any(), any()) } returns 0
        every { Log.d(any(), any()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.e(any(), any(), any()) } returns 0

        mockkStatic(Base64::class)
        every { Base64.decode(any<String>(), any()) } answers {
            java.util.Base64.getDecoder().decode(firstArg<String>())
        }

        val prefs = mockk<SharedPreferences>()
        every { prefs.getString(any(), any()) } answers { stored[firstArg<String>()] }

        context = mockk()
        every { context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE) } returns prefs

        ca = AndroidCA(context)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    /** Stores a PEM fixture the way [AndroidCA] does: base64 of the DER, no wrapping. */
    private fun store(prefKey: String, pem: String) {
        stored[prefKey] = java.util.Base64.getEncoder()
            .encodeToString(TestCertificates.der(pem))
    }

    // -------------------------------------------------------------------------
    // Reading a stored hierarchy
    // -------------------------------------------------------------------------

    @Test
    fun `getRootCertificate returns the stored certificate`() {
        store(PREF_ROOT_CERT_DER, TestCertificates.ROOT_CA_A_PEM)

        val root = ca.getRootCertificate()

        assertTrue(root.subjectX500Principal.name.contains(TestCertificates.ROOT_A_CN))
        assertEquals(root.subjectX500Principal, root.issuerX500Principal)
    }

    @Test
    fun `getIntermediateCertificate returns the stored certificate`() {
        store(PREF_INTERMEDIATE_CERT_DER, TestCertificates.INTERMEDIATE_A_PEM)

        val intermediate = ca.getIntermediateCertificate()

        assertTrue(
            intermediate.subjectX500Principal.name.contains(TestCertificates.INTERMEDIATE_A_CN)
        )
        assertTrue(intermediate.issuerX500Principal.name.contains(TestCertificates.ROOT_A_CN))
    }

    // -------------------------------------------------------------------------
    // Absent certificates: throw rather than hand back the Keystore's CN=Fake
    // -------------------------------------------------------------------------

    @Test
    fun `reading an absent root certificate throws instead of returning a placeholder`() {
        val error = assertThrows(IllegalStateException::class.java) { ca.getRootCertificate() }

        assertTrue(
            "message should point at initialize(): ${error.message}",
            error.message!!.contains("Root CA certificate not found")
        )
    }

    @Test
    fun `reading an absent intermediate certificate throws`() {
        val error = assertThrows(IllegalStateException::class.java) {
            ca.getIntermediateCertificate()
        }

        assertTrue(
            "message should point at initialize(): ${error.message}",
            error.message!!.contains("Intermediate CA certificate not found")
        )
    }

    @Test
    fun `the certificate info accessors report null when nothing is stored`() {
        assertNull(ca.getRootCACertificateInfo())
        assertNull(ca.getIntermediateCACertificateInfo())
    }

    // -------------------------------------------------------------------------
    // Corrupt storage
    // -------------------------------------------------------------------------

    @Test
    fun `a stored value that is not base64 is treated as missing`() {
        stored[PREF_ROOT_CERT_DER] = "this is not base64 %%%"

        assertNull(ca.getRootCACertificateInfo())
        assertThrows(IllegalStateException::class.java) { ca.getRootCertificate() }
    }

    @Test
    fun `a stored value that is not a certificate is treated as missing`() {
        // A well-formed base64 blob that decodes to an EC public key, not a cert.
        store(PREF_ROOT_CERT_DER, TestCertificates.NOT_A_CERTIFICATE_PEM)

        assertNull(ca.getRootCACertificateInfo())
        assertThrows(IllegalStateException::class.java) { ca.getRootCertificate() }
    }

    @Test
    fun `a truncated certificate is treated as missing`() {
        val full = TestCertificates.der(TestCertificates.ROOT_CA_A_PEM)
        stored[PREF_INTERMEDIATE_CERT_DER] = java.util.Base64.getEncoder()
            .encodeToString(full.copyOfRange(0, full.size / 2))

        assertNull(ca.getIntermediateCACertificateInfo())
        assertThrows(IllegalStateException::class.java) { ca.getIntermediateCertificate() }
    }

    // -------------------------------------------------------------------------
    // CACertificateInfo
    // -------------------------------------------------------------------------

    @Test
    fun `certificate info mirrors the certificate and formats the fingerprint`() {
        store(PREF_ROOT_CERT_DER, TestCertificates.ROOT_CA_A_PEM)
        val root = ca.getRootCertificate()

        val info = ca.getRootCACertificateInfo()!!

        assertEquals(root.subjectX500Principal.name, info.subjectDN)
        assertEquals(root.issuerX500Principal.name, info.issuerDN)
        assertEquals(root.notBefore, info.notBefore)
        assertEquals(root.notAfter, info.notAfter)

        // "AA:BB:..." -- 32 upper-case hex byte groups of the SHA-256 digest.
        val groups = info.fingerprint.split(":")
        assertEquals(32, groups.size)
        assertTrue(groups.all { it.length == 2 && it.all { c -> c.isDigit() || c in 'A'..'F' } })
        assertEquals(
            TestCertificates.fingerprint(TestCertificates.ROOT_CA_A_PEM).uppercase(),
            groups.joinToString("")
        )
    }

    @Test
    fun `a long-lived certificate is not reported as expired`() {
        store(PREF_ROOT_CERT_DER, TestCertificates.ROOT_CA_A_PEM)

        val info = ca.getRootCACertificateInfo()!!

        assertFalse(info.isExpired)
        assertTrue(info.notAfter.after(Date()))
    }

    @Test
    fun `an expired certificate is reported as expired`() {
        // Any DER parses here; the CA slot is just storage, and an expired CA is
        // exactly the state the UI has to render.
        store(PREF_INTERMEDIATE_CERT_DER, TestCertificates.EXPIRED_LEAF_A_PEM)

        val info = ca.getIntermediateCACertificateInfo()!!

        assertTrue(info.isExpired)
        assertEquals(
            TestCertificates.EXPIRED_LEAF_A_NOT_AFTER_MILLIS,
            info.notAfter.time
        )
    }

    // -------------------------------------------------------------------------
    // Keystore aliases
    // -------------------------------------------------------------------------

    @Test
    fun `the Keystore aliases are part of the storage contract`() {
        assertEquals("xkey_root_ca", AndroidCA.ROOT_CA_ALIAS)
        assertEquals("xkey_intermediate_ca", AndroidCA.INTERMEDIATE_CA_ALIAS)
    }
}
