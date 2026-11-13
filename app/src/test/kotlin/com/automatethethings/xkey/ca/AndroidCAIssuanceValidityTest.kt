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
import com.automatethethings.xkey.audit.AuditLogger
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verify
import kotlinx.coroutines.runBlocking
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.io.OutputStream
import java.math.BigInteger
import java.security.Key
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreSpi
import java.security.PrivateKey
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Collections
import java.util.Date
import java.util.Enumeration

/**
 * Issuance-level tests for #181: a certificate [AndroidCA] signs never outlives
 * its issuer, and an expired or not-yet-valid issuer signs nothing and stores
 * nothing.
 *
 * The CA keys live in an in-memory KeyStore passed through AndroidCA's internal
 * constructor, so issuance runs on the JVM; the CA certificates are stored in
 * mocked SharedPreferences the way AndroidCA stores them. The issuer dates are
 * relative to the real clock, with margins of a day or more.
 */
class AndroidCAIssuanceValidityTest {

    private companion object {
        const val PREFS_NAME = "xkey_ca"
        const val PREF_ROOT_CERT_DER = "root_ca_cert_der"
        const val PREF_INTERMEDIATE_CERT_DER = "intermediate_ca_cert_der"
        const val DAY = 24L * 60 * 60 * 1000
    }

    private val stored = mutableMapOf<String, String>()
    private val keys = InMemoryKeyStoreSpi()
    private lateinit var dao: CertificateDao
    private lateinit var ca: AndroidCA

    private val rootKeys = ecKeyPair()
    private val intermediateKeys = ecKeyPair()
    private val leafKeys = ecKeyPair()

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.i(any(), any()) } returns 0
        every { Log.d(any(), any()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any(), any()) } returns 0

        mockkStatic(Base64::class)
        every { Base64.decode(any<String>(), any()) } answers {
            java.util.Base64.getDecoder().decode(firstArg<String>())
        }
        every { Base64.encodeToString(any(), any()) } answers {
            java.util.Base64.getEncoder().encodeToString(firstArg<ByteArray>())
        }

        mockkObject(AuditLogger)
        every { AuditLogger.logCertificateIssued(any(), any(), any()) } returns Unit

        val prefs = mockk<SharedPreferences>()
        every { prefs.getString(any(), any()) } answers { stored[firstArg<String>()] }
        val context = mockk<Context>()
        every { context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE) } returns prefs

        dao = mockk()
        coEvery { dao.insert(any()) } returns 1L

        val keyStore = object : KeyStore(keys, null, "in-memory") {}
        keyStore.load(null)
        ca = AndroidCA(context) { keyStore }
        ca.certificateDao = dao
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    // -------------------------------------------------------------------------
    // Fixtures
    // -------------------------------------------------------------------------

    private fun ecKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()

    private fun daysFromNow(days: Long) = Date(System.currentTimeMillis() + days * DAY)

    private fun signCA(
        subject: String,
        issuer: String,
        subjectKeys: KeyPair,
        issuerKey: PrivateKey,
        notBefore: Date,
        notAfter: Date
    ): X509Certificate {
        val holder = JcaX509v3CertificateBuilder(
            X500Name(issuer), BigInteger.valueOf(System.nanoTime()), notBefore, notAfter,
            X500Name(subject), subjectKeys.public
        ).addExtension(Extension.basicConstraints, true, BasicConstraints(1))
            .build(JcaContentSignerBuilder("SHA256withECDSA").build(issuerKey))
        return JcaX509CertificateConverter().getCertificate(holder)
    }

    private fun root(notBefore: Date = daysFromNow(-10), notAfter: Date = daysFromNow(3650)) =
        signCA("CN=Test Root", "CN=Test Root", rootKeys, rootKeys.private, notBefore, notAfter)

    /** A CA whose intermediate is valid from [notBefore] to [notAfter], under a 10-year root. */
    private fun caWithIntermediate(notBefore: Date, notAfter: Date): X509Certificate {
        val rootCert = root()
        val intermediate = signCA(
            "CN=Test Intermediate", "CN=Test Root", intermediateKeys, rootKeys.private,
            notBefore, notAfter
        )
        stored[PREF_ROOT_CERT_DER] = java.util.Base64.getEncoder().encodeToString(rootCert.encoded)
        stored[PREF_INTERMEDIATE_CERT_DER] =
            java.util.Base64.getEncoder().encodeToString(intermediate.encoded)
        keys.put(AndroidCA.ROOT_CA_ALIAS, rootKeys.private, rootCert)
        keys.put(AndroidCA.INTERMEDIATE_CA_ALIAS, intermediateKeys.private, intermediate)
        return intermediate
    }

    private fun issue(profile: CertificateProfile = CertificateProfile.TLSServer()) = runBlocking {
        ca.issueForPublicKey(leafKeys.public, X500Name("CN=leaf.example.com"), profile)
    }

    private fun parse(der: ByteArray) = CertificateFactory.getInstance("X.509")
        .generateCertificate(ByteArrayInputStream(der)) as X509Certificate

    private fun assertNothingIssuedOrStored() {
        coVerify(exactly = 0) { dao.insert(any()) }
        verify(exactly = 0) { AuditLogger.logCertificateIssued(any(), any(), any()) }
    }

    // -------------------------------------------------------------------------
    // Leaf issuance (issueForPublicKey, behind every issuance path)
    // -------------------------------------------------------------------------

    @Test
    fun `leaf under an issuer with 30 days left ends at the issuer notAfter`() {
        val issuer = caWithIntermediate(daysFromNow(-10), daysFromNow(30))

        val issued = issue(CertificateProfile.TLSServer(validityDays = 365))

        val leaf = parse(issued.certificate)
        assertEquals(issuer.notAfter, leaf.notAfter)
        assertEquals(issuer.notAfter.time, issued.notAfter)
        coVerify(exactly = 1) { dao.insert(match { it.notAfter == issuer.notAfter.time }) }
    }

    @Test
    fun `leaf under an issuer with years left keeps the profile validity`() {
        caWithIntermediate(daysFromNow(-10), daysFromNow(1000))

        val leaf = parse(issue(CertificateProfile.TLSServer(validityDays = 365)).certificate)

        val days = (leaf.notAfter.time - leaf.notBefore.time) / DAY
        assertEquals(365L, days)
    }

    @Test
    fun `expired issuer issues no certificate and stores no row`() {
        val issuer = caWithIntermediate(daysFromNow(-400), daysFromNow(-1))

        val e = assertThrows(IllegalStateException::class.java) { issue() }

        assertTrue(e.message!!.contains(issuer.notAfter.toInstant().toString()))
        assertNothingIssuedOrStored()
    }

    @Test
    fun `issuer not yet valid issues no certificate and stores no row`() {
        val issuer = caWithIntermediate(daysFromNow(1), daysFromNow(1000))

        val e = assertThrows(IllegalStateException::class.java) { issue() }

        assertTrue(e.message!!.contains(issuer.notBefore.toInstant().toString()))
        assertNothingIssuedOrStored()
    }

    @Test
    fun `zero validity days issues no certificate and stores no row`() {
        caWithIntermediate(daysFromNow(-10), daysFromNow(1000))

        assertThrows(IllegalArgumentException::class.java) {
            issue(CertificateProfile.TLSServer(validityDays = 0))
        }
        assertNothingIssuedOrStored()
    }

    @Test
    fun `negative validity days issues no certificate and stores no row`() {
        caWithIntermediate(daysFromNow(-10), daysFromNow(1000))

        assertThrows(IllegalArgumentException::class.java) {
            issue(CertificateProfile.TLSServer(validityDays = -1))
        }
        assertNothingIssuedOrStored()
    }

    // -------------------------------------------------------------------------
    // Intermediate issuance (generateIntermediateCertificate)
    // -------------------------------------------------------------------------

    @Test
    fun `intermediate under a root with 400 days left ends at the root notAfter`() {
        val rootCert = root(notAfter = daysFromNow(400))
        keys.put(AndroidCA.INTERMEDIATE_CA_ALIAS, intermediateKeys.private,
            signCA("CN=Fake", "CN=Fake", intermediateKeys, intermediateKeys.private,
                daysFromNow(-1), daysFromNow(1)))

        val intermediate = ca.generateIntermediateCertificate(
            rootCert, rootKeys.private, X500Name("CN=Test Intermediate")
        )

        assertEquals(rootCert.notAfter, intermediate.notAfter)
    }

    @Test
    fun `expired root signs no intermediate`() {
        val rootCert = root(notBefore = daysFromNow(-4000), notAfter = daysFromNow(-1))
        keys.put(AndroidCA.INTERMEDIATE_CA_ALIAS, intermediateKeys.private,
            signCA("CN=Fake", "CN=Fake", intermediateKeys, intermediateKeys.private,
                daysFromNow(-1), daysFromNow(1)))

        assertThrows(IllegalStateException::class.java) {
            ca.generateIntermediateCertificate(rootCert, rootKeys.private, X500Name("CN=Test Intermediate"))
        }
    }

    // -------------------------------------------------------------------------
    // In-memory KeyStore: private-key entries without passwords, like the
    // Android Keystore's.
    // -------------------------------------------------------------------------

    private class InMemoryKeyStoreSpi : KeyStoreSpi() {
        private val entries = linkedMapOf<String, Pair<Key, Array<Certificate>>>()

        fun put(alias: String, key: PrivateKey, cert: Certificate) {
            entries[alias] = key to arrayOf(cert)
        }

        override fun engineGetKey(alias: String, password: CharArray?): Key? = entries[alias]?.first
        override fun engineGetCertificateChain(alias: String): Array<Certificate>? = entries[alias]?.second
        override fun engineGetCertificate(alias: String): Certificate? = entries[alias]?.second?.first()
        override fun engineGetCreationDate(alias: String): Date? = entries[alias]?.let { Date() }
        override fun engineSetKeyEntry(
            alias: String, key: Key, password: CharArray?, chain: Array<Certificate>?
        ) {
            entries[alias] = key to (chain ?: emptyArray())
        }
        override fun engineSetKeyEntry(alias: String, key: ByteArray, chain: Array<Certificate>?) =
            throw UnsupportedOperationException()
        override fun engineSetCertificateEntry(alias: String, cert: Certificate) =
            throw UnsupportedOperationException()
        override fun engineDeleteEntry(alias: String) {
            entries.remove(alias)
        }
        override fun engineAliases(): Enumeration<String> = Collections.enumeration(entries.keys.toList())
        override fun engineContainsAlias(alias: String): Boolean = alias in entries
        override fun engineSize(): Int = entries.size
        override fun engineIsKeyEntry(alias: String): Boolean = alias in entries
        override fun engineIsCertificateEntry(alias: String): Boolean = false
        override fun engineGetCertificateAlias(cert: Certificate): String? =
            entries.entries.firstOrNull { it.value.second.firstOrNull() == cert }?.key
        override fun engineStore(stream: OutputStream?, password: CharArray?) = Unit
        override fun engineLoad(stream: InputStream?, password: CharArray?) = Unit
        override fun engineGetEntry(
            alias: String, protParam: KeyStore.ProtectionParameter?
        ): KeyStore.Entry? = entries[alias]?.let { (key, chain) ->
            KeyStore.PrivateKeyEntry(key as PrivateKey, chain)
        }
    }
}
