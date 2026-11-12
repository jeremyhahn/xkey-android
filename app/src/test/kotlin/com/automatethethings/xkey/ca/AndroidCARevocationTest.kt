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
import java.security.cert.X509CRL
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Collections
import java.util.Date
import java.util.Enumeration

/**
 * Revocation tests for #213: the CRL [AndroidCA.generateCRL] signs with the
 * current intermediate lists only the revoked certificates that intermediate
 * signed, and a revocation is final (a second one changes nothing and logs
 * nothing).
 *
 * The CA runs on the JVM as in [AndroidCAIssuanceValidityTest]: an in-memory
 * KeyStore through AndroidCA's internal constructor, the CA certificates in
 * mocked SharedPreferences, and a mocked [CertificateDao].
 */
class AndroidCARevocationTest {

    private companion object {
        const val PREFS_NAME = "xkey_ca"
        const val PREF_ROOT_CERT_DER = "root_ca_cert_der"
        const val PREF_INTERMEDIATE_CERT_DER = "intermediate_ca_cert_der"
        const val DAY = 24L * 60 * 60 * 1000
        const val ROOT_NAME = "CN=Test Root"
        const val INTERMEDIATE_NAME = "CN=Test Intermediate"
    }

    private val stored = mutableMapOf<String, String>()
    private val keys = InMemoryKeyStoreSpi()
    private lateinit var dao: CertificateDao
    private lateinit var ca: AndroidCA

    private val rootKeys = ecKeyPair()
    private val intermediateKeys = ecKeyPair()
    private lateinit var intermediate: X509Certificate

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
        every { AuditLogger.logCRLGenerated(any()) } returns Unit
        every { AuditLogger.logCertificateRevoked(any(), any(), any()) } returns Unit

        val prefs = mockk<SharedPreferences>()
        every { prefs.getString(any(), any()) } answers { stored[firstArg<String>()] }
        val context = mockk<Context>()
        every { context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE) } returns prefs

        // Relaxed: an unstubbed DAO update reports no row changed.
        dao = mockk(relaxed = true)

        val rootCert = signCA(ROOT_NAME, ROOT_NAME, rootKeys, rootKeys.private)
        intermediate = signCA(INTERMEDIATE_NAME, ROOT_NAME, intermediateKeys, rootKeys.private)
        stored[PREF_ROOT_CERT_DER] = java.util.Base64.getEncoder().encodeToString(rootCert.encoded)
        stored[PREF_INTERMEDIATE_CERT_DER] =
            java.util.Base64.getEncoder().encodeToString(intermediate.encoded)
        keys.put(AndroidCA.ROOT_CA_ALIAS, rootKeys.private, rootCert)
        keys.put(AndroidCA.INTERMEDIATE_CA_ALIAS, intermediateKeys.private, intermediate)

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

    private fun signCA(
        subject: String,
        issuer: String,
        subjectKeys: KeyPair,
        issuerKey: PrivateKey
    ): X509Certificate = sign(subject, issuer, subjectKeys, issuerKey, BasicConstraints(1))

    private fun sign(
        subject: String,
        issuer: String,
        subjectKeys: KeyPair,
        issuerKey: PrivateKey,
        constraints: BasicConstraints = BasicConstraints(false)
    ): X509Certificate {
        val holder = JcaX509v3CertificateBuilder(
            X500Name(issuer), BigInteger.valueOf(System.nanoTime()),
            Date(System.currentTimeMillis() - 10 * DAY), Date(System.currentTimeMillis() + 1000 * DAY),
            X500Name(subject), subjectKeys.public
        ).addExtension(Extension.basicConstraints, true, constraints)
            .build(JcaContentSignerBuilder("SHA256withECDSA").build(issuerKey))
        return JcaX509CertificateConverter().getCertificate(holder)
    }

    private fun pem(cert: X509Certificate) =
        "-----BEGIN CERTIFICATE-----\n" +
            java.util.Base64.getEncoder().encodeToString(cert.encoded) +
            "\n-----END CERTIFICATE-----\n"

    private fun revokedRow(cert: X509Certificate, reason: Int = AndroidCA.CRLReason.KEY_COMPROMISE) =
        CertificateEntity(
            serialNumber = cert.serialNumber.toString(16),
            subjectDN = cert.subjectX500Principal.name,
            issuerDN = cert.issuerX500Principal.name,
            notBefore = cert.notBefore.time,
            notAfter = cert.notAfter.time,
            profile = "tls-server",
            fingerprint = "00",
            certificatePEM = pem(cert),
            isCA = cert.basicConstraints >= 0,
            revoked = true,
            revokedAt = System.currentTimeMillis() - DAY,
            revokedReason = reason
        )

    private fun leaf(issuerKey: PrivateKey = intermediateKeys.private) =
        sign("CN=leaf.example.com", INTERMEDIATE_NAME, ecKeyPair(), issuerKey)

    private fun crlSerials(): Set<BigInteger> {
        val crl = CertificateFactory.getInstance("X.509")
            .generateCRL(ByteArrayInputStream(runBlocking { ca.generateCRL() })) as X509CRL
        crl.verify(intermediate.publicKey)
        return crl.revokedCertificates.orEmpty().map { it.serialNumber }.toSet()
    }

    // -------------------------------------------------------------------------
    // CRL scope
    // -------------------------------------------------------------------------

    @Test
    fun `CRL lists a revoked certificate the current intermediate signed`() {
        val issued = leaf()
        coEvery { dao.getRevoked() } returns listOf(revokedRow(issued))

        assertEquals(setOf(issued.serialNumber), crlSerials())
    }

    @Test
    fun `CRL leaves out the intermediate's own revoked row, which the root signed`() {
        val issued = leaf()
        coEvery { dao.getRevoked() } returns listOf(revokedRow(intermediate), revokedRow(issued))

        assertEquals(setOf(issued.serialNumber), crlSerials())
    }

    @Test
    fun `CRL leaves out a row signed by another key under the same issuer name`() {
        // The old intermediate's leaf, left in the table after reset() and a
        // fresh initialise under the same name.
        val oldIntermediateKeys = ecKeyPair()
        val oldLeaf = leaf(issuerKey = oldIntermediateKeys.private)
        val issued = leaf()
        coEvery { dao.getRevoked() } returns listOf(revokedRow(oldLeaf), revokedRow(issued))

        assertEquals(setOf(issued.serialNumber), crlSerials())
    }

    @Test
    fun `CRL leaves out a row whose stored certificate does not parse`() {
        val issued = leaf()
        val broken = revokedRow(leaf()).copy(certificatePEM = "not a certificate")
        coEvery { dao.getRevoked() } returns listOf(broken, revokedRow(issued))

        assertEquals(setOf(issued.serialNumber), crlSerials())
    }

    // -------------------------------------------------------------------------
    // A revocation is final
    // -------------------------------------------------------------------------

    @Test
    fun `revoking an already revoked serial reports it and writes no audit entry`() {
        val row = revokedRow(leaf())
        coEvery { dao.getBySerial(row.serialNumber) } returns row
        // The DAO's revoked = 0 guard changes no row (the relaxed mock's 0).

        val result: Any = runBlocking { ca.revoke(row.serialNumber, AndroidCA.CRLReason.SUPERSEDED) }

        assertEquals(false, result)
        verify(exactly = 0) { AuditLogger.logCertificateRevoked(any(), any(), any()) }
    }
}

/** In-memory KeyStore: private-key entries without passwords, like the Android Keystore's. */
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
