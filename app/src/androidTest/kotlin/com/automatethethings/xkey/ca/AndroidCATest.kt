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
import kotlinx.coroutines.runBlocking
import org.bouncycastle.asn1.x500.X500Name
import org.junit.After
import org.junit.AfterClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509CRL
import java.security.cert.X509Certificate
import java.util.Date

/**
 * Instrumented tests for [AndroidCA] once the CA hierarchy exists.
 *
 * The root and intermediate keys are StrongBox/TEE-backed Android Keystore keys,
 * so none of this is reachable from a JVM unit test. The hierarchy is generated
 * once in `@BeforeClass` (two EC key pairs is the expensive part) and every test
 * builds its own cheap [AndroidCA] handle over that shared Keystore/SharedPreferences
 * state.
 *
 * The assertions are on the certificates themselves rather than on return codes:
 * issuer/subject chaining, real signature verification with the parent's public
 * key, BasicConstraints/KeyUsage/EKU/SAN contents and criticality, validity
 * windows, and the SHA-256 fingerprint. Rejection paths (broken CSR signature,
 * unknown profile name, revoking an unknown serial, CRL/revocation without a
 * DAO) are covered alongside them.
 *
 * Room is only ever an **in-memory** database here, so issued certificates never
 * reach the shared on-device `certificates` table; `@AfterClass` resets the CA so
 * the device is left in the uninitialised state the app ships with.
 */
@RunWith(AndroidJUnit4::class)
class AndroidCATest {

    private lateinit var context: Context
    private lateinit var ca: AndroidCA
    private lateinit var database: XKeyDatabase

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        ca = AndroidCA(context)
        database = Room.inMemoryDatabaseBuilder(context, XKeyDatabase::class.java).build()
    }

    @After
    fun tearDown() {
        database.close()
    }

    companion object {
        private val ROOT_SUBJECT = CASubject(
            cn = "xKey Test Root CA",
            org = "Automate The Things",
            ou = "Testing",
            locality = "Austin",
            province = "TX",
            country = "US"
        )
        private val INTERMEDIATE_SUBJECT = CASubject(
            cn = "xKey Test Intermediate CA",
            org = "Automate The Things",
            country = "US"
        )

        /** Start of the run, used to purge the audit rows issuance writes. */
        private var startedAt = 0L

        @JvmStatic
        @BeforeClass
        fun generateHierarchy() = runBlocking<Unit> {
            startedAt = System.currentTimeMillis()
            val ca = AndroidCA(ApplicationProvider.getApplicationContext<Context>())
            ca.reset()
            CaTestSupport.assumeCaGenerated(ca.generateRootCA(ROOT_SUBJECT), "Root CA generation")
            CaTestSupport.assumeCaGenerated(
                ca.generateIntermediateCA(INTERMEDIATE_SUBJECT),
                "Intermediate CA generation"
            )
        }

        @JvmStatic
        @AfterClass
        fun resetSharedCaState() = runBlocking<Unit> {
            val context = ApplicationProvider.getApplicationContext<Context>()
            AndroidCA(context).reset()

            // Issuance audit-logs into the shared database with a null key id, so
            // the rows cannot be removed through AuditLogDao; delete exactly the
            // certificate events this class produced.
            XKeyDatabase.getInstance(context).openHelper.writableDatabase.delete(
                "audit_logs",
                "timestamp >= ? AND operation_type IN " +
                    "('CERTIFICATE_ISSUED', 'CERTIFICATE_REVOKED', 'CSR_SIGNED', 'CRL_GENERATED')",
                arrayOf(startedAt.toString())
            )
            Unit
        }
    }

    private fun parse(der: ByteArray): X509Certificate =
        CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(der)) as X509Certificate

    private fun sha256Hex(data: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }

    private fun issue(
        profile: CertificateProfile,
        subject: String? = null,
        signingAlias: String = AndroidCA.INTERMEDIATE_CA_ALIAS
    ): IssuedCertificate = runBlocking {
        ca.issueCertificate(
            csrDER = CaTestSupport.csr(subject ?: "CN=requester"),
            profile = profile,
            subjectDN = subject?.let { X500Name(it) },
            signingAlias = signingAlias
        )
    }

    // -------------------------------------------------------------------------
    // Root CA
    // -------------------------------------------------------------------------

    @Test
    fun theCaReportsItselfInitialized() {
        assertTrue(ca.isRootCAGenerated())
        assertTrue(ca.isIntermediateCAGenerated())
        assertTrue(ca.isInitialized())
    }

    @Test
    fun theRootCertificateIsSelfSignedWithTheConfiguredSubject() {
        val root = ca.getRootCertificate()

        val subject = root.subjectX500Principal.name
        assertEquals(subject, root.issuerX500Principal.name)
        assertTrue("CN missing from $subject", subject.contains("CN=xKey Test Root CA"))
        assertTrue("O missing from $subject", subject.contains("O=Automate The Things"))
        assertTrue("OU missing from $subject", subject.contains("OU=Testing"))
        assertTrue("L missing from $subject", subject.contains("L=Austin"))
        assertTrue("ST missing from $subject", subject.contains("ST=TX"))
        assertTrue("C missing from $subject", subject.contains("C=US"))

        // A self-signed certificate must verify against its own public key.
        root.verify(root.publicKey)
        assertEquals("SHA256WITHECDSA", root.sigAlgName.uppercase())
    }

    @Test
    fun theRootCertificateIsACaThatMayIssueOneLevelOfSubordinates() {
        val root = ca.getRootCertificate()

        assertEquals("pathLenConstraint", 1, root.basicConstraints)
        val usage = root.keyUsage!!
        assertTrue("keyCertSign", usage[CaTestSupport.KU_KEY_CERT_SIGN])
        assertTrue("cRLSign", usage[CaTestSupport.KU_CRL_SIGN])
        assertFalse("digitalSignature", usage[CaTestSupport.KU_DIGITAL_SIGNATURE])

        assertTrue(root.criticalExtensionOIDs.contains(CaTestSupport.OID_BASIC_CONSTRAINTS))
        assertTrue(root.criticalExtensionOIDs.contains(CaTestSupport.OID_KEY_USAGE))
        assertNotNull(root.getExtensionValue(CaTestSupport.OID_SUBJECT_KEY_IDENTIFIER))
        assertNotNull(root.getExtensionValue(CaTestSupport.OID_AUTHORITY_KEY_IDENTIFIER))
    }

    @Test
    fun theRootCertificateIsValidForTenYears() {
        val root = ca.getRootCertificate()

        val days = CaTestSupport.validityDays(root)
        assertTrue("expected ~10 years, got $days days", days in 3650L..3654L)
        assertTrue("root must not be expired", root.notAfter.after(Date()))
    }

    @Test
    fun regeneratingTheRootReportsAlreadyInitializedWithTheStoredCertificates() = runBlocking {
        val result = ca.generateRootCA(CASubject(cn = "Ignored"))

        assertTrue("expected AlreadyInitialized, got $result", result is CAInitResult.AlreadyInitialized)
        result as CAInitResult.AlreadyInitialized
        assertEquals(
            ca.getRootCertificate().subjectX500Principal.name,
            parse(result.rootCertDER).subjectX500Principal.name
        )
        assertEquals(
            ca.getIntermediateCertificate().subjectX500Principal.name,
            parse(result.intermediateCertDER).subjectX500Principal.name
        )
    }

    // -------------------------------------------------------------------------
    // Intermediate CA
    // -------------------------------------------------------------------------

    @Test
    fun theIntermediateIsIssuedByAndVerifiesAgainstTheRoot() {
        val root = ca.getRootCertificate()
        val intermediate = ca.getIntermediateCertificate()

        assertEquals(root.subjectX500Principal.name, intermediate.issuerX500Principal.name)
        assertTrue(
            intermediate.subjectX500Principal.name.contains("CN=xKey Test Intermediate CA")
        )
        // Proves the root key actually signed it.
        intermediate.verify(root.publicKey)

        // ...and that verification is not vacuous: its own key must not verify it.
        val selfVerified = try {
            intermediate.verify(intermediate.publicKey)
            true
        } catch (_: Exception) {
            false
        }
        assertFalse("intermediate must not be self-signed", selfVerified)
    }

    @Test
    fun theIntermediateIsALeafCaValidForFiveYears() {
        val intermediate = ca.getIntermediateCertificate()

        assertEquals("pathLenConstraint", 0, intermediate.basicConstraints)
        val usage = intermediate.keyUsage!!
        assertTrue(usage[CaTestSupport.KU_KEY_CERT_SIGN])
        assertTrue(usage[CaTestSupport.KU_CRL_SIGN])

        val days = CaTestSupport.validityDays(intermediate)
        assertTrue("expected ~5 years, got $days days", days in 1824L..1828L)
    }

    @Test
    fun initializeOnAnAlreadyBuiltHierarchyIsIdempotent() = runBlocking {
        val before = ca.getIntermediateCertificate().serialNumber

        val result = ca.initialize(CASubject(cn = "Ignored"))

        assertTrue("expected AlreadyInitialized, got $result", result is CAInitResult.AlreadyInitialized)
        assertEquals(before, ca.getIntermediateCertificate().serialNumber)
    }

    // -------------------------------------------------------------------------
    // Accessors
    // -------------------------------------------------------------------------

    @Test
    fun theCaBundleIsOrderedIntermediateThenRoot() {
        val bundle = ca.getCABundle()

        assertEquals(2, bundle.size)
        assertEquals(
            ca.getIntermediateCertificate().subjectX500Principal.name,
            parse(bundle[0]).subjectX500Principal.name
        )
        assertEquals(
            ca.getRootCertificate().subjectX500Principal.name,
            parse(bundle[1]).subjectX500Principal.name
        )
    }

    @Test
    fun certificateInfoExposesAColonSeparatedFingerprintAndExpiryState() {
        val root = ca.getRootCertificate()

        val info = ca.getRootCACertificateInfo()!!

        assertEquals(root.subjectX500Principal.name, info.subjectDN)
        assertEquals(root.issuerX500Principal.name, info.issuerDN)
        assertEquals(root.notBefore, info.notBefore)
        assertEquals(root.notAfter, info.notAfter)
        assertFalse(info.isExpired)

        // "AA:BB:..." -- 32 upper-case hex byte groups.
        val groups = info.fingerprint.split(":")
        assertEquals(32, groups.size)
        assertTrue(groups.all { it.length == 2 && it.all { c -> c.isDigit() || c in 'A'..'F' } })
        assertEquals(sha256Hex(root.encoded).uppercase(), groups.joinToString(""))

        val intermediateInfo = ca.getIntermediateCACertificateInfo()!!
        assertEquals(ca.getIntermediateCertificate().subjectX500Principal.name, intermediateInfo.subjectDN)
    }

    // -------------------------------------------------------------------------
    // Issuance
    // -------------------------------------------------------------------------

    @Test
    fun aTlsServerCertificateCarriesServerAuthEkuAndItsSubjectAltNames() {
        val issued = issue(
            CertificateProfile.TLSServer(
                dnsNames = listOf("api.example.com", "www.example.com"),
                ipAddresses = listOf("10.0.0.7")
            ),
            subject = "CN=api.example.com"
        )

        val cert = parse(issued.certificate)
        assertEquals(listOf("1.3.6.1.5.5.7.3.1"), cert.extendedKeyUsage)

        val usage = cert.keyUsage!!
        assertTrue(usage[CaTestSupport.KU_DIGITAL_SIGNATURE])
        assertTrue(usage[CaTestSupport.KU_KEY_ENCIPHERMENT])
        assertFalse(usage[CaTestSupport.KU_KEY_CERT_SIGN])

        val sans = cert.subjectAlternativeNames!!.map { it[0] as Int to it[1] as String }
        assertTrue(sans.contains(CaTestSupport.SAN_DNS to "api.example.com"))
        assertTrue(sans.contains(CaTestSupport.SAN_DNS to "www.example.com"))
        assertTrue(sans.contains(CaTestSupport.SAN_IP to "10.0.0.7"))

        assertEquals(-1, cert.basicConstraints)
        assertTrue(cert.criticalExtensionOIDs.contains(CaTestSupport.OID_BASIC_CONSTRAINTS))
        assertFalse(cert.criticalExtensionOIDs.contains(CaTestSupport.OID_EXTENDED_KEY_USAGE))
        assertFalse(cert.criticalExtensionOIDs.contains(CaTestSupport.OID_SUBJECT_ALT_NAME))
    }

    @Test
    fun anIssuedCertificateIsSignedByTheIntermediateAndShipsTheFullChain() {
        val issued = issue(CertificateProfile.TLSClient(), subject = "CN=laptop")

        val cert = parse(issued.certificate)
        val intermediate = ca.getIntermediateCertificate()
        val root = ca.getRootCertificate()

        assertEquals(intermediate.subjectX500Principal.name, cert.issuerX500Principal.name)
        cert.verify(intermediate.publicKey)

        assertEquals(3, issued.chain.size)
        assertEquals(cert.serialNumber, parse(issued.chain[0]).serialNumber)
        assertEquals(intermediate.serialNumber, parse(issued.chain[1]).serialNumber)
        assertEquals(root.serialNumber, parse(issued.chain[2]).serialNumber)

        assertEquals(cert.subjectX500Principal.name, issued.subjectDN)
        assertEquals(cert.notAfter.time, issued.notAfter)
        assertEquals(cert.serialNumber, BigInteger(issued.serialNumber, 16))
        assertEquals(sha256Hex(cert.encoded), issued.fingerprint)
    }

    @Test
    fun issuingWithTheRootAliasSkipsTheIntermediateInTheChain() {
        val issued = issue(
            CertificateProfile.CodeSigning(),
            subject = "CN=root-signed",
            signingAlias = AndroidCA.ROOT_CA_ALIAS
        )

        val cert = parse(issued.certificate)
        val root = ca.getRootCertificate()

        assertEquals(root.subjectX500Principal.name, cert.issuerX500Principal.name)
        cert.verify(root.publicKey)
        assertEquals(2, issued.chain.size)
        assertEquals(root.serialNumber, parse(issued.chain[1]).serialNumber)
    }

    @Test
    fun theCsrSubjectIsUsedWhenNoSubjectOverrideIsGiven() = runBlocking {
        val issued = ca.issueCertificate(
            csrDER = CaTestSupport.csr("CN=from-the-csr,O=Requester"),
            profile = CertificateProfile.TLSClient()
        )

        val subject = parse(issued.certificate).subjectX500Principal.name
        assertTrue("got $subject", subject.contains("CN=from-the-csr"))
        assertTrue("got $subject", subject.contains("O=Requester"))
    }

    @Test
    fun anIdevidCertificateIsIssuedUnderTheDeviceIdentitySubject() = runBlocking {
        val deviceId = "device-${System.nanoTime()}"

        val issued = ca.issueIDevIDCertificate(
            csrDER = CaTestSupport.csr("CN=ignored"),
            deviceId = deviceId
        )

        val cert = parse(issued.certificate)
        val subject = cert.subjectX500Principal.name
        assertTrue("got $subject", subject.contains("CN=$deviceId"))
        assertTrue("got $subject", subject.contains("OU=IDevID"))
        assertTrue("got $subject", subject.contains("O=xKey"))

        assertNull("IDevID has no EKU", cert.extendedKeyUsage)
        assertNull("IDevID has no SAN", cert.subjectAlternativeNames)
        val usage = cert.keyUsage!!
        assertTrue(usage[CaTestSupport.KU_DIGITAL_SIGNATURE])
        assertFalse(usage[CaTestSupport.KU_KEY_CERT_SIGN])
        // A daylight-saving transition inside the window can shave an hour off.
        assertTrue(CaTestSupport.validityDays(cert) in 364L..365L)
    }

    @Test
    fun aSubordinateCaProfileIssuesAnActualCaCertificate() {
        val issued = issue(
            CertificateProfile.SubordinateCA(validityDays = 400, pathLenConstraint = 2),
            subject = "CN=Delegated CA"
        )

        val cert = parse(issued.certificate)
        assertEquals(2, cert.basicConstraints)
        val usage = cert.keyUsage!!
        assertTrue(usage[CaTestSupport.KU_KEY_CERT_SIGN])
        assertTrue(usage[CaTestSupport.KU_CRL_SIGN])
        assertTrue(CaTestSupport.validityDays(cert) in 399L..400L)
    }

    @Test
    fun namedProfilesResolveToTheirExtensions() {
        val email = runBlocking {
            ca.issueCertificateWithProfile(
                csrDER = CaTestSupport.csr("CN=Alice"),
                profileName = "email"
            )
        }
        val cert = parse(email.certificate)
        assertEquals(listOf("1.3.6.1.5.5.7.3.4"), cert.extendedKeyUsage)
        val usage = cert.keyUsage!!
        assertTrue(usage[CaTestSupport.KU_DIGITAL_SIGNATURE])
        assertTrue(usage[CaTestSupport.KU_NON_REPUDIATION])
        assertTrue(usage[CaTestSupport.KU_KEY_ENCIPHERMENT])

        val ocsp = runBlocking {
            ca.issueCertificateWithProfile(
                csrDER = CaTestSupport.csr("CN=OCSP"),
                profileName = "ocsp-responder"
            )
        }
        assertEquals(listOf("1.3.6.1.5.5.7.3.9"), parse(ocsp.certificate).extendedKeyUsage)
        assertTrue(CaTestSupport.validityDays(parse(ocsp.certificate)) in 89L..90L)
    }

    @Test
    fun signCsrIssuesUnderTheNamedProfileAndReturnsMatchingMetadata() {
        val result = runBlocking {
            ca.signCSR(
                csrBytes = CaTestSupport.csr("CN=build-server"),
                profileName = "code-signing"
            )
        }

        val cert = parse(result.certificate)
        assertEquals(listOf("1.3.6.1.5.5.7.3.3"), cert.extendedKeyUsage)
        assertEquals(cert.subjectX500Principal.name, result.subjectDN)
        assertEquals(cert.serialNumber, BigInteger(result.serialNumber, 16))
        assertEquals(sha256Hex(cert.encoded), result.fingerprint)
    }

    @Test
    fun aCsrWhoseSignatureDoesNotMatchItsContentIsRejected() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            runBlocking {
                ca.issueCertificate(
                    csrDER = CaTestSupport.csrWithBrokenSignature(),
                    profile = CertificateProfile.TLSClient()
                )
            }
        }

        assertEquals("CSR signature verification failed", error.message)
    }

    @Test
    fun everyIssuedCertificateGetsAFreshSerialNumber() {
        val first = issue(CertificateProfile.TLSClient(), subject = "CN=one")
        val second = issue(CertificateProfile.TLSClient(), subject = "CN=two")

        assertFalse(first.serialNumber == second.serialNumber)
        assertFalse(first.fingerprint == second.fingerprint)
    }

    // -------------------------------------------------------------------------
    // CSR creation from a Keystore key
    // -------------------------------------------------------------------------

    @Test
    fun createCsrProducesARequestTheCaCanSign() {
        // The CA's own intermediate key is a Keystore key with a certificate
        // entry, which is exactly what createCSR expects.
        val csr = ca.createCSR(X500Name("CN=csr-from-keystore"), AndroidCA.INTERMEDIATE_CA_ALIAS)

        val issued = runBlocking {
            ca.issueCertificate(csrDER = csr, profile = CertificateProfile.TLSClient())
        }

        val cert = parse(issued.certificate)
        assertTrue(cert.subjectX500Principal.name.contains("CN=csr-from-keystore"))
        assertTrue(
            "the CSR public key must be the one certified",
            cert.publicKey.encoded.contentEquals(ca.getIntermediateCertificate().publicKey.encoded)
        )
    }

    @Test
    fun createCsrForAnUnknownAliasFails() {
        assertThrows(Exception::class.java) {
            ca.createCSR(X500Name("CN=nothing"), "no_such_alias_${System.nanoTime()}")
        }
    }

    // -------------------------------------------------------------------------
    // Persistence, revocation and CRLs (in-memory Room only)
    // -------------------------------------------------------------------------

    @Test
    fun issuedCertificatesArePersistedAsPemWithTheirChain() = runBlocking {
        ca.certificateDao = database.certificateDao()

        val issued = issue(CertificateProfile.TLSServer(dnsNames = listOf("db.example.com")))

        val row = database.certificateDao().getBySerial(issued.serialNumber)!!
        assertEquals(issued.subjectDN, row.subjectDN)
        assertEquals("tls-server", row.profile)
        assertEquals(issued.fingerprint, row.fingerprint)
        assertEquals(issued.notAfter, row.notAfter)
        assertFalse(row.isCA)
        assertFalse(row.revoked)

        assertTrue(row.certificatePEM.startsWith("-----BEGIN CERTIFICATE-----"))
        assertTrue(row.certificatePEM.endsWith("-----END CERTIFICATE-----"))
        row.certificatePEM.lines()
            .filterNot { it.startsWith("-----") }
            .forEach { assertTrue("PEM lines must wrap at 64 chars: $it", it.length <= 64) }

        val reparsed = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(row.certificatePEM.toByteArray()))
                as X509Certificate
        assertEquals(parse(issued.certificate).serialNumber, reparsed.serialNumber)

        // The chain column holds all three certificates.
        assertEquals(3, row.chainPEM!!.split("-----BEGIN CERTIFICATE-----").size - 1)
    }

    @Test
    fun revokeMarksTheCertificateAndIsRevokedReportsIt() = runBlocking {
        ca.certificateDao = database.certificateDao()
        val issued = issue(CertificateProfile.TLSClient(), subject = "CN=revoke-me")
        assertEquals(false, ca.isRevoked(issued.serialNumber))

        ca.revoke(issued.serialNumber, AndroidCA.CRLReason.KEY_COMPROMISE)

        assertEquals(true, ca.isRevoked(issued.serialNumber))
        val row = database.certificateDao().getBySerial(issued.serialNumber)!!
        assertTrue(row.revoked)
        assertEquals(AndroidCA.CRLReason.KEY_COMPROMISE, row.revokedReason)
        assertNotNull(row.revokedAt)
    }

    @Test
    fun isRevokedIsNullForAnUnknownSerialAndWithoutADao() = runBlocking {
        assertNull("no DAO configured", ca.isRevoked("deadbeef"))

        ca.certificateDao = database.certificateDao()
        assertNull("unknown serial", ca.isRevoked("deadbeef"))
    }

    @Test
    fun revokingAnUnknownSerialIsRejected() {
        ca.certificateDao = database.certificateDao()

        assertThrows(IllegalArgumentException::class.java) {
            runBlocking { ca.revoke("00000000deadbeef") }
        }
    }

    @Test
    fun revokingWithoutADaoIsRejected() {
        val error = assertThrows(IllegalStateException::class.java) {
            runBlocking { ca.revoke("00000000deadbeef") }
        }

        assertEquals("CertificateDao not configured", error.message)
    }

    @Test
    fun theCrlListsRevokedSerialsAndVerifiesAgainstTheIntermediate() = runBlocking {
        ca.certificateDao = database.certificateDao()
        val revoked = issue(CertificateProfile.TLSClient(), subject = "CN=revoked")
        val live = issue(CertificateProfile.TLSClient(), subject = "CN=live")
        ca.revoke(revoked.serialNumber, AndroidCA.CRLReason.CESSATION_OF_OPERATION)

        val crl = CertificateFactory.getInstance("X.509")
            .generateCRL(ByteArrayInputStream(ca.generateCRL())) as X509CRL

        val intermediate = ca.getIntermediateCertificate()
        assertEquals(intermediate.subjectX500Principal.name, crl.issuerX500Principal.name)
        crl.verify(intermediate.publicKey)

        val entry = crl.getRevokedCertificate(BigInteger(revoked.serialNumber, 16))
        assertNotNull("revoked serial must be listed", entry)
        assertNull(
            "a live certificate must not be listed",
            crl.getRevokedCertificate(BigInteger(live.serialNumber, 16))
        )

        assertNotNull(crl.nextUpdate)
        val validForDays = (crl.nextUpdate.time - crl.thisUpdate.time) / 86_400_000L
        assertTrue("CRL should be valid for ~7 days, got $validForDays", validForDays in 6L..7L)
        assertNotNull(crl.getExtensionValue("2.5.29.20")) // cRLNumber
        assertNotNull(crl.getExtensionValue(CaTestSupport.OID_AUTHORITY_KEY_IDENTIFIER))
    }

    @Test
    fun anEmptyCrlIsStillIssuedAndSigned() = runBlocking {
        ca.certificateDao = database.certificateDao()

        val crl = CertificateFactory.getInstance("X.509")
            .generateCRL(ByteArrayInputStream(ca.generateCRL())) as X509CRL

        crl.verify(ca.getIntermediateCertificate().publicKey)
        assertTrue(crl.revokedCertificates.isNullOrEmpty())
    }

    @Test
    fun generatingACrlWithoutADaoIsRejected() {
        val error = assertThrows(IllegalStateException::class.java) {
            runBlocking { ca.generateCRL() }
        }

        assertEquals("CertificateDao not configured", error.message)
    }

    @Test
    fun theCaKeysLiveInTheAndroidKeystore() {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

        assertTrue(keyStore.containsAlias(AndroidCA.ROOT_CA_ALIAS))
        assertTrue(keyStore.containsAlias(AndroidCA.INTERMEDIATE_CA_ALIAS))
        assertNotNull(keyStore.getKey(AndroidCA.ROOT_CA_ALIAS, null))
        assertNotNull(keyStore.getKey(AndroidCA.INTERMEDIATE_CA_ALIAS, null))
    }
}
