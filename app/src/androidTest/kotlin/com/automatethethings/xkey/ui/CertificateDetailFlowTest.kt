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
package com.automatethethings.xkey.ui

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.view.ViewGroup
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.withId
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.ca.CertificateDao
import com.automatethethings.xkey.ca.CertificateEntity
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.runBlocking
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date

/**
 * End-to-end flow tests for [CertificateDetailActivity].
 *
 * `CertificateDetailActivityUiTest` seeds three plain rows and checks the cards
 * they produce. Everything this screen derives from the *parsed* X.509 is left
 * untouched by that suite, because an Android Keystore self-signed certificate
 * carries no key usage, no extended key usage, no subject alternative names and
 * no basic constraints — so `buildKeyUsageCard` and `buildSANCard` return early
 * and the CA rows of `buildSecurityCard` are unreachable.
 *
 * This suite therefore mints its certificates with BouncyCastle (already a
 * dependency of the app) so each extension branch can be driven directly, and
 * adds the lifecycle states the other suite skips: expiring-soon, CA, an
 * unparseable PEM, a named and an unrecognised CRL reason, chain length, export,
 * and revoke-cancelled.
 *
 * The signing keys are ordinary software key pairs, so nothing is written to the
 * Android Keystore and there is no alias to clean up; every seeded row is
 * removed in @After.
 */
@RunWith(AndroidJUnit4::class)
class CertificateDetailFlowTest {

    private val runId = System.nanoTime()

    private lateinit var dao: CertificateDao

    /** Serial numbers seeded during a test, removed in @After. */
    private val seededSerials = mutableListOf<String>()

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        dao = XKeyDatabase.getInstance(context).certificateDao()
    }

    @After
    fun tearDown() {
        runBlocking {
            for (serial in seededSerials) {
                dao.deleteBySerial(serial)
            }
        }
        seededSerials.clear()
    }

    // -----------------------------------------------------------------
    // Key usage extensions
    // -----------------------------------------------------------------

    /** Every asserted Key Usage bit is spelled out, in RFC 5280 bit order. */
    @Test
    fun keyUsageCard_namesEveryAssertedKeyUsageBit() {
        val serial = seed(
            certificate(
                "Key Usage Cert",
                keyUsage = KeyUsage.digitalSignature or
                    KeyUsage.keyEncipherment or
                    KeyUsage.keyCertSign
            )
        )
        val scenario = launch(serial)

        assertTextInTree(scenario, string(R.string.cert_detail_key_usage))
        assertValueForLabel(
            scenario,
            string(R.string.cert_detail_key_usage),
            "Digital Signature, Key Encipherment, Key Cert Sign"
        )
    }

    /** Well-known EKU OIDs are rendered as their human names. */
    @Test
    fun keyUsageCard_translatesKnownExtendedKeyUsageOids() {
        val serial = seed(
            certificate(
                "EKU Cert",
                extendedKeyUsage = listOf(OID_SERVER_AUTH, OID_CLIENT_AUTH)
            )
        )
        val scenario = launch(serial)

        assertValueForLabel(
            scenario,
            string(R.string.cert_detail_ext_key_usage),
            "TLS Server Authentication, TLS Client Authentication"
        )
    }

    /** An OID the screen does not know is shown verbatim rather than dropped. */
    @Test
    fun keyUsageCard_fallsBackToTheRawOidForAnUnknownExtendedKeyUsage() {
        val serial = seed(
            certificate("Private EKU Cert", extendedKeyUsage = listOf(OID_PRIVATE_EKU))
        )
        val scenario = launch(serial)

        assertValueForLabel(
            scenario,
            string(R.string.cert_detail_ext_key_usage),
            OID_PRIVATE_EKU
        )
    }

    /** With neither extension present the whole card is skipped. */
    @Test
    fun keyUsageCard_isOmittedWithoutUsageExtensions() {
        val serial = seed(certificate("Bare Cert"))
        val scenario = launch(serial)
        assertShownTextInTree(scenario, "Bare Cert")

        assertTextNotInTree(scenario, string(R.string.cert_detail_key_usage))
    }

    // -----------------------------------------------------------------
    // Subject alternative names
    // -----------------------------------------------------------------

    @Test
    fun sanCard_groupsDnsIpAndEmailNames() {
        val serial = seed(
            certificate(
                "SAN Cert",
                dnsNames = listOf("xkey.example.test", "alt.example.test"),
                ipAddresses = listOf("203.0.113.40"),
                emailAddresses = listOf("ops@example.test")
            )
        )
        val scenario = launch(serial)

        assertTextInTree(scenario, string(R.string.cert_detail_san))
        assertValueForLabel(
            scenario,
            string(R.string.cert_detail_dns_names),
            "xkey.example.test\nalt.example.test"
        )
        assertValueForLabel(
            scenario,
            string(R.string.cert_detail_ip_addresses),
            "203.0.113.40"
        )
        assertValueForLabel(
            scenario,
            string(R.string.cert_detail_email_addresses),
            "ops@example.test"
        )
    }

    @Test
    fun sanCard_isOmittedWithoutSubjectAlternativeNames() {
        val serial = seed(certificate("No SAN Cert"))
        val scenario = launch(serial)
        assertShownTextInTree(scenario, "No SAN Cert")

        assertTextNotInTree(scenario, string(R.string.cert_detail_san))
    }

    // -----------------------------------------------------------------
    // Basic constraints
    // -----------------------------------------------------------------

    @Test
    fun securityCard_reportsTheCaFlagAndPathLengthConstraint() {
        val serial = seed(
            certificate("Constrained CA", basicConstraints = BasicConstraints(2)),
            isCA = true
        )
        val scenario = launch(serial)

        assertValueForLabel(scenario, string(R.string.cert_detail_is_ca), "Yes")
        assertValueForLabel(scenario, string(R.string.cert_detail_path_length), "2")
    }

    /** A CA with no path length constraint is reported as unlimited. */
    @Test
    fun securityCard_reportsAnUnconstrainedCaAsUnlimited() {
        val serial = seed(
            certificate("Unconstrained CA", basicConstraints = BasicConstraints(true)),
            isCA = true
        )
        val scenario = launch(serial)

        assertValueForLabel(scenario, string(R.string.cert_detail_path_length), "Unlimited")
    }

    /**
     * When the certificate itself carries no basic constraints the screen falls
     * back to the stored `isCA` flag.
     */
    @Test
    fun securityCard_fallsBackToTheStoredCaFlag() {
        val serial = seed(certificate("Flagged CA"), isCA = true)
        val scenario = launch(serial)

        assertValueForLabel(scenario, string(R.string.cert_detail_is_ca), "Yes")
        assertTextNotInTree(scenario, string(R.string.cert_detail_path_length))
    }

    // -----------------------------------------------------------------
    // Lifecycle status
    // -----------------------------------------------------------------

    /** Inside the thirty day window the certificate is flagged for renewal. */
    @Test
    fun heroSection_warnsWhenTheCertificateExpiresSoon() {
        val notAfter = System.currentTimeMillis() + 10L * ONE_DAY_MS
        val serial = seed(
            certificate("Expiring Cert", notAfter = Date(notAfter)),
            notAfter = notAfter
        )
        val scenario = launch(serial)

        assertShownTextInTree(scenario, string(R.string.cert_status_expiring))
    }

    /** A long-lived CA gets its own status rather than plain "Valid". */
    @Test
    fun heroSection_showsTheCaStatusForACaCertificate() {
        val serial = seed(certificate("Status CA", basicConstraints = BasicConstraints(0)), isCA = true)
        val scenario = launch(serial)

        assertShownTextInTree(scenario, string(R.string.cert_detail_status_ca))
    }

    /** An unrecognised profile is title-cased rather than left blank. */
    @Test
    fun heroSection_capitalisesAnUnrecognisedProfile() {
        val serial = seed(certificate("Custom Profile Cert"), profile = "widget-signing")
        val scenario = launch(serial)

        assertShownTextInTree(scenario, "Widget-signing")
    }

    @Test
    fun heroSection_namesTheRootCaProfile() {
        val serial = seed(certificate("Root Profile Cert"), profile = "ca-root")
        val scenario = launch(serial)

        assertShownTextInTree(scenario, "Root CA")
    }

    // -----------------------------------------------------------------
    // Chain card
    // -----------------------------------------------------------------

    /** A parseable certificate always gets a verification verdict. */
    @Test
    fun chainCard_reportsAVerificationVerdict() {
        val serial = seed(certificate("Chain Cert"))
        val scenario = launch(serial)

        assertTextInTree(scenario, string(R.string.cert_detail_chain))
        // The row label is a literal in the activity, not a string resource.
        assertTextInTree(scenario, "Verification")

        val verified = string(R.string.cert_detail_chain_verified)
        val unverified = string(R.string.cert_detail_chain_unverified)
        val verdict = withActivity(scenario) { activity ->
            findTextViewContaining(activity.window.decorView, verified) != null ||
                findTextViewContaining(activity.window.decorView, unverified) != null
        }
        assertTrue("The chain card must report one verdict or the other", verdict)
    }

    /** The chain length is derived from the stored chain PEM. */
    @Test
    fun chainCard_countsTheCertificatesInTheStoredChain() {
        val first = certificate("Chain Leaf")
        val second = certificate("Chain Issuer")
        val serial = seed(
            first,
            chainPEM = TestCertificates.toPem(first) + TestCertificates.toPem(second)
        )
        val scenario = launch(serial)

        // "Chain Length" is a literal in the activity, not a string resource.
        assertValueForLabel(scenario, "Chain Length", "2 certificate(s)")
    }

    /** Nothing can be verified when the stored PEM does not parse. */
    @Test
    fun chainCard_omitsVerificationForAnUnparseablePem() {
        val serial = seedRaw(pem = "this is not a certificate", commonName = "Broken Cert")
        val scenario = launch(serial)
        assertShownTextInTree(scenario, "Broken Cert")

        assertTextNotInTree(scenario, "Verification")
        assertTextNotInTree(scenario, string(R.string.cert_detail_signature_algorithm))
    }

    // -----------------------------------------------------------------
    // Revocation card
    // -----------------------------------------------------------------

    @Test
    fun revocationCard_namesAKnownCrlReason() {
        val serial = seed(
            certificate("Compromised Cert"),
            revoked = true,
            revokedReason = CRL_REASON_KEY_COMPROMISE
        )
        val scenario = launch(serial)

        assertTextInTree(scenario, string(R.string.cert_detail_revocation))
        assertValueForLabel(
            scenario,
            string(R.string.cert_detail_revoke_reason),
            "Key Compromise"
        )
    }

    /** An out-of-range CRL code is surfaced, not silently dropped. */
    @Test
    fun revocationCard_reportsAnUnrecognisedCrlReason() {
        val serial = seed(
            certificate("Odd Reason Cert"),
            revoked = true,
            revokedReason = UNKNOWN_CRL_REASON
        )
        val scenario = launch(serial)

        assertValueForLabel(
            scenario,
            string(R.string.cert_detail_revoke_reason),
            "Unknown ($UNKNOWN_CRL_REASON)"
        )
    }

    // -----------------------------------------------------------------
    // Actions
    // -----------------------------------------------------------------

    @Test
    fun exportPem_confirmsTheCopy() {
        val serial = seed(certificate("Export Cert"))
        val scenario = launch(serial)

        clickTextInTree(scenario, string(R.string.cert_detail_export))

        assertShownTextInTree(scenario, string(R.string.cert_export_copied))
    }

    /** CA certificates are not revocable from this screen. */
    @Test
    fun actionsCard_hidesRevokeForACaCertificate() {
        val serial = seed(certificate("CA Actions Cert"), isCA = true)
        val scenario = launch(serial)
        assertShownTextInTree(scenario, "CA Actions Cert")

        assertTextNotInTree(scenario, string(R.string.cert_detail_revoke))
        assertTextInTree(scenario, string(R.string.cert_detail_delete))
    }

    @Test
    fun revokeCancelled_leavesTheCertificateActive() {
        val serial = seed(certificate("Revoke Cancel Cert"))
        val scenario = launch(serial)
        assertShownTextInTree(scenario, "Revoke Cancel Cert")

        clickTextInTree(scenario, string(R.string.cert_detail_revoke))
        onView(withId(android.R.id.button2)).inRoot(isDialog()).perform(click())
        waitForIdle()

        assertFalse(
            "Cancelling must leave the certificate un-revoked",
            runBlocking { dao.getBySerial(serial)?.revoked ?: true }
        )
    }

    /** Revoking reloads the screen, which then has a revocation card to show. */
    @Test
    fun revokeConfirmed_surfacesTheRevocationCard() {
        val serial = seed(certificate("Revoke Confirm Cert"))
        val scenario = launch(serial)
        assertShownTextInTree(scenario, "Revoke Confirm Cert")

        clickTextInTree(scenario, string(R.string.cert_detail_revoke))
        onView(withId(android.R.id.button1)).inRoot(isDialog()).perform(click())

        awaitCondition("The certificate should be marked revoked") {
            runBlocking { dao.getBySerial(serial)?.revoked } == true
        }
        assertTextInTree(scenario, string(R.string.cert_detail_revocation))
    }

    // -----------------------------------------------------------------
    // Helpers: detail rows
    // -----------------------------------------------------------------

    /**
     * Asserts that [expected] is rendered beside [label].
     *
     * Detail rows are built as `[label][value]` with no ids, and a card's title
     * can repeat a row's label (the Key Usage card is titled "Key Usage" and
     * also carries a "Key Usage" row), so every row carrying the label is
     * considered and the expected value has to appear in one of them. Polls,
     * because the cards are only built once the row has been read from Room.
     */
    private fun assertValueForLabel(
        scenario: ActivityScenario<CertificateDetailActivity>,
        label: String,
        expected: String
    ) {
        var seen: List<String> = emptyList()
        val matched = awaitActivity(scenario) { activity ->
            seen = valuesBesideLabel(activity, label)
            seen.contains(expected)
        }
        assertTrue(
            "Expected '$expected' beside '$label', but found $seen",
            matched
        )
    }

    private fun valuesBesideLabel(activity: Activity, label: String): List<String> =
        collectViews(activity.window.decorView) {
            it is TextView && it.text?.toString() == label
        }.flatMap { labelView ->
            val row = labelView.parent as? ViewGroup ?: return@flatMap emptyList<String>()
            collectViews(row) { it is TextView && it !== labelView }
                .map { (it as TextView).text?.toString().orEmpty() }
        }

    // -----------------------------------------------------------------
    // Helpers: seeding
    // -----------------------------------------------------------------

    private fun launch(serial: String): ActivityScenario<CertificateDetailActivity> {
        val intent = Intent(
            ApplicationProvider.getApplicationContext(),
            CertificateDetailActivity::class.java
        ).apply {
            putExtra(CertificateDetailActivity.EXTRA_SERIAL_NUMBER, serial)
        }
        return ActivityScenario.launch(intent)
    }

    private fun string(resId: Int): String =
        ApplicationProvider.getApplicationContext<Context>().getString(resId)

    /** Stores [cert] and returns the serial number the screen is launched with. */
    private fun seed(
        cert: X509Certificate,
        profile: String = "tls-server",
        isCA: Boolean = false,
        revoked: Boolean = false,
        revokedReason: Int? = null,
        chainPEM: String? = null,
        notAfter: Long = System.currentTimeMillis() + 365L * ONE_DAY_MS
    ): String = insert(
        pem = TestCertificates.toPem(cert),
        subjectDN = cert.subjectX500Principal.name,
        profile = profile,
        isCA = isCA,
        revoked = revoked,
        revokedReason = revokedReason,
        chainPEM = chainPEM,
        notAfter = notAfter
    )

    /** Stores a row whose PEM is deliberately not a certificate. */
    private fun seedRaw(pem: String, commonName: String): String = insert(
        pem = pem,
        subjectDN = "CN=$commonName,O=Automate The Things",
        profile = "tls-server",
        isCA = false,
        revoked = false,
        revokedReason = null,
        chainPEM = null,
        notAfter = System.currentTimeMillis() + 365L * ONE_DAY_MS
    )

    private fun insert(
        pem: String,
        subjectDN: String,
        profile: String,
        isCA: Boolean,
        revoked: Boolean,
        revokedReason: Int?,
        chainPEM: String?,
        notAfter: Long
    ): String {
        val serial = "ui-certflow-${seededSerials.size}-$runId"
        val now = System.currentTimeMillis()
        runBlocking {
            dao.insert(
                CertificateEntity(
                    serialNumber = serial,
                    subjectDN = subjectDN,
                    issuerDN = subjectDN,
                    notBefore = now - ONE_DAY_MS,
                    notAfter = notAfter,
                    profile = profile,
                    fingerprint = "%064x".format(BigInteger.valueOf(seededSerials.size + 1L)),
                    certificatePEM = pem,
                    chainPEM = chainPEM,
                    revoked = revoked,
                    revokedAt = if (revoked) now - ONE_DAY_MS else null,
                    revokedReason = revokedReason,
                    isCA = isCA
                )
            )
        }
        seededSerials.add(serial)
        return serial
    }

    // -----------------------------------------------------------------
    // Helpers: certificate minting
    // -----------------------------------------------------------------

    /**
     * Mints a self-signed certificate carrying exactly the extensions a test
     * needs.
     *
     * [TestCertificates] cannot do this: Android Keystore chooses the extension
     * set for the certificate it self-signs during key generation, so key usage,
     * extended key usage, subject alternative names and basic constraints are
     * all out of reach there. The key pair here is a plain software key, so
     * nothing is left in the Android Keystore.
     */
    private fun certificate(
        commonName: String,
        notBefore: Date = Date(System.currentTimeMillis() - ONE_DAY_MS),
        notAfter: Date = Date(System.currentTimeMillis() + 365L * ONE_DAY_MS),
        keyUsage: Int? = null,
        extendedKeyUsage: List<String>? = null,
        dnsNames: List<String> = emptyList(),
        ipAddresses: List<String> = emptyList(),
        emailAddresses: List<String> = emptyList(),
        basicConstraints: BasicConstraints? = null
    ): X509Certificate {
        val keyPair = KeyPairGenerator.getInstance("EC")
            .apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()
        val subject = X500Name("CN=$commonName,O=Automate The Things")

        val builder = JcaX509v3CertificateBuilder(
            subject,
            BigInteger.valueOf(System.nanoTime()),
            notBefore,
            notAfter,
            subject,
            keyPair.public
        )

        basicConstraints?.let { builder.addExtension(Extension.basicConstraints, true, it) }
        keyUsage?.let { builder.addExtension(Extension.keyUsage, true, KeyUsage(it)) }
        extendedKeyUsage?.let { oids ->
            builder.addExtension(
                Extension.extendedKeyUsage,
                false,
                ExtendedKeyUsage(
                    oids.map { KeyPurposeId.getInstance(ASN1ObjectIdentifier(it)) }.toTypedArray()
                )
            )
        }

        val names = mutableListOf<GeneralName>()
        dnsNames.forEach { names.add(GeneralName(GeneralName.dNSName, it)) }
        ipAddresses.forEach { names.add(GeneralName(GeneralName.iPAddress, it)) }
        emailAddresses.forEach { names.add(GeneralName(GeneralName.rfc822Name, it)) }
        if (names.isNotEmpty()) {
            builder.addExtension(
                Extension.subjectAlternativeName,
                false,
                GeneralNames(names.toTypedArray())
            )
        }

        val holder = builder.build(
            JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(keyPair.private)
        )
        return JcaX509CertificateConverter().getCertificate(holder)
    }

    private companion object {
        const val ONE_DAY_MS = 86_400_000L
        const val SIGNATURE_ALGORITHM = "SHA256withECDSA"

        const val OID_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
        const val OID_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"

        /** A private-enterprise OID the screen has no name for. */
        const val OID_PRIVATE_EKU = "1.3.6.1.4.1.99999.7"

        const val CRL_REASON_KEY_COMPROMISE = 1

        /** Not an RFC 5280 CRLReason, so the screen must fall back. */
        const val UNKNOWN_CRL_REASON = 42
    }
}
