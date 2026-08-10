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
package com.automatethethings.xkey.bootstrap

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate

/**
 * Unit tests for the parts of [DaneVerifier] that need a chain rather than a
 * single certificate.
 *
 * `DaneVerifierTest` pins the digest arithmetic and the self-signed DANE-TA
 * case against a fixed certificate. What is left, and what this covers, is the
 * RFC 7671 Section 5.2 half of DANE-TA: an anchor that is *not* the leaf, which
 * means the presented chain has to PKIX-validate up to it and the leaf has to
 * pass a name check. The [DaneVerifier.trustManager] wrapper -- the object the
 * bootstrap client actually installs into its `SSLContext` -- is covered here too.
 */
class DaneChainVerificationTest {

    private val hostname = "kms.example.test"

    private val authority = TestPki.selfSigned("xKey DANE Test CA", isCa = true)
    private val leaf = TestPki.issuedBy(authority, hostname, dnsNames = listOf(hostname))
    private val chain = listOf(leaf.certificate, authority.certificate)

    private fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    private fun sha512(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-512").digest(data)

    private fun record(
        certificate: X509Certificate,
        usage: Int,
        selector: Int = TlsaRecord.SELECTOR_FULL_CERT,
        matching: Int = TlsaRecord.MATCHING_SHA256
    ) = TlsaRecord(
        usage = usage,
        selector = selector,
        matchingType = matching,
        certData = DaneVerifier.computeTlsaData(certificate, selector, matching)
    )

    // ---------------------------------------------------------- DANE-TA (5.2)

    @Test
    fun daneTaAcceptsALeafThatValidatesToTheAssertedAnchor() {
        DaneVerifier.verifyPeerChain(
            chain,
            listOf(record(authority.certificate, TlsaRecord.USAGE_DANE_TA)),
            hostname
        )
    }

    @Test
    fun daneTaAcceptsAnAnchorAssertedByItsPublicKey() {
        DaneVerifier.verifyPeerChain(
            chain,
            listOf(
                record(
                    authority.certificate,
                    TlsaRecord.USAGE_DANE_TA,
                    selector = TlsaRecord.SELECTOR_SPKI,
                    matching = TlsaRecord.MATCHING_SHA512
                )
            ),
            hostname
        )
    }

    @Test
    fun daneTaAcceptsAnAnchorAssertedByItsExactCertificate() {
        DaneVerifier.verifyPeerChain(
            chain,
            listOf(
                record(
                    authority.certificate,
                    TlsaRecord.USAGE_DANE_TA,
                    matching = TlsaRecord.MATCHING_EXACT
                )
            ),
            hostname
        )
    }

    @Test
    fun daneTaRejectsALeafWhoseNameDoesNotMatch() {
        assertThrows(DaneTlsaException::class.java) {
            DaneVerifier.verifyPeerChain(
                chain,
                listOf(record(authority.certificate, TlsaRecord.USAGE_DANE_TA)),
                "other.example.test"
            )
        }
    }

    @Test
    fun daneTaRejectsALeafThatDoesNotChainToTheAnchor() {
        // The anchor is presented, and the leaf's name is right, but the leaf
        // was issued by a different CA: PKIX validation must reject it.
        val foreignAuthority = TestPki.selfSigned("xKey Foreign CA", isCa = true)
        val impostor = TestPki.issuedBy(foreignAuthority, hostname, dnsNames = listOf(hostname))

        assertThrows(DaneTlsaException::class.java) {
            DaneVerifier.verifyPeerChain(
                listOf(impostor.certificate, authority.certificate),
                listOf(record(authority.certificate, TlsaRecord.USAGE_DANE_TA)),
                hostname
            )
        }
    }

    @Test
    fun daneTaRejectsAnAnchorThatIsNotInThePresentedChain() {
        val absent = TestPki.selfSigned("xKey Absent CA", isCa = true)

        assertThrows(DaneTlsaException::class.java) {
            DaneVerifier.verifyPeerChain(
                chain,
                listOf(record(absent.certificate, TlsaRecord.USAGE_DANE_TA)),
                hostname
            )
        }
    }

    @Test
    fun anyUsableRecordThatMatchesSatisfiesThePolicy() {
        // A failing DANE-TA record ahead of a matching DANE-EE record must not
        // short-circuit the decision.
        val records = listOf(
            record(TestPki.selfSigned("xKey Wrong CA", isCa = true).certificate, TlsaRecord.USAGE_DANE_TA),
            record(leaf.certificate, TlsaRecord.USAGE_DANE_EE, selector = TlsaRecord.SELECTOR_SPKI)
        )

        DaneVerifier.verifyPeerChain(chain, records, hostname)
    }

    @Test
    fun anEmptyRecordSetIsNotUsable() {
        val failure = assertThrows(DaneTlsaException::class.java) {
            DaneVerifier.verifyPeerChain(chain, emptyList(), hostname)
        }
        assertTrue(failure.message!!, failure.message!!.contains("no usable"))
    }

    // -------------------------------------------------------- association data

    @Test
    fun computesTheSha512AssociationOfTheFullCertificate() {
        assertArrayEquals(
            sha512(leaf.certificate.encoded),
            DaneVerifier.computeTlsaData(
                leaf.certificate,
                TlsaRecord.SELECTOR_FULL_CERT,
                TlsaRecord.MATCHING_SHA512
            )
        )
    }

    @Test
    fun computesTheSha256AssociationOfThePublicKey() {
        assertArrayEquals(
            sha256(leaf.certificate.publicKey.encoded),
            DaneVerifier.computeTlsaData(
                leaf.certificate,
                TlsaRecord.SELECTOR_SPKI,
                TlsaRecord.MATCHING_SHA256
            )
        )
    }

    @Test
    fun rejectsAnUnsupportedMatchingType() {
        val failure = assertThrows(DaneTlsaException::class.java) {
            DaneVerifier.computeTlsaData(leaf.certificate, TlsaRecord.SELECTOR_SPKI, 7)
        }
        assertTrue(failure.message!!, failure.message!!.contains("matching type"))
    }

    @Test
    fun aRecordWithAnUnusableSelectorSimplyDoesNotMatch() {
        val unusable = TlsaRecord(
            usage = TlsaRecord.USAGE_DANE_EE,
            selector = 9,
            matchingType = TlsaRecord.MATCHING_SHA256,
            certData = sha256(leaf.certificate.encoded)
        )

        assertFalse(DaneVerifier.matches(leaf.certificate, unusable))
        assertThrows(DaneTlsaException::class.java) {
            DaneVerifier.verifyPeerChain(chain, listOf(unusable), hostname)
        }
    }

    // ------------------------------------------------------------ trust manager

    @Test
    fun theTrustManagerAcceptsAChainThatSatisfiesTheRecords() {
        val manager = DaneVerifier.trustManager(
            listOf(record(leaf.certificate, TlsaRecord.USAGE_DANE_EE)),
            hostname
        )

        manager.checkServerTrusted(chain.toTypedArray(), "ECDHE_ECDSA")
    }

    @Test
    fun theTrustManagerRejectsAChainThatDoesNot() {
        val manager = DaneVerifier.trustManager(
            listOf(
                TlsaRecord(
                    usage = TlsaRecord.USAGE_DANE_EE,
                    selector = TlsaRecord.SELECTOR_SPKI,
                    matchingType = TlsaRecord.MATCHING_SHA256,
                    certData = ByteArray(32)
                )
            ),
            hostname
        )

        val failure = assertThrows(CertificateException::class.java) {
            manager.checkServerTrusted(chain.toTypedArray(), "ECDHE_ECDSA")
        }
        assertTrue(failure.cause is DaneTlsaException)
    }

    @Test
    fun theTrustManagerRefusesToVerifyClients() {
        val manager = DaneVerifier.trustManager(
            listOf(record(leaf.certificate, TlsaRecord.USAGE_DANE_EE)),
            hostname
        )

        assertThrows(CertificateException::class.java) {
            manager.checkClientTrusted(chain.toTypedArray(), "ECDHE_ECDSA")
        }
    }

    @Test
    fun theTrustManagerAdvertisesNoIssuers() {
        val manager = DaneVerifier.trustManager(emptyList(), hostname)

        assertEquals(0, manager.acceptedIssuers.size)
    }

    // -------------------------------------------------------- hostname matching

    @Test
    fun aCertificateWithoutSubjectAlternativeNamesMatchesNothing() {
        val bare = TestPki.selfSigned("bare.example.test").certificate

        assertFalse(DaneVerifier.matchesHostname(bare, "bare.example.test"))
    }

    @Test
    fun nonDnsAlternativeNamesAreIgnored() {
        val mixed = TestPki.selfSigned(
            commonName = "mixed.example.test",
            dnsNames = listOf("mixed.example.test"),
            emailNames = listOf("security@example.test")
        ).certificate

        assertTrue(DaneVerifier.matchesHostname(mixed, "mixed.example.test"))
        assertFalse(DaneVerifier.matchesHostname(mixed, "security@example.test"))
    }

    @Test
    fun aTrailingDotOnTheQueriedNameIsIgnored() {
        assertTrue(DaneVerifier.matchesHostname(leaf.certificate, "$hostname."))
    }
}
