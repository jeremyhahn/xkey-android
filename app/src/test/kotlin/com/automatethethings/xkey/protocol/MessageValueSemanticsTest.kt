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
package com.automatethethings.xkey.protocol

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Value semantics of the wire messages that carry raw bytes.
 *
 * A Kotlin `data class` compares a `ByteArray` property by reference, which
 * would make two payloads holding identical bytes unequal. Every message in
 * `Messages.kt` that carries a `ByteArray`, a `List<ByteArray>` or a
 * `Map<Int, ByteArray>` therefore hand-writes `equals` and `hashCode`, and a
 * hand-written comparison is exactly where a field gets forgotten when a new
 * one is added to the wire contract.
 *
 * Each class here is checked the same way: reflexivity, rejection of `null` and
 * of a foreign type, equality between two independently built instances holding
 * equal content, `hashCode` agreement for equal instances, and one case per
 * property where only that property differs. The per-property cases are the
 * point of the suite — a field left out of `equals` shows up as an instance
 * that compares equal despite differing.
 *
 * The nullable byte properties are additionally checked in both directions
 * (present vs absent and absent vs present), because the two arms of
 * `if (x != null) ... else if (other.x != null)` are separate branches.
 *
 * Counterpart: `go-xkms/xkey/pkg/pairing`. Nothing here touches Android
 * framework classes, so it runs as a plain JVM test.
 */
class MessageValueSemanticsTest {

    private fun bytes(vararg values: Int): ByteArray =
        ByteArray(values.size) { values[it].toByte() }

    /** Content-equal but reference-distinct copy, so `===` can never pass. */
    private fun copyOf(data: ByteArray): ByteArray = data.copyOf()

    private fun certInfo(serial: String = "01"): IDevIDCertificateInfo =
        IDevIDCertificateInfo(
            serialNumber = serial,
            issuer = "CN=Issuing CA",
            subject = "CN=device",
            notBefore = 1_700_000_000L,
            notAfter = 1_800_000_000L,
            algorithm = "SHA256withECDSA",
            publicKeyAlgorithm = "EC",
            keySizeBits = 256,
            fingerprint = "aa:bb"
        )

    /**
     * Asserts the shared contract every hand-written `equals` must honour and
     * that two independently built, content-equal instances agree.
     */
    private fun assertValueSemantics(first: Any, sameContent: Any) {
        assertTrue("an instance must equal itself", first.equals(first))
        assertFalse("an instance must not equal null", first.equals(null))
        assertFalse(
            "an instance must not equal a foreign type",
            first.equals("not a protocol message")
        )
        assertEquals("content-equal instances must be equal", first, sameContent)
        assertEquals(
            "content-equal instances must share a hashCode",
            first.hashCode(),
            sameContent.hashCode()
        )
        assertEquals("hashCode must be stable", first.hashCode(), first.hashCode())
    }

    // -------------------------------------------------------------------------
    // LocalGetCABundleResult
    // -------------------------------------------------------------------------

    private fun caBundle(
        bundlePem: ByteArray? = bytes(1, 2, 3),
        certificates: List<ByteArray> = listOf(bytes(0x30, 0x01), bytes(0x30, 0x02)),
        count: Int = 2,
        rootSubject: String? = "CN=Root"
    ) = LocalGetCABundleResult(bundlePem, certificates, count, rootSubject)

    @Test
    fun `LocalGetCABundleResult compares its bundle and certificates by content`() {
        assertValueSemantics(caBundle(), caBundle(bundlePem = copyOf(bytes(1, 2, 3))))
    }

    @Test
    fun `LocalGetCABundleResult detects a change in every field`() {
        assertNotEquals(caBundle(), caBundle(bundlePem = bytes(9, 9, 9)))
        assertNotEquals(caBundle(), caBundle(certificates = listOf(bytes(0x30, 0x01))))
        assertNotEquals(
            caBundle(),
            caBundle(certificates = listOf(bytes(0x30, 0x01), bytes(0x30, 0xFF)))
        )
        assertNotEquals(caBundle(), caBundle(count = 3))
        assertNotEquals(caBundle(), caBundle(rootSubject = "CN=Other"))
        assertNotEquals(caBundle(), caBundle(rootSubject = null))
    }

    @Test
    fun `LocalGetCABundleResult treats an absent bundle as distinct in both directions`() {
        assertNotEquals(caBundle(bundlePem = null), caBundle())
        assertNotEquals(caBundle(), caBundle(bundlePem = null))
        assertEquals(caBundle(bundlePem = null), caBundle(bundlePem = null))
        assertEquals(
            caBundle(bundlePem = null).hashCode(),
            caBundle(bundlePem = null).hashCode()
        )
    }

    // -------------------------------------------------------------------------
    // LocalGetIDevIDCertificateParams
    // -------------------------------------------------------------------------

    @Test
    fun `LocalGetIDevIDCertificateParams compares its nonce by content`() {
        assertValueSemantics(
            LocalGetIDevIDCertificateParams(bytes(7, 7)),
            LocalGetIDevIDCertificateParams(copyOf(bytes(7, 7)))
        )
    }

    @Test
    fun `LocalGetIDevIDCertificateParams distinguishes a present nonce from an absent one`() {
        assertNotEquals(
            LocalGetIDevIDCertificateParams(bytes(7, 7)),
            LocalGetIDevIDCertificateParams(null)
        )
        assertNotEquals(
            LocalGetIDevIDCertificateParams(null),
            LocalGetIDevIDCertificateParams(bytes(7, 7))
        )
        assertNotEquals(
            LocalGetIDevIDCertificateParams(bytes(7, 7)),
            LocalGetIDevIDCertificateParams(bytes(8, 8))
        )
    }

    /** An absent nonce hashes to zero, which is the documented default. */
    @Test
    fun `LocalGetIDevIDCertificateParams hashes an absent nonce to zero`() {
        assertEquals(0, LocalGetIDevIDCertificateParams(null).hashCode())
        assertEquals(
            LocalGetIDevIDCertificateParams(bytes(7, 7)).hashCode(),
            LocalGetIDevIDCertificateParams(copyOf(bytes(7, 7))).hashCode()
        )
    }

    // -------------------------------------------------------------------------
    // LocalGetIDevIDCertificateResult
    // -------------------------------------------------------------------------

    private fun certResult(
        hasCertificate: Boolean = true,
        chain: List<ByteArray>? = listOf(bytes(0x30, 0x10), bytes(0x30, 0x11)),
        nonce: ByteArray? = bytes(5),
        info: IDevIDCertificateInfo? = certInfo()
    ) = LocalGetIDevIDCertificateResult(hasCertificate, chain, nonce, info)

    @Test
    fun `LocalGetIDevIDCertificateResult compares its chain and nonce by content`() {
        assertValueSemantics(
            certResult(),
            certResult(
                chain = listOf(copyOf(bytes(0x30, 0x10)), copyOf(bytes(0x30, 0x11))),
                nonce = copyOf(bytes(5))
            )
        )
    }

    @Test
    fun `LocalGetIDevIDCertificateResult detects a change in every field`() {
        assertNotEquals(certResult(), certResult(hasCertificate = false))
        assertNotEquals(certResult(), certResult(chain = listOf(bytes(0x30, 0x10))))
        assertNotEquals(
            certResult(),
            certResult(chain = listOf(bytes(0x30, 0x10), bytes(0x30, 0xEE)))
        )
        assertNotEquals(certResult(), certResult(nonce = bytes(6)))
        assertNotEquals(certResult(), certResult(info = certInfo(serial = "02")))
        assertNotEquals(certResult(), certResult(info = null))
    }

    @Test
    fun `LocalGetIDevIDCertificateResult distinguishes absent optionals in both directions`() {
        assertNotEquals(certResult(chain = null), certResult())
        assertNotEquals(certResult(), certResult(chain = null))
        assertNotEquals(certResult(nonce = null), certResult())
        assertNotEquals(certResult(), certResult(nonce = null))
        assertEquals(
            certResult(chain = null, nonce = null, info = null),
            certResult(chain = null, nonce = null, info = null)
        )
        assertEquals(
            certResult(chain = null, nonce = null, info = null).hashCode(),
            certResult(chain = null, nonce = null, info = null).hashCode()
        )
    }

    // -------------------------------------------------------------------------
    // LocalRequestIDevIDIssuanceParams
    // -------------------------------------------------------------------------

    private fun issuanceParams(
        csr: ByteArray = bytes(0x30, 0x81),
        csrFormat: String? = "der",
        attestationData: ByteArray? = bytes(0xAB),
        validityDays: Int? = 365
    ) = LocalRequestIDevIDIssuanceParams(csr, csrFormat, attestationData, validityDays)

    @Test
    fun `LocalRequestIDevIDIssuanceParams compares its csr and attestation by content`() {
        assertValueSemantics(
            issuanceParams(),
            issuanceParams(csr = copyOf(bytes(0x30, 0x81)), attestationData = copyOf(bytes(0xAB)))
        )
    }

    @Test
    fun `LocalRequestIDevIDIssuanceParams detects a change in every field`() {
        assertNotEquals(issuanceParams(), issuanceParams(csr = bytes(0x30, 0x82)))
        assertNotEquals(issuanceParams(), issuanceParams(csrFormat = "pem"))
        assertNotEquals(issuanceParams(), issuanceParams(csrFormat = null))
        assertNotEquals(issuanceParams(), issuanceParams(attestationData = bytes(0xCD)))
        assertNotEquals(issuanceParams(), issuanceParams(attestationData = null))
        assertNotEquals(issuanceParams(attestationData = null), issuanceParams())
        assertNotEquals(issuanceParams(), issuanceParams(validityDays = 30))
        assertNotEquals(issuanceParams(), issuanceParams(validityDays = null))
    }

    // -------------------------------------------------------------------------
    // LocalRequestIDevIDIssuanceResult
    // -------------------------------------------------------------------------

    private fun issuanceResult(
        issued: Boolean = true,
        certificate: ByteArray? = bytes(0x30, 0x20),
        chain: List<ByteArray>? = listOf(bytes(0x30, 0x21)),
        info: IDevIDCertificateInfo? = certInfo(),
        errorCode: String? = null,
        errorMessage: String? = null
    ) = LocalRequestIDevIDIssuanceResult(issued, certificate, chain, info, errorCode, errorMessage)

    @Test
    fun `LocalRequestIDevIDIssuanceResult compares its certificate and chain by content`() {
        assertValueSemantics(
            issuanceResult(),
            issuanceResult(
                certificate = copyOf(bytes(0x30, 0x20)),
                chain = listOf(copyOf(bytes(0x30, 0x21)))
            )
        )
    }

    @Test
    fun `LocalRequestIDevIDIssuanceResult detects a change in every field`() {
        assertNotEquals(issuanceResult(), issuanceResult(issued = false))
        assertNotEquals(issuanceResult(), issuanceResult(certificate = bytes(0x30, 0x99)))
        assertNotEquals(issuanceResult(), issuanceResult(certificate = null))
        assertNotEquals(issuanceResult(certificate = null), issuanceResult())
        assertNotEquals(issuanceResult(), issuanceResult(chain = emptyList()))
        assertNotEquals(issuanceResult(), issuanceResult(chain = listOf(bytes(0x30, 0x99))))
        assertNotEquals(issuanceResult(), issuanceResult(chain = null))
        assertNotEquals(issuanceResult(chain = null), issuanceResult())
        assertNotEquals(issuanceResult(), issuanceResult(info = certInfo(serial = "ff")))
        assertNotEquals(issuanceResult(), issuanceResult(errorCode = "CA_UNAVAILABLE"))
        assertNotEquals(issuanceResult(), issuanceResult(errorMessage = "unreachable"))
    }

    /** A failure result carries no certificate; it must still hash consistently. */
    @Test
    fun `LocalRequestIDevIDIssuanceResult hashes a failure consistently`() {
        val failure = LocalRequestIDevIDIssuanceResult(
            issued = false,
            errorCode = "CA_UNAVAILABLE",
            errorMessage = "no route to CA"
        )
        val same = LocalRequestIDevIDIssuanceResult(
            issued = false,
            errorCode = "CA_UNAVAILABLE",
            errorMessage = "no route to CA"
        )
        assertValueSemantics(failure, same)
    }

    // -------------------------------------------------------------------------
    // LocalGenerateIDevIDCSRResult
    // -------------------------------------------------------------------------

    private fun csrResult(
        csr: ByteArray = bytes(0x30, 0x30),
        csrFormat: String = "der",
        keyId: String = "idevid",
        backend: String = "tpm2",
        algorithm: String = "ES256",
        publicKey: ByteArray? = bytes(0x04, 0x01)
    ) = LocalGenerateIDevIDCSRResult(csr, csrFormat, keyId, backend, algorithm, publicKey)

    @Test
    fun `LocalGenerateIDevIDCSRResult compares its csr and public key by content`() {
        assertValueSemantics(
            csrResult(),
            csrResult(csr = copyOf(bytes(0x30, 0x30)), publicKey = copyOf(bytes(0x04, 0x01)))
        )
    }

    @Test
    fun `LocalGenerateIDevIDCSRResult detects a change in every field`() {
        assertNotEquals(csrResult(), csrResult(csr = bytes(0x30, 0x31)))
        assertNotEquals(csrResult(), csrResult(csrFormat = "pem"))
        assertNotEquals(csrResult(), csrResult(keyId = "other"))
        assertNotEquals(csrResult(), csrResult(backend = "software"))
        assertNotEquals(csrResult(), csrResult(algorithm = "ES384"))
        assertNotEquals(csrResult(), csrResult(publicKey = bytes(0x04, 0x02)))
        assertNotEquals(csrResult(), csrResult(publicKey = null))
        assertNotEquals(csrResult(publicKey = null), csrResult())
        assertEquals(csrResult(publicKey = null), csrResult(publicKey = null))
        assertEquals(csrResult(publicKey = null).hashCode(), csrResult(publicKey = null).hashCode())
    }

    // -------------------------------------------------------------------------
    // LocalStoreIDevIDCertificateParams
    // -------------------------------------------------------------------------

    private fun storeCertParams(
        certificate: ByteArray = bytes(0x30, 0x40),
        chain: List<ByteArray>? = listOf(bytes(0x30, 0x41)),
        keyId: String = "idevid",
        backend: String? = "tpm2"
    ) = LocalStoreIDevIDCertificateParams(certificate, chain, keyId, backend)

    @Test
    fun `LocalStoreIDevIDCertificateParams compares its certificate and chain by content`() {
        assertValueSemantics(
            storeCertParams(),
            storeCertParams(
                certificate = copyOf(bytes(0x30, 0x40)),
                chain = listOf(copyOf(bytes(0x30, 0x41)))
            )
        )
    }

    @Test
    fun `LocalStoreIDevIDCertificateParams detects a change in every field`() {
        assertNotEquals(storeCertParams(), storeCertParams(certificate = bytes(0x30, 0x4F)))
        assertNotEquals(storeCertParams(), storeCertParams(chain = emptyList()))
        assertNotEquals(storeCertParams(), storeCertParams(chain = listOf(bytes(0x30, 0x4F))))
        assertNotEquals(storeCertParams(), storeCertParams(chain = null))
        assertNotEquals(storeCertParams(chain = null), storeCertParams())
        assertNotEquals(storeCertParams(), storeCertParams(keyId = "other"))
        assertNotEquals(storeCertParams(), storeCertParams(backend = "software"))
        assertNotEquals(storeCertParams(), storeCertParams(backend = null))
    }

    // -------------------------------------------------------------------------
    // LocalGetTCGCSRIDevIDResult
    // -------------------------------------------------------------------------

    private fun tcgCsr(
        csr: ByteArray = bytes(0x30, 0x50),
        ekCert: ByteArray? = bytes(0x30, 0x51),
        iakPublicKey: ByteArray = bytes(0x04, 0x10),
        idevidPublicKey: ByteArray = bytes(0x04, 0x11),
        platformSerial: String? = "SN-1",
        platformModel: String? = "Pixel",
        firmwareVersion: String? = "1.0"
    ) = LocalGetTCGCSRIDevIDResult(
        csr, ekCert, iakPublicKey, idevidPublicKey, platformSerial, platformModel, firmwareVersion
    )

    @Test
    fun `LocalGetTCGCSRIDevIDResult compares every key blob by content`() {
        assertValueSemantics(
            tcgCsr(),
            tcgCsr(
                csr = copyOf(bytes(0x30, 0x50)),
                ekCert = copyOf(bytes(0x30, 0x51)),
                iakPublicKey = copyOf(bytes(0x04, 0x10)),
                idevidPublicKey = copyOf(bytes(0x04, 0x11))
            )
        )
    }

    @Test
    fun `LocalGetTCGCSRIDevIDResult detects a change in every field`() {
        assertNotEquals(tcgCsr(), tcgCsr(csr = bytes(0x30, 0x5F)))
        assertNotEquals(tcgCsr(), tcgCsr(ekCert = bytes(0x30, 0x5F)))
        assertNotEquals(tcgCsr(), tcgCsr(ekCert = null))
        assertNotEquals(tcgCsr(ekCert = null), tcgCsr())
        assertNotEquals(tcgCsr(), tcgCsr(iakPublicKey = bytes(0x04, 0x1F)))
        assertNotEquals(tcgCsr(), tcgCsr(idevidPublicKey = bytes(0x04, 0x1F)))
        assertNotEquals(tcgCsr(), tcgCsr(platformSerial = "SN-2"))
        assertNotEquals(tcgCsr(), tcgCsr(platformModel = "Galaxy"))
        assertNotEquals(tcgCsr(), tcgCsr(firmwareVersion = "2.0"))
    }

    /**
     * The IAK and IDevID public keys are distinct fields; swapping them must
     * change the identity of the result, or an enrolment could accept the wrong
     * key as the identity key.
     */
    @Test
    fun `LocalGetTCGCSRIDevIDResult does not confuse the IAK and IDevID public keys`() {
        assertNotEquals(
            tcgCsr(iakPublicKey = bytes(1), idevidPublicKey = bytes(2)),
            tcgCsr(iakPublicKey = bytes(2), idevidPublicKey = bytes(1))
        )
    }

    // -------------------------------------------------------------------------
    // LocalActivateCredentialParams / Result
    // -------------------------------------------------------------------------

    @Test
    fun `LocalActivateCredentialParams compares both blobs by content`() {
        val base = LocalActivateCredentialParams(bytes(1, 2), bytes(3, 4))
        assertValueSemantics(
            base,
            LocalActivateCredentialParams(copyOf(bytes(1, 2)), copyOf(bytes(3, 4)))
        )
        assertNotEquals(base, LocalActivateCredentialParams(bytes(9, 9), bytes(3, 4)))
        assertNotEquals(base, LocalActivateCredentialParams(bytes(1, 2), bytes(9, 9)))
        assertNotEquals(
            "the blob and the secret must not be interchangeable",
            LocalActivateCredentialParams(bytes(1), bytes(2)),
            LocalActivateCredentialParams(bytes(2), bytes(1))
        )
    }

    @Test
    fun `LocalActivateCredentialResult compares the decrypted secret by content`() {
        val base = LocalActivateCredentialResult(bytes(0xDE, 0xAD))
        assertValueSemantics(base, LocalActivateCredentialResult(copyOf(bytes(0xDE, 0xAD))))
        assertNotEquals(base, LocalActivateCredentialResult(bytes(0xBE, 0xEF)))
        assertNotEquals(base, LocalActivateCredentialResult(ByteArray(0)))
    }

    // -------------------------------------------------------------------------
    // LocalGetAttestationQuoteParams / Result
    // -------------------------------------------------------------------------

    private fun quoteParams(
        nonce: ByteArray = bytes(0x11, 0x22),
        pcrIndices: List<Int> = listOf(0, 1, 7),
        pcrBank: String? = "sha256"
    ) = LocalGetAttestationQuoteParams(nonce, pcrIndices, pcrBank)

    @Test
    fun `LocalGetAttestationQuoteParams compares its nonce by content`() {
        assertValueSemantics(quoteParams(), quoteParams(nonce = copyOf(bytes(0x11, 0x22))))
    }

    @Test
    fun `LocalGetAttestationQuoteParams detects a change in every field`() {
        assertNotEquals(quoteParams(), quoteParams(nonce = bytes(0x33)))
        assertNotEquals(quoteParams(), quoteParams(pcrIndices = listOf(0, 1)))
        assertNotEquals(quoteParams(), quoteParams(pcrIndices = listOf(7, 1, 0)))
        assertNotEquals(quoteParams(), quoteParams(pcrBank = "sha1"))
        assertNotEquals(quoteParams(), quoteParams(pcrBank = null))
        assertEquals(quoteParams(pcrBank = null), quoteParams(pcrBank = null))
    }

    private fun quoteResult(
        quoted: ByteArray = bytes(0xFF, 0x54),
        signature: ByteArray = bytes(0x00, 0x14),
        pcrValues: Map<Int, ByteArray> = mapOf(0 to bytes(0xA0), 7 to bytes(0xA7)),
        eventLog: ByteArray? = bytes(0xE0),
        pcrBank: String = "sha256"
    ) = LocalGetAttestationQuoteResult(quoted, signature, pcrValues, eventLog, pcrBank)

    @Test
    fun `LocalGetAttestationQuoteResult compares its quote signature and PCR map by content`() {
        assertValueSemantics(
            quoteResult(),
            quoteResult(
                quoted = copyOf(bytes(0xFF, 0x54)),
                signature = copyOf(bytes(0x00, 0x14)),
                pcrValues = mapOf(0 to copyOf(bytes(0xA0)), 7 to copyOf(bytes(0xA7))),
                eventLog = copyOf(bytes(0xE0))
            )
        )
    }

    @Test
    fun `LocalGetAttestationQuoteResult detects a change in every field`() {
        assertNotEquals(quoteResult(), quoteResult(quoted = bytes(0xFF, 0x55)))
        assertNotEquals(quoteResult(), quoteResult(signature = bytes(0x00, 0x15)))
        assertNotEquals(quoteResult(), quoteResult(pcrValues = mapOf(0 to bytes(0xA0))))
        assertNotEquals(quoteResult(), quoteResult(eventLog = bytes(0xE1)))
        assertNotEquals(quoteResult(), quoteResult(eventLog = null))
        assertNotEquals(quoteResult(eventLog = null), quoteResult())
        assertNotEquals(quoteResult(), quoteResult(pcrBank = "sha1"))
    }

    /**
     * Same number of PCRs, but a different digest for one index, and the same
     * digests under different indices. Both must be unequal: a quote is only
     * meaningful together with which PCR each digest came from.
     */
    @Test
    fun `LocalGetAttestationQuoteResult compares PCR digests per index`() {
        assertNotEquals(
            quoteResult(pcrValues = mapOf(0 to bytes(0xA0), 7 to bytes(0xA7))),
            quoteResult(pcrValues = mapOf(0 to bytes(0xA0), 7 to bytes(0xFF)))
        )
        assertNotEquals(
            quoteResult(pcrValues = mapOf(0 to bytes(0xA0), 7 to bytes(0xA7))),
            quoteResult(pcrValues = mapOf(0 to bytes(0xA0), 8 to bytes(0xA7)))
        )
    }

    // -------------------------------------------------------------------------
    // LocalGetIAKPublicKeyResult
    // -------------------------------------------------------------------------

    private fun iakResult(
        publicKey: ByteArray = bytes(0x04, 0x20),
        algorithm: String = "ES256",
        publicKeyDer: ByteArray? = bytes(0x30, 0x59),
        name: ByteArray? = bytes(0x00, 0x0B)
    ) = LocalGetIAKPublicKeyResult(publicKey, algorithm, publicKeyDer, name)

    @Test
    fun `LocalGetIAKPublicKeyResult compares every key encoding by content`() {
        assertValueSemantics(
            iakResult(),
            iakResult(
                publicKey = copyOf(bytes(0x04, 0x20)),
                publicKeyDer = copyOf(bytes(0x30, 0x59)),
                name = copyOf(bytes(0x00, 0x0B))
            )
        )
    }

    @Test
    fun `LocalGetIAKPublicKeyResult detects a change in every field`() {
        assertNotEquals(iakResult(), iakResult(publicKey = bytes(0x04, 0x21)))
        assertNotEquals(iakResult(), iakResult(algorithm = "RS256"))
        assertNotEquals(iakResult(), iakResult(publicKeyDer = bytes(0x30, 0x5A)))
        assertNotEquals(iakResult(), iakResult(publicKeyDer = null))
        assertNotEquals(iakResult(publicKeyDer = null), iakResult())
        assertNotEquals(iakResult(), iakResult(name = bytes(0x00, 0x0C)))
        assertNotEquals(iakResult(), iakResult(name = null))
        assertNotEquals(iakResult(name = null), iakResult())
        assertEquals(
            iakResult(publicKeyDer = null, name = null),
            iakResult(publicKeyDer = null, name = null)
        )
        assertEquals(
            iakResult(publicKeyDer = null, name = null).hashCode(),
            iakResult(publicKeyDer = null, name = null).hashCode()
        )
    }

    // -------------------------------------------------------------------------
    // LocalStoreEnrollmentCertsParams
    // -------------------------------------------------------------------------

    private fun enrollmentCerts(
        iakCert: ByteArray = bytes(0x30, 0x60),
        idevidCert: ByteArray = bytes(0x30, 0x61),
        chain: List<ByteArray>? = listOf(bytes(0x30, 0x62))
    ) = LocalStoreEnrollmentCertsParams(iakCert, idevidCert, chain)

    @Test
    fun `LocalStoreEnrollmentCertsParams compares both certificates and the chain by content`() {
        assertValueSemantics(
            enrollmentCerts(),
            enrollmentCerts(
                iakCert = copyOf(bytes(0x30, 0x60)),
                idevidCert = copyOf(bytes(0x30, 0x61)),
                chain = listOf(copyOf(bytes(0x30, 0x62)))
            )
        )
    }

    @Test
    fun `LocalStoreEnrollmentCertsParams detects a change in every field`() {
        assertNotEquals(enrollmentCerts(), enrollmentCerts(iakCert = bytes(0x30, 0x6F)))
        assertNotEquals(enrollmentCerts(), enrollmentCerts(idevidCert = bytes(0x30, 0x6F)))
        assertNotEquals(enrollmentCerts(), enrollmentCerts(chain = emptyList()))
        assertNotEquals(enrollmentCerts(), enrollmentCerts(chain = listOf(bytes(0x30, 0x6F))))
        assertNotEquals(enrollmentCerts(), enrollmentCerts(chain = null))
        assertNotEquals(enrollmentCerts(chain = null), enrollmentCerts())
    }

    /**
     * The IAK and IDevID certificates are stored under different identities;
     * swapping them must not produce an equal payload.
     */
    @Test
    fun `LocalStoreEnrollmentCertsParams does not confuse the IAK and IDevID certificates`() {
        assertNotEquals(
            enrollmentCerts(iakCert = bytes(1), idevidCert = bytes(2)),
            enrollmentCerts(iakCert = bytes(2), idevidCert = bytes(1))
        )
    }
}
