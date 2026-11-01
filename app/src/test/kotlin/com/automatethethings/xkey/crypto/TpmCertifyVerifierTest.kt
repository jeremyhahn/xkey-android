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
package com.automatethethings.xkey.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPair
import java.security.Signature
import java.security.interfaces.ECPublicKey

/**
 * Covers the check that binds a device's signing key to its attestation key.
 *
 * Credential activation proves the IAK sits in the TPM holding the endorsement
 * key, and the quote proves that IAK signs the TPM's current state. Neither
 * says anything about the IDevID. The CSR's own self-signature proves only that
 * the requester holds the IDevID private key — which is exactly as true of a
 * key generated in software.
 *
 * So without this verification a device with a real TPM can be issued a device
 * identity certificate over a software key, and every relying party afterwards
 * reads that certificate as a hardware-resident identity.
 */
class TpmCertifyVerifierTest {

    private val nonce = ByteArray(32) { (it * 7 + 3).toByte() }

    private class Certification(
        val certifyInfo: ByteArray,
        val signature: ByteArray,
        val attester: TpmPublicArea,
        val subject: TpmPublicArea
    )

    /**
     * Builds a certification of [subjectKeys] by [attesterKeys].
     *
     * Each parameter exists so one property can be spoiled at a time while
     * everything else stays genuine — that is what makes each refusal below
     * attributable to the thing it names.
     */
    private fun buildCertification(
        attesterKeys: KeyPair = TpmTestStructures.generateEcKeyPair(),
        subjectKeys: KeyPair = TpmTestStructures.generateEcKeyPair(),
        signWith: KeyPair = attesterKeys,
        certifiedName: ByteArray? = null,
        signerName: ByteArray? = null,
        extraData: ByteArray = ByteArray(0),
        magic: Int = TpmAttest.TPM_GENERATED,
        type: Int = TpmAttest.ST_ATTEST_CERTIFY
    ): Certification {
        val attester = TpmPublicArea.parse(
            TpmTestStructures.eccPublicArea(
                attesterKeys.public as ECPublicKey, TpmTestStructures.IAK_ATTRIBUTES
            )
        )
        val subject = TpmPublicArea.parse(
            TpmTestStructures.eccPublicArea(
                subjectKeys.public as ECPublicKey, TpmTestStructures.IAK_ATTRIBUTES
            )
        )

        val certifyInfo = TpmTestStructures.certifyAttest(
            qualifiedSigner = signerName ?: attester.name(),
            certifiedName = certifiedName ?: subject.name(),
            extraData = extraData,
            magic = magic,
            type = type
        )
        val signature = Signature.getInstance("SHA256withECDSA").apply {
            initSign(signWith.private)
            update(certifyInfo)
        }.sign()

        return Certification(certifyInfo, signature, attester, subject)
    }

    @Test
    fun `a genuine certification verifies`() {
        val c = buildCertification()

        val attest = TpmCertifyVerifier.verify(c.attester, c.subject, c.certifyInfo, c.signature)

        assertArrayEquals(c.subject.name(), attest.certifiedName)
        assertArrayEquals(c.attester.name(), attest.qualifiedSigner)
    }

    @Test
    fun `a certification of a different key is refused`() {
        // Entirely genuine: a real attestation key certified a real key. It
        // simply is not the key being presented for certification, which is
        // exactly what pairing borrowed hardware evidence with your own key
        // looks like.
        val stranger = TpmTestStructures.generateEcKeyPair()
        val strangerArea = TpmPublicArea.parse(
            TpmTestStructures.eccPublicArea(
                stranger.public as ECPublicKey, TpmTestStructures.IAK_ATTRIBUTES
            )
        )
        val c = buildCertification()

        val error = assertThrows(TpmQuoteException::class.java) {
            TpmCertifyVerifier.verify(c.attester, strangerArea, c.certifyInfo, c.signature)
        }
        assertTrue(
            "should name the key mismatch: ${error.message}",
            error.message!!.contains("different key")
        )
    }

    @Test
    fun `a certification signed by another key is refused`() {
        val c = buildCertification(signWith = TpmTestStructures.generateEcKeyPair())

        val error = assertThrows(TpmQuoteException::class.java) {
            TpmCertifyVerifier.verify(c.attester, c.subject, c.certifyInfo, c.signature)
        }
        assertTrue(
            "should name the signature: ${error.message}",
            error.message!!.contains("signature")
        )
    }

    @Test
    fun `a certification naming another signer is refused`() {
        // Signed correctly by the IAK, but claiming a different signer inside
        // the signed body. A verifier that only checked the signature would
        // accept a structure that describes a key it never examined.
        val c = buildCertification(signerName = ByteArray(34) { 0x5A })

        val error = assertThrows(TpmQuoteException::class.java) {
            TpmCertifyVerifier.verify(c.attester, c.subject, c.certifyInfo, c.signature)
        }
        assertTrue(
            "should name the signer: ${error.message}",
            error.message!!.contains("signer")
        )
    }

    @Test
    fun `hand-built attestation bytes are refused`() {
        // The magic is the one field a TPM will not write over caller-chosen
        // data, so it is what separates "a TPM said this" from "somebody with a
        // key said this".
        val c = buildCertification(magic = 0xDEADBEEF.toInt())

        val error = assertThrows(TpmQuoteException::class.java) {
            TpmCertifyVerifier.verify(c.attester, c.subject, c.certifyInfo, c.signature)
        }
        assertTrue(
            "should name TPM_GENERATED: ${error.message}",
            error.message!!.contains("TPM_GENERATED")
        )
    }

    @Test
    fun `a quote cannot stand in for a certification`() {
        // A quote is genuine and TPM-generated; it just attests PCR state
        // rather than a key, so reading a certified name out of it would be
        // reading whichever bytes sit at that offset.
        val c = buildCertification(type = TpmAttest.ST_ATTEST_QUOTE)

        val error = assertThrows(TpmQuoteException::class.java) {
            TpmCertifyVerifier.verify(c.attester, c.subject, c.certifyInfo, c.signature)
        }
        assertTrue(
            "should name the type: ${error.message}",
            error.message!!.contains("type")
        )
    }

    @Test
    fun `an absent certification is refused rather than skipped`() {
        // A CSR that simply omits the certification must not sail through: the
        // whole point is that its absence is what an attacker wants.
        val c = buildCertification()

        assertThrows(TpmQuoteException::class.java) {
            TpmCertifyVerifier.verify(c.attester, c.subject, ByteArray(0), c.signature)
        }
        assertThrows(TpmQuoteException::class.java) {
            TpmCertifyVerifier.verify(c.attester, c.subject, c.certifyInfo, ByteArray(0))
        }
    }

    @Test
    fun `a nonce is checked when one is supplied`() {
        val c = buildCertification(extraData = nonce)

        TpmCertifyVerifier.verify(c.attester, c.subject, c.certifyInfo, c.signature, nonce)

        val error = assertThrows(TpmQuoteException::class.java) {
            TpmCertifyVerifier.verify(
                c.attester, c.subject, c.certifyInfo, c.signature,
                ByteArray(32) { 0x11 }
            )
        }
        assertTrue(
            "should name the nonce: ${error.message}",
            error.message!!.contains("nonce")
        )
    }
}
