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
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.security.KeyPair
import java.security.Signature
import java.security.interfaces.ECPublicKey

/**
 * Bounds of the TCG-CSR-IDEVID parser: truncation at every offset, bytes past
 * the signature, and public areas the CSR carries but that do not parse.
 */
class TcgCsrIDevIDBoundsTest {

    private val idevidKeys: KeyPair = TpmTestStructures.generateEcKeyPair()

    private fun ecdsa(keys: KeyPair, data: ByteArray): ByteArray =
        Signature.getInstance("SHA256withECDSA").apply {
            initSign(keys.private)
            update(data)
        }.sign()

    private fun publicArea(keys: KeyPair, attributes: Int) =
        TpmTestStructures.eccPublicArea(keys.public as ECPublicKey, attributes)

    private fun packCsr(
        attestPub: ByteArray = publicArea(TpmTestStructures.generateEcKeyPair(), TpmTestStructures.IAK_ATTRIBUTES),
        signingPub: ByteArray = publicArea(idevidKeys, TpmTestStructures.IDEVID_ATTRIBUTES)
    ): ByteArray {
        val contents = TpmTestStructures.csrContents(
            prodCaData = byteArrayOf(9, 8, 7),
            attestPub = attestPub,
            atCertifyInfo = byteArrayOf(1, 2, 3, 4),
            atCertifyInfoSig = byteArrayOf(5, 6),
            signingPub = signingPub,
            sgnCertifyInfo = byteArrayOf(7, 8, 9),
            sgnCertifyInfoSig = byteArrayOf(10),
            pad = byteArrayOf(0, 0)
        )
        return TpmTestStructures.packCsr(contents, ecdsa(idevidKeys, contents))
    }

    private inline fun <reified T : Throwable> refused(block: () -> Unit): T {
        try {
            block()
        } catch (e: Throwable) {
            assertEquals("exception type", T::class.java, e.javaClass)
            return e as T
        }
        fail("expected ${T::class.java.simpleName}")
        throw AssertionError("unreachable")
    }

    @Test
    fun `every prefix of a valid CSR is refused as a CSR error`() {
        val packed = packCsr()
        TcgCsrIDevID.parse(packed).verifySelfSignature()
        for (n in 0 until packed.size) {
            refused<TcgCsrException> { TcgCsrIDevID.parse(packed.copyOf(n)) }
        }
    }

    @Test
    fun `bytes after the signature are ignored (recorded)`() {
        // The signature size is declared in the header, so trailing bytes are
        // never read: the CSR parses, the signature excludes them and the
        // self-signature still verifies.
        val packed = packCsr()
        val parsed = TcgCsrIDevID.parse(packed)
        val padded = TcgCsrIDevID.parse(packed + byteArrayOf(1, 2, 3))
        assertArrayEquals(parsed.signature, padded.signature)
        assertArrayEquals(parsed.contents, padded.contents)
        padded.verifySelfSignature()
    }

    @Test
    fun `an unreadable IAK public area is refused as a CSR error`() {
        val csr = TcgCsrIDevID.parse(packCsr(attestPub = byteArrayOf(0, 0x23, 0)))
        val e = refused<TcgCsrException> { csr.verifySelfSignature() }
        assertTrue(e.message!!.contains("IAK public area is unreadable"))
    }

    @Test
    fun `an unreadable IDevID public area is refused as a CSR error`() {
        val csr = TcgCsrIDevID.parse(packCsr(signingPub = byteArrayOf(0, 0x01)))
        val e = refused<TcgCsrException> { csr.verifySelfSignature() }
        assertTrue(e.message!!.contains("IDevID public area is unreadable"))
    }

    @Test
    fun `an empty IAK public area is refused as a CSR error`() {
        val csr = TcgCsrIDevID.parse(packCsr(attestPub = ByteArray(0)))
        refused<TcgCsrException> { csr.verifySelfSignature() }
    }

    @Test
    fun `reading the iak property directly throws the structure error (recorded)`() {
        // Enrollment reads csr.iak only after verifySelfSignature, which
        // converts the error; the property itself does not.
        val csr = TcgCsrIDevID.parse(packCsr(attestPub = byteArrayOf(0, 0x23, 0)))
        refused<TpmStructureException> { csr.iak }
    }

    @Test
    fun `certify verifier accepts an attester that is not restricted (recorded)`() {
        // TpmCertifyVerifier checks no attribute of the attester; enrollment
        // relies on verifySelfSignature having refused an unrestricted IAK.
        val attesterKeys = TpmTestStructures.generateEcKeyPair()
        val attester = TpmPublicArea.parse(publicArea(attesterKeys, TpmTestStructures.IDEVID_ATTRIBUTES))
        assertFalse(attester.isRestricted)
        val subject = TpmPublicArea.parse(publicArea(idevidKeys, TpmTestStructures.IDEVID_ATTRIBUTES))
        val certifyInfo = TpmTestStructures.certifyAttest(attester.name(), subject.name())

        val attest = TpmCertifyVerifier.verify(attester, subject, certifyInfo, ecdsa(attesterKeys, certifyInfo))
        assertArrayEquals(subject.name(), attest.certifiedName)
    }
}
