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
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.security.KeyPair
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

/**
 * Covers the CA's reading of a TCG-CSR-IDEVID: what it accepts, and every way it
 * must refuse.
 *
 * A CA that mis-parses this structure signs the wrong key; one that skips the
 * signature or the TPMA_OBJECT attributes signs a key that may not be in a TPM
 * at all. Each refusal below is a real enrollment that must not complete.
 */
class TcgCsrIDevIDTest {

    private class Package(val packed: ByteArray, val iakPub: ByteArray, val idevidPub: ByteArray)

    private fun buildPackage(
        iakKeys: KeyPair = TpmTestStructures.generateEcKeyPair(),
        idevidKeys: KeyPair = TpmTestStructures.generateEcKeyPair(),
        iakAttributes: Int = TpmTestStructures.IAK_ATTRIBUTES,
        idevidAttributes: Int = TpmTestStructures.IDEVID_ATTRIBUTES,
        signWith: PrivateKey = idevidKeys.private,
        signatureAlgorithm: String = "SHA256withECDSA",
        hashAlgId: Int = TpmAlg.SHA256,
        ekCert: ByteArray = ByteArray(0)
    ): Package {
        val iakPub = TpmTestStructures.eccPublicArea(iakKeys.public as ECPublicKey, iakAttributes)
        val idevidPub =
            TpmTestStructures.eccPublicArea(idevidKeys.public as ECPublicKey, idevidAttributes)
        val contents = TpmTestStructures.csrContents(
            hashAlgId = hashAlgId,
            ekCert = ekCert,
            attestPub = iakPub,
            signingPub = idevidPub
        )
        val signature = Signature.getInstance(signatureAlgorithm).apply {
            initSign(signWith)
            update(contents)
        }.sign()
        return Package(TpmTestStructures.packCsr(contents, signature), iakPub, idevidPub)
    }

    // ---------------------------------------------------------------
    // Parsing
    // ---------------------------------------------------------------

    @Test
    fun `parses the fields a CA reads`() {
        val pkg = buildPackage()
        val csr = TcgCsrIDevID.parse(pkg.packed)

        assertArrayEquals(pkg.iakPub, csr.attestPub)
        assertArrayEquals(pkg.idevidPub, csr.signingPub)
        assertEquals(TpmAlg.SHA256, csr.hashAlgId)
        assertEquals("TEST-MODEL", String(csr.prodModel))
        assertEquals("TEST-SERIAL", String(csr.prodSerial))
    }

    @Test
    fun `refuses a CSR too short to hold its own header`() {
        try {
            TcgCsrIDevID.parse(ByteArray(20))
            fail("a truncated CSR must not parse")
        } catch (e: TcgCsrException) {
            assertTrue(e.message!!.contains("too short"))
        }
    }

    @Test
    fun `refuses a field that runs past the end of the CSR`() {
        val pkg = buildPackage()
        val truncated = pkg.packed.copyOfRange(0, pkg.packed.size - 8)
        try {
            TcgCsrIDevID.parse(truncated)
            fail("a CSR whose fields overrun must not parse")
        } catch (e: TcgCsrException) {
            assertTrue(e.message!!.contains("remain"))
        }
    }

    @Test
    fun `refuses an implausible field size rather than allocating it`() {
        val pkg = buildPackage()
        val hostile = pkg.packed.copyOf()
        // The prodModel size is the fourth uint32 of the contents block, which
        // begins at offset 12.
        val offset = 12 + 3 * 4
        hostile[offset] = 0x7F
        hostile[offset + 1] = 0xFF.toByte()
        hostile[offset + 2] = 0xFF.toByte()
        hostile[offset + 3] = 0xFF.toByte()
        try {
            TcgCsrIDevID.parse(hostile)
            fail("an implausible size must be refused")
        } catch (e: TcgCsrException) {
            assertTrue(e.message!!.contains("implausible"))
        }
    }

    // ---------------------------------------------------------------
    // Verification
    // ---------------------------------------------------------------

    @Test
    fun `accepts a well-formed ECDSA package`() {
        TcgCsrIDevID.parse(buildPackage().packed).verifySelfSignature()
    }

    @Test
    fun `accepts a well-formed RSA package`() {
        val iakKeys = TpmTestStructures.generateRsaKeyPair()
        val idevidKeys = TpmTestStructures.generateRsaKeyPair()
        val iakPub = TpmTestStructures.rsaPublicArea(
            iakKeys.public as RSAPublicKey, TpmTestStructures.IAK_ATTRIBUTES
        )
        val idevidPub = TpmTestStructures.rsaPublicArea(
            idevidKeys.public as RSAPublicKey, TpmTestStructures.IDEVID_ATTRIBUTES
        )
        val contents = TpmTestStructures.csrContents(attestPub = iakPub, signingPub = idevidPub)
        val signature = Signature.getInstance("SHA256withRSA").apply {
            initSign(idevidKeys.private)
            update(contents)
        }.sign()

        TcgCsrIDevID.parse(TpmTestStructures.packCsr(contents, signature)).verifySelfSignature()
    }

    @Test
    fun `refuses a signature made by the wrong key`() {
        val idevidKeys = TpmTestStructures.generateEcKeyPair()
        val impostor = TpmTestStructures.generateEcKeyPair()
        val pkg = buildPackage(idevidKeys = idevidKeys, signWith = impostor.private)
        expectRefusal(pkg.packed, "does not verify")
    }

    @Test
    fun `refuses a tampered contents block`() {
        val pkg = buildPackage()
        val tampered = pkg.packed.copyOf()
        // Flip a byte of prodSerial, which is inside the signed contents.
        val serialOffset = 12 + 16 * 4 + "TEST-MODEL".length
        tampered[serialOffset] = (tampered[serialOffset] + 1).toByte()
        expectRefusal(tampered, "does not verify")
    }

    @Test
    fun `refuses a CSR with no signature`() {
        val pkg = buildPackage()
        val csr = TcgCsrIDevID.parse(pkg.packed)
        val unsigned = TpmTestStructures.packCsr(csr.contents, ByteArray(0))
        expectRefusal(unsigned, "no signature")
    }

    @Test
    fun `refuses an IAK that is not restricted`() {
        val pkg = buildPackage(
            iakAttributes = TpmTestStructures.IAK_ATTRIBUTES and TpmObjectAttributes.RESTRICTED.inv()
        )
        expectRefusal(pkg.packed, "IAK is not a restricted key")
    }

    @Test
    fun `refuses an IAK that is not fixedTPM`() {
        val pkg = buildPackage(
            iakAttributes = TpmTestStructures.IAK_ATTRIBUTES and TpmObjectAttributes.FIXED_TPM.inv()
        )
        expectRefusal(pkg.packed, "IAK is not fixedTPM")
    }

    @Test
    fun `refuses an IAK that cannot sign`() {
        val pkg = buildPackage(
            iakAttributes =
                TpmTestStructures.IAK_ATTRIBUTES and TpmObjectAttributes.SIGN_ENCRYPT.inv()
        )
        expectRefusal(pkg.packed, "IAK is not a signing key")
    }

    @Test
    fun `refuses an IDevID that is restricted`() {
        val pkg = buildPackage(
            idevidAttributes = TpmTestStructures.IDEVID_ATTRIBUTES or TpmObjectAttributes.RESTRICTED
        )
        expectRefusal(pkg.packed, "IDevID is a restricted key")
    }

    @Test
    fun `refuses an IDevID that is not fixedParent`() {
        val pkg = buildPackage(
            idevidAttributes =
                TpmTestStructures.IDEVID_ATTRIBUTES and TpmObjectAttributes.FIXED_PARENT.inv()
        )
        expectRefusal(pkg.packed, "IDevID is not fixedParent")
    }

    @Test
    fun `refuses a hash algorithm it cannot compute`() {
        val pkg = buildPackage(hashAlgId = 0x0027)
        expectRefusal(pkg.packed, "unsupported hash algorithm")
    }

    // ---------------------------------------------------------------
    // EK certificate handling
    // ---------------------------------------------------------------

    @Test
    fun `refuses a CSR with no EK certificate`() {
        val csr = TcgCsrIDevID.parse(buildPackage().packed)
        try {
            csr.ekCertificate()
            fail("a CSR with no EK certificate must not yield one")
        } catch (e: TcgCsrException) {
            assertTrue(e.message!!.contains("no EK certificate"))
        }
    }

    @Test
    fun `refuses bytes that are not a certificate`() {
        try {
            TcgCsrIDevID.parseCertificate("not a certificate".toByteArray())
            fail("arbitrary bytes must not parse as a certificate")
        } catch (e: TcgCsrException) {
            assertTrue(e.message!!.contains("X.509"))
        }
    }

    private fun expectRefusal(packed: ByteArray, expectedReason: String) {
        try {
            TcgCsrIDevID.parse(packed).verifySelfSignature()
            fail("expected refusal containing '$expectedReason'")
        } catch (e: TcgCsrException) {
            assertTrue(
                "expected '$expectedReason' but got '${e.message}'",
                e.message!!.contains(expectedReason)
            )
        }
    }
}
