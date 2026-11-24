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

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.security.KeyPair
import java.security.Security
import java.security.Signature

/**
 * Covers the PCR selection inside a quote, the signature schemes a real IAK
 * uses beyond P-256, and the binding between the PCR values the desktop
 * reports and the pcrDigest the TPM signed.
 */
class TpmQuoteBindingTest {

    private val nonce = ByteArray(32) { (it * 7 + 3).toByte() }

    private var addedProvider = false

    @Before
    fun registerBouncyCastle() {
        // Android resolves SHA256withRSA/PSS through its own providers; the
        // host JDK has no such name, so the verifier finds it in Bouncy Castle.
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
            addedProvider = true
        }
    }

    @After
    fun removeBouncyCastle() {
        if (addedProvider) Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
    }

    private fun ecdsa(keys: KeyPair, data: ByteArray, alg: String = "SHA256withECDSA"): ByteArray =
        Signature.getInstance(alg).apply {
            initSign(keys.private)
            update(data)
        }.sign()

    /** Runs [block] and insists it throws exactly [TpmQuoteException]. */
    private fun refused(block: () -> Unit): TpmQuoteException {
        try {
            block()
        } catch (e: Throwable) {
            assertEquals("exception type", TpmQuoteException::class.java, e.javaClass)
            return e as TpmQuoteException
        }
        fail("expected TpmQuoteException")
        throw AssertionError("unreachable")
    }

    // ---------------------------------------------------------------
    // Signature schemes
    // ---------------------------------------------------------------

    @Test
    fun `an RSA-PSS IAK quote verifies`() {
        val keys = TpmTestStructures.generateRsaKeyPair()
        val iak = TpmTestStructures.rsaPssIak(keys)
        val quoted = TpmTestStructures.quoteAttest(iak.name(), nonce)
        val signature = TpmTestStructures.signRsaPss(keys.private, quoted)

        val attest = TpmQuoteVerifier.verify(iak, quoted, signature, nonce)
        assertArrayEquals(nonce, attest.extraData)
    }

    @Test
    fun `a PSS signature with the maximum salt length is refused (recorded)`() {
        // Salt = modulus bytes - hash length - 2. The verifier fixes the salt
        // at the hash length, so a TPM that signs with the maximum salt fails.
        val keys = TpmTestStructures.generateRsaKeyPair()
        val iak = TpmTestStructures.rsaPssIak(keys)
        val quoted = TpmTestStructures.quoteAttest(iak.name(), nonce)
        val signature = TpmTestStructures.signRsaPss(keys.private, quoted, saltLength = 256 - 32 - 2)

        val e = refused { TpmQuoteVerifier.verify(iak, quoted, signature, nonce) }
        assertTrue(e.message!!.contains("does not verify"))
    }

    @Test
    fun `a P-384 IAK with a SHA-384 scheme verifies`() {
        val keys = TpmTestStructures.generateEcKeyPair("secp384r1")
        val iak = TpmTestStructures.p384Iak(keys)
        assertEquals(TpmAlg.SHA384, iak.nameAlg)
        val quoted = TpmTestStructures.quoteAttest(iak.name(), nonce)
        val signature = ecdsa(keys, quoted, "SHA384withECDSA")

        TpmQuoteVerifier.verify(iak, quoted, signature, nonce)
    }

    @Test
    fun `a P-384 quote signed over SHA-256 is refused`() {
        val keys = TpmTestStructures.generateEcKeyPair("secp384r1")
        val iak = TpmTestStructures.p384Iak(keys)
        val quoted = TpmTestStructures.quoteAttest(iak.name(), nonce)
        val signature = ecdsa(keys, quoted, "SHA256withECDSA")

        refused { TpmQuoteVerifier.verify(iak, quoted, signature, nonce) }
    }

    // ---------------------------------------------------------------
    // PCR selection structure
    // ---------------------------------------------------------------

    private fun quoteWithSelection(selection: ByteArray) = TpmTestStructures.quoteAttestWithSelection(
        qualifiedSigner = ByteArray(34),
        extraData = nonce,
        selection = selection,
        pcrDigest = ByteArray(32)
    )

    @Test
    fun `refuses a selection count of 17`() {
        val selection = TpmTestStructures.pcrSelection(List(17) { TpmAlg.SHA256 to setOf(0) })
        val e = refused { TpmAttest.parse(quoteWithSelection(selection)) }
        assertTrue(e.message!!.contains("17"))
    }

    @Test
    fun `refuses a sizeOfSelect that runs past the end`() {
        // One SHA-256 selection declaring a 255-byte bitmap; only the 34-byte
        // pcrDigest follows it.
        val selection = byteArrayOf(0, 0, 0, 1, 0, TpmAlg.SHA256.toByte(), 0xFF.toByte())
        val e = refused { TpmAttest.parse(quoteWithSelection(selection)) }
        assertTrue(e.message!!.contains("past the end"))
    }

    @Test
    fun `every prefix of a quote is refused as a quote error`() {
        val quoted = TpmTestStructures.quoteAttest(ByteArray(34), nonce)
        TpmAttest.parse(quoted)
        for (n in 0 until quoted.size) {
            refused { TpmAttest.parse(quoted.copyOf(n)) }
        }
    }

    // ---------------------------------------------------------------
    // Binding the reported PCR values to the signed digest
    // ---------------------------------------------------------------

    private val requested = (0..7).toSet()

    private fun pcrValues(size: Int, indices: Set<Int> = requested): Map<Int, ByteArray> =
        indices.associateWith { i -> ByteArray(size) { (i * 31 + it).toByte() } }

    private class BoundQuote(val iak: TpmPublicArea, val quoted: ByteArray, val signature: ByteArray)

    /** A P-256 IAK quote over [selected] in [bank], digesting [signedValues]. */
    private fun boundQuote(
        signedValues: Map<Int, ByteArray>,
        bank: Int = TpmAlg.SHA256,
        selected: Set<Int> = signedValues.keys
    ): BoundQuote {
        val keys = TpmTestStructures.generateEcKeyPair()
        val iak = TpmPublicArea.parse(
            TpmTestStructures.eccPublicArea(
                keys.public as java.security.interfaces.ECPublicKey, TpmTestStructures.IAK_ATTRIBUTES
            )
        )
        val quoted = TpmTestStructures.quoteAttest(
            qualifiedSigner = iak.name(),
            extraData = nonce,
            bank = bank,
            pcrIndices = selected,
            pcrDigest = TpmTestStructures.pcrDigest(iak.schemeHashAlg, signedValues)
        )
        return BoundQuote(iak, quoted, ecdsa(keys, quoted))
    }

    @Test
    fun `a quote whose pcrDigest matches the reported values verifies`() {
        val values = pcrValues(32)
        val q = boundQuote(values)
        TpmQuoteVerifier.verify(q.iak, q.quoted, q.signature, nonce, "sha256", values)
    }

    @Test
    fun `a P-384 quote bound in the sha384 bank verifies`() {
        val keys = TpmTestStructures.generateEcKeyPair("secp384r1")
        val iak = TpmTestStructures.p384Iak(keys)
        val values = pcrValues(48)
        val quoted = TpmTestStructures.quoteAttest(
            qualifiedSigner = iak.name(),
            extraData = nonce,
            bank = TpmAlg.SHA384,
            pcrIndices = requested,
            pcrDigest = TpmTestStructures.pcrDigest(TpmAlg.SHA384, values)
        )
        val signature = ecdsa(keys, quoted, "SHA384withECDSA")
        TpmQuoteVerifier.verify(iak, quoted, signature, nonce, "sha384", values)
    }

    @Test
    fun `refuses reported PCR values that differ from the signed digest`() {
        val values = pcrValues(32)
        val q = boundQuote(values)
        val reported = values.toMutableMap().apply { put(4, ByteArray(32) { 0x5A }) }

        val e = refused {
            TpmQuoteVerifier.verify(q.iak, q.quoted, q.signature, nonce, "sha256", reported)
        }
        assertTrue(e.message!!.contains("digest"))
    }

    @Test
    fun `refuses a quote whose selection names a different bank than requested`() {
        val values = pcrValues(32)
        val q = boundQuote(values, bank = TpmAlg.SHA1)

        val e = refused {
            TpmQuoteVerifier.verify(q.iak, q.quoted, q.signature, nonce, "sha256", values)
        }
        assertTrue(e.message!!.contains("bank"))
    }

    @Test
    fun `refuses a quote whose selection misses a requested index`() {
        // The signed digest covers PCRs 0-6 only; PCR 7 is reported beside
        // the quote but nothing signed vouches for it.
        val values = pcrValues(32)
        val q = boundQuote(values.filterKeys { it != 7 })

        val e = refused {
            TpmQuoteVerifier.verify(q.iak, q.quoted, q.signature, nonce, "sha256", values)
        }
        assertTrue(e.message!!.contains("PCRs"))
    }

    @Test
    fun `refuses a quote selecting PCRs that were not reported`() {
        val values = pcrValues(32)
        val q = boundQuote(values, selected = requested + 8)

        refused {
            TpmQuoteVerifier.verify(q.iak, q.quoted, q.signature, nonce, "sha256", values)
        }
    }
}
